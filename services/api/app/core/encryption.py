"""Envelope encryption for sensitive application data."""
import argparse
import base64
import os
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.settings import settings


class EncryptionError(RuntimeError):
    """Raised when an encryption key is unavailable or an envelope is invalid."""


class KEKProvider(Protocol):
    def wrap_key(self, data_key: bytes, *, context: str) -> dict[str, Any]: ...

    def unwrap_key(self, metadata: dict[str, Any], *, context: str) -> bytes: ...


_configured_kek_provider: KEKProvider | None = None


def configure_kek_provider(provider: KEKProvider | None) -> None:
    """Install an external KEK provider during application bootstrap."""
    global _configured_kek_provider
    _configured_kek_provider = provider


@dataclass(frozen=True)
class EncryptedEnvelope:
    ciphertext: str
    wrapped_dek: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"ciphertext": self.ciphertext, "wrapped_dek": self.wrapped_dek}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EncryptedEnvelope":
        if not isinstance(value, dict):
            raise EncryptionError("Encrypted envelope is invalid.")
        ciphertext = value.get("ciphertext")
        wrapped_dek = value.get("wrapped_dek")
        if not isinstance(ciphertext, str) or not ciphertext or not isinstance(wrapped_dek, dict):
            raise EncryptionError("Encrypted envelope is invalid.")
        return cls(ciphertext, wrapped_dek)


class AESGCMKeyringProvider:
    """Local KEK provider; retain old key IDs in the keyring during rotation."""

    def __init__(self, keys: dict[str, bytes], active_key_id: str):
        if not keys or active_key_id not in keys:
            raise EncryptionError("The active KEK is missing from the keyring.")
        if any(not isinstance(key, bytes) or len(key) != 32 for key in keys.values()):
            raise EncryptionError("Every KEK must be exactly 32 bytes.")
        self._keys = dict(keys)
        self.active_key_id = active_key_id

    @classmethod
    def from_secret(cls, secret: str, key_id: str = "env-v1") -> "AESGCMKeyringProvider":
        if len(secret.encode("utf-8")) < 32:
            raise EncryptionError("MASTER_KEK_SECRET must contain at least 32 bytes of high-entropy secret material.")
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"007-envelope-kek-v1",
            info=b"MASTER_KEK_SECRET",
        ).derive(secret.encode("utf-8"))
        return cls({key_id: key}, key_id)

    def with_rotated_key(self, key_id: str, key: bytes) -> "AESGCMKeyringProvider":
        """Return a keyring that uses a new KEK while retaining old wrapped keys."""
        return AESGCMKeyringProvider({**self._keys, key_id: key}, key_id)

    @staticmethod
    def _wrapping_aad(context: str) -> bytes:
        return b"007:wrapped-dek:v1:" + context.encode("utf-8")

    def wrap_key(self, data_key: bytes, *, context: str) -> dict[str, Any]:
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._keys[self.active_key_id]).encrypt(
            nonce, data_key, self._wrapping_aad(context)
        )
        return {
            "version": 1,
            "provider": "aesgcm-keyring",
            "algorithm": "AES-256-GCM",
            "key_id": self.active_key_id,
            "nonce": _encode(nonce),
            "ciphertext": _encode(ciphertext),
        }

    def unwrap_key(self, metadata: dict[str, Any], *, context: str) -> bytes:
        try:
            if metadata.get("version") != 1 or metadata.get("provider") != "aesgcm-keyring":
                raise ValueError("Unsupported wrapped key.")
            key = self._keys[metadata["key_id"]]
            return AESGCM(key).decrypt(
                _decode(metadata["nonce"]),
                _decode(metadata["ciphertext"]),
                self._wrapping_aad(context),
            )
        except (AttributeError, InvalidTag, KeyError, TypeError, ValueError) as exc:
            raise EncryptionError("Unable to unwrap the data encryption key.") from exc


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Encoded value must be text.")
    return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)


class EnvelopeEncryptionService:
    """Encrypt values with unique DEKs and wrap those DEKs with a configured KEK."""

    def __init__(self, kek_provider: KEKProvider):
        self._kek_provider = kek_provider

    @classmethod
    def from_settings(cls) -> "EnvelopeEncryptionService":
        secret = settings.master_kek_secret
        if not secret:
            raise EncryptionError("MASTER_KEK_SECRET is not configured.")
        return cls(AESGCMKeyringProvider.from_secret(secret, settings.master_kek_key_id))

    def encrypt(self, plaintext: str, *, context: str) -> EncryptedEnvelope:
        if not context:
            raise ValueError("Encryption context is required.")
        data_key = os.urandom(32)
        nonce = os.urandom(12)
        ciphertext = AESGCM(data_key).encrypt(
            nonce, plaintext.encode("utf-8"), b"007:data:v1:" + context.encode("utf-8")
        )
        return EncryptedEnvelope(
            ciphertext=_encode(nonce + ciphertext),
            wrapped_dek=self._kek_provider.wrap_key(data_key, context=context),
        )

    def decrypt(self, envelope: EncryptedEnvelope | dict[str, Any], *, context: str) -> str:
        try:
            parsed = EncryptedEnvelope.from_dict(envelope) if isinstance(envelope, dict) else envelope
            packed = _decode(parsed.ciphertext)
            if len(packed) < 12 + 16:
                raise ValueError("Ciphertext is truncated.")
            data_key = self._kek_provider.unwrap_key(parsed.wrapped_dek, context=context)
            plaintext = AESGCM(data_key).decrypt(
                packed[:12], packed[12:], b"007:data:v1:" + context.encode("utf-8")
            )
            return plaintext.decode("utf-8")
        except (AttributeError, InvalidTag, TypeError, ValueError) as exc:
            raise EncryptionError("Unable to decrypt the encrypted envelope.") from exc

    def rewrap(self, envelope: EncryptedEnvelope | dict[str, Any], *, context: str) -> EncryptedEnvelope:
        """Rewrap the existing DEK with the active KEK without re-encrypting data."""
        parsed = EncryptedEnvelope.from_dict(envelope) if isinstance(envelope, dict) else envelope
        data_key = self._kek_provider.unwrap_key(parsed.wrapped_dek, context=context)
        return EncryptedEnvelope(
            ciphertext=parsed.ciphertext,
            wrapped_dek=self._kek_provider.wrap_key(data_key, context=context),
        )

    def health_check(self) -> None:
        probe = self.encrypt("007-envelope-health-check", context="health-check")
        if self.decrypt(probe, context="health-check") != "007-envelope-health-check":
            raise EncryptionError("Envelope encryption health check failed.")


def get_encryption_service() -> EnvelopeEncryptionService:
    if _configured_kek_provider is not None:
        return EnvelopeEncryptionService(_configured_kek_provider)
    return EnvelopeEncryptionService.from_settings()


def main() -> None:
    parser = argparse.ArgumentParser(description="Check envelope encryption configuration.")
    parser.add_argument("--check", action="store_true", help="run a KEK wrap/unwrap health check")
    args = parser.parse_args()
    if not args.check:
        parser.error("specify --check")
    get_encryption_service().health_check()
    print("Envelope encryption KEK health check passed.")


if __name__ == "__main__":
    main()
