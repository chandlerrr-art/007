import base64
import hashlib
import hmac
import os
import threading
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.db import Base
from app.settings import settings


# In-memory registry of known secret values for dynamic redaction.
# Ensures that even if a secret is somehow formatted unexpectedly, it is scrubbed.
_KNOWN_SECRETS_LOCK = threading.Lock()
_KNOWN_SECRETS: set[str] = set()


def register_secret_for_redaction(secret: str) -> None:
    """Register a cleartext secret into the memory scrubbing set."""
    cleaned = secret.strip()
    if len(cleaned) >= 4:  # Avoid matching single short common strings
        with _KNOWN_SECRETS_LOCK:
            _KNOWN_SECRETS.add(cleaned)


def scrub_known_secrets(text: str) -> str:
    """Scrub any dynamically registered secret strings from text."""
    if not text:
        return ""
    with _KNOWN_SECRETS_LOCK:
        secrets_snapshot = list(_KNOWN_SECRETS)
    for secret in secrets_snapshot:
        if secret in text:
            text = text.replace(secret, "[REDACTED_CREDENTIAL]")
    return text


def _derive_keys(master_key: str, salt: bytes) -> tuple[bytes, bytes]:
    """Derive 32-byte encryption key and 32-byte HMAC key using PBKDF2."""
    derived = hashlib.pbkdf2_hmac("sha256", master_key.encode("utf-8"), salt, 100_000, dklen=64)
    return derived[:32], derived[32:]


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """Deterministic HMAC-SHA256 keystream (CTR mode)."""
    blocks = []
    counter = 0
    generated = 0
    while generated < length:
        block = hmac.new(enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        blocks.append(block)
        generated += len(block)
        counter += 1
    return b"".join(blocks)[:length]


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret for storage at rest with authenticated encryption."""
    if not plaintext:
        return ""
    register_secret_for_redaction(plaintext)
    master_key = getattr(settings, "credential_encryption_key", "007-staging-secret-encryption-master-key-v1")
    salt = os.urandom(16)
    nonce = os.urandom(16)
    enc_key, mac_key = _derive_keys(master_key, salt)
    
    raw_data = plaintext.encode("utf-8")
    stream = _keystream(enc_key, nonce, len(raw_data))
    ciphertext = bytes(a ^ b for a, b in zip(raw_data, stream))
    
    tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
    payload = salt + nonce + tag + ciphertext
    return base64.urlsafe_b64encode(payload).decode("ascii")


def decrypt_secret(encrypted_value: str) -> str:
    """Decrypt an encrypted-at-rest secret."""
    if not encrypted_value:
        return ""
    try:
        payload = base64.urlsafe_b64decode(encrypted_value.encode("ascii"))
        if len(payload) < 16 + 16 + 32:
            return ""
        salt = payload[:16]
        nonce = payload[16:32]
        expected_tag = payload[32:64]
        ciphertext = payload[64:]
        
        master_key = getattr(settings, "credential_encryption_key", "007-staging-secret-encryption-master-key-v1")
        enc_key, mac_key = _derive_keys(master_key, salt)
        
        computed_tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_tag, computed_tag):
            raise ValueError("Credential integrity verification failed.")
        
        stream = _keystream(enc_key, nonce, len(ciphertext))
        decrypted = bytes(a ^ b for a, b in zip(ciphertext, stream)).decode("utf-8")
        register_secret_for_redaction(decrypted)
        return decrypted
    except Exception as exc:
        raise ValueError("Failed to decrypt stored credential.") from exc


class TestAccountCredential(Base):
    """Scoped test account credentials for staging targets. Stored encrypted at rest."""
    __tablename__ = "test_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[str] = mapped_column(String(80), nullable=False)  # e.g. admin, travel_agent, customer
    username: Mapped[str] = mapped_column(String(120), nullable=False)
    auth_type: Mapped[str] = mapped_column(String(40), default="bearer")  # bearer, basic, header, api_key
    header_name: Mapped[str] = mapped_column(String(80), default="Authorization")
    encrypted_secret: Mapped[str] = mapped_column(Text(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


def store_credential(
    db: Session,
    target_id: int,
    role: str,
    username: str,
    secret: str,
    auth_type: str = "bearer",
    header_name: str = "Authorization",
) -> TestAccountCredential:
    """Store test credential encrypted at rest and register secret into redaction set."""
    encrypted = encrypt_secret(secret)
    credential = TestAccountCredential(
        target_id=target_id,
        role=role,
        username=username,
        auth_type=auth_type,
        header_name=header_name,
        encrypted_secret=encrypted,
    )
    db.add(credential)
    db.commit()
    db.refresh(credential)
    return credential


def get_call_time_auth_headers(db: Session, target_id: int, role: str) -> dict[str, str]:
    """Strict call-time injection: decrypts credential strictly when constructing the request.
    
    The returned headers must be used directly in the outbound HTTP request and NEVER logged.
    """
    credential = db.execute(
        select(TestAccountCredential)
        .where(TestAccountCredential.target_id == target_id, TestAccountCredential.role == role)
        .order_by(TestAccountCredential.id.desc())
        .limit(1)
    ).scalars().first()
    
    if not credential:
        return {}
    
    secret = decrypt_secret(credential.encrypted_secret)
    if not secret:
        return {}

    auth_type = credential.auth_type.lower()
    header_name = credential.header_name or "Authorization"
    
    if auth_type == "bearer":
        return {header_name: f"Bearer {secret}"}
    elif auth_type == "basic":
        encoded = base64.b64encode(f"{credential.username}:{secret}".encode("utf-8")).decode("ascii")
        return {header_name: f"Basic {encoded}"}
    elif auth_type == "api_key" or auth_type == "header":
        return {header_name: secret}
    else:
        return {header_name: secret}
