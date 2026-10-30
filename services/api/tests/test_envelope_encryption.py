import unittest
from unittest.mock import patch

from app.core.encryption import (
    AESGCMKeyringProvider,
    EncryptionError,
    EnvelopeEncryptionService,
    configure_kek_provider,
    get_encryption_service,
)
from app.settings import settings


class EnvelopeEncryptionTests(unittest.TestCase):
    def setUp(self):
        self.provider = AESGCMKeyringProvider({"test-v1": b"a" * 32}, "test-v1")
        self.service = EnvelopeEncryptionService(self.provider)

    def test_generates_unique_data_keys_and_round_trips_plaintext(self):
        first = self.service.encrypt("provider-token", context="organization:1")
        second = self.service.encrypt("provider-token", context="organization:1")

        self.assertNotEqual(first.ciphertext, second.ciphertext)
        self.assertNotEqual(first.wrapped_dek, second.wrapped_dek)
        self.assertEqual(self.service.decrypt(first, context="organization:1"), "provider-token")
        self.assertEqual(self.service.decrypt(second.as_dict(), context="organization:1"), "provider-token")

    def test_kek_rotation_rewraps_dek_without_changing_ciphertext(self):
        original = self.service.encrypt("rotation-safe", context="ticket:42:organization:7")
        rotated_provider = self.provider.with_rotated_key("test-v2", b"b" * 32)
        rotated_service = EnvelopeEncryptionService(rotated_provider)

        rotated = rotated_service.rewrap(original, context="ticket:42:organization:7")

        self.assertEqual(rotated.ciphertext, original.ciphertext)
        self.assertEqual(rotated.wrapped_dek["key_id"], "test-v2")
        self.assertEqual(rotated_service.decrypt(rotated, context="ticket:42:organization:7"), "rotation-safe")

    def test_context_prevents_cross_tenant_decryption(self):
        envelope = self.service.encrypt("tenant-one-secret", context="organization:1:ticket:42")
        with self.assertRaises(EncryptionError):
            self.service.decrypt(envelope, context="organization:2:ticket:42")

    def test_rejects_short_master_key_secret(self):
        with self.assertRaises(EncryptionError):
            AESGCMKeyringProvider.from_secret("too-short")

    def test_health_check_wraps_and_unwraps_a_probe(self):
        self.service.health_check()

    def test_external_provider_can_be_installed_for_application_services(self):
        configure_kek_provider(self.provider)
        try:
            service = get_encryption_service()
            envelope = service.encrypt("external-provider", context="organization:9")
            self.assertEqual(service.decrypt(envelope, context="organization:9"), "external-provider")
        finally:
            configure_kek_provider(None)

    def test_invalid_key_id_fails_closed(self):
        envelope = self.service.encrypt("secret", context="test")
        wrong_provider = AESGCMKeyringProvider({"other": b"c" * 32}, "other")
        with self.assertRaises(EncryptionError):
            EnvelopeEncryptionService(wrong_provider).decrypt(envelope, context="test")

    def test_tampered_ciphertext_fails_authentication(self):
        envelope = self.service.encrypt("authentic-value", context="test")
        tampered = envelope.as_dict()
        tampered["ciphertext"] = ("A" if tampered["ciphertext"][0] != "A" else "B") + tampered["ciphertext"][1:]
        with self.assertRaises(EncryptionError):
            self.service.decrypt(tampered, context="test")

    def test_environment_provider_requires_configured_master_kek(self):
        with patch.object(settings, "master_kek_secret", ""):
            with self.assertRaises(EncryptionError):
                EnvelopeEncryptionService.from_settings()


if __name__ == "__main__":
    unittest.main()
