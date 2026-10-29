import unittest

from app.models import Target
from app.safety.policy import ScopeRejected, TokenBucket, assert_request_scope, redact_operational_text, supports_demo_executor, validate_target_url
from app.settings import settings


class TargetScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original = settings.allowed_target_origins
        settings.allowed_target_origins = "http://demo-app:8080,http://localhost:8080"

    def tearDown(self) -> None:
        settings.allowed_target_origins = self.original

    def test_allows_configured_local_demo_origin(self) -> None:
        self.assertEqual(validate_target_url("http://demo-app:8080"), "http://demo-app:8080")

    def test_rejects_origin_outside_allowlist(self) -> None:
        with self.assertRaises(ScopeRejected):
            validate_target_url("https://example.com")

    def test_rejects_credentials_embedded_in_target_url(self) -> None:
        with self.assertRaises(ScopeRejected):
            validate_target_url("http://user:password@demo-app:8080")

    def test_each_request_must_keep_the_approved_origin(self) -> None:
        target = Target(name="demo", base_url="http://demo-app:8080", environment="local", status="authorized")
        assert_request_scope(target, "http://demo-app:8080/api/v1/bookings/2002")
        with self.assertRaises(ScopeRejected):
            assert_request_scope(target, "http://example.com/api/v1/bookings/2002")

    def test_malformed_port_is_a_scope_rejection(self) -> None:
        with self.assertRaises(ScopeRejected):
            validate_target_url("http://demo-app:not-a-port")

    def test_executor_is_limited_to_the_synthetic_demo_environment(self) -> None:
        demo = Target(name="demo", base_url="http://demo-app:8080", environment="local-demo", status="authorized")
        staging = Target(name="staging", base_url="http://demo-app:8080", environment="staging", status="authorized")
        self.assertTrue(supports_demo_executor(demo))
        self.assertFalse(supports_demo_executor(staging))

    def test_operational_text_redacts_credentials_and_identifiers(self) -> None:
        safe = redact_operational_text("incident Bearer abc.def password=hunter email=dev@example.com +1 (555) 123-4567")
        self.assertNotIn("abc.def", safe)
        self.assertNotIn("hunter", safe)
        self.assertNotIn("dev@example.com", safe)
        self.assertNotIn("555", safe)


class TokenBucketTests(unittest.TestCase):
    def test_allows_up_to_capacity_then_blocks(self) -> None:
        bucket = TokenBucket(capacity=2, refill_per_second=0.0)
        self.assertTrue(bucket.allow("endpoint-a"))
        self.assertTrue(bucket.allow("endpoint-a"))
        self.assertFalse(bucket.allow("endpoint-a"))

    def test_keys_are_independent(self) -> None:
        bucket = TokenBucket(capacity=1, refill_per_second=0.0)
        self.assertTrue(bucket.allow("endpoint-a"))
        self.assertFalse(bucket.allow("endpoint-a"))
        self.assertTrue(bucket.allow("endpoint-b"))


if __name__ == "__main__":
    unittest.main()
