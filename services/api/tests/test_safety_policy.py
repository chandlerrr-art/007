import unittest

from app.models import Target
from app.safety.policy import ScopeRejected, assert_request_scope, validate_target_url
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


if __name__ == "__main__":
    unittest.main()
