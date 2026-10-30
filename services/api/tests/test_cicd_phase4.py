import asyncio
import hashlib
import hmac
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Target, WebhookSubscription
from app.cicd.gates import evaluate_gate
from app.cicd.webhooks import dispatch_event, dispatch_subscription, signature_for
from app.safety.credentials import encrypt_secret


class CICDPhase4Tests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)
        self.db = self.Session()
        self.target = Target(name="CI target", base_url="http://demo", environment="test", status="authorized")
        self.db.add(self.target); self.db.flush()

    def tearDown(self):
        self.db.close(); Base.metadata.drop_all(self.engine); self.engine.dispose()

    def test_gate_pass_warn_and_fail_policies(self):
        high = SimpleNamespace(id=1, vuln_type="bola_idor", severity="high", cvss_score=7.5, endpoint_id=10, status="open")
        critical = SimpleNamespace(id=2, vuln_type="sqli", severity="critical", cvss_score=9.2, endpoint_id=11, status="open")
        resolved = SimpleNamespace(id=3, vuln_type="old", severity="critical", cvss_score=10, endpoint_id=12, status="resolved")

        passed = evaluate_gate([resolved], {"fail_on_severities": ["critical"]})
        self.assertEqual((passed["gate_status"], passed["exit_code"]), ("passed", 0))
        warned = evaluate_gate([high], {"fail_on_severities": ["critical"], "warn_on_severities": ["high"]})
        self.assertEqual((warned["gate_status"], warned["exit_code"]), ("warn", 0))
        failed = evaluate_gate([high, critical], {"fail_on_severities": ["critical"], "fail_cvss_above": 8.0})
        self.assertEqual((failed["gate_status"], failed["exit_code"]), ("failed", 1))
        self.assertEqual(failed["summary"]["violation_count"], 1)

    def test_gate_cvss_threshold_is_strictly_greater_than(self):
        boundary = SimpleNamespace(id=1, vuln_type="x", severity="medium", cvss_score=8.0, endpoint_id=1, status="open")
        over = SimpleNamespace(id=2, vuln_type="x", severity="medium", cvss_score=8.1, endpoint_id=1, status="open")
        result = evaluate_gate([boundary, over], {"fail_on_severities": [], "fail_cvss_above": 8.0})
        self.assertEqual(result["gate_status"], "failed")
        self.assertEqual([v["vulnerability_id"] for v in result["violations"]], [2])

    def test_hmac_signature_matches_sha256_reference(self):
        body, secret = b'{"event":"gate.failed"}', "test-signing-secret"
        expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        self.assertEqual(signature_for(secret, body), expected)

    def test_dispatch_sends_signed_payload_and_reports_success(self):
        secret = "long-enough-test-secret"
        subscription = WebhookSubscription(id=7, target_id=self.target.id, url="https://example.com/hook", secret_key=encrypt_secret(secret), events=["gate.failed"], is_active=True)
        with patch("app.cicd.webhooks.validate_webhook_url"), patch("app.cicd.webhooks._post_json", return_value=204) as post:
            result = asyncio.run(dispatch_subscription(subscription, "gate.failed", {"scan_id": 4}))
        self.assertTrue(result["delivered"])
        self.assertEqual(result["http_status"], 204)
        args = post.call_args.args
        self.assertEqual(args[0], subscription.url)
        self.assertEqual(args[2], signature_for(secret, args[1]))
        self.assertIn(b"gate.failed", args[1])

    def test_dispatch_event_matches_target_and_global_subscriptions(self):
        local = WebhookSubscription(target_id=self.target.id, url="https://local.example/hook", secret_key=encrypt_secret("secret-local"), events=["gate.failed"], is_active=True)
        global_hook = WebhookSubscription(target_id=None, url="https://global.example/hook", secret_key=encrypt_secret("secret-global"), events=["gate.failed"], is_active=True)
        other_event = WebhookSubscription(target_id=self.target.id, url="https://unused.example/hook", secret_key=encrypt_secret("secret-unused"), events=["scan.completed"], is_active=True)
        self.db.add_all([local, global_hook, other_event]); self.db.commit()
        with patch("app.cicd.webhooks.validate_webhook_url"), patch("app.cicd.webhooks._post_json", return_value=200) as post:
            results = asyncio.run(dispatch_event(self.db, self.target.id, "gate.failed", {"status": "failed"}))
        self.assertEqual(len(results), 2)
        self.assertEqual(post.call_count, 2)
        self.assertTrue(all(item["delivered"] for item in results))


if __name__ == "__main__":
    unittest.main()
