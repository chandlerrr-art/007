import json
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import httpx
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import AuditEvent, Evidence, Finding, SafetyControl, Scan, ScanStage, Target, TestAccountCredential, TestExecution
from app.safety.credentials import (
    decrypt_secret,
    encrypt_secret,
    get_call_time_auth_headers,
    scrub_known_secrets,
    store_credential,
)
from app.settings import settings
from app.safety.policy import (
    ScopeRejected,
    endpoint_rate_limiter,
    redact_operational_text,
    supports_demo_executor,
    supports_staging_executor,
    validate_target_url,
)
from app.scans.orchestrator import _run_scan
from app.scans.registry import executor_registry, StagingTargetExecutor
class StagingReadinessGuardrailsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old_origins = settings.allowed_target_origins
        self.old_staging_origins = settings.allowed_staging_origins
        self.old_master_kek = settings.master_kek_secret
        self.old_legacy_key = settings.credential_encryption_key
        settings.master_kek_secret = "staging-test-master-kek-secret-0123456789"
        settings.credential_encryption_key = "staging-legacy-encryption-key-123456"
        settings.allowed_target_origins = "http://demo-app:8080"
        settings.allowed_staging_origins = "http://staging-app:8080,https://staging.internal:8443"

        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)
        endpoint_rate_limiter.reset()

        with self.session_factory() as db:
            db.add(SafetyControl(id=1, kill_switch_engaged=False, reason=""))
            db.commit()

        def override_get_db():
            with self.session_factory() as session:
                yield session

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(self.engine)
        self.engine.dispose()
        settings.allowed_target_origins = self.old_origins
        settings.allowed_staging_origins = self.old_staging_origins
        settings.master_kek_secret = self.old_master_kek
        settings.credential_encryption_key = self.old_legacy_key
        endpoint_rate_limiter.reset()

    # --- 1. Separate Staging-Target Executor & Registry ---

    def test_target_allowlist_accepts_explicit_staging_entry_while_restricting_demo_executor(self) -> None:
        # Staging origin is valid in allowlist
        self.assertEqual(validate_target_url("http://staging-app:8080"), "http://staging-app:8080")
        
        # Local-demo executor strictly rejects staging target
        staging_target = Target(name="Staging", base_url="http://staging-app:8080", environment="staging", status="authorized")
        demo_target = Target(name="Demo", base_url="http://demo-app:8080", environment="local-demo", status="authorized")
        
        self.assertFalse(supports_demo_executor(staging_target))
        self.assertTrue(supports_staging_executor(staging_target))

        self.assertTrue(supports_demo_executor(demo_target))
        self.assertFalse(supports_staging_executor(demo_target))

    def test_executor_registry_dispatches_independent_executors(self) -> None:
        demo_target = Target(name="Demo", base_url="http://demo-app:8080", environment="local-demo", status="authorized")
        staging_target = Target(name="Staging", base_url="http://staging-app:8080", environment="staging", status="authorized")

        demo_exec = executor_registry.get_for_target(demo_target)
        staging_exec = executor_registry.get_for_target(staging_target)

        self.assertIsNotNone(demo_exec)
        self.assertIsNotNone(staging_exec)
        self.assertEqual(demo_exec.name, "local_demo")
        self.assertEqual(staging_exec.name, "staging_executor")
        self.assertNotEqual(demo_exec, staging_exec)
        # Staging executor carries its own budget
        self.assertGreaterEqual(staging_exec.request_budget, 10)

    # --- 2. Scoped Test-Account Credential Store & Strict Redaction ---

    def test_credential_store_encryption_at_rest_and_call_time_injection(self) -> None:
        with self.session_factory() as db:
            target = Target(name="Staging Service", base_url="http://staging-app:8080", environment="staging", status="authorized")
            db.add(target)
            db.commit()
            target_id = target.id

        secret_text = "super-secret-bearer-jwt-token-xyz-987"
        cred_res = self.client.post(
            f"/api/targets/{target_id}/credentials",
            json={
                "role": "travel_agent",
                "username": "agent_alpha",
                "secret": secret_text,
                "auth_type": "bearer",
            },
        )
        self.assertEqual(cred_res.status_code, 201)
        cred_data = cred_res.json()
        
        # Verify secret is NEVER returned in API response
        self.assertNotIn(secret_text, json.dumps(cred_data))
        self.assertNotIn("secret", cred_data)

        # Verify encrypted-at-rest in DB
        with self.session_factory() as db:
            row = db.get(TestAccountCredential, cred_data["id"])
            self.assertIsNotNone(row)
            self.assertNotEqual(row.encrypted_secret, secret_text)
            self.assertNotIn(secret_text, row.encrypted_secret)
            
            # Verify call-time decryption
            decrypted = decrypt_secret(
                {"ciphertext": row.encrypted_secret, "wrapped_dek": row.encrypted_secret_wrapped_dek},
                context=f"test-credential:{row.id}:target:{target_id}",
            )
            self.assertEqual(decrypted, secret_text)
            
            headers = get_call_time_auth_headers(db, target_id, "travel_agent")
            self.assertEqual(headers.get("Authorization"), f"Bearer {secret_text}")

        # Verify GET credentials list redacts secret entirely
        list_res = self.client.get(f"/api/targets/{target_id}/credentials")
        self.assertEqual(list_res.status_code, 200)
        self.assertNotIn(secret_text, list_res.text)

    def test_strict_redaction_rule_everywhere(self) -> None:
        secret_value = "top-secret-staging-key-abc-456"
        encrypt_secret(secret_value)  # Registers into dynamic scrubbing set

        # Audit log text redaction
        sanitized = redact_operational_text(f"Notice: operation used {secret_value} for authorization.")
        self.assertNotIn(secret_value, sanitized)
        self.assertIn("[REDACTED_CREDENTIAL]", sanitized)

        # Bearer pattern redaction
        bearer_text = redact_operational_text("Header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature")
        self.assertNotIn("eyJhbGciOi", bearer_text)

    # --- 3. Human Approval States & Reviewer API ---

    def test_risky_test_is_blocked_until_human_approval(self) -> None:
        with self.session_factory() as db:
            target = Target(name="Staging API", base_url="http://staging-app:8080", environment="staging", status="authorized")
            db.add(target)
            db.commit()
            target_id = target.id

            scan = Scan(target_id=target_id, status="queued", trigger="manual", started_at=datetime.now(timezone.utc), summary="")
            db.add(scan)
            db.commit()
            scan_id = scan.id

        # Mock httpx responses for staging health checks
        fake_responses = [
            httpx.Response(200, json={"status": "ok"}),  # preflight health
            httpx.Response(200, json={"user": "agent"}),  # baseline auth verification
            httpx.Response(200, json={"status": "ok"}),  # postflight health
        ]

        with patch("app.scans.orchestrator.SessionLocal", self.session_factory), \
             patch("app.scans.staging_executor.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__.return_value = mock_client
            mock_client.request.side_effect = fake_responses
            mock_client_cls.return_value = mock_client

            # Run staging scan: should hit risky test gate and BLOCK
            _run_scan(scan_id, target_id)

        with self.session_factory() as db:
            # Check test execution state
            test_exec = db.execute(select(TestExecution).where(TestExecution.scan_id == scan_id)).scalars().first()
            self.assertIsNotNone(test_exec)
            self.assertEqual(test_exec.status, "pending_review")
            self.assertTrue(test_exec.is_risky)

            # Check audit event for blockage
            audit_events = db.execute(select(AuditEvent).where(AuditEvent.scan_id == scan_id)).scalars().all()
            blocked_events = [e for e in audit_events if e.event_type == "risky_test_blocked"]
            self.assertEqual(len(blocked_events), 1)
            self.assertEqual(blocked_events[0].decision, "deny")

        # Reviewer queue should show the pending test
        queue_res = self.client.get("/api/reviews")
        self.assertEqual(queue_res.status_code, 200)
        pending_tests = queue_res.json()["pending_tests"]
        self.assertTrue(any(t["id"] == test_exec.id for t in pending_tests))

        # Human Reviewer approves the risky test
        approve_res = self.client.post(f"/api/reviews/tests/{test_exec.id}/approve", json={"notes": "Approved for staging test run."})
        self.assertEqual(approve_res.status_code, 200)
        self.assertEqual(approve_res.json()["status"], "approved")

        with self.session_factory() as db:
            updated_test = db.get(TestExecution, test_exec.id)
            self.assertEqual(updated_test.status, "approved")
            self.assertIsNotNone(updated_test.reviewed_at)

            # Verify audit recorded approval
            approvals = db.execute(select(AuditEvent).where(AuditEvent.event_type == "test_approved_by_reviewer")).scalars().all()
            self.assertEqual(len(approvals), 1)
            self.assertEqual(approvals[0].decision, "allow")

    def test_high_severity_finding_held_in_pending_review_until_human_review(self) -> None:
        with self.session_factory() as db:
            target = Target(name="Staging API 2", base_url="http://staging-app:8080", environment="staging", status="authorized")
            db.add(target)
            db.commit()
            target_id = target.id

            scan = Scan(target_id=target_id, status="queued", trigger="manual", started_at=datetime.now(timezone.utc), summary="")
            db.add(scan)
            db.commit()
            scan_id = scan.id

            # Pre-approve the risky test
            test_exec = TestExecution(
                scan_id=scan_id,
                target_id=target_id,
                name="Cross-Role Administrative Privilege Escalation",
                test_type="privilege_escalation",
                is_risky=True,
                status="approved",
            )
            db.add(test_exec)
            db.commit()

        # Responses: preflight health, auth check, risky check (200 = vulnerable!), postflight health
        fake_responses = [
            httpx.Response(200, json={"status": "ok"}),
            httpx.Response(200, json={"role": "travel_agent"}),
            httpx.Response(200, json={"agencies": ["admin_secret"]}),  # Vulnerable admin access!
            httpx.Response(200, json={"status": "ok"}),
        ]

        with patch("app.scans.orchestrator.SessionLocal", self.session_factory), \
             patch("app.scans.staging_executor.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__.return_value = mock_client
            mock_client.request.side_effect = fake_responses
            mock_client_cls.return_value = mock_client

            _run_scan(scan_id, target_id)

        with self.session_factory() as db:
            finding = db.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().first()
            self.assertIsNotNone(finding)
            self.assertEqual(finding.severity, "high")
            # Must be pending_review!
            self.assertEqual(finding.status, "pending_review")
            finding_id = finding.id

        # Human Reviewer approves the finding
        approve_res = self.client.post(f"/api/reviews/findings/{finding_id}/approve", json={"notes": "Confirmed valid finding."})
        self.assertEqual(approve_res.status_code, 200)
        self.assertEqual(approve_res.json()["status"], "approved")
        self.assertTrue(approve_res.json()["verified"])

        with self.session_factory() as db:
            approved_finding = db.get(Finding, finding_id)
            self.assertEqual(approved_finding.status, "approved")
            self.assertTrue(approved_finding.verified)


if __name__ == "__main__":
    unittest.main()
