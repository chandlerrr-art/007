import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.ai.patcher_tasks import generate_patch_task
from app.auth.rbac import issue_workspace_token
from app.core.celery_app import celery_app
from app.db import Base, get_db
from app.main import app
from app.models import (CodePatch, DiscoveredVulnerability, Endpoint, Organization,
                        Target, VulnerabilityScan, WorkspaceUser)
from app.core.encryption import get_encryption_service
from app.settings import settings
from app.vulnerability.tasks import run_scan_task


class CeleryWorkerTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)
        self.db = self.Session()
        self.old_secret = settings.enterprise_auth_secret
        self.old_enterprise = settings.enterprise_auth_enabled
        self.old_legacy_key = settings.credential_encryption_key
        self.old_master_kek = settings.master_kek_secret
        settings.master_kek_secret = "worker-test-master-kek-secret-0123456789"
        settings.credential_encryption_key = "legacy-worker-test-key-1234567890"
        settings.enterprise_auth_secret = "worker-test-signing-secret-0123456789"
        settings.enterprise_auth_enabled = True
        self.old_eager = celery_app.conf.task_always_eager
        self.old_propagates = celery_app.conf.task_eager_propagates
        celery_app.conf.task_always_eager = True  # Equivalent to CELERY_ALWAYS_EAGER=true.
        celery_app.conf.task_eager_propagates = False
        self.org = Organization(name="Worker Org", slug="worker-org")
        self.db.add(self.org); self.db.flush()
        self.db.add(WorkspaceUser(organization_id=self.org.id, user_id="worker-user", workspace_role="security_engineer", permissions=[]))
        self.target = Target(name="Worker Target", organization_id=self.org.id, base_url="http://demo", environment="test", status="authorized")
        self.db.add(self.target); self.db.flush()
        self.endpoint = Endpoint(target_id=self.target.id, method="GET", path="/items/{id}", classification="active", sensitivity="medium", last_seen=datetime.now(timezone.utc), source="test")
        self.db.add(self.endpoint); self.db.flush()
        self.scan = VulnerabilityScan(target_id=self.target.id, status="pending", config_snapshot='{"profile":"quick"}')
        self.db.add(self.scan); self.db.flush()
        self.vulnerability = DiscoveredVulnerability(scan_id=self.scan.id, endpoint_id=self.endpoint.id,
            vuln_type="sqli", severity="high", cvss_score=8.1,
            remediation_advice="Use parameterized queries.", status="open")
        self.db.add(self.vulnerability); self.db.commit()
        self.authorization = "Bearer " + issue_workspace_token("worker-user", self.org.id)
        self.encrypted_authorization = get_encryption_service().encrypt(
            self.authorization,
            context=f"celery:scan:{self.scan.id}:organization:{self.org.id}:authorization",
        ).as_dict()

    def tearDown(self):
        self.client_cleanup()
        app.dependency_overrides.clear()
        celery_app.conf.task_always_eager = self.old_eager
        celery_app.conf.task_eager_propagates = self.old_propagates
        settings.enterprise_auth_secret = self.old_secret
        settings.enterprise_auth_enabled = self.old_enterprise
        settings.credential_encryption_key = self.old_legacy_key
        settings.master_kek_secret = self.old_master_kek
        self.db.close(); Base.metadata.drop_all(self.engine); self.engine.dispose()

    def client_cleanup(self):
        client = getattr(self, "client", None)
        if client:
            client.close()

    def test_scan_task_persists_success_using_isolated_session(self):
        def finish_scan(db, scan_id):
            scan = db.get(VulnerabilityScan, scan_id)
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.config_snapshot = '{"findings_summary":{"high":1}}'
            db.commit()
            return scan

        task_kwargs = {
                "scan_id": self.scan.id, "target_id": self.target.id,
                "organization_id": self.org.id,
                "authorization_header": self.encrypted_authorization,
            }
        with patch("app.vulnerability.tasks.SessionLocal", self.Session), patch("app.vulnerability.tasks.run_vulnerability_scan", side_effect=finish_scan) as run_scan:
            result = run_scan_task.apply_async(kwargs=task_kwargs, task_id="idempotent-scan-task")
            replayed = run_scan_task.apply_async(kwargs=task_kwargs, task_id="idempotent-scan-task")
        self.assertEqual(result.state, "SUCCESS")
        self.assertEqual(replayed.state, "SUCCESS")
        self.assertEqual(run_scan.call_count, 1)
        self.assertEqual(result.result["status"], "completed")
        with self.Session() as db:
            self.assertEqual(db.get(VulnerabilityScan, self.scan.id).status, "completed")

    def test_scan_task_marks_database_failed_when_engine_raises(self):
        with patch("app.vulnerability.tasks.SessionLocal", self.Session), patch("app.vulnerability.tasks.run_vulnerability_scan", side_effect=RuntimeError("controlled failure")):
            result = run_scan_task.apply_async(kwargs={
                "scan_id": self.scan.id, "target_id": self.target.id,
                "organization_id": self.org.id,
                "authorization_header": self.encrypted_authorization,
            })
        self.assertEqual(result.state, "FAILURE")
        with self.Session() as db:
            scan = db.get(VulnerabilityScan, self.scan.id)
            self.assertEqual(scan.status, "failed")
            self.assertIn("controlled failure", scan.config_snapshot)

    def test_patch_task_failure_is_reported_without_persisting_a_bad_patch(self):
        with patch("app.ai.patcher_tasks.SessionLocal", self.Session):
            result = generate_patch_task.apply_async(kwargs={
                "vulnerability_id": self.vulnerability.id,
                "target_file_path": "app/items.py",
                "encrypted_source_code": get_encryption_service().encrypt(
                    "db.execute(query)\n",
                    context=f"celery:patch:{self.vulnerability.id}:organization:{self.org.id}:source",
                ).as_dict(),
                "organization_id": self.org.id,
                "authorization_header": get_encryption_service().encrypt(
                    self.authorization,
                    context=f"celery:patch:{self.vulnerability.id}:organization:{self.org.id}:authorization",
                ).as_dict(),
                "db_dialect": "sqlite",
            })
        self.assertEqual(result.state, "FAILURE")
        with self.Session() as db:
            self.assertEqual(db.query(CodePatch).count(), 0)

    def test_celery_uses_json_serialization_prefetch_one_and_bounded_limits(self):
        self.assertEqual(celery_app.conf.task_serializer, "json")
        self.assertEqual(celery_app.conf.result_serializer, "json")
        self.assertEqual(celery_app.conf.accept_content, ["json"])
        self.assertEqual(celery_app.conf.worker_prefetch_multiplier, 1)
        self.assertGreater(celery_app.conf.task_time_limit, celery_app.conf.task_soft_time_limit)

    def test_patch_task_persists_candidate_and_returns_json_result(self):
        source = 'def load_item(item_id):\n    return db.execute(f"SELECT * FROM items WHERE id = {item_id}")\n'
        task_kwargs = {
                "vulnerability_id": self.vulnerability.id,
                "target_file_path": "app/items.py",
                "encrypted_source_code": get_encryption_service().encrypt(
                    source,
                    context=f"celery:patch:{self.vulnerability.id}:organization:{self.org.id}:source",
                ).as_dict(),
                "organization_id": self.org.id,
                "authorization_header": get_encryption_service().encrypt(
                    self.authorization,
                    context=f"celery:patch:{self.vulnerability.id}:organization:{self.org.id}:authorization",
                ).as_dict(),
                "db_dialect": "sqlite",
            }
        with patch("app.ai.patcher_tasks.SessionLocal", self.Session):
            result = generate_patch_task.apply_async(kwargs=task_kwargs, task_id="idempotent-patch-task")
            replayed = generate_patch_task.apply_async(kwargs=task_kwargs, task_id="idempotent-patch-task")
        self.assertEqual(result.state, "SUCCESS")
        self.assertEqual(replayed.state, "SUCCESS")
        self.assertEqual(result.result["patch_id"], replayed.result["patch_id"])
        self.assertEqual(result.result["status"], "generated")
        with self.Session() as db:
            patch_row = db.get(CodePatch, result.result["patch_id"])
            self.assertIsNotNone(patch_row)
            self.assertIn("?", patch_row.unified_diff)
            self.assertEqual(patch_row.status, "generated")
            self.assertEqual(db.query(CodePatch).count(), 1)

    def test_api_dispatches_scan_with_tenant_and_encrypted_auth_context(self):
        def override_get_db():
            with self.Session() as db:
                yield db
        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)
        fake_result = Mock(id="celery-scan-id", state="PENDING")
        fake_result.successful.return_value = False
        with patch("app.main.validate_target_url"), patch("app.main.run_scan_task.apply_async", return_value=fake_result) as dispatch:
            response = self.client.post(f"/api/targets/{self.target.id}/scans", headers={"Authorization": self.authorization}, json={"profile": "quick"})
        self.assertEqual(response.status_code, 202, response.text)
        kwargs = dispatch.call_args.kwargs["kwargs"]
        self.assertEqual(kwargs["organization_id"], self.org.id)
        self.assertEqual(get_encryption_service().decrypt(
            kwargs["authorization_header"],
            context=f"celery:scan:{kwargs['scan_id']}:organization:{self.org.id}:authorization",
        ), self.authorization)
        self.assertEqual(kwargs["target_id"], self.target.id)
        self.assertEqual(kwargs["scan_id"], response.json()["id"])

    def test_patch_dispatch_encrypts_source_and_authorization(self):
        def override_get_db():
            with self.Session() as db:
                yield db
        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)
        fake_result = Mock(id="celery-patch-id", state="PENDING")
        fake_result.successful.return_value = False
        source = 'db.execute(f"SELECT * FROM items WHERE id = {item_id}")\n'
        with patch("app.main.generate_patch_task.apply_async", return_value=fake_result) as dispatch:
            response = self.client.post(f"/api/vulnerabilities/{self.vulnerability.id}/patch",
                headers={"Authorization": self.authorization}, json={"target_file_path": "app/items.py", "source_code": source, "db_dialect": "sqlite"})
        self.assertEqual(response.status_code, 202, response.text)
        kwargs = dispatch.call_args.kwargs["kwargs"]
        self.assertEqual(kwargs["organization_id"], self.org.id)
        self.assertEqual(get_encryption_service().decrypt(
            kwargs["authorization_header"],
            context=f"celery:patch:{self.vulnerability.id}:organization:{self.org.id}:authorization",
        ), self.authorization)
        self.assertEqual(get_encryption_service().decrypt(
            kwargs["encrypted_source_code"],
            context=f"celery:patch:{self.vulnerability.id}:organization:{self.org.id}:source",
        ), source)


if __name__ == "__main__":
    unittest.main()
