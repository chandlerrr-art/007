import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.ai.patcher import PatchGenerationError, generate_patch
from app.auth.rbac import (ensure_target_access, issue_workspace_token, require_permission,
                           resolve_workspace_context)
from app.db import Base, get_db
from app.core.celery_app import celery_app
from app.main import app
from app.models import (CodePatch, DiscoveredVulnerability, Endpoint, Organization,
                        Target, VulnerabilityScan, WorkspaceUser)
from app.settings import settings


class EnterprisePhase5Tests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)
        self.db = self.Session()
        self.secret_before = settings.enterprise_auth_secret
        self.master_kek_before = settings.master_kek_secret
        settings.enterprise_auth_secret = "test-workspace-signing-secret-0123456789"
        settings.master_kek_secret = "enterprise-test-master-kek-secret-0123456789"
        self.org_a = Organization(name="Workspace A", slug="workspace-a")
        self.org_b = Organization(name="Workspace B", slug="workspace-b")
        self.db.add_all([self.org_a, self.org_b]); self.db.flush()
        self.db.add_all([
            WorkspaceUser(organization_id=self.org_a.id, user_id="dev-a", workspace_role="developer", permissions=[]),
            WorkspaceUser(organization_id=self.org_a.id, user_id="engineer-a", workspace_role="security_engineer", permissions=[]),
            WorkspaceUser(organization_id=self.org_b.id, user_id="dev-b", workspace_role="developer", permissions=[]),
        ])
        self.target_a = Target(name="Target A", organization_id=self.org_a.id, base_url="http://demo-a", environment="test", status="authorized")
        self.target_b = Target(name="Target B", organization_id=self.org_b.id, base_url="http://demo-b", environment="test", status="authorized")
        self.db.add_all([self.target_a, self.target_b]); self.db.flush()
        self.endpoint_a = Endpoint(target_id=self.target_a.id, method="GET", path="/bookings/{id}", classification="active", sensitivity="high", last_seen=datetime.now(timezone.utc), source="test")
        self.endpoint_b = Endpoint(target_id=self.target_b.id, method="GET", path="/customers/{id}", classification="active", sensitivity="high", last_seen=datetime.now(timezone.utc), source="test")
        self.db.add_all([self.endpoint_a, self.endpoint_b]); self.db.flush()
        self.scan_a = VulnerabilityScan(target_id=self.target_a.id, status="completed", config_snapshot="{}")
        self.scan_b = VulnerabilityScan(target_id=self.target_b.id, status="completed", config_snapshot="{}")
        self.db.add_all([self.scan_a, self.scan_b]); self.db.flush()
        self.vuln_a = DiscoveredVulnerability(scan_id=self.scan_a.id, endpoint_id=self.endpoint_a.id, vuln_type="sqli", severity="high", cvss_score=8.1, remediation_advice="Use parameterized queries.", status="open")
        self.vuln_b = DiscoveredVulnerability(scan_id=self.scan_b.id, endpoint_id=self.endpoint_b.id, vuln_type="bola_idor", severity="high", cvss_score=8.1, status="open")
        self.db.add_all([self.vuln_a, self.vuln_b]); self.db.commit()

    def tearDown(self):
        self.client_cleanup()
        self.db.close(); Base.metadata.drop_all(self.engine); self.engine.dispose()
        settings.enterprise_auth_secret = self.secret_before
        settings.master_kek_secret = self.master_kek_before
        app.dependency_overrides.clear()

    def client_cleanup(self):
        if getattr(self, "client", None):
            self.client.close()

    def test_sqli_patch_is_a_valid_git_diff_with_confidence(self):
        source = 'def find_booking(user_id):\n    return db.execute(f"SELECT * FROM bookings WHERE id = {user_id}")\n'
        candidate = generate_patch(self.vuln_a, "app/booking.py", source, db_dialect="sqlite", endpoint_parameter="user_id")
        self.assertTrue(candidate.unified_diff.startswith("diff --git a/app/booking.py b/app/booking.py\n"))
        self.assertIn('db.execute("SELECT * FROM bookings WHERE id = ?", (user_id,))', candidate.unified_diff)
        self.assertGreaterEqual(candidate.confidence, 0.8)
        self.assertLessEqual(candidate.confidence, 1.0)

    def test_configured_model_provider_is_confidence_checked_and_diff_generated(self):
        class Provider:
            def propose(self, **context):
                self.context = context
                return context["source_code"].replace("unsafe()", "safe()"), 0.77, "review the replacement"
        provider = Provider()
        candidate = generate_patch(self.vuln_a, "app/query.py", "result = unsafe()\n", inference_provider=provider)
        self.assertEqual(candidate.confidence, 0.77)
        self.assertEqual(candidate.strategy, "configured-model-provider")
        self.assertIn("parameterized queries", provider.context["remediation_advice"])
        self.assertTrue(candidate.unified_diff.startswith("diff --git"))

    def test_bola_patch_uses_explicit_owner_and_principal_marker(self):
        candidate = generate_patch(self.vuln_b, "app/routes.py", "def show(resource, current_user):\n    # 007:AUTHZ owner=resource.owner_id principal=current_user.id\n    return resource\n")
        self.assertIn("if resource.owner_id != current_user.id:", candidate.unified_diff)
        self.assertIn("raise PermissionError(\"Forbidden\")", candidate.unified_diff)
        self.assertEqual(candidate.strategy, "object ownership authorization guard")

    def test_unsupported_or_traversal_patch_input_fails_closed(self):
        with self.assertRaises(PatchGenerationError):
            generate_patch(self.vuln_a, "../secrets.py", "print('no safe transform')\n", db_dialect="sqlite")
        with self.assertRaises(PatchGenerationError):
            generate_patch(self.vuln_a, "app/query.py", "db.execute(query)\n", db_dialect="sqlite")

    def test_database_scope_hides_another_organizations_targets_and_findings(self):
        self.db.info["organization_id"] = self.org_a.id
        visible = self.db.execute(select(Target).order_by(Target.id)).scalars().all()
        vulnerabilities = self.db.execute(select(DiscoveredVulnerability).order_by(DiscoveredVulnerability.id)).scalars().all()
        self.assertEqual([t.id for t in visible], [self.target_a.id])
        self.assertEqual([v.id for v in vulnerabilities], [self.vuln_a.id])
        with self.assertRaises(HTTPException) as denied:
            ensure_target_access(self.db, self.target_b.id)
        self.assertEqual(denied.exception.status_code, 404)

    def test_rbac_resolves_membership_and_denies_role_escalation(self):
        dev_token = "Bearer " + issue_workspace_token("dev-a", self.org_a.id)
        developer = resolve_workspace_context(dev_token, self.db)
        self.assertEqual(developer.workspace_role, "developer")
        require_permission(developer, "patches.generate")
        with self.assertRaises(HTTPException) as denied:
            require_permission(developer, "patches.review")
        self.assertEqual(denied.exception.status_code, 403)
        with self.assertRaises(HTTPException) as wrong_workspace:
            ensure_target_access(self.db, self.target_b.id, developer)
        self.assertEqual(wrong_workspace.exception.status_code, 404)

    def test_patch_api_requires_workspace_review_before_recorded_application(self):
        def override_get_db():
            with self.Session() as session:
                yield session
        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)
        dev = {"Authorization": "Bearer " + issue_workspace_token("dev-a", self.org_a.id)}
        engineer = {"Authorization": "Bearer " + issue_workspace_token("engineer-a", self.org_a.id)}
        outsider = {"Authorization": "Bearer " + issue_workspace_token("dev-b", self.org_b.id)}
        previous_eager = celery_app.conf.task_always_eager
        celery_app.conf.task_always_eager = True
        try:
            with patch("app.ai.patcher_tasks.SessionLocal", self.Session):
                generated = self.client.post(f"/api/vulnerabilities/{self.vuln_a.id}/patch", headers=dev, json={
                    "target_file_path": "app/booking.py", "db_dialect": "sqlite",
                    "source_code": 'def find_booking(user_id):\n    return db.execute(f"SELECT * FROM bookings WHERE id = {user_id}")\n',
                })
        finally:
            celery_app.conf.task_always_eager = previous_eager
        self.assertEqual(generated.status_code, 202, generated.text)
        patch_id = generated.json()["patch_id"]
        cross_tenant = self.client.post(f"/api/vulnerabilities/{self.vuln_b.id}/patch", headers=dev, json={
            "target_file_path": "app/routes.py", "source_code": "# 007:AUTHZ owner=obj.owner_id principal=user.id\n",
        })
        self.assertEqual(cross_tenant.status_code, 404)
        before_review = self.client.post(f"/api/patches/{patch_id}/apply", headers=dev, json={"mode": "simulate"})
        self.assertEqual(before_review.status_code, 409)
        denied_review = self.client.post(f"/api/patches/{patch_id}/review", headers=dev, json={"decision": "approved"})
        self.assertEqual(denied_review.status_code, 403)
        approved = self.client.post(f"/api/patches/{patch_id}/review", headers=engineer, json={"decision": "approved"})
        self.assertEqual(approved.status_code, 200, approved.text)
        applied = self.client.post(f"/api/patches/{patch_id}/apply", headers=dev, json={"mode": "simulate"})
        self.assertEqual(applied.status_code, 200, applied.text)
        self.assertEqual(applied.json()["status"], "applied")
        self.assertFalse(applied.json()["repository_modified"])
        context = self.client.get("/api/workspaces/context", headers=dev)
        self.assertEqual(context.status_code, 200)
        self.assertEqual(context.json()["organization"]["id"], self.org_a.id)
        self.assertNotIn("enterprise_auth_secret", str(context.json()))
        outsider_read = self.client.post(f"/api/vulnerabilities/{self.vuln_a.id}/patch", headers=outsider, json={
            "target_file_path": "app/booking.py", "db_dialect": "sqlite",
            "source_code": 'db.execute(f"SELECT * FROM bookings WHERE id = {user_id}")\n',
        })
        self.assertEqual(outsider_read.status_code, 404)


if __name__ == "__main__":
    unittest.main()
