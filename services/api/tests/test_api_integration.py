import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.settings import settings


class ApiIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old_origins = settings.allowed_target_origins
        settings.allowed_target_origins = "http://demo-app:8080"
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)

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

    def test_dashboard_reads_live_database_state(self) -> None:
        response = self.client.get("/api/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["summary"]["targets"], 0)

    def test_target_creation_enforces_allowlist_and_har_import_redacts_query(self) -> None:
        rejected = self.client.post("/api/targets", json={"name": "External", "base_url": "https://example.com", "environment": "staging"})
        self.assertEqual(rejected.status_code, 422)

        target_response = self.client.post("/api/targets", json={"name": "Local demo", "base_url": "http://demo-app:8080", "environment": "local-demo"})
        self.assertEqual(target_response.status_code, 201)
        target_id = target_response.json()["id"]
        har = {"log": {"entries": [
            {"request": {"method": "GET", "url": "http://demo-app:8080/api/v1/bookings/2002?token=do-not-store"}},
            {"request": {"method": "GET", "url": "https://outside.example/private"}},
        ]}}
        imported = self.client.post(f"/api/targets/{target_id}/har-import", json={"content": json.dumps(har)})
        self.assertEqual(imported.status_code, 200)
        self.assertEqual(imported.json()["inserted"], 1)
        self.assertNotIn("do-not-store", imported.text)

    @patch("app.main.run_scan")
    def test_deploy_webhook_records_change_event_and_autostarts_scan(self, mock_run_scan) -> None:
        target_id = self.client.post("/api/targets", json={"name": "Local demo", "base_url": "http://demo-app:8080", "environment": "local-demo"}).json()["id"]
        response = self.client.post("/api/webhooks/deploy", json={"target_id": target_id, "release": "v1.2.3"})
        self.assertEqual(response.status_code, 202)
        mock_run_scan.assert_called_once()
        body = response.json()
        self.assertTrue(body["scan_started"])
        self.assertIn("scan_id", body)

        changes = self.client.get("/api/changes").json()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["source"], "ci_cd_webhook")
        self.assertEqual(changes[0]["triggered_scan_id"], body["scan_id"])

    def test_kill_switch_blocks_future_scans_until_cleared(self) -> None:
        target_id = self.client.post("/api/targets", json={"name": "Local demo", "base_url": "http://demo-app:8080", "environment": "local-demo"}).json()["id"]

        engaged = self.client.post("/api/safety/kill-switch", json={"engaged": True, "reason": "incident drill"})
        self.assertEqual(engaged.status_code, 200)
        self.assertTrue(self.client.get("/api/safety/status").json()["kill_switch_engaged"])

        webhook = self.client.post("/api/webhooks/deploy", json={"target_id": target_id, "release": "v2.0.0"})
        self.assertEqual(webhook.status_code, 202)
        self.assertFalse(webhook.json()["scan_started"])
        self.assertEqual(webhook.json()["reason"], "kill switch engaged")

        cleared = self.client.post("/api/safety/kill-switch", json={"engaged": False, "reason": ""})
        self.assertFalse(cleared.json()["kill_switch_engaged"])


if __name__ == "__main__":
    unittest.main()
