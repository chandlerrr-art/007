import json
import unittest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.inventory.service import (
    classify_endpoints,
    extract_parameters_from_har_entry,
    infer_api_version,
    infer_business_flow,
    infer_likely_owner,
    ingest_gateway_logs,
    normalize_endpoint_path,
)
from app.main import app
from app.models import (
    Endpoint,
    EndpointParameter,
    EndpointRoleObservation,
    SafetyControl,
    Target,
    TrafficLogEntry,
)
from app.settings import settings


class EvidenceBackedInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old_origins = settings.allowed_target_origins
        settings.allowed_target_origins = "http://demo-app:8080,http://staging-app:8080"
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)

        with self.session_factory() as db:
            db.add(SafetyControl(id=1, kill_switch_engaged=False, reason=""))
            self.target = Target(
                name="Staging Travel Service",
                base_url="http://staging-app:8080",
                environment="staging",
                status="authorized",
            )
            db.add(self.target)
            db.commit()
            self.target_id = self.target.id

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

    # --- 1. Schema Extensions & Business Flow Links ---

    def test_endpoint_schema_and_business_flow_inference(self) -> None:
        flows = {
            "/api/v1/flights/search": "search",
            "/api/v1/bookings/hold": "hold",
            "/api/v1/bookings/100": "book",
            "/api/v1/payments/refunds": "pay",
            "/api/v1/tickets/cancel": "cancel",
            "/api/v1/internal/config": "other",
        }
        for path, expected_flow in flows.items():
            self.assertEqual(infer_business_flow(path, "POST"), expected_flow)

        self.assertEqual(infer_api_version("/api/v1/bookings"), "v1")
        self.assertEqual(infer_api_version("/api/v2/flights"), "v2")
        self.assertEqual(infer_likely_owner("/api/v1/bookings"), "Booking & Orders Team")
        self.assertEqual(infer_likely_owner("/api/v1/payments/refunds"), "Payments & Settlement Team")

    # --- 2. HAR Importer: Preserves Shapes and Discards Raw Values ---

    def test_har_import_preserves_parameter_shapes_under_strict_redaction(self) -> None:
        har = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": "http://staging-app:8080/api/v1/bookings/2002?session_token=sensitive-secret-token&tier=gold",
                            "headers": [
                                {"name": "Authorization", "value": "Bearer top-secret-jwt"},
                                {"name": "X-Custom-Client", "value": "partner-portal"},
                            ],
                            "cookies": [
                                {"name": "auth_cookie", "value": "cookie-secret-xyz"}
                            ],
                            "postData": {
                                "mimeType": "application/json",
                                "text": json.dumps({
                                    "customer_email": "real-user@example.com",
                                    "seat_count": 2,
                                    "is_flexible": True,
                                    "price": 499.50,
                                })
                            }
                        }
                    }
                ]
            }
        }

        res = self.client.post(f"/api/targets/{self.target_id}/har-import", json={"content": json.dumps(har)})
        self.assertEqual(res.status_code, 200)

        # 1. Verify raw secret and PII values NEVER exist anywhere in API responses
        self.assertNotIn("sensitive-secret-token", res.text)
        self.assertNotIn("top-secret-jwt", res.text)
        self.assertNotIn("cookie-secret-xyz", res.text)
        self.assertNotIn("real-user@example.com", res.text)

        # 2. Verify in database: parameter names and types exist, but values are absent
        with self.session_factory() as db:
            endpoint = db.execute(select(Endpoint).where(Endpoint.target_id == self.target_id)).scalars().first()
            self.assertIsNotNone(endpoint)
            self.assertEqual(endpoint.business_flow, "book")
            self.assertEqual(endpoint.api_version, "v1")
            self.assertTrue(endpoint.auth_required)

            params = db.execute(select(EndpointParameter).where(EndpointParameter.endpoint_id == endpoint.id)).scalars().all()
            param_dict = {(p.name, p.location): p.observed_type for p in params}

            # Query params
            self.assertIn(("session_token", "query"), param_dict)
            self.assertIn(("tier", "query"), param_dict)
            # Headers & cookies
            self.assertIn(("authorization", "header"), {(k.lower(), loc) for (k, loc) in param_dict})
            self.assertIn(("auth_cookie", "cookie"), param_dict)
            # Body params
            self.assertEqual(param_dict.get(("customer_email", "body")), "string")
            self.assertEqual(param_dict.get(("seat_count", "body")), "integer")
            self.assertEqual(param_dict.get(("is_flexible", "body")), "boolean")
            self.assertEqual(param_dict.get(("price", "body")), "number")

            # Assert database has NO cleartext PII or token
            for p in params:
                self.assertNotIn("real-user@example.com", p.name)
                self.assertNotIn("top-secret-jwt", p.name)

    # --- 3. Gateway / Access Log Ingestion with Time Bounds ---

    def test_gateway_log_ingestion_supports_json_and_clf_formats(self) -> None:
        now = datetime.now(timezone.utc)
        recent_ts = (now - timedelta(days=5)).isoformat()

        json_log = json.dumps({
            "timestamp": recent_ts,
            "method": "GET",
            "path": "/api/v1/bookings/5050",
            "status": 200,
            "role": "travel_agent",
        })
        clf_log = f'10.0.0.1 - admin [{(now - timedelta(days=10)).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /api/v1/admin/agencies HTTP/1.1" 403 200'

        combined_logs = f"{json_log}\n{clf_log}"
        res = self.client.post(
            f"/api/targets/{self.target_id}/gateway-logs",
            json={"content": combined_logs, "window_days": 90},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["ingested_entries"], 2)

        with self.session_factory() as db:
            entries = db.execute(select(TrafficLogEntry).where(TrafficLogEntry.target_id == self.target_id)).scalars().all()
            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[0].window_days, 90)

            # Check that role observations were recorded
            roles = db.execute(select(EndpointRoleObservation)).scalars().all()
            self.assertEqual(len(roles), 2)
            role_map = {r.role: r.allowed for r in roles}
            self.assertTrue(role_map.get("travel_agent"))
            self.assertFalse(role_map.get("admin"))

    # --- 4. Classifier: Active, Zombie, and Shadow Classification ---

    def test_classifier_labels_active_zombie_and_shadow_accurately(self) -> None:
        now = datetime.now(timezone.utc)
        with self.session_factory() as db:
            # 1. Documented endpoint WITH recent traffic within 90 days -> ACTIVE
            ep_active = Endpoint(
                target_id=self.target_id, method="GET", path="/api/v1/flights/search",
                classification="unknown", sensitivity="public", last_seen=now, source="HAR",
                first_seen_traffic=now - timedelta(days=20), last_seen_traffic=now - timedelta(days=2),
            )
            # 2. Documented endpoint with NO traffic or traffic older than 90 days -> ZOMBIE
            ep_zombie = Endpoint(
                target_id=self.target_id, method="GET", path="/api/v1/legacy/export",
                classification="unknown", sensitivity="internal", last_seen=now, source="HAR",
                first_seen_traffic=now - timedelta(days=120), last_seen_traffic=now - timedelta(days=95),
            )
            # 3. Documented endpoint NEVER seen in traffic at all -> ZOMBIE (decommission)
            ep_never_seen = Endpoint(
                target_id=self.target_id, method="GET", path="/api/v1/experimental/feature",
                classification="unknown", sensitivity="internal", last_seen=now, source="HAR",
                first_seen_traffic=None, last_seen_traffic=None,
            )
            # 4. Undocumented endpoint seen only in traffic -> SHADOW
            ep_shadow = Endpoint(
                target_id=self.target_id, method="POST", path="/api/v1/debug/dump",
                classification="unknown", sensitivity="sensitive", last_seen=now, source="traffic",
                first_seen_traffic=now - timedelta(days=10), last_seen_traffic=now - timedelta(days=1),
            )
            db.add_all([ep_active, ep_zombie, ep_never_seen, ep_shadow])
            db.commit()

        # Run classification with 90-day window
        res = self.client.post(f"/api/targets/{self.target_id}/classify", json={"window_days": 90})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["active_count"], 1)
        self.assertEqual(data["zombie_count"], 2)
        self.assertEqual(data["shadow_count"], 1)

        with self.session_factory() as db:
            eps = {e.path: e for e in db.execute(select(Endpoint).where(Endpoint.target_id == self.target_id)).scalars().all()}
            self.assertEqual(eps["/api/v1/flights/search"].classification, "active")
            self.assertEqual(eps["/api/v1/flights/search"].recommended_action, "keep_active")

            self.assertEqual(eps["/api/v1/legacy/export"].classification, "zombie")
            self.assertEqual(eps["/api/v1/legacy/export"].recommended_action, "restrict")

            self.assertEqual(eps["/api/v1/experimental/feature"].classification, "zombie")
            self.assertEqual(eps["/api/v1/experimental/feature"].recommended_action, "decommission")

            self.assertEqual(eps["/api/v1/debug/dump"].classification, "shadow")
            self.assertEqual(eps["/api/v1/debug/dump"].recommended_action, "bring_up_to_date")

    # --- 5. Edge Cases: Stale Windows and Window Boundaries (Day 30 & Day 90) ---

    def test_window_boundary_edge_behavior(self) -> None:
        now = datetime.now(timezone.utc)
        with self.session_factory() as db:
            # Day 30 boundary: 29.9 days vs 30.1 days
            ep_inside_30 = Endpoint(
                target_id=self.target_id, method="GET", path="/api/v1/day30/inside",
                classification="unknown", sensitivity="public", last_seen=now, source="HAR",
                last_seen_traffic=now - timedelta(days=29, hours=22),
            )
            ep_outside_30 = Endpoint(
                target_id=self.target_id, method="GET", path="/api/v1/day30/outside",
                classification="unknown", sensitivity="public", last_seen=now, source="HAR",
                last_seen_traffic=now - timedelta(days=30, hours=2),
            )
            db.add_all([ep_inside_30, ep_outside_30])
            db.commit()

        # Classify with window_days = 30
        res = self.client.post(f"/api/targets/{self.target_id}/classify", json={"window_days": 30})
        self.assertEqual(res.status_code, 200)

        with self.session_factory() as db:
            inside = db.execute(select(Endpoint).where(Endpoint.path == "/api/v1/day30/inside")).scalars().first()
            outside = db.execute(select(Endpoint).where(Endpoint.path == "/api/v1/day30/outside")).scalars().first()
            self.assertEqual(inside.classification, "active")
            self.assertEqual(outside.classification, "zombie")

    def test_day_90_boundary_behavior(self) -> None:
        now = datetime.now(timezone.utc)
        with self.session_factory() as db:
            # Day 90 boundary: 89.9 days vs 90.1 days
            ep_inside_90 = Endpoint(
                target_id=self.target_id, method="GET", path="/api/v1/day90/inside",
                classification="unknown", sensitivity="public", last_seen=now, source="HAR",
                last_seen_traffic=now - timedelta(days=89, hours=22),
            )
            ep_outside_90 = Endpoint(
                target_id=self.target_id, method="GET", path="/api/v1/day90/outside",
                classification="unknown", sensitivity="public", last_seen=now, source="HAR",
                last_seen_traffic=now - timedelta(days=90, hours=2),
            )
            db.add_all([ep_inside_90, ep_outside_90])
            db.commit()

        # Classify with window_days = 90
        res = self.client.post(f"/api/targets/{self.target_id}/classify", json={"window_days": 90})
        self.assertEqual(res.status_code, 200)

        with self.session_factory() as db:
            inside = db.execute(select(Endpoint).where(Endpoint.path == "/api/v1/day90/inside")).scalars().first()
            outside = db.execute(select(Endpoint).where(Endpoint.path == "/api/v1/day90/outside")).scalars().first()
            self.assertEqual(inside.classification, "active")
            self.assertEqual(outside.classification, "zombie")

    def test_definition_of_done_e2e_scan_with_har_and_gateway_logs(self) -> None:
        """Definition of Done verification:
        A scan against a target with supplied HAR and gateway-log input produces
        endpoint records carrying parameters, role observations, flow links, versions,
        traffic timestamps, and active/zombie/shadow classifications with owners & recommendations.
        """
        from unittest.mock import MagicMock, patch
        import httpx
        from app.models import Scan
        from app.scans.orchestrator import _run_scan

        now = datetime.now(timezone.utc)

        # 1. Supply HAR input (2 endpoints: /bookings and /payments)
        har_data = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": "http://staging-app:8080/api/v1/bookings?agency=travel-pro",
                            "headers": [{"name": "Authorization", "value": "Bearer test-token"}],
                            "postData": {"mimeType": "application/json", "text": json.dumps({"guests": 2})},
                        }
                    },
                    {
                        "request": {
                            "method": "POST",
                            "url": "http://staging-app:8080/api/v1/payments/refunds?reason=cancel",
                            "headers": [{"name": "Authorization", "value": "Bearer test-token"}],
                        }
                    },
                ]
            }
        }
        har_res = self.client.post(f"/api/targets/{self.target_id}/har-import", json={"content": json.dumps(har_data)})
        self.assertEqual(har_res.status_code, 200)

        # 2. Supply Gateway log input:
        # Traffic for /bookings (active), but NO traffic for /payments (zombie)
        # Plus undocumented traffic for /debug/server-status (shadow)
        gw_log = f"""
{{"timestamp": "{(now - timedelta(days=2)).isoformat()}", "method": "POST", "path": "/api/v1/bookings?agency=travel-pro", "status": 200, "role": "travel_agent"}}
{{"timestamp": "{(now - timedelta(days=3)).isoformat()}", "method": "GET", "path": "/api/v1/debug/server-status", "status": 200, "role": "admin"}}
"""
        gw_res = self.client.post(
            f"/api/targets/{self.target_id}/gateway-logs",
            json={"content": gw_log, "window_days": 90},
        )
        self.assertEqual(gw_res.status_code, 200)

        # 3. Create and execute scan
        with self.session_factory() as db:
            scan = Scan(target_id=self.target_id, status="queued", trigger="manual", started_at=now, summary="")
            db.add(scan)
            db.commit()
            scan_id = scan.id

        fake_responses = [
            httpx.Response(200, json={"status": "ok"}),  # preflight health
            httpx.Response(200, json={"user": "travel_agent"}),  # baseline auth
            httpx.Response(200, json={"status": "ok"}),  # postflight health
        ]

        with patch("app.scans.orchestrator.SessionLocal", self.session_factory), \
             patch("app.scans.staging_executor.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__.return_value = mock_client
            mock_client.request.side_effect = fake_responses
            mock_client_cls.return_value = mock_client

            _run_scan(scan_id, self.target_id)

        # 4. Fetch endpoints via API and verify all required DoD fields
        ep_res = self.client.get(f"/api/targets/{self.target_id}/endpoints")
        self.assertEqual(ep_res.status_code, 200)
        endpoints = {e["path"]: e for e in ep_res.json()}

        # Verify active endpoint (/api/v1/bookings)
        bookings_ep = endpoints.get("/api/v1/bookings")
        self.assertIsNotNone(bookings_ep)
        self.assertEqual(bookings_ep["classification"], "active")
        self.assertEqual(bookings_ep["business_flow"], "book")
        self.assertEqual(bookings_ep["api_version"], "v1")
        self.assertEqual(bookings_ep["recommended_action"], "keep_active")
        self.assertEqual(bookings_ep["owner"], "Booking & Orders Team")
        self.assertIsNotNone(bookings_ep["last_seen_traffic"])
        self.assertGreater(len(bookings_ep["parameters"]), 0)
        self.assertTrue(any(p["name"] == "agency" and p["location"] == "query" for p in bookings_ep["parameters"]))
        self.assertTrue(any(r["role"] == "travel_agent" and r["allowed"] for r in bookings_ep["role_observations"]))

        # Verify zombie endpoint (/api/v1/payments/refunds - documented in HAR but no traffic in window)
        refunds_ep = endpoints.get("/api/v1/payments/refunds")
        self.assertIsNotNone(refunds_ep)
        self.assertEqual(refunds_ep["classification"], "zombie")
        self.assertEqual(refunds_ep["business_flow"], "pay")
        self.assertEqual(refunds_ep["recommended_action"], "decommission")
        self.assertEqual(refunds_ep["owner"], "Payments & Settlement Team")
        self.assertIsNone(refunds_ep["last_seen_traffic"])

        # Verify shadow endpoint (/api/v1/debug/server-status - seen in traffic, not in HAR)
        debug_ep = endpoints.get("/api/v1/debug/server-status")
        self.assertIsNotNone(debug_ep)
        self.assertEqual(debug_ep["classification"], "shadow")
        self.assertEqual(debug_ep["recommended_action"], "bring_up_to_date")
        self.assertIsNotNone(debug_ep["last_seen_traffic"])
        self.assertTrue(any(r["role"] == "admin" for r in debug_ep["role_observations"]))

    def test_version_comparison_notes_generated_correctly(self) -> None:
        now = datetime.now(timezone.utc)
        with self.session_factory() as db:
            v1_ep = Endpoint(
                target_id=self.target_id, method="GET", path="/api/v1/bookings/{id}",
                classification="active", sensitivity="public", last_seen=now, source="HAR",
                api_version="v1", last_seen_traffic=now,
            )
            v3_ep = Endpoint(
                target_id=self.target_id, method="GET", path="/api/v3/bookings/{id}",
                classification="active", sensitivity="public", last_seen=now, source="HAR",
                api_version="v3", last_seen_traffic=now,
            )
            db.add_all([v1_ep, v3_ep])
            db.commit()

        self.client.post(f"/api/targets/{self.target_id}/classify", json={"window_days": 90})

        with self.session_factory() as db:
            v1 = db.execute(select(Endpoint).where(Endpoint.path == "/api/v1/bookings/{id}")).scalars().first()
            self.assertIn("Legacy v1 route remains active while v3 is available", v1.version_notes)


if __name__ == "__main__":
    unittest.main()
