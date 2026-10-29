import json
import unittest
from datetime import datetime, timezone

import httpx
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import AuditEvent, Endpoint, Evidence, Finding, InventorySnapshot, SafetyControl, Scan, ScanStage, Target
from app.safety.policy import endpoint_rate_limiter
from app.settings import settings
from app.scans import orchestrator


class FakeClient:
    def __init__(self, responses, after_get=None):
        self.responses = list(responses)
        self.after_get = after_get
        self.requests = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def get(self, url, *, headers, timeout, follow_redirects):
        self.requests.append({"url": url, "headers": headers, "timeout": timeout, "follow_redirects": follow_redirects})
        response = self.responses.pop(0)
        if self.after_get:
            self.after_get(url, response)
        return response


def json_response(status: int, body: dict | None = None):
    return httpx.Response(status, json=body or {})


class ScanOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.old_origins = settings.allowed_target_origins
        settings.allowed_target_origins = "http://demo-app:8080"
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)
        endpoint_rate_limiter.reset()
        with self.session_factory() as db:
            self.target = Target(name="Synthetic target", base_url="http://demo-app:8080", environment="local-demo", status="authorized")
            db.add(self.target)
            db.flush()
            self.endpoint = Endpoint(target_id=self.target.id, method="GET", path="/api/v1/bookings/{booking_id}", classification="active", sensitivity="synthetic", last_seen=datetime.now(timezone.utc), source="fixture")
            db.add(self.endpoint)
            db.flush()
            self.target_id = self.target.id
            self.endpoint_id = self.endpoint.id
            db.add(SafetyControl(id=1, kill_switch_engaged=False, reason=""))
            db.commit()
        self.client = None

    def tearDown(self):
        Base.metadata.drop_all(self.engine)
        self.engine.dispose()
        settings.allowed_target_origins = self.old_origins
        endpoint_rate_limiter.reset()

    def add_scan(self, *, cancelled=False):
        with self.session_factory() as db:
            scan = Scan(target_id=self.target_id, status="queued", trigger="manual", started_at=datetime.now(timezone.utc), summary="", cancel_requested=cancelled)
            db.add(scan)
            db.flush()
            snapshot = InventorySnapshot(target_id=self.target_id, scan_id=scan.id, endpoint_count=1, inventory_json=json.dumps(["GET /api/v1/bookings/{booking_id}"]))
            db.add(snapshot)
            scan_id = scan.id
            db.commit()
            return scan_id

    def respond_with(self, responses, after_get=None):
        self.client = FakeClient(responses, after_get=after_get)

    def run_with_fake_client(self, scan_id, *, retest_finding_id=None, request_budget=None):
        from unittest.mock import patch

        with patch.object(orchestrator, "SessionLocal", self.session_factory), patch.object(orchestrator.httpx, "Client", return_value=self.client):
            if request_budget is None:
                orchestrator.run_scan(scan_id, self.target_id, retest_finding_id)
            else:
                with patch.object(orchestrator, "REQUEST_BUDGET", request_budget):
                    orchestrator.run_scan(scan_id, self.target_id, retest_finding_id)

    def scan_records(self, scan_id):
        with self.session_factory() as db:
            scan = db.get(Scan, scan_id)
            stages = db.execute(select(ScanStage).where(ScanStage.scan_id == scan_id)).scalars().all()
            audits = db.execute(select(AuditEvent).where(AuditEvent.scan_id == scan_id)).scalars().all()
            findings = db.execute(select(Finding)).scalars().all()
            return scan, stages, audits, findings

    def test_confirms_and_persists_only_redacted_evidence(self):
        exposed = {"booking_id": "2002", "agency_id": "agency-b", "email": "traveler@example.invalid", "token": "raw-secret"}
        self.respond_with([json_response(200), json_response(200, exposed), json_response(200, exposed), json_response(200)])
        scan_id = self.add_scan()
        self.run_with_fake_client(scan_id)

        scan, stages, audits, findings = self.scan_records(scan_id)
        self.assertEqual(scan.status, "completed")
        self.assertTrue(any(s.name == "independent_verification" and s.status == "completed" for s in stages))
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].verified)
        with self.session_factory() as db:
            evidence = db.execute(select(Evidence).where(Evidence.finding_id == findings[0].id)).scalars().all()
        self.assertTrue(evidence)
        persisted = " ".join([e.summary for e in evidence] + [a.details for a in audits])
        self.assertNotIn("traveler@example.invalid", persisted)
        self.assertNotIn("raw-secret", persisted)
        self.assertTrue(any(a.event_type == "outbound_request_result" and "HTTP 200" in a.details for a in audits))
        self.assertTrue(all(request["timeout"] == orchestrator.REQUEST_TIMEOUT_SECONDS and request["follow_redirects"] is False for request in self.client.requests))

    def test_rejects_unexpected_probe_result_without_verified_finding(self):
        self.respond_with([json_response(200), json_response(200, {"booking_id": "2002", "agency_id": "agency-b"}), json_response(200, {"booking_id": "2002", "agency_id": "agency-a"}), json_response(200)])
        scan_id = self.add_scan()
        self.run_with_fake_client(scan_id)
        scan, stages, _audits, findings = self.scan_records(scan_id)
        self.assertEqual(scan.status, "completed")
        self.assertFalse(findings)
        self.assertTrue(any(s.name == "independent_verification" and s.status == "completed" for s in stages))

    def test_health_failure_closes_stage_and_sends_no_probe(self):
        self.respond_with([json_response(503)])
        scan_id = self.add_scan()
        self.run_with_fake_client(scan_id)
        scan, stages, _audits, findings = self.scan_records(scan_id)
        self.assertEqual(scan.status, "failed")
        self.assertTrue(any(s.name == "preflight_health" and s.status == "failed" for s in stages))
        self.assertFalse(findings)
        self.assertEqual(len(self.client.requests), 1)

    def test_cancel_requested_during_probe_stops_before_verification_request(self):
        scan_id = self.add_scan()

        def cancel_after_probe(url, _response):
            if "/bookings/" in url:
                with self.session_factory() as db:
                    db.get(Scan, scan_id).cancel_requested = True
                    db.commit()

        exposed = {"booking_id": "2002", "agency_id": "agency-b"}
        self.respond_with([json_response(200), json_response(200, exposed)], after_get=cancel_after_probe)
        self.run_with_fake_client(scan_id)
        scan, stages, _audits, findings = self.scan_records(scan_id)
        self.assertEqual(scan.status, "cancelled")
        self.assertTrue(any(s.name == "independent_verification" and s.status == "failed" for s in stages))
        self.assertFalse(findings)
        self.assertEqual(len(self.client.requests), 2)

    def test_kill_switch_engaged_during_probe_stops_before_verification_request(self):
        scan_id = self.add_scan()

        def engage_after_probe(url, _response):
            if "/bookings/" in url:
                with self.session_factory() as db:
                    control = db.get(SafetyControl, 1)
                    control.kill_switch_engaged = True
                    control.reason = "test"
                    db.commit()

        exposed = {"booking_id": "2002", "agency_id": "agency-b"}
        self.respond_with([json_response(200), json_response(200, exposed)], after_get=engage_after_probe)
        self.run_with_fake_client(scan_id)
        scan, stages, audits, findings = self.scan_records(scan_id)
        self.assertEqual(scan.status, "halted")
        self.assertTrue(any(s.name == "independent_verification" and s.status == "failed" for s in stages))
        self.assertFalse(findings)
        self.assertTrue(any(a.event_type == "outbound_request" and a.decision == "deny" for a in audits))
        self.assertEqual(len(self.client.requests), 2)

    def test_request_budget_exhaustion_fails_verification_stage(self):
        exposed = {"booking_id": "2002", "agency_id": "agency-b"}
        self.respond_with([json_response(200), json_response(200, exposed)])
        scan_id = self.add_scan()
        self.run_with_fake_client(scan_id, request_budget=2)
        scan, stages, audits, findings = self.scan_records(scan_id)
        self.assertEqual(scan.status, "failed")
        self.assertTrue(any(s.name == "independent_verification" and s.status == "failed" for s in stages))
        self.assertFalse(findings)
        self.assertTrue(any(a.event_type == "outbound_request" and a.decision == "deny" for a in audits))

    def test_repeated_scan_deduplicates_finding_and_retains_evidence(self):
        exposed = {"booking_id": "2002", "agency_id": "agency-b"}
        scan_id = self.add_scan()
        self.respond_with([json_response(200), json_response(200, exposed), json_response(200, exposed), json_response(200)])
        self.run_with_fake_client(scan_id)
        endpoint_rate_limiter.reset()
        second_id = self.add_scan()
        self.respond_with([json_response(200), json_response(200, exposed), json_response(200, exposed), json_response(200)])
        self.run_with_fake_client(second_id)
        with self.session_factory() as db:
            findings = db.execute(select(Finding)).scalars().all()
            audits = db.execute(select(AuditEvent).where(AuditEvent.scan_id == second_id)).scalars().all()
            evidence = db.execute(select(Evidence).where(Evidence.finding_id == findings[0].id)).scalars().all()
        self.assertEqual(len(findings), 1)
        self.assertTrue(any(a.event_type == "finding_deduplicated" for a in audits))
        self.assertEqual(len(evidence), 2)

    def test_retest_resolves_original_finding_only_after_fixed_result(self):
        original_scan_id = self.add_scan()
        with self.session_factory() as db:
            finding = Finding(scan_id=original_scan_id, endpoint_id=self.endpoint_id, title="IDOR", category="access_control", severity="high", confidence="high", business_impact="Synthetic test", status="open", verified=True)
            db.add(finding)
            db.flush()
            finding_id = finding.id
            retest_id = self.add_scan()
        self.respond_with([json_response(200), json_response(404), json_response(200)])
        self.run_with_fake_client(retest_id, retest_finding_id=finding_id)
        with self.session_factory() as db:
            self.assertEqual(db.get(Finding, finding_id).status, "resolved")
            self.assertEqual(db.get(Scan, retest_id).status, "completed")


if __name__ == "__main__":
    unittest.main()
