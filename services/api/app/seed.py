from datetime import datetime, timedelta, timezone
import json

from sqlalchemy import select

from app.db import SessionLocal
from app.models import AuditEvent, Endpoint, Evidence, Finding, InventorySnapshot, Scan, ScanStage, Target


def seed() -> None:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        if db.scalar(select(Target.id).limit(1)):
            print("Demo data already exists; seed skipped.")
            return

        target = Target(name="Sentinel Travel Demo", base_url="http://demo-app:8080", environment="local-demo", status="authorized", scope_note="Synthetic data only; isolated local demo target.")
        db.add(target)
        db.flush()
        endpoint_specs = [
            ("GET", "/api/v1/bookings", "active", "sensitive", "HAR"),
            ("GET", "/api/v1/bookings/{booking_id}", "active", "sensitive", "HAR"),
            ("POST", "/api/v1/refunds/quote", "active", "financial", "HAR"),
            ("GET", "/api/v1/agencies/current", "active", "internal", "crawler"),
            ("GET", "/api/v1/debug/health-details", "shadow", "internal", "traffic"),
        ]
        endpoints = []
        for method, path, classification, sensitivity, source in endpoint_specs:
            endpoint = Endpoint(target_id=target.id, method=method, path=path, classification=classification, sensitivity=sensitivity, last_seen=now - timedelta(minutes=12), source=source)
            db.add(endpoint)
            endpoints.append(endpoint)
        scan = Scan(target_id=target.id, status="completed", trigger="manual", started_at=now - timedelta(minutes=15), finished_at=now - timedelta(minutes=12), summary="Seeded dashboard example; no requests were sent.")
        db.add(scan)
        db.flush()
        inventory_keys = sorted(f"{endpoint.method} {endpoint.path}" for endpoint in endpoints)
        db.add(InventorySnapshot(target_id=target.id, scan_id=scan.id, endpoint_count=len(inventory_keys), inventory_json=json.dumps(inventory_keys)))
        db.add_all([
            ScanStage(scan_id=scan.id, name="scope_validation", status="completed", started_at=now - timedelta(minutes=15), finished_at=now - timedelta(minutes=15)),
            ScanStage(scan_id=scan.id, name="inventory", status="completed", started_at=now - timedelta(minutes=15), finished_at=now - timedelta(minutes=12)),
            AuditEvent(scan_id=scan.id, event_type="demo_seed_created", decision="allow", details="Synthetic seed record only; no target requests were issued."),
        ])
        finding = Finding(scan_id=scan.id, endpoint_id=endpoints[1].id, title="Example only: cross-agency booking access requires review", category="demo_sample", severity="high", confidence="low", business_impact="Illustrative dashboard data only; not a scan result.", status="needs_verification", verified=False, created_at=now - timedelta(minutes=13))
        db.add(finding)
        db.flush()
        db.add(Evidence(finding_id=finding.id, kind="seed_note", summary="Illustrative unverified record for dashboard layout. It is not a scan result.", redacted=True))
        db.commit()
        print("Inserted synthetic SentinelFlow dashboard data.")


if __name__ == "__main__":
    seed()
