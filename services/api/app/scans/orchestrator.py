from datetime import datetime, timezone
import json
from threading import BoundedSemaphore
from urllib.parse import quote

import httpx
from sqlalchemy import select

from app.db import SessionLocal
from app.models import AuditEvent, ChangeEvent, Endpoint, Evidence, Finding, InventorySnapshot, Scan, ScanStage, Target
from app.safety.policy import (
    KillSwitchEngaged,
    RateLimited,
    ScopeRejected,
    assert_kill_switch_clear,
    assert_rate_limit,
    assert_request_scope,
    supports_demo_executor,
    validate_target_url,
)

REQUEST_TIMEOUT_SECONDS = 3.0
REQUEST_BUDGET = 4
MAX_CONCURRENCY = 1
_SCAN_SEMAPHORE = BoundedSemaphore(MAX_CONCURRENCY)
_SCAN_CANCELLED = "Scan cancelled by user."


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _cancelled(db, scan_id: int) -> bool:
    # Use a fresh SELECT: the long-lived scan session has expire_on_commit=False and must
    # observe cancellation written by the API in a separate session.
    cancelled = db.scalar(select(Scan.cancel_requested).where(Scan.id == scan_id))
    return cancelled is None or cancelled


def _ensure_scan_active(db, scan_id: int) -> None:
    if _cancelled(db, scan_id):
        raise RuntimeError(_SCAN_CANCELLED)
    assert_kill_switch_clear(db)


def _stage(db, scan_id: int, name: str) -> ScanStage:
    row = ScanStage(scan_id=scan_id, name=name, status="running", started_at=_now())
    db.add(row)
    db.commit()
    db.refresh(row)
    try:
        _ensure_scan_active(db, scan_id)
    except Exception as exc:
        _finish_stage(db, row, "failed", str(exc))
        raise
    return row


def _finish_stage(db, stage: ScanStage, status: str, error: str | None = None) -> None:
    stage.status = status
    stage.error = error
    stage.finished_at = _now()
    db.commit()


def _audit(db, scan_id: int, event_type: str, decision: str, details: str) -> None:
    db.add(AuditEvent(scan_id=scan_id, event_type=event_type, decision=decision, details=details[:1000]))
    db.commit()


def _bounded_get(db, scan_id: int, client: httpx.Client, target: Target, url: str, headers: dict[str, str], counter: list[int]) -> httpx.Response:
    try:
        _ensure_scan_active(db, scan_id)
    except (KillSwitchEngaged, RuntimeError) as exc:
        _audit(db, scan_id, "outbound_request", "deny", f"GET blocked by scan safety state: {exc}")
        raise
    if counter[0] >= REQUEST_BUDGET:
        _audit(db, scan_id, "outbound_request", "deny", "GET blocked because the per-scan request budget was exhausted.")
        raise RuntimeError("Request budget exhausted.")
    try:
        assert_request_scope(target, url)
    except ScopeRejected as exc:
        _audit(db, scan_id, "outbound_request", "deny", f"GET {url.split('?', 1)[0]} rejected by target scope policy: {exc}")
        raise
    path = url.split(target.base_url.rstrip("/"), 1)[-1].split("?", 1)[0]
    try:
        assert_rate_limit(target, path)
    except RateLimited as exc:
        _audit(db, scan_id, "outbound_request", "deny", f"GET {path} rejected by the per-endpoint rate limiter: {exc}")
        raise
    counter[0] += 1
    _audit(db, scan_id, "outbound_request", "allow", f"GET {path}; request {counter[0]}/{REQUEST_BUDGET}; timeout {REQUEST_TIMEOUT_SECONDS}s.")
    try:
        response = client.get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=False)
    except httpx.RequestError as exc:
        _audit(db, scan_id, "outbound_request_result", "error", f"GET {path} failed with {type(exc).__name__}; no response content stored.")
        raise
    _audit(db, scan_id, "outbound_request_result", "complete", f"GET {path} returned HTTP {response.status_code}; response content not stored.")
    return response


def _health_check(db, scan: Scan, target: Target, client: httpx.Client, counter: list[int], stage_name: str, failure_message: str) -> None:
    stage = _stage(db, scan.id, stage_name)
    try:
        url = f"{target.base_url.rstrip('/')}/health"
        response = _bounded_get(db, scan.id, client, target, url, {}, counter)
        if response.status_code != 200:
            raise RuntimeError(failure_message)
        _finish_stage(db, stage, "completed")
    except Exception as exc:
        _finish_stage(db, stage, "failed", str(exc))
        raise


def _run_access_control_check(db, scan: Scan, target: Target, endpoint: Endpoint, retest_finding_id: int | None = None) -> tuple[bool, str]:
    booking_id = "2002"  # Synthetic record belongs to agency-b in the local demo fixture.
    url = f"{target.base_url.rstrip('/')}/api/v1/bookings/{quote(booking_id, safe='')}"
    counter = [0]
    with httpx.Client(trust_env=False) as client:
        _health_check(db, scan, target, client, counter, "preflight_health", "Target health check failed; scan stopped before security checks.")

        probe_stage = _stage(db, scan.id, "access_control_check")
        try:
            # Test with a least-privilege synthetic agency identity.
            response = _bounded_get(db, scan.id, client, target, url, {"X-Demo-Agency": "agency-a"}, counter)
            is_candidate = response.status_code == 200 and response.headers.get("content-type", "").startswith("application/json")
            try:
                body = response.json() if is_candidate else {}
            except ValueError:
                body = {}
            is_candidate = is_candidate and body.get("booking_id") == booking_id and body.get("agency_id") == "agency-b"
            _finish_stage(db, probe_stage, "completed")
        except Exception as exc:
            _finish_stage(db, probe_stage, "failed", str(exc))
            raise

        verify_stage = _stage(db, scan.id, "independent_verification")
        try:
            if _cancelled(db, scan.id):
                raise RuntimeError(_SCAN_CANCELLED)
            # Repeat the minimal read as an independent deterministic confirmation.
            is_vulnerable = False
            if is_candidate:
                confirm = _bounded_get(db, scan.id, client, target, url, {"X-Demo-Agency": "agency-a"}, counter)
                try:
                    confirm_body = confirm.json()
                except ValueError:
                    confirm_body = {}
                is_vulnerable = confirm.status_code == 200 and confirm_body.get("booking_id") == booking_id and confirm_body.get("agency_id") == "agency-b"
            _finish_stage(db, verify_stage, "completed")
        except Exception as exc:
            _finish_stage(db, verify_stage, "failed", str(exc))
            raise

        _health_check(db, scan, target, client, counter, "postflight_health", "Target health degraded after check; scan stopped.")
    if is_vulnerable:
        existing = db.get(Finding, retest_finding_id) if retest_finding_id else db.execute(
            select(Finding).where(Finding.endpoint_id == endpoint.id, Finding.category == "access_control", Finding.status != "resolved")
            .order_by(Finding.created_at.desc()).limit(1)
        ).scalars().first()
        if existing:
            existing.verified = True
            existing.status = "open"
            db.add(Evidence(finding_id=existing.id, kind="deterministic_response_match",
                summary="A later scan independently repeated the synthetic cross-agency ownership mismatch. Response content and credentials were not stored.", redacted=True))
            _audit(db, scan.id, "finding_deduplicated", "confirm", f"Repeated access-control evidence linked to existing finding SF-{existing.id:04d}.")
        else:
            finding = Finding(scan_id=scan.id, endpoint_id=endpoint.id,
                title="Cross-agency booking access control failure", category="access_control", severity="high",
                confidence="high", business_impact="An agency user can read another agency's booking record.",
                status="open", verified=True, created_at=_now())
            db.add(finding)
            db.flush()
            db.add(Evidence(finding_id=finding.id, kind="deterministic_response_match",
                summary="Two bounded reads as agency-a returned the synthetic booking 2002 owned by agency-b. Response body and credentials were not stored.", redacted=True))
            _audit(db, scan.id, "finding_verified", "confirm", "Cross-agency ownership mismatch confirmed using synthetic record 2002; response content redacted.")
        db.commit()
        return True, "One high severity cross-agency access-control finding was independently verified."

    _audit(db, scan.id, "check_completed", "no_issue_observed", "Access-control check did not reproduce cross-agency data access.")
    db.commit()
    return False, "Access-control check completed; no cross-agency exposure was observed."


def run_scan(scan_id: int, target_id: int, retest_finding_id: int | None = None) -> None:
    with _SCAN_SEMAPHORE:
        _run_scan(scan_id, target_id, retest_finding_id)


def _run_scan(scan_id: int, target_id: int, retest_finding_id: int | None = None) -> None:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        target = db.get(Target, target_id)
        if not scan or not target:
            return
        try:
            scan.status = "running"
            db.commit()
            scope_stage = _stage(db, scan.id, "scope_validation")
            try:
                # Phase 0.2 kill switch: checked before scope validation so a halted engine
                # never even evaluates whether the target would otherwise be in scope.
                assert_kill_switch_clear(db)
                # The target was allowlist-checked at registration and is checked again before any request.
                validate_target_url(target.base_url)
                if target.status != "authorized":
                    raise ScopeRejected("Target is not marked authorized.")
                if not supports_demo_executor(target):
                    raise ScopeRejected("The available executor is limited to the configured local synthetic demo fixture.")
                _finish_stage(db, scope_stage, "completed")
                _audit(db, scan.id, "scope_validated", "allow", f"Authorized target {target.name}; origin allowlisted.")
            except Exception as exc:
                _finish_stage(db, scope_stage, "failed", str(exc))
                raise

            inventory_stage = _stage(db, scan.id, "inventory")
            try:
                inventory = db.execute(select(Endpoint).where(Endpoint.target_id == target.id).order_by(Endpoint.method, Endpoint.path)).scalars().all()
                if not any(endpoint.path == "/api/v1/bookings/{booking_id}" for endpoint in inventory):
                    endpoint = Endpoint(target_id=target.id, method="GET", path="/api/v1/bookings/{booking_id}", classification="active", sensitivity="sensitive", last_seen=_now(), source="demo_fixture")
                    db.add(endpoint)
                    db.flush()
                    inventory.append(endpoint)
                inventory_keys = sorted({f"{endpoint.method} {endpoint.path}" for endpoint in inventory})
                previous_snapshot = db.execute(select(InventorySnapshot).where(InventorySnapshot.target_id == target.id).order_by(InventorySnapshot.id.desc()).limit(1)).scalars().first()
                previous_keys = set(json.loads(previous_snapshot.inventory_json)) if previous_snapshot else set()
                added, removed = set(inventory_keys) - previous_keys, previous_keys - set(inventory_keys)
                db.add(InventorySnapshot(target_id=target.id, scan_id=scan.id, endpoint_count=len(inventory_keys), inventory_json=json.dumps(inventory_keys)))
                db.commit()
                _finish_stage(db, inventory_stage, "completed")
                _audit(db, scan.id, "inventory_compared", "allow", f"Endpoint snapshot recorded: {len(inventory_keys)} routes; {len(added)} added and {len(removed)} removed since the prior snapshot.")
                if previous_snapshot and (added or removed):
                    # Phase 1.2 traffic-diff watcher: surface the delta as a change event.
                    db.add(ChangeEvent(target_id=target.id, source="traffic_diff",
                        detail=f"{len(added)} endpoint(s) added, {len(removed)} removed since the last snapshot.",
                        triggered_scan_id=scan.id))
                    db.commit()
            except Exception as exc:
                _finish_stage(db, inventory_stage, "failed", str(exc))
                raise
            endpoints = db.execute(select(Endpoint).where(Endpoint.target_id == target.id, Endpoint.path == "/api/v1/bookings/{booking_id}")).scalars().first()

            _ensure_scan_active(db, scan.id)
            vulnerable, summary = _run_access_control_check(db, scan, target, endpoints, retest_finding_id)

            if retest_finding_id is not None:
                previous = db.get(Finding, retest_finding_id)
                if previous:
                    previous.status = "open" if vulnerable else "resolved"
                    _audit(db, scan.id, "finding_retested", "issue_remains" if vulnerable else "resolved", f"Retest result for finding SF-{previous.id:04d}: {'still reproducible' if vulnerable else 'not reproduced'}.")
            scan.status = "completed"
            scan.summary = summary
            scan.finished_at = _now()
            db.commit()
        except Exception as exc:
            scan = db.get(Scan, scan_id)
            if scan:
                if str(exc) == _SCAN_CANCELLED:
                    scan.status = "cancelled"
                elif isinstance(exc, KillSwitchEngaged):
                    scan.status = "halted"
                else:
                    scan.status = "failed"
                scan.summary = str(exc)[:500]
                scan.finished_at = _now()
                _audit(db, scan.id, "scan_stopped", "cancel" if scan.status in ("cancelled", "halted") else "deny", scan.summary)
                db.commit()
