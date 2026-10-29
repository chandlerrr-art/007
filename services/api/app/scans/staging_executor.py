from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent, Endpoint, Evidence, Finding, Scan, ScanStage, Target, TestExecution
from app.safety.credentials import get_call_time_auth_headers, scrub_known_secrets
from app.safety.policy import (
    KillSwitchEngaged,
    RateLimited,
    ScopeRejected,
    assert_kill_switch_clear,
    assert_rate_limit,
    assert_request_scope,
    redact_operational_text,
    supports_staging_executor,
    validate_target_url,
)
from app.settings import settings

REQUEST_TIMEOUT_SECONDS = 3.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _audit(db: Session, scan_id: int | None, event_type: str, decision: str, details: str) -> None:
    sanitized = redact_operational_text(scrub_known_secrets(details))
    db.add(AuditEvent(scan_id=scan_id, event_type=event_type, decision=decision, details=sanitized[:1000]))
    db.commit()


def _stage(db: Session, scan_id: int, name: str) -> ScanStage:
    row = ScanStage(scan_id=scan_id, name=name, status="running", started_at=_now())
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _finish_stage(db: Session, stage: ScanStage, status: str, error: str | None = None) -> None:
    stage.status = status
    stage.error = redact_operational_text(scrub_known_secrets(error)) if error else None
    stage.finished_at = _now()
    db.commit()


class StagingTargetExecutor:
    """Independent staging-target executor.
    
    Reuses the shared safety layer (allowlist check, token-bucket rate limiter,
    timeout, health check, kill switch, audit log), but carries its own request
    budget, scoped test-account credentials, and modular attack logic (never
    the local-demo IDOR probe).
    """

    name: str = "staging_executor"

    def __init__(self, request_budget: int | None = None) -> None:
        self.request_budget = request_budget or getattr(settings, "staging_request_budget", 10)

    def supports(self, target: Target) -> bool:
        return supports_staging_executor(target)

    def _bounded_request(
        self,
        db: Session,
        scan_id: int,
        client: httpx.Client,
        target: Target,
        method: str,
        url: str,
        headers: dict[str, str],
        counter: list[int],
    ) -> httpx.Response:
        assert_kill_switch_clear(db)
        if counter[0] >= self.request_budget:
            _audit(db, scan_id, "outbound_request", "deny", "Request blocked: staging scan request budget exhausted.")
            raise RuntimeError(f"Staging request budget of {self.request_budget} exhausted.")
        
        try:
            assert_request_scope(target, url)
        except ScopeRejected as exc:
            _audit(db, scan_id, "outbound_request", "deny", f"{method} {url.split('?', 1)[0]} rejected by target scope policy: {exc}")
            raise
        
        path = url.split(target.base_url.rstrip("/"), 1)[-1].split("?", 1)[0] or "/"
        try:
            assert_rate_limit(target, path)
        except RateLimited as exc:
            _audit(db, scan_id, "outbound_request", "deny", f"{method} {path} rejected by rate limiter: {exc}")
            raise
        
        counter[0] += 1
        # Redaction rule: Headers and credentials are NEVER written to the audit log.
        _audit(db, scan_id, "outbound_request", "allow", f"{method} {path}; request {counter[0]}/{self.request_budget}; timeout {REQUEST_TIMEOUT_SECONDS}s.")
        
        try:
            response = client.request(method, url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=False)
        except httpx.RequestError as exc:
            _audit(db, scan_id, "outbound_request_result", "error", f"{method} {path} failed with {type(exc).__name__}; no response body stored.")
            raise
        
        _audit(db, scan_id, "outbound_request_result", "complete", f"{method} {path} returned HTTP {response.status_code}; response content not stored.")
        return response

    def _health_check(
        self,
        db: Session,
        scan: Scan,
        target: Target,
        client: httpx.Client,
        counter: list[int],
        stage_name: str,
    ) -> None:
        stage = _stage(db, scan.id, stage_name)
        try:
            url = f"{target.base_url.rstrip('/')}/health"
            response = self._bounded_request(db, scan.id, client, target, "GET", url, {}, counter)
            if response.status_code != 200:
                raise RuntimeError("Staging target health check failed.")
            _finish_stage(db, stage, "completed")
        except Exception as exc:
            _finish_stage(db, stage, "failed", str(exc))
            raise

    def run(
        self,
        db: Session,
        scan: Scan,
        target: Target,
        retest_finding_id: int | None = None,
    ) -> tuple[bool, str]:
        counter = [0]
        with httpx.Client(trust_env=False) as client:
            self._health_check(db, scan, target, client, counter, "staging_preflight_health")

            # 1. Scoped Test-Account Baseline Check (inject credential strictly at call time)
            auth_stage = _stage(db, scan.id, "staging_auth_verification")
            try:
                headers = get_call_time_auth_headers(db, target.id, role="travel_agent")
                ping_url = f"{target.base_url.rstrip('/')}/api/v1/session/me"
                try:
                    self._bounded_request(db, scan.id, client, target, "GET", ping_url, headers, counter)
                except httpx.RequestError:
                    pass  # Non-fatal during exploratory baseline
                _finish_stage(db, auth_stage, "completed")
            except Exception as exc:
                _finish_stage(db, auth_stage, "failed", str(exc))
                raise

            # 2. Risky Test Gate Evaluation
            # Define or locate the risky test for this target/scan
            test_stmt = select(TestExecution).where(
                TestExecution.target_id == target.id,
                TestExecution.test_type == "privilege_escalation",
            ).order_by(TestExecution.id.desc()).limit(1)
            test_execution = db.execute(test_stmt).scalars().first()

            if not test_execution:
                test_execution = TestExecution(
                    scan_id=scan.id,
                    target_id=target.id,
                    name="Cross-Role Administrative Privilege Escalation",
                    test_type="privilege_escalation",
                    is_risky=True,
                    risk_level="high",
                    risk_rationale="Tests mutation/access on administrative routes using a standard role test account. Requires human review.",
                    status="pending_review",
                )
                db.add(test_execution)
                db.commit()
                db.refresh(test_execution)

            gate_stage = _stage(db, scan.id, "risky_test_approval_gate")
            if test_execution.status == "pending_review":
                # BLOCKED: Risky test must not execute until approved by a human
                _audit(
                    db,
                    scan.id,
                    "risky_test_blocked",
                    "deny",
                    f"Risky test #{test_execution.id} ('{test_execution.name}') blocked: awaiting human reviewer approval.",
                )
                _finish_stage(db, gate_stage, "blocked", "Awaiting human reviewer approval.")
                self._health_check(db, scan, target, client, counter, "staging_postflight_health")
                return False, f"Staging scan completed safely. Risky test #{test_execution.id} was held in pending_review."

            elif test_execution.status == "rejected":
                _audit(
                    db,
                    scan.id,
                    "risky_test_skipped",
                    "deny",
                    f"Risky test #{test_execution.id} ('{test_execution.name}') skipped: rejected by human reviewer.",
                )
                _finish_stage(db, gate_stage, "skipped", "Rejected by human reviewer.")
                self._health_check(db, scan, target, client, counter, "staging_postflight_health")
                return False, f"Staging scan completed. Risky test #{test_execution.id} was skipped (rejected by reviewer)."

            # If test is approved, execute the risky test logic
            _finish_stage(db, gate_stage, "completed")
            exec_stage = _stage(db, scan.id, "risky_test_execution")
            try:
                # Call-time injected credentials
                call_headers = get_call_time_auth_headers(db, target.id, role="travel_agent")
                admin_probe_url = f"{target.base_url.rstrip('/')}/api/v1/admin/agencies"
                response = self._bounded_request(db, scan.id, client, target, "GET", admin_probe_url, call_headers, counter)
                
                is_vulnerable = response.status_code == 200
                _finish_stage(db, exec_stage, "completed")
            except Exception as exc:
                _finish_stage(db, exec_stage, "failed", str(exc))
                raise

            self._health_check(db, scan, target, client, counter, "staging_postflight_health")

            if is_vulnerable:
                # High-severity finding detected: Must enter pending_review before escalation
                finding = Finding(
                    scan_id=scan.id,
                    endpoint_id=None,
                    title="Cross-Role Administrative Privilege Escalation",
                    category="access_control",
                    severity="high",
                    confidence="high",
                    business_impact="Standard test account can access administrative agency management endpoint.",
                    status="pending_review",  # Human approval state machine: pending_review
                    verified=True,
                )
                db.add(finding)
                db.flush()
                # Strict redaction: No credentials, no response body
                db.add(
                    Evidence(
                        finding_id=finding.id,
                        kind="unauthorized_role_access",
                        summary="Standard travel_agent test account accessed administrative endpoint /api/v1/admin/agencies. Response body and credentials not stored.",
                        redacted=True,
                    )
                )
                _audit(
                    db,
                    scan.id,
                    "high_severity_finding_held",
                    "hold",
                    f"High-severity finding SF-{finding.id:04d} held in pending_review until approved by human reviewer.",
                )
                db.commit()
                return True, f"One high-severity finding was identified and placed in pending_review for human evaluation."

            return False, "Staging scan completed; no unauthorized privilege escalation observed."
