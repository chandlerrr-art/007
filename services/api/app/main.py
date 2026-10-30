import json
import re
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.db import SessionLocal, get_db
from app.models import (
    AuditEvent,
    ChangeEvent,
    DiscoveredVulnerability,
    Endpoint,
    EndpointParameter,
    EndpointRoleObservation,
    Evidence,
    Finding,
    InventorySnapshot,
    Scan,
    ScanStage,
    Target,
    TestAccountCredential,
    TestExecution,
    TrafficLogEntry,
    VulnerabilityScan,
)
from app.inventory.service import (
    classify_endpoints,
    extract_parameters_from_har_entry,
    infer_api_version,
    infer_business_flow,
    infer_likely_owner,
    ingest_gateway_logs,
    normalize_endpoint_path,
)
from app.safety.credentials import (
    decrypt_secret,
    get_call_time_auth_headers,
    scrub_known_secrets,
    store_credential,
)
from app.safety.policy import (
    ScopeRejected,
    get_safety_control,
    redact_operational_text,
    supports_demo_executor,
    supports_staging_executor,
    validate_target_url,
)
from app.scans.orchestrator import run_scan
from app.scans.registry import executor_registry
from app.vulnerability.engine import run_vulnerability_scan

app = FastAPI(title="007 API", version="0.1.0", description="Local-first authorized security testing platform")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


class TargetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    base_url: str = Field(min_length=8, max_length=500)
    environment: str = Field(default="staging", max_length=40)
    scope_note: str = Field(default="", max_length=500)


class HARImport(BaseModel):
    content: str = Field(max_length=5_000_000)


class ScanCreate(BaseModel):
    target_id: int = Field(gt=0)


class DeployWebhook(BaseModel):
    target_id: int = Field(gt=0)
    release: str = Field(default="", max_length=200, pattern=r"^[A-Za-z0-9._+/-]*$")
    # Retained for caller compatibility; free-form notes are intentionally not persisted.
    note: str = Field(default="", max_length=500)


class KillSwitchUpdate(BaseModel):
    engaged: bool
    reason: str = Field(default="", max_length=500)


class CredentialCreate(BaseModel):
    role: str = Field(min_length=2, max_length=80)
    username: str = Field(min_length=1, max_length=120)
    secret: str = Field(min_length=1, max_length=1000)
    auth_type: str = Field(default="bearer", max_length=40)
    header_name: str = Field(default="Authorization", max_length=80)


class CredentialResponse(BaseModel):
    id: int
    target_id: int
    role: str
    username: str
    auth_type: str
    header_name: str
    created_at: datetime
    configured: bool = True


class ReviewNoteRequest(BaseModel):
    notes: str = Field(default="", max_length=500)


class ReviewDecisionRequest(BaseModel):
    decision: Literal["approved", "rejected"] = "approved"
    notes: str = Field(default="", max_length=500)


class TestExecutionResponse(BaseModel):
    id: int
    scan_id: int
    target_id: int
    name: str
    test_type: str
    is_risky: bool
    risk_level: str
    risk_rationale: str
    status: str
    reviewer_notes: str
    reviewed_at: datetime | None
    created_at: datetime


class HealthResponse(BaseModel):
    status: Literal["healthy"]
    database: Literal["connected"]


class TargetResponse(BaseModel):
    id: int
    name: str
    base_url: str
    environment: str
    status: str
    scope_note: str = ""


class DashboardSummary(BaseModel):
    active_scans: int
    verified_findings: int
    endpoints: int
    targets: int
    pending_reviews: int = 0


class DashboardFinding(BaseModel):
    id: int
    title: str
    category: str
    severity: str
    confidence: str
    verified: bool
    status: str
    path: str
    target: str


class DashboardScan(BaseModel):
    id: int
    target: str
    status: str
    trigger: str
    started_at: datetime
    summary: str


class DashboardChange(BaseModel):
    id: int
    target: str
    source: str
    detail: str
    created_at: datetime


class ChangeResponse(DashboardChange):
    triggered_scan_id: int | None = None


class ParameterResponse(BaseModel):
    name: str
    location: str
    observed_type: str


class RoleObservationResponse(BaseModel):
    role: str
    allowed: bool
    status_code: int
    last_observed: datetime


class EndpointResponse(BaseModel):
    id: int
    target_id: int
    method: str
    path: str
    classification: str
    sensitivity: str
    last_seen: datetime
    source: str
    business_flow: str | None = None
    api_version: str = "v1"
    first_seen_traffic: datetime | None = None
    last_seen_traffic: datetime | None = None
    traffic_hit_count: int = 0
    auth_required: bool = True
    auth_reachability: str = "authenticated_only"
    owner: str = "Unassigned"
    likely_owner: str = "Unassigned"
    version_notes: str = ""
    data_fields_summary: str = ""
    recommended_action: str = "keep_active"
    parameters: list[ParameterResponse] = []
    role_observations: list[RoleObservationResponse] = []


class DashboardResponse(BaseModel):
    summary: DashboardSummary
    severity: dict[str, int]
    targets: list[TargetResponse]
    findings: list[DashboardFinding]
    scans: list[DashboardScan]
    changes: list[DashboardChange]
    safety: dict[str, str | bool]
    recent_audit_events: int
    pending_tests: list[TestExecutionResponse] = []


class ReviewQueueResponse(BaseModel):
    pending_tests: list[TestExecutionResponse]
    pending_findings: list[DashboardFinding]
    recent_audit_events: int


class SafetyStatusResponse(BaseModel):
    kill_switch_engaged: bool
    reason: str
    updated_at: datetime | None


class ScanAcceptedResponse(BaseModel):
    id: int
    target_id: int
    status: Literal["queued"]


class CancelResponse(BaseModel):
    id: int
    status: str
    message: str | None = None


class StageReport(BaseModel):
    name: str
    status: str
    error: str | None


class ScanStatusResponse(BaseModel):
    id: int
    target_id: int
    status: str
    trigger: str
    started_at: datetime
    finished_at: datetime | None
    summary: str
    stages: list[StageReport]


class FindingReport(BaseModel):
    id: int
    title: str
    category: str
    severity: str
    confidence: str
    business_impact: str
    status: str
    verified: bool
    affected_endpoint: str
    reproduction_steps: list[str]
    evidence: list[dict[str, str | bool]]
    remediation: str
    owner: str


class ScanReportResponse(BaseModel):
    scan: dict[str, int | str | None]
    target: dict[str, str]
    stages: list[StageReport]
    inventory_snapshots: list[dict[str, object]]
    audit_events: list[dict[str, object]]
    findings: list[FindingReport]


class RetestAcceptedResponse(ScanAcceptedResponse):
    retests_finding: int


class DeployResponse(BaseModel):
    change_event_id: int
    scan_started: bool
    reason: str | None = None
    scan_id: int | None = None


class HARImportResponse(BaseModel):
    target_id: int
    discovered: int
    inserted: int
    note: str


class GatewayLogImport(BaseModel):
    content: str = Field(max_length=10_000_000)
    window_days: int = Field(default=90, ge=1, le=365)
    source: str = Field(default="gateway_access_log", max_length=80)


class GatewayLogImportResponse(BaseModel):
    target_id: int
    ingested_entries: int
    endpoints_discovered: int
    window_days: int
    note: str


class ClassifyRequest(BaseModel):
    window_days: int = Field(default=90, ge=1, le=365)


class ClassificationSummaryResponse(BaseModel):
    target_id: int
    total_endpoints: int
    active_count: int
    zombie_count: int
    shadow_count: int
    window_days: int
    endpoints: list[EndpointResponse]


HAR_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
HAR_STATIC_RESOURCE_SEGMENTS = {"current", "me", "search", "all", "recent", "active", "quote", "history", "summary"}


def normalize_har_path(raw_path: str) -> str:
    """Normalize dynamic IDs and redact common direct identifiers before inventory storage."""
    path = unquote(raw_path or "/")
    path = re.sub(r"[\x00-\x1f\x7f]", "", path)
    path = re.sub(r"(?i)(?<=[/])[0-9a-f]{8}-[0-9a-f-]{27,}", "{id}", path)
    path = re.sub(r"(?<=/)\d+(?=/|$)", "{id}", path)
    path = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "{id}", path)
    path = re.sub(r"(?<!\w)\+?\d[\d ().-]{7,}\d(?!\w)", "{id}", path)
    path = re.sub(r"(?i)(/(?:access[_-]?tokens?|tokens?|sessions?|secrets?|api[_-]?keys?)/)[^/]+", r"\1{redacted}", path)

    def normalize_resource(match: re.Match[str]) -> str:
        if match.group(2).casefold() in HAR_STATIC_RESOURCE_SEGMENTS:
            return match.group(0)
        return f"{match.group(1)}{{id}}"

    return re.sub(r"(?i)(/(?:bookings?|users?|agencies|orders?|travelers?|refunds?)/)([^/]+)", normalize_resource, path)


@app.get("/api/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> dict[str, str]:
    db.execute(text("SELECT 1"))
    return {"status": "healthy", "database": "connected"}


@app.get("/api/dashboard", response_model=DashboardResponse)
def dashboard(db: Session = Depends(get_db)) -> dict:
    severity_counts = dict(db.execute(select(Finding.severity, func.count(Finding.id)).where(Finding.status != "resolved").group_by(Finding.severity)).all())
    findings = db.execute(
        select(Finding, Endpoint.path, Scan.target_id, Target.name)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .outerjoin(Endpoint, Finding.endpoint_id == Endpoint.id)
        .order_by(Finding.created_at.desc()).limit(8)
    ).all()
    recent_scans = db.execute(
        select(Scan, Target.name).join(Target, Scan.target_id == Target.id).order_by(Scan.started_at.desc()).limit(6)
    ).all()
    target_rows = db.execute(select(Target).order_by(Target.name)).scalars().all()
    change_rows = db.execute(
        select(ChangeEvent, Target.name).join(Target, ChangeEvent.target_id == Target.id)
        .order_by(ChangeEvent.created_at.desc()).limit(6)
    ).all()
    control = get_safety_control(db)

    pending_tests = db.execute(
        select(TestExecution).where(TestExecution.status == "pending_review").order_by(TestExecution.created_at.desc()).limit(10)
    ).scalars().all()
    pending_findings_count = db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "pending_review")) or 0
    pending_tests_count = len(pending_tests)

    return {
        "summary": {
            "active_scans": db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running", "cancel_requested"]))) or 0,
            "verified_findings": db.scalar(select(func.count()).select_from(Finding).where(Finding.verified.is_(True))) or 0,
            "endpoints": db.scalar(select(func.count()).select_from(Endpoint)) or 0,
            "targets": len(target_rows),
            "pending_reviews": pending_findings_count + pending_tests_count,
        },
        "severity": {key: severity_counts.get(key, 0) for key in ("critical", "high", "medium", "low", "info")},
        "targets": [{"id": t.id, "name": t.name, "base_url": t.base_url, "environment": t.environment, "status": t.status} for t in target_rows],
        "findings": [{"id": f.id, "title": f.title, "category": f.category, "severity": f.severity, "confidence": f.confidence, "verified": f.verified, "status": f.status, "path": path or "Endpoint unavailable", "target": target_name} for f, path, _target_id, target_name in findings],
        "scans": [{"id": scan.id, "target": target_name, "status": scan.status, "trigger": scan.trigger, "started_at": scan.started_at.isoformat(), "summary": scan.summary} for scan, target_name in recent_scans],
        "changes": [{"id": c.id, "target": name, "source": c.source, "detail": c.detail, "created_at": c.created_at.isoformat()} for c, name in change_rows],
        "safety": {"kill_switch_engaged": control.kill_switch_engaged, "reason": control.reason},
        "recent_audit_events": db.scalar(select(func.count()).select_from(AuditEvent)) or 0,
        "pending_tests": [
            {
                "id": t.id,
                "scan_id": t.scan_id,
                "target_id": t.target_id,
                "name": t.name,
                "test_type": t.test_type,
                "is_risky": t.is_risky,
                "risk_level": t.risk_level,
                "risk_rationale": t.risk_rationale,
                "status": t.status,
                "reviewer_notes": t.reviewer_notes,
                "reviewed_at": t.reviewed_at,
                "created_at": t.created_at,
            }
            for t in pending_tests
        ],
    }


@app.get("/api/targets", response_model=list[TargetResponse])
def list_targets(db: Session = Depends(get_db)) -> list[dict]:
    return [{"id": t.id, "name": t.name, "base_url": t.base_url, "environment": t.environment, "status": t.status, "scope_note": t.scope_note}
            for t in db.execute(select(Target).order_by(Target.name)).scalars()]


@app.post("/api/targets", status_code=201, response_model=TargetResponse)
def create_target(payload: TargetCreate, db: Session = Depends(get_db)) -> dict:
    try:
        validate_target_url(payload.base_url)
    except ScopeRejected as exc:
        db.add(AuditEvent(event_type="target_registration_denied", decision="deny", details="Target registration blocked by the configured origin allowlist."))
        db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    target = Target(name=payload.name, base_url=payload.base_url.rstrip("/"), environment=payload.environment,
                    status="authorized", scope_note=payload.scope_note)
    db.add(target)
    db.flush()
    db.add(AuditEvent(event_type="target_registered", decision="allow", details=f"Target {target.name} registered at allowlisted origin ({target.environment})."))
    db.commit()
    db.refresh(target)
    return {"id": target.id, "name": target.name, "base_url": target.base_url, "environment": target.environment, "status": target.status}


@app.get("/api/targets/{target_id}/endpoints", response_model=list[EndpointResponse])
def list_endpoints(target_id: int, db: Session = Depends(get_db)) -> list[dict]:
    if not db.get(Target, target_id):
        raise HTTPException(status_code=404, detail="Target not found.")
    endpoints = db.execute(select(Endpoint).where(Endpoint.target_id == target_id).order_by(Endpoint.method, Endpoint.path)).scalars().all()
    results = []
    for endpoint in endpoints:
        params = db.execute(select(EndpointParameter).where(EndpointParameter.endpoint_id == endpoint.id).order_by(EndpointParameter.location, EndpointParameter.name)).scalars().all()
        roles = db.execute(select(EndpointRoleObservation).where(EndpointRoleObservation.endpoint_id == endpoint.id).order_by(EndpointRoleObservation.last_observed.desc())).scalars().all()
        results.append({
            "id": endpoint.id,
            "target_id": endpoint.target_id,
            "method": endpoint.method,
            "path": endpoint.path,
            "classification": endpoint.classification,
            "sensitivity": endpoint.sensitivity,
            "last_seen": endpoint.last_seen,
            "source": endpoint.source,
            "business_flow": endpoint.business_flow,
            "api_version": endpoint.api_version,
            "first_seen_traffic": endpoint.first_seen_traffic,
            "last_seen_traffic": endpoint.last_seen_traffic,
            "traffic_hit_count": endpoint.traffic_hit_count,
            "auth_required": endpoint.auth_required,
            "auth_reachability": endpoint.auth_reachability,
            "owner": endpoint.owner,
            "likely_owner": endpoint.likely_owner,
            "version_notes": endpoint.version_notes,
            "data_fields_summary": endpoint.data_fields_summary,
            "recommended_action": endpoint.recommended_action,
            "parameters": [{"name": p.name, "location": p.location, "observed_type": p.observed_type} for p in params],
            "role_observations": [{"role": r.role, "allowed": r.allowed, "status_code": r.status_code, "last_observed": r.last_observed} for r in roles],
        })
    return results


@app.post("/api/targets/{target_id}/har-import", response_model=HARImportResponse)
def import_har(target_id: int, payload: HARImport, db: Session = Depends(get_db)) -> dict:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")
    try:
        validate_target_url(target.base_url)
        har = json.loads(payload.content)
    except (ScopeRejected, json.JSONDecodeError) as exc:
        db.add(AuditEvent(event_type="har_import_denied", decision="deny", details="HAR import rejected because the target scope or HAR JSON was invalid."))
        db.commit()
        raise HTTPException(status_code=422, detail=f"Invalid or out-of-scope HAR: {exc}") from exc
    entries = har.get("log", {}).get("entries", []) if isinstance(har, dict) else []
    if not isinstance(entries, list):
        raise HTTPException(status_code=422, detail="HAR log.entries must be an array.")
    base_origin = urlsplit(target.base_url)
    extracted_entries: list[tuple[str, str, dict]] = []
    seen_routes: set[tuple[str, str]] = set()

    for entry in entries[:10000]:
        request = entry.get("request", {}) if isinstance(entry, dict) else {}
        try:
            method = str(request.get("method", "GET")).upper()[:12]
            if method not in HAR_METHODS:
                continue
            parts = urlsplit(request.get("url", ""))
            if parts.scheme != base_origin.scheme or parts.netloc.lower() != base_origin.netloc.lower():
                continue
            path = normalize_endpoint_path(parts.path)
            if len(path) <= 1000:
                seen_routes.add((method, path))
                extracted_entries.append((method, path, entry))
        except (TypeError, ValueError):
            continue

    inserted = 0
    now = datetime.now(timezone.utc)
    for method, path, entry in extracted_entries:
        endpoint = db.execute(
            select(Endpoint).where(Endpoint.target_id == target.id, Endpoint.method == method, Endpoint.path == path)
        ).scalars().first()
        req = entry.get("request", {})
        has_auth = any(h.get("name", "").lower() in {"authorization", "cookie", "x-api-key", "token"} for h in req.get("headers", []))
        if endpoint:
            endpoint.last_seen = now
            endpoint.source = "HAR"
        else:
            endpoint = Endpoint(
                target_id=target.id,
                method=method,
                path=path,
                classification="active",
                sensitivity="unknown",
                last_seen=now,
                source="HAR",
                business_flow=infer_business_flow(path, method),
                api_version=infer_api_version(path),
                owner=infer_likely_owner(path),
                likely_owner=infer_likely_owner(path),
                auth_required=has_auth,
                auth_reachability="authenticated_only" if has_auth else "unauthenticated",
                recommended_action="keep_active",
            )
            db.add(endpoint)
            db.flush()
            inserted += 1

        discovered_params = extract_parameters_from_har_entry(entry)
        existing_params = {
            (p.name.lower(), p.location)
            for p in db.execute(select(EndpointParameter).where(EndpointParameter.endpoint_id == endpoint.id)).scalars().all()
        }
        for dp in discovered_params:
            if (dp["name"].lower(), dp["location"]) not in existing_params:
                db.add(EndpointParameter(
                    endpoint_id=endpoint.id,
                    name=dp["name"],
                    location=dp["location"],
                    observed_type=dp["observed_type"],
                ))
                existing_params.add((dp["name"].lower(), dp["location"]))

    classify_endpoints(db, target.id, window_days=90)
    db.add(AuditEvent(
        event_type="har_imported",
        decision="allow",
        details=f"Imported {inserted} new endpoints with parameter shapes for target {target.name}; raw parameter values discarded.",
    ))
    db.commit()
    return {
        "target_id": target.id,
        "discovered": len(seen_routes),
        "inserted": inserted,
        "note": "Request headers, cookies, and query/body parameter names and types preserved under strict redaction rules (raw values discarded).",
    }


@app.post("/api/targets/{target_id}/gateway-logs", response_model=GatewayLogImportResponse)
def import_gateway_logs_endpoint(target_id: int, payload: GatewayLogImport, db: Session = Depends(get_db)) -> dict:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")
    try:
        validate_target_url(target.base_url)
    except ScopeRejected as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    results = ingest_gateway_logs(db, target_id=target.id, raw_logs=payload.content, window_days=payload.window_days, source=payload.source)
    classify_endpoints(db, target.id, window_days=payload.window_days)
    db.add(AuditEvent(
        event_type="gateway_logs_ingested",
        decision="allow",
        details=f"Ingested {results['ingested_entries']} traffic log records for target {target.name} (window: {payload.window_days} days). Discovered {results['endpoints_discovered']} shadow/new endpoints.",
    ))
    db.commit()
    return {
        "target_id": target.id,
        "ingested_entries": results["ingested_entries"],
        "endpoints_discovered": results["endpoints_discovered"],
        "window_days": payload.window_days,
        "note": "Traffic log entries ingested with observation window tagging; endpoints classified into active/zombie/shadow.",
    }


@app.post("/api/targets/{target_id}/classify", response_model=ClassificationSummaryResponse)
def trigger_classification(target_id: int, payload: ClassifyRequest | None = None, db: Session = Depends(get_db)) -> dict:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")
    window_days = payload.window_days if payload else 90
    endpoints = classify_endpoints(db, target.id, window_days=window_days)

    active_count = sum(1 for e in endpoints if e.classification == "active")
    zombie_count = sum(1 for e in endpoints if e.classification == "zombie")
    shadow_count = sum(1 for e in endpoints if e.classification == "shadow")

    ep_responses = []
    for ep in endpoints:
        params = db.execute(select(EndpointParameter).where(EndpointParameter.endpoint_id == ep.id)).scalars().all()
        roles = db.execute(select(EndpointRoleObservation).where(EndpointRoleObservation.endpoint_id == ep.id)).scalars().all()
        ep_responses.append({
            "id": ep.id,
            "target_id": ep.target_id,
            "method": ep.method,
            "path": ep.path,
            "classification": ep.classification,
            "sensitivity": ep.sensitivity,
            "last_seen": ep.last_seen,
            "source": ep.source,
            "business_flow": ep.business_flow,
            "api_version": ep.api_version,
            "first_seen_traffic": ep.first_seen_traffic,
            "last_seen_traffic": ep.last_seen_traffic,
            "traffic_hit_count": ep.traffic_hit_count,
            "auth_required": ep.auth_required,
            "auth_reachability": ep.auth_reachability,
            "owner": ep.owner,
            "likely_owner": ep.likely_owner,
            "version_notes": ep.version_notes,
            "data_fields_summary": ep.data_fields_summary,
            "recommended_action": ep.recommended_action,
            "parameters": [{"name": p.name, "location": p.location, "observed_type": p.observed_type} for p in params],
            "role_observations": [{"role": r.role, "allowed": r.allowed, "status_code": r.status_code, "last_observed": r.last_observed} for r in roles],
        })

    db.add(AuditEvent(
        event_type="endpoints_classified",
        decision="allow",
        details=f"Target {target.name} classified: {active_count} active, {zombie_count} zombie, {shadow_count} shadow (window: {window_days}d).",
    ))
    db.commit()
    return {
        "target_id": target.id,
        "total_endpoints": len(endpoints),
        "active_count": active_count,
        "zombie_count": zombie_count,
        "shadow_count": shadow_count,
        "window_days": window_days,
        "endpoints": ep_responses,
    }


# --- Scoped Test-Account Credential Store Endpoints ---

@app.post("/api/targets/{target_id}/credentials", status_code=201, response_model=CredentialResponse)
def add_credential(target_id: int, payload: CredentialCreate, db: Session = Depends(get_db)) -> dict:
    """Store a role-scoped test account encrypted at rest. Never exposes secret in response."""
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")
    
    cred = store_credential(
        db,
        target_id=target.id,
        role=payload.role,
        username=payload.username,
        secret=payload.secret,
        auth_type=payload.auth_type,
        header_name=payload.header_name,
    )
    # Redaction discipline: Only role and username in audit log; cleartext secret NEVER logged
    db.add(AuditEvent(
        event_type="test_credential_registered",
        decision="allow",
        details=f"Scoped test credential registered for target {target.name}: role={cred.role}, username={cred.username}. Secret encrypted at rest.",
    ))
    db.commit()
    return {
        "id": cred.id,
        "target_id": cred.target_id,
        "role": cred.role,
        "username": cred.username,
        "auth_type": cred.auth_type,
        "header_name": cred.header_name,
        "created_at": cred.created_at,
        "configured": True,
    }


@app.get("/api/targets/{target_id}/credentials", response_model=list[CredentialResponse])
def list_credentials(target_id: int, db: Session = Depends(get_db)) -> list[dict]:
    """List configured test credentials. Secrets are strictly omitted/redacted."""
    if not db.get(Target, target_id):
        raise HTTPException(status_code=404, detail="Target not found.")
    creds = db.execute(
        select(TestAccountCredential).where(TestAccountCredential.target_id == target_id).order_by(TestAccountCredential.id)
    ).scalars().all()
    return [
        {
            "id": c.id,
            "target_id": c.target_id,
            "role": c.role,
            "username": c.username,
            "auth_type": c.auth_type,
            "header_name": c.header_name,
            "created_at": c.created_at,
            "configured": True,
        }
        for c in creds
    ]


@app.delete("/api/targets/{target_id}/credentials/{credential_id}")
def delete_credential(target_id: int, credential_id: int, db: Session = Depends(get_db)) -> dict:
    cred = db.get(TestAccountCredential, credential_id)
    if not cred or cred.target_id != target_id:
        raise HTTPException(status_code=404, detail="Credential not found.")
    db.delete(cred)
    db.add(AuditEvent(
        event_type="test_credential_deleted",
        decision="allow",
        details=f"Test credential #{credential_id} deleted for target #{target_id}.",
    ))
    db.commit()
    return {"message": "Credential deleted successfully."}


# --- Human Approval & Reviewer Endpoints ---

@app.get("/api/reviews", response_model=ReviewQueueResponse)
def get_review_queue(db: Session = Depends(get_db)) -> dict:
    """Retrieve all items currently pending human reviewer approval."""
    pending_tests = db.execute(
        select(TestExecution).where(TestExecution.status == "pending_review").order_by(TestExecution.created_at.desc())
    ).scalars().all()
    pending_findings = db.execute(
        select(Finding, Endpoint.path, Scan.target_id, Target.name)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .outerjoin(Endpoint, Finding.endpoint_id == Endpoint.id)
        .where(Finding.status == "pending_review")
        .order_by(Finding.created_at.desc())
    ).all()
    
    return {
        "pending_tests": [
            {
                "id": t.id,
                "scan_id": t.scan_id,
                "target_id": t.target_id,
                "name": t.name,
                "test_type": t.test_type,
                "is_risky": t.is_risky,
                "risk_level": t.risk_level,
                "risk_rationale": t.risk_rationale,
                "status": t.status,
                "reviewer_notes": t.reviewer_notes,
                "reviewed_at": t.reviewed_at,
                "created_at": t.created_at,
            }
            for t in pending_tests
        ],
        "pending_findings": [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "verified": f.verified,
                "status": f.status,
                "path": path or "Endpoint unavailable",
                "target": target_name,
            }
            for f, path, _tid, target_name in pending_findings
        ],
        "recent_audit_events": db.scalar(select(func.count()).select_from(AuditEvent)) or 0,
    }


@app.post("/api/reviews/tests/{test_id}/approve")
def approve_test(test_id: int, payload: ReviewNoteRequest | None = None, db: Session = Depends(get_db)) -> dict:
    test = db.get(TestExecution, test_id)
    if not test:
        raise HTTPException(status_code=404, detail="Test execution record not found.")
    notes = redact_operational_text(payload.notes if payload else "")
    test.status = "approved"
    test.reviewed_at = datetime.now(timezone.utc)
    test.reviewer_notes = notes
    db.add(AuditEvent(
        scan_id=test.scan_id,
        event_type="test_approved_by_reviewer",
        decision="allow",
        details=f"Risky test #{test.id} ('{test.name}') was approved by human reviewer. Notes: {notes or 'None'}.",
    ))
    db.commit()
    db.refresh(test)
    return {"id": test.id, "status": test.status, "message": f"Test '{test.name}' approved."}


@app.post("/api/reviews/tests/{test_id}/reject")
def reject_test(test_id: int, payload: ReviewNoteRequest | None = None, db: Session = Depends(get_db)) -> dict:
    test = db.get(TestExecution, test_id)
    if not test:
        raise HTTPException(status_code=404, detail="Test execution record not found.")
    notes = redact_operational_text(payload.notes if payload else "")
    test.status = "rejected"
    test.reviewed_at = datetime.now(timezone.utc)
    test.reviewer_notes = notes
    db.add(AuditEvent(
        scan_id=test.scan_id,
        event_type="test_rejected_by_reviewer",
        decision="deny",
        details=f"Risky test #{test.id} ('{test.name}') was rejected by human reviewer. Notes: {notes or 'None'}.",
    ))
    db.commit()
    db.refresh(test)
    return {"id": test.id, "status": test.status, "message": f"Test '{test.name}' rejected."}


@app.post("/api/reviews/findings/{finding_id}/approve")
def approve_finding(finding_id: int, payload: ReviewNoteRequest | None = None, db: Session = Depends(get_db)) -> dict:
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    notes = redact_operational_text(payload.notes if payload else "")
    finding.status = "approved"
    finding.verified = True
    finding.reviewed_at = datetime.now(timezone.utc)
    finding.review_notes = notes
    db.add(AuditEvent(
        scan_id=finding.scan_id,
        event_type="finding_approved_by_reviewer",
        decision="allow",
        details=f"Finding SF-{finding.id:04d} ('{finding.title}') was approved by reviewer. Escalated to verified finding.",
    ))
    db.commit()
    db.refresh(finding)
    return {"id": finding.id, "status": finding.status, "verified": finding.verified}


@app.post("/api/reviews/findings/{finding_id}/reject")
def reject_finding(finding_id: int, payload: ReviewNoteRequest | None = None, db: Session = Depends(get_db)) -> dict:
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    notes = redact_operational_text(payload.notes if payload else "")
    finding.status = "rejected"
    finding.verified = False
    finding.reviewed_at = datetime.now(timezone.utc)
    finding.review_notes = notes
    db.add(AuditEvent(
        scan_id=finding.scan_id,
        event_type="finding_rejected_by_reviewer",
        decision="deny",
        details=f"Finding SF-{finding.id:04d} ('{finding.title}') was rejected as false positive / out of scope.",
    ))
    db.commit()
    db.refresh(finding)
    return {"id": finding.id, "status": finding.status, "verified": finding.verified}


@app.post("/api/findings/{finding_id}/review")
def review_finding(finding_id: int, payload: ReviewDecisionRequest, db: Session = Depends(get_db)) -> dict:
    if payload.decision == "approved":
        return approve_finding(finding_id, payload, db)
    return reject_finding(finding_id, payload, db)


@app.post("/api/tests/{test_id}/review")
def review_test(test_id: int, payload: ReviewDecisionRequest, db: Session = Depends(get_db)) -> dict:
    if payload.decision == "approved":
        return approve_test(test_id, payload, db)
    return reject_test(test_id, payload, db)


# --- Core Scan & Safety Operations ---

@app.get("/api/safety/status", response_model=SafetyStatusResponse)
def safety_status(db: Session = Depends(get_db)) -> dict:
    control = get_safety_control(db)
    return {"kill_switch_engaged": control.kill_switch_engaged, "reason": control.reason,
            "updated_at": control.updated_at.isoformat() if control.updated_at else None}


@app.post("/api/safety/kill-switch", response_model=SafetyStatusResponse)
def set_kill_switch(payload: KillSwitchUpdate, db: Session = Depends(get_db)) -> dict:
    control = get_safety_control(db, lock=True)
    control.kill_switch_engaged = payload.engaged
    control.reason = redact_operational_text(payload.reason)
    control.updated_at = datetime.now(timezone.utc)
    db.add(AuditEvent(event_type="kill_switch_toggled", decision="allow" if not payload.engaged else "deny",
        details=f"Kill switch {'engaged' if payload.engaged else 'cleared'}: {control.reason or 'no reason given'}."))
    db.commit()
    return {"kill_switch_engaged": control.kill_switch_engaged, "reason": control.reason,
            "updated_at": control.updated_at.isoformat() if control.updated_at else None}


@app.get("/api/changes", response_model=list[ChangeResponse])
def list_changes(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(
        select(ChangeEvent, Target.name).join(Target, ChangeEvent.target_id == Target.id)
        .order_by(ChangeEvent.created_at.desc()).limit(20)
    ).all()
    return [{"id": c.id, "target": name, "source": c.source, "detail": c.detail,
             "triggered_scan_id": c.triggered_scan_id, "created_at": c.created_at.isoformat()} for c, name in rows]


@app.post("/api/webhooks/deploy", status_code=202, response_model=DeployResponse)
def deploy_webhook(payload: DeployWebhook, background: BackgroundTasks, db: Session = Depends(get_db)) -> dict:
    target = db.get(Target, payload.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")
    detail = f"Deploy event for release '{payload.release or 'unspecified'}'."
    change = ChangeEvent(target_id=target.id, source="ci_cd_webhook", detail=detail[:1000])
    db.add(change)
    db.flush()
    db.add(AuditEvent(event_type="change_detected", decision="allow", details=f"CI/CD deploy webhook received for {target.name}: {detail[:400]}"))
    db.commit()
    db.refresh(change)

    control = get_safety_control(db, lock=True)
    already_running = db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running", "cancel_requested"]))) or 0
    if control.kill_switch_engaged or already_running or target.status not in {"authorized", "approved"}:
        reason = "kill switch engaged" if control.kill_switch_engaged else "a scan is already running" if already_running else "target is not authorized"
        db.add(AuditEvent(event_type="auto_scan_skipped", decision="deny", details=f"Deploy-triggered scan for {target.name} skipped: {reason}."))
        db.commit()
        return {"change_event_id": change.id, "scan_started": False, "reason": reason}

    try:
        validate_target_url(target.base_url)
    except ScopeRejected:
        db.add(AuditEvent(event_type="auto_scan_skipped", decision="deny", details=f"Deploy-triggered scan for target {target.id} skipped: origin not allowlisted."))
        db.commit()
        return {"change_event_id": change.id, "scan_started": False, "reason": "target origin not allowlisted"}
    
    executor = executor_registry.get_for_target(target)
    if not supports_demo_executor(target) and not executor:
        db.add(AuditEvent(event_type="auto_scan_skipped", decision="deny", details=f"Deploy-triggered scan for target {target.id} skipped: no active executor supports this target."))
        db.commit()
        return {"change_event_id": change.id, "scan_started": False, "reason": "no active executor supports this target"}
    
    scan = Scan(target_id=target.id, status="queued", trigger="change_detected", started_at=datetime.now(timezone.utc),
        summary=f"Auto-triggered by deploy event for release '{payload.release or 'unspecified'}'.", cancel_requested=False)
    db.add(scan)
    db.flush()
    change.triggered_scan_id = scan.id
    db.add(AuditEvent(scan_id=scan.id, event_type="scan_requested", decision="allow", details=f"Deploy-triggered bounded scan queued for {target.name}."))
    db.commit()
    db.refresh(scan)
    background.add_task(run_scan, scan.id, target.id)
    return {"change_event_id": change.id, "scan_started": True, "scan_id": scan.id}


@app.post("/api/scans", status_code=202, response_model=ScanAcceptedResponse)
def start_scan(payload: ScanCreate, background: BackgroundTasks, db: Session = Depends(get_db)) -> dict:
    control = get_safety_control(db, lock=True)
    if control.kill_switch_engaged:
        db.add(AuditEvent(event_type="scan_request_denied", decision="deny", details="Manual scan request blocked because the kill switch is engaged."))
        db.commit()
        raise HTTPException(status_code=409, detail="The safety kill switch is engaged.")
    target_id = payload.target_id
    if db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running", "cancel_requested"]))) or 0:
        db.add(AuditEvent(event_type="scan_request_denied", decision="deny", details="Manual scan request blocked because the single scan slot is occupied."))
        db.commit()
        raise HTTPException(status_code=409, detail="A scan is already queued or running. Concurrency is limited to one scan.")
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")
    try:
        validate_target_url(target.base_url)
    except ScopeRejected as exc:
        db.add(AuditEvent(event_type="scan_request_denied", decision="deny", details=f"Manual scan request for target {target.id} blocked by the allowlist."))
        db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if target.status not in {"authorized", "approved"}:
        db.add(AuditEvent(event_type="scan_request_denied", decision="deny", details=f"Manual scan request for target {target.id} blocked because it is not authorized."))
        db.commit()
        raise HTTPException(status_code=403, detail="Target is not authorized.")
    
    executor = executor_registry.get_for_target(target)
    if not supports_demo_executor(target) and not executor:
        db.add(AuditEvent(event_type="scan_request_denied", decision="deny", details=f"Manual scan request for target {target.id} blocked because no executor supports it."))
        db.commit()
        raise HTTPException(status_code=422, detail="The available executor is limited to the local synthetic demo target or registered staging targets.")
    
    scan = Scan(target_id=target.id, status="queued", trigger="manual", started_at=datetime.now(timezone.utc), summary="Waiting to run.", cancel_requested=False)
    db.add(scan)
    db.flush()
    db.add(AuditEvent(scan_id=scan.id, event_type="scan_requested", decision="allow", details=f"Manual bounded scan requested for {target.name}."))
    db.commit()
    db.refresh(scan)
    background.add_task(run_scan, scan.id, target.id)
    return {"id": scan.id, "target_id": target.id, "status": scan.status}


@app.post("/api/scans/{scan_id}/cancel", response_model=CancelResponse)
def cancel_scan(scan_id: int, db: Session = Depends(get_db)) -> dict:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if scan.status in {"completed", "failed", "cancelled", "halted"}:
        return {"id": scan.id, "status": scan.status, "message": "Scan already finished."}
    scan.cancel_requested = True
    scan.status = "cancel_requested"
    db.add(AuditEvent(scan_id=scan.id, event_type="scan_cancel_requested", decision="allow", details="Cancellation requested; current bounded request will finish before the next stage stops."))
    db.commit()
    return {"id": scan.id, "status": scan.status}


@app.get("/api/scans/{scan_id}", response_model=ScanStatusResponse)
def scan_status(scan_id: int, db: Session = Depends(get_db)) -> dict:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    stages = db.execute(select(ScanStage).where(ScanStage.scan_id == scan.id).order_by(ScanStage.id)).scalars().all()
    return {"id": scan.id, "target_id": scan.target_id, "status": scan.status, "trigger": scan.trigger,
            "started_at": scan.started_at, "finished_at": scan.finished_at, "summary": scan.summary,
            "stages": [{"name": stage.name, "status": stage.status, "error": stage.error} for stage in stages]}


@app.get("/api/scans/{scan_id}/report", response_model=ScanReportResponse)
def scan_report(scan_id: int, db: Session = Depends(get_db)) -> dict:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    target = db.get(Target, scan.target_id)
    findings = db.execute(select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.created_at)).scalars().all()
    stages = db.execute(select(ScanStage).where(ScanStage.scan_id == scan.id).order_by(ScanStage.id)).scalars().all()
    snapshots = db.execute(select(InventorySnapshot).where(InventorySnapshot.scan_id == scan.id).order_by(InventorySnapshot.id)).scalars().all()
    audit_events = db.execute(select(AuditEvent).where(AuditEvent.scan_id == scan.id).order_by(AuditEvent.id)).scalars().all()
    finding_rows = []
    for finding in findings:
        endpoint = db.get(Endpoint, finding.endpoint_id) if finding.endpoint_id else None
        evidence = db.execute(select(Evidence).where(Evidence.finding_id == finding.id).order_by(Evidence.id)).scalars().all()
        finding_rows.append({
            "id": finding.id,
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "business_impact": finding.business_impact,
            "status": finding.status,
            "verified": finding.verified,
            "affected_endpoint": f"{endpoint.method} {endpoint.path}" if endpoint else "Administrative / Role Route",
            "reproduction_steps": ["Use scoped test-account credentials for the target role.", "Request the protected endpoint.", "Verify access control and role boundaries."],
            "evidence": [{"kind": item.kind, "summary": item.summary, "redacted": item.redacted} for item in evidence],
            "remediation": "Enforce strict role-based access control and principle of least privilege.",
            "owner": "Security Reviewer",
        })
    return {
        "scan": {"id": scan.id, "status": scan.status, "started_at": scan.started_at.isoformat(), "finished_at": scan.finished_at.isoformat() if scan.finished_at else None, "summary": scan.summary},
        "target": {"name": target.name if target else "Unavailable", "base_url": target.base_url if target else ""},
        "stages": [{"name": s.name, "status": s.status, "error": s.error} for s in stages],
        "inventory_snapshots": [{"endpoint_count": s.endpoint_count, "endpoints": json.loads(s.inventory_json), "created_at": s.created_at.isoformat()} for s in snapshots],
        "audit_events": [{"event_type": e.event_type, "decision": e.decision, "details": e.details, "created_at": e.created_at.isoformat()} for e in audit_events],
        "findings": finding_rows,
    }


@app.post("/api/findings/{finding_id}/retest", status_code=202, response_model=RetestAcceptedResponse)
def retest_finding(finding_id: int, background: BackgroundTasks, db: Session = Depends(get_db)) -> dict:
    control = get_safety_control(db, lock=True)
    if control.kill_switch_engaged:
        db.add(AuditEvent(event_type="retest_request_denied", decision="deny", details="Retest request blocked because the kill switch is engaged."))
        db.commit()
        raise HTTPException(status_code=409, detail="The safety kill switch is engaged.")
    if db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running", "cancel_requested"]))) or 0:
        db.add(AuditEvent(event_type="retest_request_denied", decision="deny", details="Retest request blocked because the single scan slot is occupied."))
        db.commit()
        raise HTTPException(status_code=409, detail="A scan is already queued or running. Concurrency is limited to one scan.")
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    if finding.category != "access_control" or not finding.verified:
        db.add(AuditEvent(event_type="retest_request_denied", decision="deny", details=f"Retest request for finding {finding.id} blocked because no supported verified executor exists."))
        db.commit()
        raise HTTPException(status_code=422, detail="Only verified access-control findings have a supported retest executor.")
    original_scan = db.get(Scan, finding.scan_id)
    target = db.get(Target, original_scan.target_id) if original_scan else None
    if not target:
        raise HTTPException(status_code=404, detail="Finding target not found.")
    
    executor = executor_registry.get_for_target(target)
    if target.status not in {"authorized", "approved"} or (not supports_demo_executor(target) and not executor):
        db.add(AuditEvent(event_type="retest_request_denied", decision="deny", details=f"Retest request for finding {finding.id} blocked because its target is not authorized or supported."))
        db.commit()
        raise HTTPException(status_code=422, detail="Retesting is limited to an authorized local synthetic demo target or supported staging target.")
    try:
        validate_target_url(target.base_url)
    except ScopeRejected as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scan = Scan(target_id=target.id, status="queued", trigger="retest", started_at=datetime.now(timezone.utc), summary=f"Retest for finding SF-{finding.id:04d}.", cancel_requested=False)
    db.add(scan)
    db.flush()
    db.add(AuditEvent(scan_id=scan.id, event_type="retest_requested", decision="allow", details=f"Safe bounded retest requested for finding SF-{finding.id:04d}."))
    db.commit()
    db.refresh(scan)
    background.add_task(run_scan, scan.id, target.id, finding.id)
    return {"id": scan.id, "target_id": target.id, "status": scan.status, "retests_finding": finding.id}


# ==============================================================================
# Phase 2: Targeted Vulnerability Scanning, Authorization Fuzzing & Business Flow
# ==============================================================================

class Phase2ScanRequest(BaseModel):
    profile: Literal["quick", "deep", "auth_matrix_only"] = "quick"
    options: dict[str, Any] = Field(default_factory=dict)


class Phase2ScanCreateResponse(BaseModel):
    id: int
    target_id: int
    status: str
    profile: str
    started_at: str | None = None
    message: str


class Phase2ScanStatusResponse(BaseModel):
    id: int
    target_id: int
    status: str
    profile: str
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    progress_percentage: int
    findings_count: int
    findings_by_severity: dict[str, int]
    metrics: dict[str, Any]
    config_snapshot: dict[str, Any]


class DiscoveredVulnerabilityResponse(BaseModel):
    id: int
    scan_id: int
    endpoint_id: int
    parameter_id: int | None = None
    endpoint_path: str
    endpoint_method: str
    parameter_name: str | None = None
    parameter_location: str | None = None
    parameter_type: str | None = None
    vuln_type: str
    severity: str
    cvss_score: float
    evidence_payload: str
    remediation_advice: str
    status: str
    created_at: str


@app.post("/api/targets/{target_id}/scans", status_code=202, response_model=Phase2ScanCreateResponse)
def trigger_target_vulnerability_scan(
    target_id: int,
    payload: Phase2ScanRequest = Phase2ScanRequest(),
    background: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Initialize and trigger an asynchronous Phase 2 vulnerability scan with configurable scan profiles."""
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    control = get_safety_control(db)
    if control.kill_switch_engaged:
        db.add(AuditEvent(event_type="scan_request_denied", decision="deny", details="Phase 2 scan blocked: kill switch engaged."))
        db.commit()
        raise HTTPException(status_code=409, detail=f"Kill switch engaged: {control.reason or 'administrative halt'}.")

    try:
        validate_target_url(target.base_url)
    except ScopeRejected as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    snapshot = {
        "profile": payload.profile,
        "options": payload.options,
        "triggered_at": datetime.now(timezone.utc).isoformat(),
    }
    vscan = VulnerabilityScan(
        target_id=target.id,
        status="pending",
        config_snapshot=json.dumps(snapshot),
    )
    db.add(vscan)
    db.flush()
    db.add(
        AuditEvent(
            scan_id=None,
            event_type="phase2_scan_queued",
            decision="allow",
            details=f"Phase 2 scan #{vscan.id} queued for target #{target.id} with profile '{payload.profile}'.",
        )
    )
    db.commit()
    db.refresh(vscan)

    def _execute_scan_async(scan_id: int) -> None:
        with SessionLocal() as worker_db:
            try:
                run_vulnerability_scan(worker_db, scan_id)
            except Exception:
                pass

    background.add_task(_execute_scan_async, vscan.id)

    return {
        "id": vscan.id,
        "target_id": target.id,
        "status": vscan.status,
        "profile": payload.profile,
        "started_at": vscan.started_at.isoformat() if vscan.started_at else None,
        "message": f"Phase 2 scan #{vscan.id} initiated with profile '{payload.profile}'.",
    }


@app.get("/api/targets/{target_id}/scans/{scan_id}", response_model=Phase2ScanStatusResponse)
def get_target_vulnerability_scan_status(
    target_id: int,
    scan_id: int,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve real-time scan progress, live finding counts by severity, and execution metrics."""
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    vscan = db.get(VulnerabilityScan, scan_id)
    if not vscan or vscan.target_id != target.id:
        raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found for target #{target_id}.")

    config_data: dict[str, Any] = {}
    try:
        config_data = json.loads(vscan.config_snapshot) if vscan.config_snapshot else {}
    except Exception:
        config_data = {}

    profile = config_data.get("profile", "quick")
    metrics = config_data.get("metrics", {})

    # Live finding counts
    live_findings = db.execute(
        select(DiscoveredVulnerability).where(DiscoveredVulnerability.scan_id == vscan.id)
    ).scalars().all()

    severity_counts = {
        "critical": sum(1 for f in live_findings if f.severity == "critical"),
        "high": sum(1 for f in live_findings if f.severity == "high"),
        "medium": sum(1 for f in live_findings if f.severity == "medium"),
        "low": sum(1 for f in live_findings if f.severity == "low"),
        "info": sum(1 for f in live_findings if f.severity == "info"),
    }
    total_findings = len(live_findings)

    duration = None
    if vscan.started_at:
        end_time = vscan.completed_at or datetime.now(timezone.utc)
        duration = round((end_time - vscan.started_at).total_seconds(), 2)

    progress = 0
    if vscan.status == "completed":
        progress = 100
    elif vscan.status == "running":
        progress = 50
    elif vscan.status == "pending":
        progress = 0
    elif vscan.status == "failed":
        progress = 100

    return {
        "id": vscan.id,
        "target_id": target.id,
        "status": vscan.status,
        "profile": profile,
        "started_at": vscan.started_at.isoformat() if vscan.started_at else None,
        "completed_at": vscan.completed_at.isoformat() if vscan.completed_at else None,
        "duration_seconds": duration,
        "progress_percentage": progress,
        "findings_count": total_findings,
        "findings_by_severity": severity_counts,
        "metrics": metrics,
        "config_snapshot": config_data,
    }


@app.get("/api/targets/{target_id}/vulnerabilities", response_model=list[DiscoveredVulnerabilityResponse])
def list_target_vulnerabilities(
    target_id: int,
    scan_id: int | None = None,
    severity: str | None = None,
    vuln_type: str | None = None,
    status: str | None = None,
    endpoint_id: int | None = None,
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """Filterable vulnerability register with parameter links, evidence snippets, and remediation guidance."""
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    stmt = (
        select(
            DiscoveredVulnerability,
            Endpoint.path,
            Endpoint.method,
            EndpointParameter.name,
            EndpointParameter.location,
            EndpointParameter.observed_type,
        )
        .join(Endpoint, DiscoveredVulnerability.endpoint_id == Endpoint.id)
        .outerjoin(EndpointParameter, DiscoveredVulnerability.parameter_id == EndpointParameter.id)
        .where(Endpoint.target_id == target.id)
    )

    if scan_id is not None:
        stmt = stmt.where(DiscoveredVulnerability.scan_id == scan_id)
    if severity is not None:
        stmt = stmt.where(DiscoveredVulnerability.severity == severity.strip().lower())
    if vuln_type is not None:
        stmt = stmt.where(DiscoveredVulnerability.vuln_type == vuln_type.strip().lower())
    if status is not None:
        stmt = stmt.where(DiscoveredVulnerability.status == status.strip().lower())
    if endpoint_id is not None:
        stmt = stmt.where(DiscoveredVulnerability.endpoint_id == endpoint_id)

    stmt = stmt.order_by(DiscoveredVulnerability.cvss_score.desc(), DiscoveredVulnerability.id.desc())
    rows = db.execute(stmt).all()

    results = []
    for vuln, ep_path, ep_method, param_name, param_location, param_type in rows:
        results.append({
            "id": vuln.id,
            "scan_id": vuln.scan_id,
            "endpoint_id": vuln.endpoint_id,
            "parameter_id": vuln.parameter_id,
            "endpoint_path": ep_path,
            "endpoint_method": ep_method,
            "parameter_name": param_name,
            "parameter_location": param_location,
            "parameter_type": param_type,
            "vuln_type": vuln.vuln_type,
            "severity": vuln.severity,
            "cvss_score": vuln.cvss_score,
            "evidence_payload": vuln.evidence_payload,
            "remediation_advice": vuln.remediation_advice,
            "status": vuln.status,
            "created_at": vuln.created_at.isoformat() if vuln.created_at else datetime.now(timezone.utc).isoformat(),
        })

    return results

