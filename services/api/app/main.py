import json
import re
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import AuditEvent, ChangeEvent, Endpoint, Evidence, Finding, InventorySnapshot, Scan, ScanStage, Target
from app.safety.policy import ScopeRejected, get_safety_control, redact_operational_text, supports_demo_executor, validate_target_url
from app.scans.orchestrator import run_scan

app = FastAPI(title="007 API", version="0.1.0", description="Local-first authorized security testing platform")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
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


class DashboardResponse(BaseModel):
    summary: DashboardSummary
    severity: dict[str, int]
    targets: list[TargetResponse]
    findings: list[DashboardFinding]
    scans: list[DashboardScan]
    changes: list[DashboardChange]
    safety: dict[str, str | bool]
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
    return {
        "summary": {
            "active_scans": db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running", "cancel_requested"]))) or 0,
            "verified_findings": db.scalar(select(func.count()).select_from(Finding).where(Finding.verified.is_(True))) or 0,
            "endpoints": db.scalar(select(func.count()).select_from(Endpoint)) or 0,
            "targets": len(target_rows),
        },
        "severity": {key: severity_counts.get(key, 0) for key in ("critical", "high", "medium", "low", "info")},
        "targets": [{"id": t.id, "name": t.name, "base_url": t.base_url, "environment": t.environment, "status": t.status} for t in target_rows],
        "findings": [{"id": f.id, "title": f.title, "category": f.category, "severity": f.severity, "confidence": f.confidence, "verified": f.verified, "status": f.status, "path": path or "Endpoint unavailable", "target": target_name} for f, path, _target_id, target_name in findings],
        "scans": [{"id": scan.id, "target": target_name, "status": scan.status, "trigger": scan.trigger, "started_at": scan.started_at.isoformat(), "summary": scan.summary} for scan, target_name in recent_scans],
        "changes": [{"id": c.id, "target": name, "source": c.source, "detail": c.detail, "created_at": c.created_at.isoformat()} for c, name in change_rows],
        "safety": {"kill_switch_engaged": control.kill_switch_engaged, "reason": control.reason},
        "recent_audit_events": db.scalar(select(func.count()).select_from(AuditEvent)) or 0,
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
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    target = Target(name=payload.name, base_url=payload.base_url.rstrip("/"), environment=payload.environment,
                    status="authorized", scope_note=payload.scope_note)
    db.add(target)
    db.flush()
    db.add(AuditEvent(event_type="target_registered", decision="allow", details=f"Target {target.name} registered at allowlisted origin."))
    db.commit()
    db.refresh(target)
    return {"id": target.id, "name": target.name, "base_url": target.base_url, "environment": target.environment, "status": target.status}


@app.post("/api/targets/{target_id}/har-import", response_model=HARImportResponse)
def import_har(target_id: int, payload: HARImport, db: Session = Depends(get_db)) -> dict:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")
    try:
        validate_target_url(target.base_url)
        har = json.loads(payload.content)
    except (ScopeRejected, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid or out-of-scope HAR: {exc}") from exc
    entries = har.get("log", {}).get("entries", []) if isinstance(har, dict) else []
    if not isinstance(entries, list):
        raise HTTPException(status_code=422, detail="HAR log.entries must be an array.")
    base_origin = urlsplit(target.base_url)
    extracted: set[tuple[str, str]] = set()
    for entry in entries[:10000]:
        request = entry.get("request", {}) if isinstance(entry, dict) else {}
        try:
            method = str(request.get("method", "GET")).upper()[:12]
            parts = urlsplit(request.get("url", ""))
            if parts.scheme != base_origin.scheme or parts.netloc.lower() != base_origin.netloc.lower():
                continue
            path = parts.path or "/"
            path = re.sub(r"(?i)(?<=[/])[0-9a-f]{8}-[0-9a-f-]{27,}", "{id}", path)
            path = re.sub(r"(?<=/)\d+(?=/|$)", "{id}", path)
            path = re.sub(r"(?i)(/(?:bookings?|users?|agencies|orders?|travelers?|refunds?)/)[^/]+", r"\1{id}", path)
            if len(path) <= 1000:
                extracted.add((method, path))
        except (TypeError, ValueError):
            continue
    inserted = 0
    for method, path in sorted(extracted):
        existing = db.execute(select(Endpoint).where(Endpoint.target_id == target.id, Endpoint.method == method, Endpoint.path == path)).scalars().first()
        if existing:
            existing.last_seen = datetime.now(timezone.utc)
            existing.source = "HAR"
            continue
        db.add(Endpoint(target_id=target.id, method=method, path=path, classification="active", sensitivity="unknown", last_seen=datetime.now(timezone.utc), source="HAR"))
        inserted += 1
    db.add(AuditEvent(event_type="har_imported", decision="allow", details=f"Imported {inserted} new endpoint paths for target {target.name}; query strings and headers discarded."))
    db.commit()
    return {"target_id": target.id, "discovered": len(extracted), "inserted": inserted, "note": "Request headers, cookies, bodies, and query strings were not stored."}


@app.get("/api/safety/status", response_model=SafetyStatusResponse)
def safety_status(db: Session = Depends(get_db)) -> dict:
    control = get_safety_control(db)
    return {"kill_switch_engaged": control.kill_switch_engaged, "reason": control.reason,
            "updated_at": control.updated_at.isoformat() if control.updated_at else None}


@app.post("/api/safety/kill-switch", response_model=SafetyStatusResponse)
def set_kill_switch(payload: KillSwitchUpdate, db: Session = Depends(get_db)) -> dict:
    """Phase 0.2 kill switch: a single override that halts all agents instantly.

    Engaging it does not touch any in-flight scan directly; the orchestrator checks this
    flag before starting every stage, so the current bounded request still finishes but no
    further stage, and no new scan, will begin until the switch is cleared.
    """
    control = get_safety_control(db)
    control.kill_switch_engaged = payload.engaged
    control.reason = redact_operational_text(payload.reason)
    control.updated_at = datetime.now(timezone.utc)
    db.add(AuditEvent(event_type="kill_switch_toggled", decision="allow" if not payload.engaged else "deny",
        details=f"Kill switch {'engaged' if payload.engaged else 'cleared'}: {control.reason or 'no reason given'}."))
    db.commit()
    return {"kill_switch_engaged": control.kill_switch_engaged, "reason": control.reason,
            "updated_at": control.updated_at.isoformat() if control.updated_at else None}


@app.get("/api/changes")
def list_changes(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(
        select(ChangeEvent, Target.name).join(Target, ChangeEvent.target_id == Target.id)
        .order_by(ChangeEvent.created_at.desc()).limit(20)
    ).all()
    return [{"id": c.id, "target": name, "source": c.source, "detail": c.detail,
             "triggered_scan_id": c.triggered_scan_id, "created_at": c.created_at.isoformat()} for c, name in rows]


@app.post("/api/webhooks/deploy", status_code=202, response_model=DeployResponse)
def deploy_webhook(payload: DeployWebhook, background: BackgroundTasks, db: Session = Depends(get_db)) -> dict:
    """Phase 1.1 CI/CD listener: a webhook receiver for deploy events.

    Records the change event unconditionally (for the discovery feed and SLA clock), then
    auto-starts a bounded scan through the same safety-checked path as a manual scan, unless
    the kill switch is engaged, the target is not authorized, or a scan is already running.
    """
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

    control = get_safety_control(db)
    already_running = db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running", "cancel_requested"]))) or 0
    if control.kill_switch_engaged or already_running or target.status != "authorized":
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
    if not supports_demo_executor(target):
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
    control = get_safety_control(db)
    if control.kill_switch_engaged:
        db.add(AuditEvent(event_type="scan_request_denied", decision="deny", details="Manual scan request blocked because the kill switch is engaged."))
        db.commit()
        raise HTTPException(status_code=409, detail="The safety kill switch is engaged.")
    target_id = payload.target_id
    if db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running", "cancel_requested"]))) or 0:
        raise HTTPException(status_code=409, detail="A scan is already queued or running. Concurrency is limited to one scan.")
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")
    try:
        validate_target_url(target.base_url)
    except ScopeRejected as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if target.status != "authorized":
        raise HTTPException(status_code=403, detail="Target is not authorized.")
    if not supports_demo_executor(target):
        raise HTTPException(status_code=422, detail="The available executor is limited to the local synthetic demo target.")
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
        finding_rows.append({"id": finding.id, "title": finding.title, "category": finding.category, "severity": finding.severity,
            "confidence": finding.confidence, "business_impact": finding.business_impact, "status": finding.status, "verified": finding.verified,
            "affected_endpoint": f"{endpoint.method} {endpoint.path}" if endpoint else "Unknown",
            "reproduction_steps": ["Use a dedicated synthetic agency-a identity.", "Request the synthetic booking endpoint for booking 2002.", "Confirm that the returned owner is agency-b."],
            "evidence": [{"kind": item.kind, "summary": item.summary, "redacted": item.redacted} for item in evidence],
            "remediation": "Enforce agency ownership on every booking read; return a non-disclosing 404 for records outside the caller's agency.", "owner": "Unassigned"})
    return {"scan": {"id": scan.id, "status": scan.status, "started_at": scan.started_at.isoformat(), "finished_at": scan.finished_at.isoformat() if scan.finished_at else None, "summary": scan.summary},
            "target": {"name": target.name if target else "Unavailable", "base_url": target.base_url if target else ""},
            "stages": [{"name": s.name, "status": s.status, "error": s.error} for s in stages],
            "inventory_snapshots": [{"endpoint_count": s.endpoint_count, "endpoints": json.loads(s.inventory_json), "created_at": s.created_at.isoformat()} for s in snapshots],
            "audit_events": [{"event_type": e.event_type, "decision": e.decision, "details": e.details, "created_at": e.created_at.isoformat()} for e in audit_events],
            "findings": finding_rows}


@app.post("/api/findings/{finding_id}/retest", status_code=202, response_model=RetestAcceptedResponse)
def retest_finding(finding_id: int, background: BackgroundTasks, db: Session = Depends(get_db)) -> dict:
    control = get_safety_control(db)
    if control.kill_switch_engaged:
        db.add(AuditEvent(event_type="retest_request_denied", decision="deny", details="Retest request blocked because the kill switch is engaged."))
        db.commit()
        raise HTTPException(status_code=409, detail="The safety kill switch is engaged.")
    if db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running", "cancel_requested"]))) or 0:
        raise HTTPException(status_code=409, detail="A scan is already queued or running. Concurrency is limited to one scan.")
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    if finding.category != "access_control" or not finding.verified:
        raise HTTPException(status_code=422, detail="Only verified access-control findings have a supported retest executor.")
    original_scan = db.get(Scan, finding.scan_id)
    target = db.get(Target, original_scan.target_id) if original_scan else None
    if not target:
        raise HTTPException(status_code=404, detail="Finding target not found.")
    if target.status != "authorized" or not supports_demo_executor(target):
        raise HTTPException(status_code=422, detail="Retesting is limited to an authorized local synthetic demo target.")
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
