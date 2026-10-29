from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.safety.credentials import TestAccountCredential


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    base_url: Mapped[str] = mapped_column(String(500))
    environment: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(40))
    scope_note: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    status: Mapped[str] = mapped_column(String(40))
    trigger: Mapped[str] = mapped_column(String(40))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    summary: Mapped[str] = mapped_column(String(500), default="")
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)


class ScanStage(Base):
    __tablename__ = "scan_stages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(40))
    error: Mapped[str | None] = mapped_column(String(1000))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class InventorySnapshot(Base):
    __tablename__ = "inventory_snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    endpoint_count: Mapped[int] = mapped_column(Integer)
    inventory_json: Mapped[str] = mapped_column(Text())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Endpoint(Base):
    __tablename__ = "endpoints"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    method: Mapped[str] = mapped_column(String(12))
    path: Mapped[str] = mapped_column(String(1000))
    classification: Mapped[str] = mapped_column(String(40), default="active")  # active, zombie, shadow
    sensitivity: Mapped[str] = mapped_column(String(40), default="unknown")
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(40))

    # --- Phase 1: Evidence-Backed Inventory Extensions ---
    business_flow: Mapped[str | None] = mapped_column(String(40), nullable=True)  # search, hold, book, pay, cancel, other
    api_version: Mapped[str] = mapped_column(String(20), default="v1")
    first_seen_traffic: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_traffic: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    traffic_hit_count: Mapped[int] = mapped_column(Integer, default=0)
    auth_required: Mapped[bool] = mapped_column(Boolean, default=True)
    auth_reachability: Mapped[str] = mapped_column(String(80), default="authenticated_only")  # unauthenticated, authenticated_only, role_restricted
    owner: Mapped[str] = mapped_column(String(120), default="Unassigned")
    likely_owner: Mapped[str] = mapped_column(String(120), default="Unassigned")
    version_notes: Mapped[str] = mapped_column(String(500), default="")
    data_fields_summary: Mapped[str] = mapped_column(Text(), default="")
    recommended_action: Mapped[str] = mapped_column(String(100), default="keep_active")  # decommission, restrict, bring_up_to_date, keep_active


class EndpointParameter(Base):
    """Phase 1: Discovered parameters with locations and observed types (strictly no raw values)."""
    __tablename__ = "endpoint_parameters"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    location: Mapped[str] = mapped_column(String(40), nullable=False)  # path, query, body, header, cookie
    observed_type: Mapped[str] = mapped_column(String(40), default="string")  # string, integer, number, boolean, object, array
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EndpointRoleObservation(Base):
    """Phase 1: Observations of which roles successfully or unsuccessfully hit an endpoint."""
    __tablename__ = "endpoint_role_observations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[str] = mapped_column(String(80), nullable=False)  # admin, travel_agent, customer, unauthenticated
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    last_observed: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TrafficLogEntry(Base):
    """Phase 1: Ingested gateway / access log entries with observation window tagging."""
    __tablename__ = "traffic_log_entries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True)
    method: Mapped[str] = mapped_column(String(12), nullable=False)
    path: Mapped[str] = mapped_column(String(1000), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_days: Mapped[int] = mapped_column(Integer, default=90)
    role: Mapped[str | None] = mapped_column(String(80), nullable=True)
    source: Mapped[str] = mapped_column(String(80), default="gateway_access_log")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoints.id"))
    title: Mapped[str] = mapped_column(String(240))
    category: Mapped[str] = mapped_column(String(80))
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[str] = mapped_column(String(20))
    business_impact: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(40))  # pending_review, approved, rejected, open, resolved
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    review_notes: Mapped[str | None] = mapped_column(String(500), nullable=True, default=None)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(80))
    summary: Mapped[str] = mapped_column(String(1000))
    redacted: Mapped[bool] = mapped_column(Boolean, default=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    event_type: Mapped[str] = mapped_column(String(100))
    decision: Mapped[str] = mapped_column(String(40))
    details: Mapped[str] = mapped_column(String(1000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ChangeEvent(Base):
    """Phase 1 (Change Detection): a signal that something changed on a target and may need testing now."""
    __tablename__ = "change_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    source: Mapped[str] = mapped_column(String(40))  # ci_cd_webhook | traffic_diff | js_bundle_diff | dns_cert
    detail: Mapped[str] = mapped_column(String(1000))
    triggered_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SafetyControl(Base):
    """Phase 0 (Safety Layer): a single row holding the global kill switch state."""
    __tablename__ = "safety_controls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kill_switch_engaged: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str] = mapped_column(String(500), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TestExecution(Base):
    """Phase 0 (Human Approval Gate): tracks planned tests and reviewer lifecycle states."""
    __tablename__ = "test_executions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    test_type: Mapped[str] = mapped_column(String(80), nullable=False)
    is_risky: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_level: Mapped[str] = mapped_column(String(20), default="low")  # low, medium, high, critical
    risk_rationale: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(40), default="pending_review")  # pending_review, approved, rejected, executed, skipped
    reviewer_notes: Mapped[str] = mapped_column(String(500), default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
