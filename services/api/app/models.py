from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.safety.credentials import TestAccountCredential


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, default=1, index=True)
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


class VulnerabilityScan(Base):
    """Phase 2: Targeted vulnerability scan runs against targets."""
    __tablename__ = "vulnerability_scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="pending")  # pending, running, completed, failed
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    config_snapshot: Mapped[str] = mapped_column(Text(), default="{}")


class DiscoveredVulnerability(Base):
    """Phase 2: Discovered vulnerabilities linked to endpoints and parameters."""
    __tablename__ = "discovered_vulnerabilities"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("vulnerability_scans.id", ondelete="CASCADE"), nullable=False)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    parameter_id: Mapped[int | None] = mapped_column(ForeignKey("endpoint_parameters.id", ondelete="SET NULL"), nullable=True)
    vuln_type: Mapped[str] = mapped_column(String(100), nullable=False)  # bola_idor, sqli, nosqli, command_injection, mass_assignment, business_logic_bypass, unauthorized_shadow_exposure, unrestricted_zombie_access, etc.
    severity: Mapped[str] = mapped_column(String(40), default="medium")  # critical, high, medium, low, info
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    evidence_payload: Mapped[str] = mapped_column(Text(), default="")
    remediation_advice: Mapped[str] = mapped_column(Text(), default="")
    status: Mapped[str] = mapped_column(String(40), default="open")  # open, verified, false_positive
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RemediationTicket(Base):
    __tablename__ = "remediation_tickets"
    __table_args__ = (UniqueConstraint("vulnerability_id", "external_system", name="uq_vuln_ticket_system"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("discovered_vulnerabilities.id", ondelete="CASCADE"), nullable=False)
    external_system: Mapped[str] = mapped_column(String(20), nullable=False)
    external_ticket_key: Mapped[str] = mapped_column(String(200), nullable=False)
    external_ticket_url: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    assignee: Mapped[str | None] = mapped_column(String(200), nullable=True)
    access_token_ciphertext: Mapped[str | None] = mapped_column(Text(), nullable=True)
    access_token_wrapped_dek: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"
    __table_args__ = (UniqueConstraint("name", "version", "external_id", name="uq_compliance_framework_item"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    external_id: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str] = mapped_column(Text(), default="")


class VulnerabilityComplianceMapping(Base):
    __tablename__ = "vulnerability_compliance_mappings"
    __table_args__ = (UniqueConstraint("vulnerability_id", "framework_id", name="uq_vuln_compliance_mapping"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("discovered_vulnerabilities.id", ondelete="CASCADE"), nullable=False)
    framework_id: Mapped[int] = mapped_column(ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=False)
    rationale: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CICDBuildEvaluation(Base):
    __tablename__ = "cicd_build_evaluations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[int] = mapped_column(ForeignKey("vulnerability_scans.id", ondelete="CASCADE"), nullable=False)
    pipeline_provider: Mapped[str] = mapped_column(String(30), nullable=False)
    repository: Mapped[str] = mapped_column(String(500), default="")
    commit_hash: Mapped[str] = mapped_column(String(200), default="")
    branch: Mapped[str] = mapped_column(String(200), default="")
    gate_status: Mapped[str] = mapped_column(String(20), nullable=False)
    policy_snapshot_id: Mapped[str] = mapped_column(String(100), nullable=False)
    policy_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class WorkspaceUser(Base):
    __tablename__ = "workspace_users"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_workspace_org_user"),
        CheckConstraint("workspace_role in ('org_admin', 'security_engineer', 'developer')", name="ck_workspace_role"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    workspace_role: Mapped[str] = mapped_column(String(40), nullable=False)
    permissions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CodePatch(Base):
    __tablename__ = "code_patches"
    __table_args__ = (Index("ix_code_patches_celery_task_id", "celery_task_id", unique=True),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    celery_task_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("discovered_vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    target_file_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    unified_diff: Mapped[str] = mapped_column(Text(), nullable=False)
    ai_confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="generated")
    application_mode: Mapped[str | None] = mapped_column(String(20), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class WebhookSubscription(Base):
    __tablename__ = "webhook_subscriptions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=True)
    url: Mapped[str] = mapped_column(String(2000), nullable=False)
    secret_key: Mapped[str] = mapped_column(String(1000), nullable=False)  # encrypted at rest
    secret_key_wrapped_dek: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    events: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
