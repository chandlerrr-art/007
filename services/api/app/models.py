from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


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
    classification: Mapped[str] = mapped_column(String(40))
    sensitivity: Mapped[str] = mapped_column(String(40))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(40))


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
    status: Mapped[str] = mapped_column(String(40))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
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
