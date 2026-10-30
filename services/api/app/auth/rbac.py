"""Signed workspace tokens, role permissions, and SQLAlchemy tenant scoping.

Tokens are HS256 JWTs minted by a trusted identity gateway. Authorization is
resolved from the active database membership on every request; role claims in
tokens are never trusted.
"""
import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, HTTPException, Request
from sqlalchemy import event, select
from sqlalchemy.orm import Session as ORMSession, with_loader_criteria

from app.db import get_db
from app.models import (
    AuditEvent, CICDBuildEvaluation, ChangeEvent, CodePatch, ComplianceFramework,
    DiscoveredVulnerability, Endpoint, EndpointParameter, EndpointRoleObservation,
    Evidence, Finding, InventorySnapshot, Organization, RemediationTicket, Scan,
    ScanStage, Target, TestExecution, TrafficLogEntry, VulnerabilityComplianceMapping,
    VulnerabilityScan, WebhookSubscription, WorkspaceUser,
)
from app.safety.credentials import TestAccountCredential
from app.settings import settings

ROLE_PERMISSIONS = {
    "org_admin": {"*"},
    "security_engineer": {"workspace.read", "targets.read", "targets.manage", "scans.execute", "vulnerabilities.read", "tickets.create", "patches.generate", "patches.review", "patches.apply"},
    "developer": {"workspace.read", "targets.read", "vulnerabilities.read", "patches.generate", "patches.apply"},
}
ALL_PERMISSIONS = set().union(*(p for p in ROLE_PERMISSIONS.values() if "*" not in p))


@dataclass(frozen=True)
class WorkspaceContext:
    organization_id: int
    organization_name: str
    user_id: str
    workspace_role: str
    permissions: tuple[str, ...]

    def allows(self, permission: str) -> bool:
        return "*" in self.permissions or permission in self.permissions


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def issue_workspace_token(user_id: str, organization_id: int, *, expires_in: int = 3600, now: int | None = None) -> str:
    """Mint an HS256 JWT for a trusted identity gateway or tests."""
    secret = settings.enterprise_auth_secret
    if not secret:
        raise RuntimeError("ENTERPRISE_AUTH_SECRET must be configured before issuing workspace tokens.")
    issued = int(now if now is not None else time.time())
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = _b64(json.dumps({"sub": user_id, "org_id": organization_id, "iat": issued, "exp": issued + expires_in}, separators=(",", ":")).encode())
    signing_input = f"{header}.{claims}".encode("ascii")
    signature = _b64(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{header}.{claims}.{signature}"


def _verify_token(authorization: str | None) -> tuple[str, int]:
    if not settings.enterprise_auth_secret:
        raise HTTPException(status_code=503, detail="Workspace authentication is not configured.")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="A signed workspace Bearer token is required.")
    token = authorization[7:].strip()
    try:
        header_b64, claims_b64, signature = token.split(".")
        padded = lambda value: value + "=" * (-len(value) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded(header_b64)))
        claims = json.loads(base64.urlsafe_b64decode(padded(claims_b64)))
        signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
        expected = _b64(hmac.new(settings.enterprise_auth_secret.encode(), signing_input, hashlib.sha256).digest())
        if header != {"alg": "HS256", "typ": "JWT"} or not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        user_id, org_id, expiry = claims["sub"], claims["org_id"], claims["exp"]
        if not isinstance(user_id, str) or not user_id or not isinstance(org_id, int) or int(expiry) <= int(time.time()):
            raise ValueError("claims")
        return user_id, org_id
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=401, detail="Workspace token is invalid or expired.") from exc


def resolve_workspace_context(authorization: str | None, db: ORMSession) -> WorkspaceContext:
    user_id, organization_id = _verify_token(authorization)
    membership = db.scalar(select(WorkspaceUser).where(
        WorkspaceUser.organization_id == organization_id,
        WorkspaceUser.user_id == user_id,
        WorkspaceUser.is_active.is_(True),
    ))
    if membership is None:
        raise HTTPException(status_code=403, detail="User has no active membership in this workspace.")
    role_permissions = ROLE_PERMISSIONS[membership.workspace_role]
    custom = set(membership.permissions or [])
    permissions = role_permissions if "*" in role_permissions else (custom & role_permissions if custom else role_permissions)
    organization = db.get(Organization, organization_id)
    if organization is None:
        raise HTTPException(status_code=403, detail="Workspace is unavailable.")
    return WorkspaceContext(organization_id, organization.name, user_id, membership.workspace_role, tuple(sorted(permissions)))


def require_permission(context: WorkspaceContext, permission: str) -> None:
    if not context.allows(permission):
        raise HTTPException(status_code=403, detail=f"Workspace role does not grant '{permission}'.")


def require_session_permission(db: ORMSession, permission: str) -> None:
    """Enforce action permission on legacy endpoints using the request-scoped session."""
    permissions = db.info.get("workspace_permissions")
    if permissions is None:  # Supports local legacy/test database overrides; production get_db always binds a principal.
        return
    if "*" not in permissions and permission not in permissions:
        raise HTTPException(status_code=403, detail=f"Workspace role does not grant '{permission}'.")


def ensure_target_access(db: ORMSession, target_id: int, context: WorkspaceContext | None = None) -> Target:
    target = db.get(Target, target_id)
    organization_id = context.organization_id if context else db.info.get("organization_id")
    if target is None or (organization_id is not None and target.organization_id != organization_id):
        raise HTTPException(status_code=404, detail="Target not found.")
    return target


def ensure_vulnerability_access(db: ORMSession, vulnerability_id: int, context: WorkspaceContext) -> DiscoveredVulnerability:
    vulnerability = db.get(DiscoveredVulnerability, vulnerability_id)
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")
    endpoint = db.get(Endpoint, vulnerability.endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")
    ensure_target_access(db, endpoint.target_id, context)
    return vulnerability


def get_workspace_context(request: Request, db: ORMSession = Depends(get_db)) -> WorkspaceContext:
    context = resolve_workspace_context(request.headers.get("authorization"), db)
    db.info["organization_id"] = context.organization_id
    db.info["workspace_permissions"] = context.permissions
    return context


@event.listens_for(ORMSession, "do_orm_execute")
def _apply_workspace_scope(execute_state) -> None:
    organization_id = execute_state.session.info.get("organization_id")
    if organization_id is None or not (execute_state.is_select or execute_state.is_update or execute_state.is_delete):
        return
    target_ids = select(Target.id).where(Target.organization_id == organization_id)
    scan_ids = select(Scan.id).where(Scan.target_id.in_(target_ids))
    endpoint_ids = select(Endpoint.id).where(Endpoint.target_id.in_(target_ids))
    vscan_ids = select(VulnerabilityScan.id).where(VulnerabilityScan.target_id.in_(target_ids))
    finding_ids = select(Finding.id).where(Finding.scan_id.in_(scan_ids))
    vuln_ids = select(DiscoveredVulnerability.id).where(
        DiscoveredVulnerability.endpoint_id.in_(endpoint_ids), DiscoveredVulnerability.scan_id.in_(vscan_ids))
    criteria = [
        (Organization, lambda entity: entity.id == organization_id),
        (WorkspaceUser, lambda entity: entity.organization_id == organization_id),
        (Target, lambda entity: entity.organization_id == organization_id),
        (Scan, lambda entity: entity.target_id.in_(target_ids)),
        (ScanStage, lambda entity: entity.scan_id.in_(scan_ids)),
        (InventorySnapshot, lambda entity: entity.target_id.in_(target_ids)),
        (Endpoint, lambda entity: entity.target_id.in_(target_ids)),
        (EndpointParameter, lambda entity: entity.endpoint_id.in_(endpoint_ids)),
        (EndpointRoleObservation, lambda entity: entity.endpoint_id.in_(endpoint_ids)),
        (TrafficLogEntry, lambda entity: entity.target_id.in_(target_ids)),
        (Finding, lambda entity: entity.scan_id.in_(scan_ids)),
        (Evidence, lambda entity: entity.finding_id.in_(finding_ids)),
        (ChangeEvent, lambda entity: entity.target_id.in_(target_ids)),
        (TestExecution, lambda entity: entity.target_id.in_(target_ids)),
        (TestAccountCredential, lambda entity: entity.target_id.in_(target_ids)),
        (VulnerabilityScan, lambda entity: entity.target_id.in_(target_ids)),
        (DiscoveredVulnerability, lambda entity: entity.id.in_(vuln_ids)),
        (RemediationTicket, lambda entity: entity.vulnerability_id.in_(vuln_ids)),
        (VulnerabilityComplianceMapping, lambda entity: entity.vulnerability_id.in_(vuln_ids)),
        (CodePatch, lambda entity: entity.vulnerability_id.in_(vuln_ids)),
        (CICDBuildEvaluation, lambda entity: entity.target_id.in_(target_ids)),
        (WebhookSubscription, lambda entity: entity.target_id.is_(None) | entity.target_id.in_(target_ids)),
        (AuditEvent, lambda entity: entity.scan_id.in_(scan_ids)),
    ]
    for entity_type, criterion in criteria:
        execute_state.statement = execute_state.statement.options(
            with_loader_criteria(entity_type, criterion, include_aliases=True))


@event.listens_for(ORMSession, "before_flush")
def _prevent_workspace_reassignment(session: ORMSession, flush_context, instances) -> None:
    organization_id = session.info.get("organization_id")
    if organization_id is None:
        return
    for target in session.new.union(session.dirty):
        if isinstance(target, Target):
            if target in session.new and target.organization_id is None:
                target.organization_id = organization_id
            if target.organization_id != organization_id:
                raise HTTPException(status_code=403, detail="A target cannot be created or reassigned outside the active workspace.")
