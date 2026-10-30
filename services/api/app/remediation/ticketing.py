"""Ticket adapters. Credentials and project coordinates come from environment settings."""
import base64
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.encryption import EncryptedEnvelope, EncryptionError, get_encryption_service
from app.models import (DiscoveredVulnerability, Endpoint, RemediationTicket,
                        Target, VulnerabilityScan)
from app.safety.credentials import register_secret_for_redaction
from app.settings import settings


class TicketingError(RuntimeError):
    pass


class RestAdapter:
    def request(self, url: str, *, method: str = "GET", headers: dict | None = None, payload: dict | None = None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        request = Request(url, data=data, headers={"Accept": "application/json", **(headers or {})}, method=method)
        try:
            with urlopen(request, timeout=15) as response:
                body = response.read()
                return json.loads(body) if body else {}
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise TicketingError(f"Ticket service request failed: {getattr(exc, 'code', type(exc).__name__)}") from exc


class JiraCloudAdapter(RestAdapter):
    def __init__(self, api_token: str | None = None):
        root = settings.jira_base_url.rstrip("/")
        self.credential_token = api_token or settings.jira_api_token
        token = base64.b64encode(f"{settings.jira_email}:{self.credential_token}".encode()).decode()
        self.root, self.project, self.headers = root, settings.jira_project_key, {"Authorization": f"Basic {token}", "Content-Type": "application/json"}

    def create_issue(self, vulnerability: DiscoveredVulnerability, endpoint: Endpoint) -> dict:
        result = self.request(f"{self.root}/rest/api/3/issue", method="POST", headers=self.headers, payload={"fields": {
            "project": {"key": self.project}, "summary": f"[{vulnerability.severity.upper()}] {vulnerability.vuln_type} at {endpoint.path}",
            "issuetype": {"name": "Bug"}, "description": {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": vulnerability.remediation_advice or "Review and remediate the finding."}]}]},
        }})
        key = result.get("key")
        return {"key": key, "url": f"{self.root}/browse/{key}", "assignee": None}

    def get_status(self, key: str) -> dict:
        result = self.request(f"{self.root}/rest/api/3/issue/{key}?fields=status,assignee", headers=self.headers)
        fields = result.get("fields", {})
        status = (fields.get("status") or {}).get("statusCategory", {}).get("key", "new")
        return {"status": "resolved" if status == "done" else "in_progress" if status == "indeterminate" else "open",
                "assignee": ((fields.get("assignee") or {}).get("displayName"))}


class GitHubIssuesAdapter(RestAdapter):
    def __init__(self, api_token: str | None = None):
        self.owner, self.repo = settings.github_owner, settings.github_repo
        self.credential_token = api_token or settings.github_token
        self.root = f"https://api.github.com/repos/{self.owner}/{self.repo}/issues"
        self.headers = {"Authorization": f"Bearer {self.credential_token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"}

    def create_issue(self, vulnerability: DiscoveredVulnerability, endpoint: Endpoint) -> dict:
        result = self.request(self.root, method="POST", headers=self.headers, payload={
            "title": f"[{vulnerability.severity.upper()}] {vulnerability.vuln_type} at {endpoint.path}",
            "body": f"Finding #{vulnerability.id}\n\n{vulnerability.remediation_advice or 'Review and remediate the finding.'}",
            "labels": ["security", vulnerability.severity.lower()],
        })
        return {"key": str(result.get("number")), "url": result.get("html_url", ""), "assignee": (result.get("assignee") or {}).get("login")}

    def get_status(self, key: str) -> dict:
        result = self.request(f"{self.root}/{key}", headers=self.headers)
        return {"status": "resolved" if result.get("state") == "closed" else "open", "assignee": (result.get("assignee") or {}).get("login")}


def adapter_for(system: str, api_token: str | None = None):
    if system == "jira":
        if not (settings.jira_base_url and settings.jira_email and (api_token or settings.jira_api_token) and settings.jira_project_key):
            raise TicketingError("Jira integration is not configured.")
        return JiraCloudAdapter(api_token)
    if system == "github":
        if not (settings.github_owner and settings.github_repo and (api_token or settings.github_token)):
            raise TicketingError("GitHub integration is not configured.")
        return GitHubIssuesAdapter(api_token)
    raise ValueError("external_system must be jira or github")


def _ticket_context(db: Session, ticket: RemediationTicket) -> str:
    vulnerability = db.get(DiscoveredVulnerability, ticket.vulnerability_id)
    if vulnerability is None:
        raise LookupError("Vulnerability not found.")
    endpoint = db.get(Endpoint, vulnerability.endpoint_id)
    if endpoint is None:
        raise LookupError("Endpoint not found.")
    organization_id = db.scalar(select(Target.organization_id).where(Target.id == endpoint.target_id))
    if organization_id is None:
        raise LookupError("Ticket workspace not found.")
    return f"remediation-ticket:{ticket.id}:organization:{organization_id}"


def create_ticket(db: Session, vulnerability_id: int, system: str) -> RemediationTicket:
    vuln = db.get(DiscoveredVulnerability, vulnerability_id)
    if vuln is None:
        raise LookupError("Vulnerability not found.")
    existing = db.scalar(select(RemediationTicket).where(RemediationTicket.vulnerability_id == vulnerability_id, RemediationTicket.external_system == system))
    if existing is not None:
        return existing
    endpoint = db.get(Endpoint, vuln.endpoint_id)
    adapter = adapter_for(system)
    credential_token = getattr(adapter, "credential_token", None)
    if not isinstance(credential_token, str) or not credential_token:
        credential_token = None
    encryption = get_encryption_service() if credential_token else None
    result = adapter.create_issue(vuln, endpoint)
    if not result.get("key"):
        raise TicketingError("Ticket provider returned no ticket key.")
    ticket = RemediationTicket(vulnerability_id=vuln.id, external_system=system, external_ticket_key=str(result["key"]), external_ticket_url=result.get("url", ""), assignee=result.get("assignee"), status="open")
    db.add(ticket)
    db.flush()
    if credential_token:
        wrapped = encryption.encrypt(credential_token, context=_ticket_context(db, ticket))
        ticket.access_token_ciphertext = wrapped.ciphertext
        ticket.access_token_wrapped_dek = wrapped.wrapped_dek
        register_secret_for_redaction(credential_token)
    db.commit()
    db.refresh(ticket)
    return ticket


def sync_ticket(db: Session, ticket: RemediationTicket) -> RemediationTicket:
    token = None
    if bool(ticket.access_token_ciphertext) != bool(ticket.access_token_wrapped_dek):
        raise EncryptionError("Ticket credential envelope is incomplete.")
    if ticket.access_token_ciphertext and ticket.access_token_wrapped_dek:
        token = get_encryption_service().decrypt(
            EncryptedEnvelope(ticket.access_token_ciphertext, ticket.access_token_wrapped_dek),
            context=_ticket_context(db, ticket),
        )
        register_secret_for_redaction(token)
    result = adapter_for(ticket.external_system, token).get_status(ticket.external_ticket_key)
    status = result.get("status", "open")
    if status not in {"open", "in_progress", "resolved", "wont_fix"}:
        status = "open"
    ticket.status, ticket.assignee = status, result.get("assignee") or ticket.assignee
    vuln = db.get(DiscoveredVulnerability, ticket.vulnerability_id)
    if vuln and status == "resolved":
        vuln.status = "resolved"
    db.commit()
    db.refresh(ticket)
    return ticket


def create_eligible_tickets(db: Session, target_id: int) -> int:
    """Create tickets for untracked critical/high issues where an integration is configured."""
    systems = [s for s in ("jira", "github") if (s == "jira" and all((settings.jira_base_url, settings.jira_email, settings.jira_api_token, settings.jira_project_key))) or (s == "github" and all((settings.github_owner, settings.github_repo, settings.github_token)))]
    if not systems:
        return 0
    vulns = db.execute(select(DiscoveredVulnerability).join(VulnerabilityScan).join(Endpoint).where(
        Endpoint.target_id == target_id, DiscoveredVulnerability.severity.in_(["critical", "high"]), DiscoveredVulnerability.status != "resolved")).scalars().all()
    made = 0
    for vuln in vulns:
        existing = db.scalar(select(RemediationTicket.id).where(RemediationTicket.vulnerability_id == vuln.id))
        if existing:
            continue
        try:
            create_ticket(db, vuln.id, systems[0])
            made += 1
        except TicketingError:
            continue
    return made
