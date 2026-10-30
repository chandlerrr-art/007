"""Ticket adapters. Credentials and project coordinates come from environment settings."""
import base64
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (DiscoveredVulnerability, Endpoint, RemediationTicket,
                        VulnerabilityScan)
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
    def __init__(self):
        root = settings.jira_base_url.rstrip("/")
        token = base64.b64encode(f"{settings.jira_email}:{settings.jira_api_token}".encode()).decode()
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
    def __init__(self):
        self.owner, self.repo, self.token = settings.github_owner, settings.github_repo, settings.github_token
        self.root = f"https://api.github.com/repos/{self.owner}/{self.repo}/issues"
        self.headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"}

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


def adapter_for(system: str):
    if system == "jira":
        if not (settings.jira_base_url and settings.jira_email and settings.jira_api_token and settings.jira_project_key):
            raise TicketingError("Jira integration is not configured.")
        return JiraCloudAdapter()
    if system == "github":
        if not (settings.github_owner and settings.github_repo and settings.github_token):
            raise TicketingError("GitHub integration is not configured.")
        return GitHubIssuesAdapter()
    raise ValueError("external_system must be jira or github")


def create_ticket(db: Session, vulnerability_id: int, system: str) -> RemediationTicket:
    vuln = db.get(DiscoveredVulnerability, vulnerability_id)
    if vuln is None:
        raise LookupError("Vulnerability not found.")
    existing = db.scalar(select(RemediationTicket).where(RemediationTicket.vulnerability_id == vulnerability_id, RemediationTicket.external_system == system))
    if existing is not None:
        return existing
    endpoint = db.get(Endpoint, vuln.endpoint_id)
    result = adapter_for(system).create_issue(vuln, endpoint)
    if not result.get("key"):
        raise TicketingError("Ticket provider returned no ticket key.")
    ticket = RemediationTicket(vulnerability_id=vuln.id, external_system=system, external_ticket_key=str(result["key"]), external_ticket_url=result.get("url", ""), assignee=result.get("assignee"), status="open")
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return ticket


def sync_ticket(db: Session, ticket: RemediationTicket) -> RemediationTicket:
    result = adapter_for(ticket.external_system).get_status(ticket.external_ticket_key)
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
