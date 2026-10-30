"""Executive and audit report aggregation with JSON and self-contained HTML exports."""
import html
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (DiscoveredVulnerability, Endpoint, RemediationTicket,
                        VulnerabilityScan)

SEVERITIES = ("critical", "high", "medium", "low", "info")


def executive_report(db: Session, target_id: int) -> dict:
    endpoints = db.execute(select(Endpoint).where(Endpoint.target_id == target_id)).scalars().all()
    vulns = db.execute(select(DiscoveredVulnerability).join(VulnerabilityScan).join(Endpoint).where(Endpoint.target_id == target_id)).scalars().all()
    severity = {level: sum(v.severity.lower() == level for v in vulns) for level in SEVERITIES}
    risk = round(sum((v.cvss_score or 0) for v in vulns) / max(len(endpoints), 1), 2)
    flow_counts: dict[str, dict] = {}
    for vuln in vulns:
        endpoint = next((e for e in endpoints if e.id == vuln.endpoint_id), None)
        flow = (endpoint.business_flow if endpoint else None) or "other"
        row = flow_counts.setdefault(flow, {"flow": flow, "vulnerabilities": 0, "critical": 0, "high": 0})
        row["vulnerabilities"] += 1
        row[vuln.severity.lower()] = row.get(vuln.severity.lower(), 0) + 1
    tickets = db.execute(select(RemediationTicket).join(DiscoveredVulnerability).join(VulnerabilityScan).join(Endpoint).where(Endpoint.target_id == target_id)).scalars().all()
    resolved_times = []
    for ticket in tickets:
        if ticket.status == "resolved" and ticket.created_at and ticket.updated_at:
            resolved_times.append(max(0, (ticket.updated_at - ticket.created_at).total_seconds() / 86400))
    unresolved = sum(v.status != "resolved" for v in vulns)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(), "target_id": target_id,
        "risk_score": risk, "risk_scale": "sum of CVSS scores divided by discovered endpoint count",
        "vulnerability_count": len(vulns), "severity_counts": severity,
        "top_vulnerable_business_flows": sorted(flow_counts.values(), key=lambda x: (-x["vulnerabilities"], x["flow"]))[:5],
        "remediation": {"open_findings": unresolved, "tickets": len(tickets), "tickets_resolved": sum(t.status == "resolved" for t in tickets),
                        "mean_ticket_resolution_days": round(sum(resolved_times) / len(resolved_times), 2) if resolved_times else None},
        "guidance": [v.remediation_advice for v in sorted(vulns, key=lambda x: (SEVERITIES.index(x.severity.lower()) if x.severity.lower() in SEVERITIES else 99, -x.cvss_score)) if v.remediation_advice][:10],
    }


def render_html(report: dict) -> str:
    safe = html.escape
    counts = "".join(f"<li>{safe(k.title())}: {v}</li>" for k, v in report["severity_counts"].items())
    flows = "".join(f"<tr><td>{safe(x['flow'])}</td><td>{x['vulnerabilities']}</td><td>{x['critical']}</td><td>{x['high']}</td></tr>" for x in report["top_vulnerable_business_flows"])
    guidance = "".join(f"<li>{safe(x)}</li>" for x in report["guidance"])
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>Executive Security Report</title>
<style>body{{font:16px system-ui;max-width:960px;margin:3rem auto;color:#17202a}}table{{border-collapse:collapse}}td,th{{border:1px solid #bbb;padding:.5rem}}.score{{font-size:2rem}}</style>
<h1>Executive Security Report</h1><p>Generated {safe(report['generated_at'])} · Target {report['target_id']}</p>
<h2>Risk score</h2><p class="score">{report['risk_score']}</p><p>{safe(report['risk_scale'])}</p>
<h2>Severity counts</h2><ul>{counts}</ul><h2>Most affected business flows</h2>
<table><thead><tr><th>Flow</th><th>Findings</th><th>Critical</th><th>High</th></tr></thead><tbody>{flows}</tbody></table>
<h2>Remediation guidance</h2><ul>{guidance}</ul></html>"""
