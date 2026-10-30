"""Deterministic security policy evaluation for CI/CD consumers."""
from collections import Counter
from uuid import uuid4

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def evaluate_gate(vulnerabilities, policy: dict | None = None) -> dict:
    policy = policy or {}
    fail_on = {str(x).lower() for x in policy.get("fail_on_severities", ["critical"])}
    warn_on = {str(x).lower() for x in policy.get("warn_on_severities", [])}
    fail_cvss_above = policy.get("fail_cvss_above")
    warn_cvss_above = policy.get("warn_cvss_above")
    active = [v for v in vulnerabilities if v.status not in {"resolved", "false_positive"}]
    counts = Counter((v.severity or "unknown").lower() for v in active)
    violations, warnings = [], []
    for vuln in active:
        severity = (vuln.severity or "unknown").lower()
        item = {"vulnerability_id": vuln.id, "type": vuln.vuln_type, "severity": severity,
                "cvss_score": vuln.cvss_score, "endpoint_id": vuln.endpoint_id}
        violation_reasons, warning_reasons = [], []
        if severity in fail_on:
            violation_reasons.append(f"Severity {severity} is configured to fail the gate.")
        elif severity in warn_on:
            warning_reasons.append(f"Severity {severity} is configured to warn.")
        if fail_cvss_above is not None and (vuln.cvss_score or 0) > float(fail_cvss_above):
            violation_reasons.append(f"CVSS score exceeds {float(fail_cvss_above):g}.")
        elif warn_cvss_above is not None and (vuln.cvss_score or 0) > float(warn_cvss_above):
            warning_reasons.append(f"CVSS score exceeds warning threshold {float(warn_cvss_above):g}.")
        if violation_reasons:
            violations.append({**item, "reason": " ".join(violation_reasons)})
        elif warning_reasons:
            warnings.append({**item, "reason": " ".join(warning_reasons)})
    status = "failed" if violations else "warn" if warnings else "passed"
    return {"gate_status": status, "exit_code": 1 if status == "failed" else 0,
            "policy_snapshot_id": str(uuid4()), "policy": policy,
            "summary": {"active_findings": len(active), "severity_counts": dict(counts),
                        "violation_count": len(violations), "warning_count": len(warnings)},
            "violations": violations, "warnings": warnings}
