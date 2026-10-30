"""Deterministic vulnerability-to-framework mapping and posture reporting."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (ComplianceFramework, DiscoveredVulnerability, Endpoint,
                        VulnerabilityComplianceMapping, VulnerabilityScan)

OWASP_RULES = {
    "bola_idor": ("API1:2023", "Object identifiers can be used across authorization boundaries."),
    "broken_authentication": ("API2:2023", "Authentication control weakness."),
    "mass_assignment": ("API3:2023", "Untrusted object properties can be modified."),
    "excessive_data_exposure": ("API3:2023", "Sensitive object properties are exposed."),
    "resource_exhaustion": ("API4:2023", "Resource consumption is not adequately bounded."),
    "business_logic_bypass": ("API6:2023", "A sensitive business flow can be abused."),
    "ssrf": ("API7:2023", "Server-side request handling can reach an unintended resource."),
    "security_misconfiguration": ("API8:2023", "Security configuration is unsafe."),
    "unauthorized_shadow_exposure": ("API9:2023", "An unmanaged or retired endpoint remains exposed."),
    "unrestricted_zombie_access": ("API9:2023", "An obsolete endpoint remains accessible."),
    "unsafe_api_consumption": ("API10:2023", "Upstream API data is consumed without adequate validation."),
    "sqli": ("API8:2023", "Injection indicates inadequate input handling."),
    "nosqli": ("API8:2023", "Injection indicates inadequate input handling."),
    "command_injection": ("API8:2023", "Injection indicates inadequate input handling."),
}
CWE_RULES = {
    "bola_idor": "CWE-639", "missing_authorization": "CWE-862", "broken_function_level_authorization": "CWE-863",
    "broken_authentication": "CWE-287", "mass_assignment": "CWE-915", "excessive_data_exposure": "CWE-862",
    "resource_exhaustion": "CWE-770", "ssrf": "CWE-918", "sqli": "CWE-89", "nosqli": "CWE-89",
    "command_injection": "CWE-78", "hardcoded_credentials": "CWE-798",
}


def classify(vulnerability: DiscoveredVulnerability) -> list[tuple[str, str]]:
    """Return category identifiers and rationale, allowing CVSS to refine broad cases."""
    kind = (vulnerability.vuln_type or "").lower().replace("-", "_").replace(" ", "_")
    results = []
    if kind in OWASP_RULES:
        results.append(OWASP_RULES[kind])
    if kind in CWE_RULES:
        results.append((CWE_RULES[kind], f"Classification for {kind}; CVSS {vulnerability.cvss_score:.1f}."))
    if kind in {"bola", "idor", "object_level_authorization"}:
        results.extend([("API1:2023", "Object-level authorization weakness."), ("CWE-639", "User-controlled object identifier can bypass authorization.")])
    return list(dict.fromkeys(results))


def map_vulnerability(db: Session, vulnerability: DiscoveredVulnerability) -> list[dict]:
    mappings = []
    for external_id, rationale in classify(vulnerability):
        framework = db.scalar(select(ComplianceFramework).where(ComplianceFramework.external_id == external_id))
        if framework is None:  # allows use before migration seed is present in test/transition environments
            continue
        mapping = db.scalar(select(VulnerabilityComplianceMapping).where(
            VulnerabilityComplianceMapping.vulnerability_id == vulnerability.id,
            VulnerabilityComplianceMapping.framework_id == framework.id))
        if mapping is None:
            mapping = VulnerabilityComplianceMapping(vulnerability_id=vulnerability.id, framework_id=framework.id, rationale=rationale)
            db.add(mapping)
            db.flush()
        mappings.append({"external_id": external_id, "title": framework.title, "category": framework.category, "rationale": mapping.rationale})
    return mappings


def target_posture(db: Session, target_id: int) -> dict:
    vulnerabilities = db.execute(select(DiscoveredVulnerability).join(VulnerabilityScan).join(
        Endpoint, DiscoveredVulnerability.endpoint_id == Endpoint.id).where(Endpoint.target_id == target_id)).scalars().all()
    all_frameworks = db.execute(select(ComplianceFramework).where(ComplianceFramework.category == "owasp_api").order_by(ComplianceFramework.external_id)).scalars().all()
    rows, failed = [], set()
    for vuln in vulnerabilities:
        mappings = map_vulnerability(db, vuln)
        active = vuln.status not in {"resolved", "false_positive"}
        if active:
            for item in mappings:
                if item["category"] == "owasp_api":
                    failed.add(item["external_id"])
        endpoint = db.get(Endpoint, vuln.endpoint_id)
        if active:
            rows.append({"vulnerability_id": vuln.id, "endpoint": f"{endpoint.method} {endpoint.path}" if endpoint else "unknown", "severity": vuln.severity, "mappings": mappings})
    db.commit()
    categories = [{"id": f.external_id, "title": f.title, "status": "failing" if f.external_id in failed else "compliant"} for f in all_frameworks]
    total = len(categories)
    return {"target_id": target_id, "framework": "OWASP API Security Top 10", "version": "2023",
            "compliance_percentage": round((total - len(failed)) * 100 / total) if total else 100,
            "categories": categories, "failing_endpoints": rows}
