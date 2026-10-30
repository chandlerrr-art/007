import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import (ComplianceFramework, DiscoveredVulnerability, Endpoint,
                        RemediationTicket, Target, VulnerabilityComplianceMapping,
                        VulnerabilityScan)
from app.remediation.compliance import classify, map_vulnerability, target_posture
from app.remediation.reporting import executive_report, render_html
from app.remediation.ticketing import create_ticket, sync_ticket


class RemediationPhase3Tests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)
        self.db = self.Session()
        target = Target(name="Demo", base_url="http://demo", environment="test", status="authorized")
        self.db.add(target); self.db.flush(); self.target = target
        endpoint = Endpoint(target_id=target.id, method="POST", path="/api/payments", classification="active", sensitivity="high", last_seen=datetime.now(timezone.utc), source="test", business_flow="pay")
        self.db.add(endpoint); self.db.flush(); self.endpoint = endpoint
        scan = VulnerabilityScan(target_id=target.id, status="completed", config_snapshot="{}")
        self.db.add(scan); self.db.flush(); self.scan = scan
        vuln = DiscoveredVulnerability(scan_id=scan.id, endpoint_id=endpoint.id, vuln_type="bola_idor", severity="critical", cvss_score=9.1, evidence_payload="redacted", remediation_advice="Enforce object-level authorization.", status="open")
        self.db.add(vuln); self.db.flush(); self.vuln = vuln
        # Same taxonomy rows seeded by migration 0008.
        self.db.add_all([
            ComplianceFramework(name="OWASP API Security Top 10", version="2023", category="owasp_api", external_id="API1:2023", title="Broken Object Level Authorization"),
            ComplianceFramework(name="CWE", version="4.15", category="cwe", external_id="CWE-639", title="Authorization Bypass Through User-Controlled Key"),
        ])
        self.db.commit()

    def tearDown(self):
        self.db.close(); Base.metadata.drop_all(self.engine); self.engine.dispose()

    def test_categorization_maps_bola_to_owasp_and_cwe(self):
        found = classify(self.vuln)
        self.assertEqual({x[0] for x in found}, {"API1:2023", "CWE-639"})
        result = map_vulnerability(self.db, self.vuln)
        self.assertEqual({x["external_id"] for x in result}, {"API1:2023", "CWE-639"})
        self.assertEqual(self.db.scalar(select(VulnerabilityComplianceMapping).where(VulnerabilityComplianceMapping.vulnerability_id == self.vuln.id)).vulnerability_id, self.vuln.id)

    @patch("app.remediation.ticketing.adapter_for")
    def test_ticket_creation_and_closed_ticket_sync(self, adapter_for):
        adapter = Mock()
        adapter.create_issue.return_value = {"key": "SEC-42", "url": "https://tracker/SEC-42", "assignee": "alice"}
        adapter.get_status.return_value = {"status": "resolved", "assignee": "alice"}
        adapter_for.return_value = adapter
        ticket = create_ticket(self.db, self.vuln.id, "jira")
        self.assertEqual(ticket.external_ticket_key, "SEC-42")
        ticket = sync_ticket(self.db, ticket)
        self.assertEqual(ticket.status, "resolved")
        self.assertEqual(self.db.get(DiscoveredVulnerability, self.vuln.id).status, "resolved")

    def test_compliance_posture_marks_bola_category_failing(self):
        posture = target_posture(self.db, self.target.id)
        self.assertEqual(posture["compliance_percentage"], 0)  # one seeded OWASP category and it fails
        self.assertEqual(posture["categories"][0]["id"], "API1:2023")
        self.assertEqual(posture["failing_endpoints"][0]["endpoint"], "POST /api/payments")

    def test_executive_report_aggregates_risk_flow_and_exports_html(self):
        report = executive_report(self.db, self.target.id)
        self.assertEqual(report["severity_counts"]["critical"], 1)
        self.assertEqual(report["top_vulnerable_business_flows"][0]["flow"], "pay")
        self.assertEqual(report["risk_score"], 9.1)
        html = render_html(report)
        self.assertIn("Executive Security Report", html)
        self.assertIn("pay", html)


if __name__ == "__main__":
    unittest.main()
