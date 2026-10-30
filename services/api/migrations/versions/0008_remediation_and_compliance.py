"""Phase 3 remediation tickets and compliance framework mappings.

Revision ID: 0008_remediation_and_compliance
Revises: 0007_vulnerability_engine
"""
from alembic import op
import sqlalchemy as sa

revision = "0008_remediation_and_compliance"
down_revision = "0007_vulnerability_engine"
branch_labels = None
depends_on = None

FRAMEWORKS = [
    ("OWASP API Security Top 10", "2023", "owasp_api", "API1:2023", "Broken Object Level Authorization"),
    ("OWASP API Security Top 10", "2023", "owasp_api", "API2:2023", "Broken Authentication"),
    ("OWASP API Security Top 10", "2023", "owasp_api", "API3:2023", "Broken Object Property Level Authorization"),
    ("OWASP API Security Top 10", "2023", "owasp_api", "API4:2023", "Unrestricted Resource Consumption"),
    ("OWASP API Security Top 10", "2023", "owasp_api", "API5:2023", "Broken Function Level Authorization"),
    ("OWASP API Security Top 10", "2023", "owasp_api", "API6:2023", "Unrestricted Access to Sensitive Business Flows"),
    ("OWASP API Security Top 10", "2023", "owasp_api", "API7:2023", "Server Side Request Forgery"),
    ("OWASP API Security Top 10", "2023", "owasp_api", "API8:2023", "Security Misconfiguration"),
    ("OWASP API Security Top 10", "2023", "owasp_api", "API9:2023", "Improper Inventory Management"),
    ("OWASP API Security Top 10", "2023", "owasp_api", "API10:2023", "Unsafe Consumption of APIs"),
]
CWES = [("CWE", "4.15", "cwe", code, title) for code, title in [
    ("CWE-639", "Authorization Bypass Through User-Controlled Key"), ("CWE-862", "Missing Authorization"),
    ("CWE-863", "Incorrect Authorization"), ("CWE-287", "Improper Authentication"),
    ("CWE-770", "Allocation of Resources Without Limits or Throttling"), ("CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
    ("CWE-89", "SQL Injection"), ("CWE-78", "OS Command Injection"), ("CWE-918", "Server-Side Request Forgery"),
    ("CWE-798", "Use of Hard-coded Credentials"),
]]


def upgrade() -> None:
    op.create_table("remediation_tickets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("discovered_vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("external_system", sa.String(20), nullable=False),
        sa.Column("external_ticket_key", sa.String(200), nullable=False),
        sa.Column("external_ticket_url", sa.String(1000), nullable=False, server_default=""),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("assignee", sa.String(200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("vulnerability_id", "external_system", name="uq_vuln_ticket_system"),
    )
    op.create_index("ix_remediation_tickets_vulnerability_id", "remediation_tickets", ["vulnerability_id"])
    op.create_table("compliance_frameworks",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(120), nullable=False),
        sa.Column("version", sa.String(40), nullable=False), sa.Column("category", sa.String(40), nullable=False),
        sa.Column("external_id", sa.String(80), nullable=False), sa.Column("title", sa.String(240), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.UniqueConstraint("name", "version", "external_id", name="uq_compliance_framework_item"),
    )
    op.create_table("vulnerability_compliance_mappings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("discovered_vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("framework_id", sa.Integer(), sa.ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rationale", sa.String(500), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("vulnerability_id", "framework_id", name="uq_vuln_compliance_mapping"),
    )
    op.create_index("ix_vuln_compliance_vulnerability_id", "vulnerability_compliance_mappings", ["vulnerability_id"])
    op.bulk_insert(sa.table("compliance_frameworks",
        sa.column("name", sa.String), sa.column("version", sa.String), sa.column("category", sa.String),
        sa.column("external_id", sa.String), sa.column("title", sa.String), sa.column("description", sa.Text)),
        [dict(name=n, version=v, category=c, external_id=e, title=t, description="OWASP API Security Top 10 (2023)") for n,v,c,e,t in FRAMEWORKS] +
        [dict(name=n, version=v, category=c, external_id=e, title=t, description="Common Weakness Enumeration") for n,v,c,e,t in CWES])


def downgrade() -> None:
    op.drop_index("ix_vuln_compliance_vulnerability_id", table_name="vulnerability_compliance_mappings")
    op.drop_table("vulnerability_compliance_mappings")
    op.drop_table("compliance_frameworks")
    op.drop_index("ix_remediation_tickets_vulnerability_id", table_name="remediation_tickets")
    op.drop_table("remediation_tickets")
