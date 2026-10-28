"""Create SentinelFlow's initial inventory and scan schema."""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("targets",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(160), nullable=False),
        sa.Column("base_url", sa.String(500), nullable=False), sa.Column("environment", sa.String(40), nullable=False),
        sa.Column("status", sa.String(40), nullable=False), sa.Column("scope_note", sa.String(500), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.create_table("scans",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("status", sa.String(40), nullable=False), sa.Column("trigger", sa.String(40), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False), sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("summary", sa.String(500), nullable=False, server_default=""),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table("scan_stages",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(80), nullable=False), sa.Column("status", sa.String(40), nullable=False),
        sa.Column("error", sa.String(1000)), sa.Column("started_at", sa.DateTime(timezone=True)), sa.Column("finished_at", sa.DateTime(timezone=True)))
    op.create_table("endpoints",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("method", sa.String(12), nullable=False), sa.Column("path", sa.String(1000), nullable=False),
        sa.Column("classification", sa.String(40), nullable=False), sa.Column("sensitivity", sa.String(40), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False), sa.Column("source", sa.String(40), nullable=False))
    op.create_table("findings",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("endpoints.id")), sa.Column("title", sa.String(240), nullable=False),
        sa.Column("category", sa.String(80), nullable=False), sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("confidence", sa.String(20), nullable=False), sa.Column("business_impact", sa.String(500), nullable=False),
        sa.Column("status", sa.String(40), nullable=False), sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.create_table("evidence",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(80), nullable=False), sa.Column("summary", sa.String(1000), nullable=False),
        sa.Column("redacted", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.create_table("audit_events",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="SET NULL")),
        sa.Column("event_type", sa.String(100), nullable=False), sa.Column("decision", sa.String(40), nullable=False),
        sa.Column("details", sa.String(1000), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("evidence")
    op.drop_table("findings")
    op.drop_table("endpoints")
    op.drop_table("scan_stages")
    op.drop_table("scans")
    op.drop_table("targets")
