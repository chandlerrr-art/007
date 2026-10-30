"""Phase 4 CI/CD evaluations and webhook subscriptions.

Revision ID: 0009_cicd_and_webhooks
Revises: 0008_remediation_and_compliance
"""
from alembic import op
import sqlalchemy as sa

revision = "0009_cicd_and_webhooks"
down_revision = "0008_remediation_and_compliance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cicd_build_evaluations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("vulnerability_scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("pipeline_provider", sa.String(30), nullable=False),
        sa.Column("repository", sa.String(500), nullable=False, server_default=""),
        sa.Column("commit_hash", sa.String(200), nullable=False, server_default=""),
        sa.Column("branch", sa.String(200), nullable=False, server_default=""),
        sa.Column("gate_status", sa.String(20), nullable=False),
        sa.Column("policy_snapshot_id", sa.String(100), nullable=False),
        sa.Column("policy_snapshot", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_cicd_build_evaluations_target_id", "cicd_build_evaluations", ["target_id"])
    op.create_index("ix_cicd_build_evaluations_scan_id", "cicd_build_evaluations", ["scan_id"])
    op.create_table(
        "webhook_subscriptions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=True),
        sa.Column("url", sa.String(2000), nullable=False),
        sa.Column("secret_key", sa.String(1000), nullable=False),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_webhook_subscriptions_target_id", "webhook_subscriptions", ["target_id"])


def downgrade() -> None:
    op.drop_index("ix_webhook_subscriptions_target_id", table_name="webhook_subscriptions")
    op.drop_table("webhook_subscriptions")
    op.drop_index("ix_cicd_build_evaluations_scan_id", table_name="cicd_build_evaluations")
    op.drop_index("ix_cicd_build_evaluations_target_id", table_name="cicd_build_evaluations")
    op.drop_table("cicd_build_evaluations")
