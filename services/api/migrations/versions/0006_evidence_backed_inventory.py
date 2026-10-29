"""Phase 1: Evidence-backed inventory, parameters, role observations, and traffic logs."""
from alembic import op
import sqlalchemy as sa

revision = "0006_evidence_backed_inventory"
down_revision = "0005_staging_readiness"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. New tables
    op.create_table(
        "endpoint_parameters",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("location", sa.String(length=40), nullable=False),
        sa.Column("observed_type", sa.String(length=40), nullable=False, server_default="string"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "endpoint_role_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(length=80), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("last_observed", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "traffic_log_entries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True),
        sa.Column("method", sa.String(length=12), nullable=False),
        sa.Column("path", sa.String(length=1000), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_days", sa.Integer(), nullable=False, server_default="90"),
        sa.Column("role", sa.String(length=80), nullable=True),
        sa.Column("source", sa.String(length=80), nullable=False, server_default="gateway_access_log"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # 2. Add columns to endpoints table
    with op.batch_alter_table("endpoints") as batch_op:
        batch_op.add_column(sa.Column("business_flow", sa.String(length=40), nullable=True))
        batch_op.add_column(sa.Column("api_version", sa.String(length=20), nullable=False, server_default="v1"))
        batch_op.add_column(sa.Column("first_seen_traffic", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("last_seen_traffic", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("traffic_hit_count", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("auth_required", sa.Boolean(), nullable=False, server_default=sa.true()))
        batch_op.add_column(sa.Column("auth_reachability", sa.String(length=80), nullable=False, server_default="authenticated_only"))
        batch_op.add_column(sa.Column("owner", sa.String(length=120), nullable=False, server_default="Unassigned"))
        batch_op.add_column(sa.Column("likely_owner", sa.String(length=120), nullable=False, server_default="Unassigned"))
        batch_op.add_column(sa.Column("version_notes", sa.String(length=500), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("data_fields_summary", sa.Text(), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("recommended_action", sa.String(length=100), nullable=False, server_default="keep_active"))


def downgrade() -> None:
    with op.batch_alter_table("endpoints") as batch_op:
        batch_op.drop_column("recommended_action")
        batch_op.drop_column("data_fields_summary")
        batch_op.drop_column("version_notes")
        batch_op.drop_column("likely_owner")
        batch_op.drop_column("owner")
        batch_op.drop_column("auth_reachability")
        batch_op.drop_column("auth_required")
        batch_op.drop_column("traffic_hit_count")
        batch_op.drop_column("last_seen_traffic")
        batch_op.drop_column("first_seen_traffic")
        batch_op.drop_column("api_version")
        batch_op.drop_column("business_flow")

    op.drop_table("traffic_log_entries")
    op.drop_table("endpoint_role_observations")
    op.drop_table("endpoint_parameters")
