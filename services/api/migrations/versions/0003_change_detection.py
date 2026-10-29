"""Phase 0 kill switch and Phase 1 change-event tables."""
from alembic import op
import sqlalchemy as sa

revision = "0003_change_detection"
down_revision = "0002_inventory_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "change_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("detail", sa.String(length=1000), nullable=False),
        sa.Column("triggered_scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "safety_controls",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kill_switch_engaged", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("reason", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("safety_controls")
    op.drop_table("change_events")
