"""Phase 0 staging readiness: test credentials, test executions, and reviewer states."""
from alembic import op
import sqlalchemy as sa

revision = "0005_staging_readiness"
down_revision = "0004_inventory_text"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "test_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(length=80), nullable=False),
        sa.Column("username", sa.String(length=120), nullable=False),
        sa.Column("auth_type", sa.String(length=40), nullable=False, server_default="bearer"),
        sa.Column("header_name", sa.String(length=80), nullable=False, server_default="Authorization"),
        sa.Column("encrypted_secret", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "test_executions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("test_type", sa.String(length=80), nullable=False),
        sa.Column("is_risky", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("risk_level", sa.String(length=20), nullable=False, server_default="low"),
        sa.Column("risk_rationale", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="pending_review"),
        sa.Column("reviewer_notes", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(sa.Column("review_notes", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("reviewed_at")
        batch_op.drop_column("review_notes")
    op.drop_table("test_executions")
    op.drop_table("test_credentials")
