"""Phase 5 enterprise workspaces and remediation patch records.

Revision ID: 0010_enterprise_ai_patching
Revises: 0009_cicd_and_webhooks
"""
from alembic import op
import sqlalchemy as sa

revision = "0010_enterprise_ai_patching"
down_revision = "0009_cicd_and_webhooks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(120), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    organizations = sa.table("organizations", sa.column("name", sa.String), sa.column("slug", sa.String))
    op.bulk_insert(organizations, [{"name": "Default Workspace", "slug": "default"}])

    op.create_table(
        "workspace_users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(200), nullable=False),
        sa.Column("workspace_role", sa.String(40), nullable=False),
        sa.Column("permissions", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_workspace_org_user"),
        sa.CheckConstraint("workspace_role in ('org_admin', 'security_engineer', 'developer')", name="ck_workspace_role"),
    )
    op.create_index("ix_workspace_users_user_id", "workspace_users", ["user_id"])

    op.add_column("targets", sa.Column("organization_id", sa.Integer(), nullable=True))
    op.execute("UPDATE targets SET organization_id = (SELECT id FROM organizations WHERE slug = 'default') WHERE organization_id IS NULL")
    with op.batch_alter_table("targets") as batch:
        batch.alter_column("organization_id", existing_type=sa.Integer(), nullable=False)
        batch.create_foreign_key("fk_targets_organization_id", "organizations", ["organization_id"], ["id"], ondelete="RESTRICT")
    op.create_index("ix_targets_organization_id", "targets", ["organization_id"])

    op.create_table(
        "code_patches",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("discovered_vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_file_path", sa.String(1000), nullable=False),
        sa.Column("unified_diff", sa.Text(), nullable=False),
        sa.Column("ai_confidence_score", sa.Float(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="generated"),
        sa.Column("application_mode", sa.String(20), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("ai_confidence_score >= 0 and ai_confidence_score <= 1", name="ck_code_patch_confidence"),
        sa.CheckConstraint("status in ('generated', 'reviewed', 'applied', 'rejected')", name="ck_code_patch_status"),
    )
    op.create_index("ix_code_patches_vulnerability_id", "code_patches", ["vulnerability_id"])


def downgrade() -> None:
    op.drop_index("ix_code_patches_vulnerability_id", table_name="code_patches")
    op.drop_table("code_patches")
    op.drop_index("ix_targets_organization_id", table_name="targets")
    with op.batch_alter_table("targets") as batch:
        batch.drop_constraint("fk_targets_organization_id", type_="foreignkey")
        batch.drop_column("organization_id")
    op.drop_index("ix_workspace_users_user_id", table_name="workspace_users")
    op.drop_table("workspace_users")
    op.drop_table("organizations")
