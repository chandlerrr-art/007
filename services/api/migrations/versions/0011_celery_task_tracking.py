"""Track patch worker IDs for idempotent Celery redelivery.

Revision ID: 0011_celery_task_tracking
Revises: 0010_enterprise_ai_patching
"""
from alembic import op
import sqlalchemy as sa

revision = "0011_celery_task_tracking"
down_revision = "0010_enterprise_ai_patching"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("code_patches", sa.Column("celery_task_id", sa.String(100), nullable=True))
    op.create_index("ix_code_patches_celery_task_id", "code_patches", ["celery_task_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_code_patches_celery_task_id", table_name="code_patches")
    op.drop_column("code_patches", "celery_task_id")
