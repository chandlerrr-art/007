"""Add wrapped DEK metadata for sensitive credentials.

Revision ID: 0012_envelope_encryption
Revises: 0011_celery_task_tracking
"""
from alembic import op
import sqlalchemy as sa

revision = "0012_envelope_encryption"
down_revision = "0011_celery_task_tracking"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "test_credentials",
        sa.Column("encrypted_secret_wrapped_dek", sa.JSON(), nullable=True),
    )
    op.add_column(
        "webhook_subscriptions",
        sa.Column("secret_key_wrapped_dek", sa.JSON(), nullable=True),
    )
    op.add_column(
        "remediation_tickets",
        sa.Column("access_token_ciphertext", sa.Text(), nullable=True),
    )
    op.add_column(
        "remediation_tickets",
        sa.Column("access_token_wrapped_dek", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("remediation_tickets", "access_token_wrapped_dek")
    op.drop_column("remediation_tickets", "access_token_ciphertext")
    op.drop_column("webhook_subscriptions", "secret_key_wrapped_dek")
    op.drop_column("test_credentials", "encrypted_secret_wrapped_dek")
