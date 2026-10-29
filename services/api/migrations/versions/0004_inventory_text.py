"""Allow endpoint snapshots larger than a fixed VARCHAR limit."""
from alembic import op
import sqlalchemy as sa

revision = "0004_inventory_text"
down_revision = "0003_change_detection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("inventory_snapshots") as batch_op:
        batch_op.alter_column(
            "inventory_json",
            existing_type=sa.String(length=100000),
            type_=sa.Text(),
            existing_nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("inventory_snapshots") as batch_op:
        batch_op.alter_column(
            "inventory_json",
            existing_type=sa.Text(),
            type_=sa.String(length=100000),
            existing_nullable=False,
        )
