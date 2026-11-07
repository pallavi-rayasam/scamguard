"""Represent investigations with no matched scam pattern as uncategorized.

Revision ID: 0004_nullable_investigation_category
Revises: 0003_agent_status_contract
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_nullable_investigation_category"
down_revision = "0003_agent_status_contract"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("investigations") as batch:
        batch.alter_column(
            "category",
            existing_type=sa.String(length=64),
            existing_nullable=False,
            nullable=True,
        )
    # Earlier releases used this placeholder when no seeded scam pattern matched.
    op.execute("UPDATE investigations SET category = NULL WHERE category = 'other_suspicious'")


def downgrade() -> None:
    op.execute("UPDATE investigations SET category = 'other_suspicious' WHERE category IS NULL")
    with op.batch_alter_table("investigations") as batch:
        batch.alter_column(
            "category",
            existing_type=sa.String(length=64),
            existing_nullable=True,
            nullable=False,
        )
