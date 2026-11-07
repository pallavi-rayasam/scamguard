"""Reapply the legacy agent-status normalization as a forward migration.

Revision ID: 0005_agent_status_repair
Revises: 0004_nullable_category
"""
from alembic import op

revision = "0005_agent_status_repair"
down_revision = "0004_nullable_category"
branch_labels = None
depends_on = None

_AGENT_STATUSES = "status IN ('completed','skipped','failed','timed_out')"
_LEGACY_STATUSES = "status IN ('completed','skipped','failed','timed_out','unavailable')"


def upgrade() -> None:
    # 0003 may already be stamped in deployed databases with an earlier body.
    # Reapply its data conversion here so existing databases receive the fix.
    with op.batch_alter_table("agent_runs") as batch:
        batch.drop_constraint("ck_agent_runs_status", type_="check")
    op.execute(
        "UPDATE agent_runs SET status = 'failed', "
        "error = COALESCE(NULLIF(error, ''), "
        "'Legacy unavailable agent run mapped to failed; provider detail remains in threat-intel results.') "
        "WHERE status = 'unavailable'"
    )
    with op.batch_alter_table("agent_runs") as batch:
        batch.create_check_constraint("ck_agent_runs_status", _AGENT_STATUSES)


def downgrade() -> None:
    # Status values are intentionally not converted back to the ambiguous
    # legacy "unavailable" value; only restore the wider accepted constraint.
    with op.batch_alter_table("agent_runs") as batch:
        batch.drop_constraint("ck_agent_runs_status", type_="check")
        batch.create_check_constraint("ck_agent_runs_status", _LEGACY_STATUSES)
