"""Narrow persisted agent execution states to the shared four-state contract.

Revision ID: 0003_agent_status_contract
Revises: 0002_unavailable_status
"""
from alembic import op

revision = "0003_agent_status_contract"
down_revision = "0002_unavailable_status"
branch_labels = None
depends_on = None

_AGENT_STATUSES = "status IN ('completed','skipped','failed','timed_out')"
_LEGACY_STATUSES = "status IN ('completed','skipped','failed','timed_out','unavailable')"


def upgrade() -> None:
    # Older releases stored unavailable scanner outcomes as agent runs. Preserve
    # the detail while moving those records into the shared execution vocabulary.
    op.execute(
        "UPDATE agent_runs SET status = 'failed', "
        "error = COALESCE(NULLIF(error, ''), "
        "'Legacy unavailable agent run mapped to failed; provider detail remains in threat-intel results.') "
        "WHERE status = 'unavailable'"
    )
    with op.batch_alter_table("agent_runs") as batch:
        batch.drop_constraint("ck_agent_runs_status", type_="check")
        batch.create_check_constraint("ck_agent_runs_status", _AGENT_STATUSES)


def downgrade() -> None:
    with op.batch_alter_table("agent_runs") as batch:
        batch.drop_constraint("ck_agent_runs_status", type_="check")
        batch.create_check_constraint("ck_agent_runs_status", _LEGACY_STATUSES)