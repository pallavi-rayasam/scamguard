"""Allow explicit provider/scanner unavailability in audit rows.

Revision ID: 0002_unavailable_status
Revises: 0001_initial_schema
"""
from alembic import op

revision = "0002_unavailable_status"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None

_OLD_STATUS = "status IN ('completed','skipped','failed','timed_out')"
_NEW_STATUS = "status IN ('completed','skipped','failed','timed_out','unavailable')"


def _replace_status_constraint(table: str, name: str, expression: str) -> None:
    with op.batch_alter_table(table) as batch:
        batch.drop_constraint(name, type_="check")
        batch.create_check_constraint(name, expression)


def upgrade() -> None:
    _replace_status_constraint("agent_runs", "ck_agent_runs_status", _NEW_STATUS)
    _replace_status_constraint("threat_intel_results", "ck_threat_intel_status", _NEW_STATUS)


def downgrade() -> None:
    bind = op.get_bind()
    for table in ("agent_runs", "threat_intel_results"):
        count = bind.exec_driver_sql(f"SELECT COUNT(*) FROM {table} WHERE status = 'unavailable'").scalar_one()
        if count:
            raise RuntimeError(f"Cannot downgrade: {table} contains unavailable status rows")
    _replace_status_constraint("agent_runs", "ck_agent_runs_status", _OLD_STATUS)
    _replace_status_constraint("threat_intel_results", "ck_threat_intel_status", _OLD_STATUS)
