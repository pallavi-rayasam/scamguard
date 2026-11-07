import ast
import importlib.util
from pathlib import Path

from sqlalchemy import create_engine
from alembic.migration import MigrationContext
from alembic.operations import Operations

from migrations.revision_compat import normalize_legacy_revision_ids


MIGRATIONS_DIR = Path(__file__).parents[1] / "migrations" / "versions"


def _revision_values(path: Path) -> tuple[str, object]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in {"revision", "down_revision"}:
                values[target.id] = ast.literal_eval(node.value)
    return values["revision"], values["down_revision"]


def test_all_alembic_revision_ids_fit_postgresql_version_column():
    migrations = sorted(MIGRATIONS_DIR.glob("*.py"))
    assert migrations
    for path in migrations:
        revision, down_revision = _revision_values(path)
        assert isinstance(revision, str), path.name
        assert len(revision) <= 32, f"{path.name} has a {len(revision)} character revision ID"
        parents = down_revision if isinstance(down_revision, tuple) else (down_revision,)
        for parent in parents:
            if parent is not None:
                assert len(parent) <= 32, f"{path.name} references an overlong revision ID: {parent}"


def test_legacy_long_revision_value_is_normalized_before_migration_lookup():
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
            connection.exec_driver_sql(
                "INSERT INTO alembic_version (version_num) VALUES ('0004_nullable_investigation_category')"
            )
            normalize_legacy_revision_ids(connection)
            current = connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
        assert current == "0004_nullable_category"
    finally:
        engine.dispose()


def test_agent_status_repair_migration_reapplies_backfill_for_an_older_0003():
    engine = create_engine("sqlite://")
    migration_path = MIGRATIONS_DIR / "0005_agent_status_repair.py"
    spec = importlib.util.spec_from_file_location("agent_status_repair", migration_path)
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE agent_runs ("
                "id INTEGER PRIMARY KEY, status VARCHAR(16) NOT NULL, error TEXT, "
                "CONSTRAINT ck_agent_runs_status CHECK "
                "(status IN ('completed','skipped','failed','timed_out','unavailable')))"
            )
            connection.exec_driver_sql(
                "INSERT INTO agent_runs (id, status) VALUES (1, 'unavailable')"
            )
            migration.op = Operations(MigrationContext.configure(connection))
            migration.upgrade()
            status, error = connection.exec_driver_sql(
                "SELECT status, error FROM agent_runs WHERE id = 1"
            ).one()
            assert status == "failed"
            assert error and "Legacy unavailable agent run mapped to failed" in error
    finally:
        engine.dispose()
