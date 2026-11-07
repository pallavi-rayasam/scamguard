"""Compatibility helpers for migration metadata written by older releases."""

from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection


LEGACY_REVISION_ALIASES = {
    "0004_nullable_investigation_category": "0004_nullable_category",
}


def normalize_legacy_revision_ids(connection: Connection) -> None:
    """Shorten historical SQLite revision values before Alembic resolves heads."""
    if not inspect(connection).has_table("alembic_version"):
        return
    for old_revision, current_revision in LEGACY_REVISION_ALIASES.items():
        connection.execute(
            text("UPDATE alembic_version SET version_num = :current WHERE version_num = :old"),
            {"current": current_revision, "old": old_revision},
        )
