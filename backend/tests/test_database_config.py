from dataclasses import replace

from sqlalchemy import inspect

from app.core.config import settings
from app.db.base import Base
from app.db.session import create_database_engine, database_engine_options
from app import models  # noqa: F401 - register all ORM metadata


def test_postgresql_engine_uses_three_second_connect_timeout(monkeypatch):
    monkeypatch.setattr("app.db.session.settings", replace(settings, app_env="production"))
    _url, options = database_engine_options(
        "postgresql+psycopg://scamguard:unused@db.example:5432/scamguard"
    )
    assert options["connect_args"] == {"connect_timeout": 3}


def test_development_localhost_uses_one_loopback_address(monkeypatch):
    monkeypatch.setattr("app.db.session.settings", replace(settings, app_env="development"))
    _url, options = database_engine_options(
        "postgresql+psycopg://scamguard:unused@localhost:5432/scamguard"
    )
    assert options["connect_args"] == {"connect_timeout": 3, "hostaddr": "127.0.0.1"}


def test_sqlite_engine_enables_foreign_keys_and_creates_application_tables():
    engine = create_database_engine("sqlite://")
    try:
        Base.metadata.create_all(engine)
        with engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        tables = set(inspect(engine).get_table_names())
        assert {"users", "investigations", "agent_runs", "evidence"}.issubset(tables)
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
