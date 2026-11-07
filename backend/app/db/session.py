from collections.abc import Generator

from sqlalchemy import create_engine, event, make_url
from sqlalchemy.engine import Engine, URL
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings


def database_engine_options(database_url: str) -> tuple[URL, dict[str, object]]:
    url = make_url(database_url)
    options = {"pool_pre_ping": True, "future": True}
    if url.get_backend_name() == "sqlite":
        options["connect_args"] = {"check_same_thread": False}
    elif url.get_backend_name() == "postgresql":
        # Bound TCP connection attempts so a missing local/remote database fails
        # promptly instead of leaving auth and API requests blocked indefinitely.
        connect_args = {"connect_timeout": 3}
        if settings.app_env == "development" and url.host and url.host.lower() == "localhost":
            # Avoid psycopg retrying multiple localhost address families on
            # platforms where each failed address can consume a full timeout.
            connect_args["hostaddr"] = "127.0.0.1"
        options["connect_args"] = connect_args
    return url, options


def create_database_engine(database_url: str) -> Engine:
    url, options = database_engine_options(database_url)
    engine = create_engine(url, **options)
    if url.get_backend_name() == "sqlite":
        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(connection, _record):
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    return engine


engine = create_database_engine(settings.database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
