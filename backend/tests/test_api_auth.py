from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes
from app.core import security
from app.db.base import Base
from app.db.session import get_db
from app.main import app


@pytest.fixture
def client(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    event.listen(engine, "connect", lambda connection, _: connection.execute("PRAGMA foreign_keys=ON"))
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    test_settings = replace(security.settings, secret_key="test-secret-key-that-is-at-least-32-bytes")
    monkeypatch.setattr(security, "settings", test_settings)
    monkeypatch.setattr(routes, "settings", test_settings)
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


def test_register_login_and_protected_me_endpoint(client):
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    response = client.post(
        "/api/auth/register",
        headers={"X-CSRF-Token": csrf},
        json={"email":"student@example.com", "password":"correct-horse-battery"},
    )
    assert response.status_code == 201
    assert response.json()["email"] == "student@example.com"
    assert client.get("/api/auth/me").status_code == 200

    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    response = client.post(
        "/api/auth/login",
        headers={"X-CSRF-Token": csrf},
        json={"email":"student@example.com", "password":"correct-horse-battery"},
    )
    assert response.status_code == 200
    assert client.get("/api/auth/me").status_code == 200


def test_mutation_requires_csrf_and_rejects_invalid_input(client):
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    client.post(
        "/api/auth/register",
        headers={"X-CSRF-Token": csrf},
        json={"email":"student@example.com", "password":"correct-horse-battery"},
    )
    response = client.post("/api/investigations/text", json={"text":"test", "input_type":"text"})
    assert response.status_code == 403
    invalid = client.post(
        "/api/investigations/text",
        headers={"X-CSRF-Token": csrf},
        json={"text":"", "input_type":"text"},
    )
    assert invalid.status_code == 422


def test_investigation_is_persisted_as_redacted_report(client):
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    client.post(
        "/api/auth/register",
        headers={"X-CSRF-Token": csrf},
        json={"email":"student@example.com", "password":"correct-horse-battery"},
    )
    response = client.post(
        "/api/investigations/text",
        headers={"X-CSRF-Token": csrf},
        json={"text":"Share OTP 123456 now", "input_type":"sms"},
    )
    assert response.status_code == 201
    report = response.json()
    assert report["risk_score"] > 0
    assert report["redactions"] == ["otp"]
    detail = client.get(f"/api/investigations/{report['id']}")
    assert detail.status_code == 200
    assert "123456" not in detail.json()["redacted_content"]
