from dataclasses import replace
from datetime import datetime, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes
from app.core import security
from app.db.base import Base
from app.db.session import get_db
from app.models.entities import Investigation
from app.main import RequestGuardMiddleware, app


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
        app.state.test_session_factory = testing_session
        yield test_client
    app.dependency_overrides.clear()
    app.state._state.pop("test_session_factory", None)
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


def test_register_returns_clear_503_when_database_connection_fails(client, tmp_path):
    missing_database_path = tmp_path / "missing-directory" / "unavailable.db"
    unreachable_engine = create_engine(f"sqlite:///{missing_database_path}")
    unreachable_session = sessionmaker(bind=unreachable_engine)

    def unavailable_db():
        with unreachable_session() as db:
            yield db

    app.dependency_overrides[get_db] = unavailable_db
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    response = client.post(
        "/api/auth/register",
        headers={"X-CSRF-Token": csrf},
        json={"email": "db-outage@example.com", "password": "correct-horse-battery"},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "Database unavailable"}
    unreachable_engine.dispose()


def test_protected_me_endpoint_rejects_unauthenticated_access(client):
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_login_rate_limit_returns_429_after_eight_attempts(client):
    client.get("/health")
    layer = client.app.middleware_stack
    guard = None
    while layer is not None:
        if isinstance(layer, RequestGuardMiddleware):
            guard = layer
            break
        layer = getattr(layer, "app", None)
    assert guard is not None
    guard.events.clear()

    responses = [
        client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "not-a-valid-password"})
        for _ in range(9)
    ]
    assert [item.status_code for item in responses[:8]] == [403] * 8
    assert responses[8].status_code == 429


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


def test_unmatched_report_is_uncategorized_and_timestamps_remain_utc(client):
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    client.post(
        "/api/auth/register",
        headers={"X-CSRF-Token": csrf},
        json={"email": "uncategorized@example.com", "password": "correct-horse-battery"},
    )
    response = client.post(
        "/api/investigations/text",
        headers={"X-CSRF-Token": csrf},
        json={"text": "Hi, are we meeting at 5pm?", "input_type": "text"},
    )

    assert response.status_code == 201
    report = response.json()
    assert report["risk_score"] == 0
    assert report["risk_level"] == "Low"
    assert report["category"] is None
    assert report["created_at"].endswith(("Z", "+00:00"))
    response_time = datetime.fromisoformat(report["created_at"])

    with client.app.state.test_session_factory() as db:
        saved = db.get(Investigation, UUID(report["id"]))
        assert saved is not None
        assert saved.category is None
        # SQLite stores this UTC value without timezone metadata; the API restores UTC.
        assert saved.created_at.tzinfo is None
        assert saved.created_at.replace(tzinfo=timezone.utc) == response_time

    history = client.get("/api/investigations").json()["items"]
    assert history[0]["category"] is None
    assert history[0]["created_at"].endswith(("Z", "+00:00"))
    stats = client.get("/api/dashboard/statistics").json()
    assert stats["category_distribution"] == {}
    stored_report = client.get(f"/api/investigations/{report['id']}/report")
    assert stored_report.json()["category"] is None
    assert stored_report.json()["created_at"].endswith(("Z", "+00:00"))

    scam = client.post(
        "/api/investigations/text",
        headers={"X-CSRF-Token": csrf},
        json={"text": "Your KYC will expire. Complete KYC immediately or your account will be blocked.", "input_type": "text"},
    )
    assert scam.status_code == 201
    assert scam.json()["category"] == "fake_kyc"
    stats = client.get("/api/dashboard/statistics").json()
    assert stats["category_distribution"] == {"fake_kyc": 1}


def test_unavailable_scanner_status_is_persisted(client, monkeypatch):
    from app.agents import workflow
    monkeypatch.setattr(workflow, "settings", replace(workflow.settings, url_scanner_url="http://url-scanner:8001"))
    monkeypatch.setattr(workflow, "_scan_url_service", lambda _url: {
        "status": "unavailable", "reason": "scanner_timed_out", "findings": [],
        "threat_intel_results": [
            {"provider": "google_safe_browsing", "status": "unavailable", "is_malicious": None, "reason": "scanner_timed_out"},
            {"provider": "virustotal", "status": "unavailable", "is_malicious": None, "reason": "scanner_timed_out"},
        ],
    })
    csrf = client.get("/api/auth/csrf").json()["csrf_token"]
    client.post(
        "/api/auth/register",
        headers={"X-CSRF-Token": csrf},
        json={"email":"scanner@example.com", "password":"correct-horse-battery"},
    )
    response = client.post(
        "/api/investigations/text",
        headers={"X-CSRF-Token": csrf},
        json={"text":"Your account will be blocked immediately. Transfer the amount now at https://example.com", "input_type":"url"},
    )
    assert response.status_code == 201
    report = response.json()
    assert {item["status"] for item in report["threat_intel_results"]} == {"unavailable"}
    assert report["evidence_strength"] == "Limited"
    assert {item["verification_level"] for item in report["findings"]} == {"heuristic"}
    assert client.get(f"/api/investigations/{report['id']}").status_code == 200
