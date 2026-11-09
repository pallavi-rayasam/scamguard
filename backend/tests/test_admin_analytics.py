from dataclasses import replace
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import admin_routes, routes
from app.cli import create_first_admin
from app.core import security
from app.db.base import Base
from app.db.session import get_db
from app.models.entities import AgentRun, Feedback, Investigation, ThreatIntelResult, User
from app.main import app


@pytest.fixture
def analytics_client(monkeypatch):
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

    test_settings = replace(security.settings, secret_key="test-secret-key-that-is-at-least-32-bytes", url_scanner_url="")
    monkeypatch.setattr(security, "settings", test_settings)
    monkeypatch.setattr(routes, "settings", test_settings)
    monkeypatch.setattr(admin_routes, "settings", test_settings)
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as client:
        app.state.test_session_factory = testing_session
        yield client
    app.dependency_overrides.clear()
    app.state._state.pop("test_session_factory", None)
    Base.metadata.drop_all(engine)
    engine.dispose()


def _seed_analytics(client):
    with client.app.state.test_session_factory() as db:
        regular_users = [
            User(email="analyst-one@example.com", password_hash="not-used", role="user"),
            User(email="analyst-two@example.com", password_hash="not-used", role="user"),
        ]
        admin = User(email="admin@example.com", password_hash="not-used", role="admin")
        db.add_all([*regular_users, admin])
        db.flush()

        investigations = [
            Investigation(
                user_id=regular_users[0].id,
                input_type="text",
                redacted_content="first",
                category="upi_fraud",
                risk_score=80,
                risk_level="High",
                report_json={},
                created_at=datetime(2026, 11, 6, 23, 50, tzinfo=timezone.utc),
            ),
            Investigation(
                user_id=regular_users[0].id,
                input_type="text",
                redacted_content="second",
                category="upi_fraud",
                risk_score=30,
                risk_level="Medium",
                report_json={},
                created_at=datetime(2026, 11, 7, 0, 10, tzinfo=timezone.utc),
            ),
            Investigation(
                user_id=regular_users[1].id,
                input_type="text",
                redacted_content="ordinary",
                category=None,
                risk_score=0,
                risk_level="Low",
                report_json={},
                created_at=datetime(2026, 11, 7, 10, 0, tzinfo=timezone.utc),
            ),
            Investigation(
                user_id=regular_users[1].id,
                input_type="text",
                redacted_content="legacy uncategorized",
                category="other_suspicious",
                risk_score=0,
                risk_level="Low",
                report_json={},
                created_at=datetime(2026, 11, 7, 11, 0, tzinfo=timezone.utc),
            ),
        ]
        db.add_all(investigations)
        db.flush()
        first, second, _, _ = investigations
        db.add_all([
            AgentRun(investigation_id=first.id, agent_name="message", status="completed", duration_ms=1000),
            AgentRun(investigation_id=first.id, agent_name="url", status="failed", duration_ms=200),
            AgentRun(investigation_id=second.id, agent_name="message", status="timed_out", duration_ms=1000),
            AgentRun(investigation_id=second.id, agent_name="risk", status="completed", duration_ms=500),
            ThreatIntelResult(investigation_id=first.id, provider="virustotal", status="failed", detail="timeout"),
            ThreatIntelResult(investigation_id=second.id, provider="safe_browsing", status="unavailable", detail="not configured"),
            ThreatIntelResult(investigation_id=second.id, provider="virustotal", status="completed", is_malicious=False, detail="no match"),
            Feedback(user_id=regular_users[0].id, investigation_id=first.id, rating="correct"),
            Feedback(user_id=regular_users[0].id, investigation_id=second.id, rating="correct"),
            Feedback(user_id=regular_users[1].id, investigation_id=first.id, rating="incorrect"),
        ])
        db.commit()
        return regular_users[0].id, admin.id


def test_admin_analytics_rejects_regular_user(analytics_client):
    regular_user_id, _ = _seed_analytics(analytics_client)
    analytics_client.cookies.set("scamguard_session", security.issue_access_token(regular_user_id), path="/")

    response = analytics_client.get("/api/admin/analytics")

    assert response.status_code == 403
    assert response.json()["detail"] == "Administrator access required"


@pytest.mark.parametrize("path", [
    "/api/admin/analytics",
    "/api/admin/investigations",
    "/api/admin/investigations/00000000-0000-0000-0000-000000000001",
    "/api/admin/system-health",
])
def test_regular_users_are_forbidden_from_every_admin_api(analytics_client, path):
    user_id, _ = _seed_analytics(analytics_client)
    analytics_client.cookies.set("scamguard_session", security.issue_access_token(user_id), path="/")

    response = analytics_client.get(path)

    assert response.status_code == 403
    assert response.json()["detail"] == "Administrator access required"


def test_admin_analytics_aggregates_database_records(analytics_client):
    _, admin_id = _seed_analytics(analytics_client)
    analytics_client.cookies.set("scamguard_session", security.issue_access_token(admin_id), path="/")

    response = analytics_client.get("/api/admin/analytics")

    assert response.status_code == 200
    data = response.json()
    assert data["total_users"] == 3
    assert data["user_counts"] == {"user": 2, "admin": 1}
    assert data["total_investigations"] == 4
    assert data["total_scam_detections"] == 2
    assert data["total_legitimate_classifications"] == 0
    assert data["total_uncertain_classifications"] == 0
    assert data["classification_counts_are_explicit_only"] is True
    assert data["scam_detection_percentage"] == 50.0
    assert data["investigations_per_day"] == [
        {"date": "2026-11-06", "count": 1},
        {"date": "2026-11-07", "count": 3},
    ]
    assert data["category_distribution"] == {"upi_fraud": 2}
    assert data["risk_distribution"] == {"High": 1, "Medium": 1, "Low": 2}
    assert data["provider_failure_counts"] == {"virustotal": 1, "safe_browsing": 1}
    assert data["provider_failure_statuses"] == {
        "virustotal": {"failed": 1},
        "safe_browsing": {"unavailable": 1},
    }
    assert data["agent_failure_counts"] == {"url": 1, "message": 1}
    assert data["agent_failure_statuses"] == {"url": {"failed": 1}, "message": {"timed_out": 1}}
    assert data["average_processing_time_ms"] == 1350
    assert data["feedback_counts"] == {"correct": 2, "incorrect": 1}
    assert len(data["recent_activity"]) == 4
    assert data["url_intelligence"]["clean_result_caveat"] == "No known threat found; not verified safe."
    assert data["ml_monitoring"]["experimental"] is True
    assert data["ml_monitoring"]["evaluation"]["test"]["n"] == 6


def test_admin_analytics_requires_authentication(analytics_client):
    response = analytics_client.get("/api/admin/analytics")

    assert response.status_code == 401


@pytest.mark.parametrize("path", [
    "/api/admin/analytics",
    "/api/admin/investigations",
    "/api/admin/investigations/00000000-0000-0000-0000-000000000001",
    "/api/admin/system-health",
])
def test_every_admin_api_requires_authentication(analytics_client, path):
    assert analytics_client.get(path).status_code == 401


def test_empty_database_returns_zero_aggregates(analytics_client):
    with analytics_client.app.state.test_session_factory() as db:
        admin = User(email="empty-admin@example.com", password_hash="not-used", role="admin")
        db.add(admin)
        db.commit()
        admin_id = admin.id
    analytics_client.cookies.set("scamguard_session", security.issue_access_token(admin_id), path="/")

    response = analytics_client.get("/api/admin/analytics")

    assert response.status_code == 200
    body = response.json()
    assert body["total_investigations"] == 0
    assert body["total_scam_detections"] == 0
    assert body["scam_detection_percentage"] == 0.0
    assert body["investigations_per_day"] == []
    assert body["category_distribution"] == {}
    assert body["risk_distribution"] == {}
    assert body["recent_activity"] == []


def test_analytics_date_range_and_validation(analytics_client):
    _, admin_id = _seed_analytics(analytics_client)
    analytics_client.cookies.set("scamguard_session", security.issue_access_token(admin_id), path="/")

    response = analytics_client.get("/api/admin/analytics?from_date=2026-11-06&to_date=2026-11-06")
    invalid = analytics_client.get("/api/admin/analytics?from_date=2026-11-07&to_date=2026-11-06")

    assert response.status_code == 200
    assert response.json()["investigations_in_range"] == 1
    assert response.json()["category_distribution"] == {"upi_fraud": 1}
    assert len(response.json()["recent_activity"]) == 1
    assert invalid.status_code == 400


def test_investigation_search_sort_pagination_and_detail_minimize_sensitive_data(analytics_client):
    _, admin_id = _seed_analytics(analytics_client)
    analytics_client.cookies.set("scamguard_session", security.issue_access_token(admin_id), path="/")
    with analytics_client.app.state.test_session_factory() as db:
        first = db.scalar(select(Investigation).where(Investigation.redacted_content == "first"))
        first.report_json = {
            "classification": "scam",
            "findings": [{"indicator": "url_shortener", "source": "deterministic", "verification_level": "heuristic", "evidence": "PRIVATE_EVIDENCE_TEXT"}],
            "urls": ["https://example.invalid/private?token=PRIVATE_QUERY"],
            "threat_intel_results": [{"provider": "virustotal", "status": "completed", "is_malicious": True, "detail": "PRIVATE_PROVIDER_DETAIL"}],
            "ml_prediction": {"status": "completed", "predicted_class": "scam", "model_version": "message-text-v1", "calibrated_probability": 0.99},
            "recommendations": ["safe recommendation"],
        }
        db.commit()

    page_one = analytics_client.get("/api/admin/investigations?from_date=2026-11-06&to_date=2026-11-07&page_size=1&sort_by=risk_score&sort_direction=desc")
    page_two = analytics_client.get("/api/admin/investigations?from_date=2026-11-06&to_date=2026-11-07&page=2&page_size=1&sort_by=risk_score&sort_direction=desc")
    search = analytics_client.get("/api/admin/investigations?q=upi_fraud&from_date=2026-11-06&to_date=2026-11-07&classification=scam&risk_level=High")
    detail = analytics_client.get(f"/api/admin/investigations/{first.id}")

    assert page_one.status_code == page_two.status_code == search.status_code == detail.status_code == 200
    assert page_one.json()["total"] == 4
    assert page_one.json()["items"][0]["risk_score"] == 80
    assert page_two.json()["items"][0]["id"] != page_one.json()["items"][0]["id"]
    assert search.json()["total"] == 1
    assert page_one.json()["privacy_note"]
    detail_body = detail.json()
    assert detail_body["findings"] == [{"indicator": "url_shortener", "source": "deterministic", "verification_level": "heuristic"}]
    assert detail_body["providers"] == [{"provider": "virustotal", "status": "completed", "is_malicious": True}]
    assert detail_body["ml_prediction"] == {"status": "completed", "predicted_class": "scam", "model_version": "message-text-v1"}
    assert "PRIVATE_EVIDENCE_TEXT" not in response_text(detail_body)
    assert "PRIVATE_QUERY" not in response_text(detail_body)
    assert "PRIVATE_PROVIDER_DETAIL" not in response_text(detail_body)


def response_text(value):
    import json
    return json.dumps(value)


def test_admin_system_health_checks_only_internal_scanner_and_never_returns_keys(analytics_client, monkeypatch):
    _, admin_id = _seed_analytics(analytics_client)
    analytics_client.cookies.set("scamguard_session", security.issue_access_token(admin_id), path="/")
    test_settings = replace(
        admin_routes.settings,
        url_scanner_url="http://scanner.internal:8001",
        llm_provider="groq",
        groq_api_key="configured-but-never-returned",
        google_safe_browsing_key="configured-but-never-returned",
        virustotal_api_key="",
    )
    monkeypatch.setattr(admin_routes, "settings", test_settings)
    checked_urls = []

    class ScannerResponse:
        status_code = 503

    def fake_get(url, **kwargs):
        checked_urls.append((url, kwargs))
        return ScannerResponse()

    monkeypatch.setattr(admin_routes.httpx, "get", fake_get)
    response = analytics_client.get("/api/admin/system-health")

    assert response.status_code == 200
    body = response.json()
    statuses = {service["id"]: service for service in body["services"]}
    assert statuses["database"]["status"] == "operational"
    assert statuses["url_scanner"]["status"] == "unavailable"
    assert statuses["groq"]["status"] == "configured"
    assert statuses["groq"]["verification"] == "not_probed"
    assert statuses["google_safe_browsing"]["status"] == "configured"
    assert statuses["virustotal"]["status"] == "not_configured"
    assert checked_urls[0][0] == "http://scanner.internal:8001/health"
    assert len(checked_urls) == 1
    assert "configured-but-never-returned" not in response_text(body)
    assert body["provider_note"]


def test_first_admin_cli_prompts_for_a_password_and_stores_only_its_hash(analytics_client):
    password_inputs = iter(["user-chosen-admin-password", "user-chosen-admin-password"])

    email = create_first_admin(
        analytics_client.app.state.test_session_factory,
        input_fn=lambda _prompt: "first-admin@example.com",
        password_fn=lambda _prompt: next(password_inputs),
    )

    with analytics_client.app.state.test_session_factory() as db:
        admin = db.scalar(select(User).where(User.email == email))
        assert admin is not None
        assert admin.role == "admin"
        assert admin.password_hash != "user-chosen-admin-password"
        assert security.verify_password("user-chosen-admin-password", admin.password_hash)


def test_first_admin_cli_refuses_to_create_another_admin(analytics_client):
    _, _ = _seed_analytics(analytics_client)
    with pytest.raises(RuntimeError, match="An administrator already exists"):
        create_first_admin(
            analytics_client.app.state.test_session_factory,
            input_fn=lambda _prompt: pytest.fail("must refuse before prompting"),
            password_fn=lambda _prompt: pytest.fail("must refuse before prompting"),
        )
