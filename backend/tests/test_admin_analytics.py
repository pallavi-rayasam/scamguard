from dataclasses import replace
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes
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

    test_settings = replace(security.settings, secret_key="test-secret-key-that-is-at-least-32-bytes")
    monkeypatch.setattr(security, "settings", test_settings)
    monkeypatch.setattr(routes, "settings", test_settings)
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


def test_admin_analytics_aggregates_database_records(analytics_client):
    _, admin_id = _seed_analytics(analytics_client)
    analytics_client.cookies.set("scamguard_session", security.issue_access_token(admin_id), path="/")

    response = analytics_client.get("/api/admin/analytics")

    assert response.status_code == 200
    assert response.json() == {
        "total_users": 3,
        "user_counts": {"user": 2, "admin": 1},
        "total_investigations": 4,
        "investigations_per_day": [
            {"date": "2026-11-06", "count": 1},
            {"date": "2026-11-07", "count": 3},
        ],
        "category_distribution": {"upi_fraud": 2},
        "risk_distribution": {"High": 1, "Medium": 1, "Low": 2},
        "provider_failure_counts": {"virustotal": 1, "safe_browsing": 1},
        "provider_failure_statuses": {
            "virustotal": {"failed": 1},
            "safe_browsing": {"unavailable": 1},
        },
        "agent_failure_counts": {"url": 1, "message": 1},
        "agent_failure_statuses": {"url": {"failed": 1}, "message": {"timed_out": 1}},
        "average_processing_time_ms": 1350,
        "feedback_counts": {"correct": 2, "incorrect": 1},
    }


def test_admin_analytics_requires_authentication(analytics_client):
    response = analytics_client.get("/api/admin/analytics")

    assert response.status_code == 401


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
