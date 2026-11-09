"""Privacy-conscious, database-backed summaries for the administrator console."""
from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
import json
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.entities import AgentRun, Feedback, Investigation, ThreatIntelResult, User

UNCATEGORIZED = {"other_suspicious", "other suspicious", "no scam pattern detected"}
URL_HEURISTIC_INDICATORS = {
    "url_not_https", "malformed_url", "url_shortener", "punycode_domain",
    "deep_subdomain", "lookalike_domain",
}
URL_PROVIDER_ALIASES = {
    "safe_browsing": "google_safe_browsing",
    "google safe browsing": "google_safe_browsing",
    "google_safe_browsing": "google_safe_browsing",
    "virustotal": "virustotal",
    "virus_total": "virustotal",
}


def date_range_bounds(
    from_date: date | None = None,
    to_date: date | None = None,
    *,
    maximum_days: int = 366,
) -> tuple[date, date, datetime, datetime]:
    today = datetime.now(timezone.utc).date()
    end = to_date or today
    start = from_date or end - timedelta(days=29)
    if start > end:
        raise ValueError("from_date must be on or before to_date")
    if (end - start).days + 1 > maximum_days:
        raise ValueError(f"Date range cannot exceed {maximum_days} days")
    start_at = datetime.combine(start, time.min, tzinfo=timezone.utc)
    end_exclusive = datetime.combine(end + timedelta(days=1), time.min, tzinfo=timezone.utc)
    return start, end, start_at, end_exclusive


def _date_predicate(start_at: datetime, end_exclusive: datetime):
    return (Investigation.created_at >= start_at, Investigation.created_at < end_exclusive)


def _category_is_scam(category_column):
    return category_column.is_not(None) & func.lower(category_column).not_in(UNCATEGORIZED)


def _utc_day_expression(db: Session):
    if db.get_bind().dialect.name == "postgresql":
        return func.date(func.timezone("UTC", Investigation.created_at))
    return func.date(Investigation.created_at)


def _class_counts(db: Session, where) -> dict[str, int]:
    classification = func.lower(Investigation.report_json["classification"].as_string())
    counts = {"scam": 0, "legitimate": 0, "uncertain": 0}
    for value, count in db.execute(
        select(classification, func.count())
        .where(*where, classification.in_(counts))
        .group_by(classification)
    ):
        counts[str(value)] = int(count)
    return counts


def _offline_evaluation_metrics() -> dict[str, Any]:
    repository_root = Path(__file__).resolve().parents[2]
    path = repository_root / "docs" / "testing" / "evaluation-report-v2.json"
    if not path.is_file():
        return {"status": "unavailable", "reason": "evaluation_report_not_bundled"}
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
        model = report["models"]["tfidf_logistic_regression"]
        test = model["test"]
        cv = model["cross_validation"]["out_of_fold_metrics"]
        metric_names = ("accuracy", "precision_scam", "recall_scam", "f1_scam", "false_positive_rate", "false_negative_rate", "n", "confusion_matrix", "confidence_intervals_95")
        return {
            "status": "available",
            "source": "evaluation-report-v2.json",
            "dataset_rows": int(report["dataset_rows"]),
            "test": {name: test[name] for name in metric_names if name in test},
            "cross_validation": {name: cv[name] for name in metric_names if name in cv},
            "test_split_counts": report.get("label_counts_by_split", {}).get("test", {}),
            "limitations": [
                "The held-out test set has only six records; these descriptive metrics do not establish generalization.",
                "The training set is strongly scam-imbalanced; see the model card for split counts and collection limits.",
                "The live prediction remains experimental and is not calibrated or used for risk scoring.",
            ],
        }
    except (OSError, ValueError, KeyError, TypeError):
        return {"status": "unavailable", "reason": "evaluation_report_invalid"}


def admin_analytics(db: Session, from_date: date | None = None, to_date: date | None = None) -> dict[str, Any]:
    start, end, start_at, end_exclusive = date_range_bounds(from_date, to_date)
    date_filter = _date_predicate(start_at, end_exclusive)
    users = {role: int(count) for role, count in db.execute(select(User.role, func.count()).group_by(User.role))}
    users.setdefault("user", 0)
    users.setdefault("admin", 0)
    total_users = sum(users.values())
    total_investigations = int(db.scalar(select(func.count()).select_from(Investigation)) or 0)
    range_total = int(db.scalar(select(func.count()).select_from(Investigation).where(*date_filter)) or 0)
    scam_predicate = _category_is_scam(Investigation.category)
    total_scam_detections = int(db.scalar(select(func.count()).select_from(Investigation).where(scam_predicate)) or 0)
    range_scam_detections = int(db.scalar(select(func.count()).select_from(Investigation).where(*date_filter, scam_predicate)) or 0)
    explicit_classifications = _class_counts(db, ())
    range_classifications = _class_counts(db, date_filter)
    today = datetime.now(timezone.utc).date()
    today_start = datetime.combine(today, time.min, tzinfo=timezone.utc)
    tomorrow = today_start + timedelta(days=1)
    investigations_today = int(db.scalar(select(func.count()).select_from(Investigation).where(*_date_predicate(today_start, tomorrow))) or 0)

    category_distribution = {
        str(category): int(count)
        for category, count in db.execute(
            select(Investigation.category, func.count())
            .where(*date_filter, scam_predicate)
            .group_by(Investigation.category)
        )
    }
    risk_distribution = {
        str(risk): int(count)
        for risk, count in db.execute(
            select(Investigation.risk_level, func.count())
            .where(*date_filter)
            .group_by(Investigation.risk_level)
        )
    }
    day_expression = _utc_day_expression(db)
    investigations_per_day = [
        {"date": str(day), "count": int(count)}
        for day, count in db.execute(
            select(day_expression, func.count())
            .where(*date_filter)
            .group_by(day_expression)
            .order_by(day_expression)
        )
    ]

    provider_failure_statuses: dict[str, dict[str, int]] = {}
    for provider, status, count in db.execute(
        select(ThreatIntelResult.provider, ThreatIntelResult.status, func.count())
        .join(Investigation, Investigation.id == ThreatIntelResult.investigation_id)
        .where(*date_filter, ThreatIntelResult.status.in_(["failed", "timed_out", "unavailable"]))
        .group_by(ThreatIntelResult.provider, ThreatIntelResult.status)
    ):
        provider_failure_statuses.setdefault(str(provider), {})[str(status)] = int(count)
    provider_failure_counts = {key: sum(counts.values()) for key, counts in provider_failure_statuses.items()}

    agent_failure_statuses: dict[str, dict[str, int]] = {}
    for agent_name, status, count in db.execute(
        select(AgentRun.agent_name, AgentRun.status, func.count())
        .join(Investigation, Investigation.id == AgentRun.investigation_id)
        .where(*date_filter, AgentRun.status.in_(["failed", "timed_out"]))
        .group_by(AgentRun.agent_name, AgentRun.status)
    ):
        agent_failure_statuses.setdefault(str(agent_name), {})[str(status)] = int(count)
    agent_failure_counts = {key: sum(counts.values()) for key, counts in agent_failure_statuses.items()}

    duration_by_investigation = (
        select(AgentRun.investigation_id, func.sum(AgentRun.duration_ms).label("duration_ms"))
        .join(Investigation, Investigation.id == AgentRun.investigation_id)
        .where(*date_filter)
        .group_by(AgentRun.investigation_id)
        .subquery()
    )
    average_duration = db.scalar(select(func.avg(duration_by_investigation.c.duration_ms)))
    feedback_counts = {
        str(rating): int(count)
        for rating, count in db.execute(
            select(Feedback.rating, func.count())
            .join(Investigation, Investigation.id == Feedback.investigation_id)
            .where(*date_filter)
            .group_by(Feedback.rating)
        )
    }
    recent_activity_rows = db.execute(
        select(Investigation.id, Investigation.input_type, Investigation.category, Investigation.risk_score, Investigation.risk_level, Investigation.created_at)
        .where(*date_filter)
        .order_by(Investigation.created_at.desc())
        .limit(8)
    ).all()
    recent_activity = [
        {"id": str(row.id), "input_type": row.input_type, "category": row.category,
         "risk_score": row.risk_score, "risk_level": row.risk_level,
         "created_at": _as_utc(row.created_at).isoformat()}
        for row in recent_activity_rows
    ]

    provider_rows = db.execute(
        select(ThreatIntelResult.provider, ThreatIntelResult.status, ThreatIntelResult.is_malicious, func.count())
        .join(Investigation, Investigation.id == ThreatIntelResult.investigation_id)
        .where(*date_filter)
        .group_by(ThreatIntelResult.provider, ThreatIntelResult.status, ThreatIntelResult.is_malicious)
    ).all()
    url_intelligence = _url_intelligence_counts_from_grouped(db, provider_rows, start_at, end_exclusive)

    ml_status = Investigation.report_json["ml_prediction"]["status"].as_string()
    ml_class = Investigation.report_json["ml_prediction"]["predicted_class"].as_string()
    ml_grouped = db.execute(
        select(ml_status, ml_class, func.count())
        .where(*date_filter, ml_status.is_not(None))
        .group_by(ml_status, ml_class)
    ).all()
    model_predictions: dict[str, int] = {"completed": 0, "skipped": 0, "unavailable": 0, "failed": 0}
    predicted_classes: dict[str, int] = {"scam": 0, "legitimate": 0}
    for status, predicted_class, count in ml_grouped:
        count = int(count)
        if status in model_predictions:
            model_predictions[str(status)] += count
        if status == "completed" and predicted_class in predicted_classes:
            predicted_classes[str(predicted_class)] += count

    return {
        "total_users": total_users,
        "user_counts": users,
        "total_investigations": total_investigations,
        "total_scam_detections": total_scam_detections,
        "total_legitimate_classifications": explicit_classifications["legitimate"],
        "total_uncertain_classifications": explicit_classifications["uncertain"],
        "classification_counts_are_explicit_only": True,
        "scam_detection_percentage": round(total_scam_detections * 100 / total_investigations, 1) if total_investigations else 0.0,
        "investigations_today_utc": investigations_today,
        "date_range": {"from_date": start.isoformat(), "to_date": end.isoformat()},
        "investigations_in_range": range_total,
        "range_detection_counts": {
            "scam_detected": range_scam_detections,
            "no_scam_category": max(range_total - range_scam_detections, 0),
            "explicit_scam": range_classifications["scam"],
            "explicit_legitimate": range_classifications["legitimate"],
            "explicit_uncertain": range_classifications["uncertain"],
        },
        "investigations_per_day": investigations_per_day,
        "category_distribution": category_distribution,
        "risk_distribution": risk_distribution,
        "provider_failure_counts": provider_failure_counts,
        "provider_failure_statuses": provider_failure_statuses,
        "agent_failure_counts": agent_failure_counts,
        "agent_failure_statuses": agent_failure_statuses,
        "average_processing_time_ms": round(float(average_duration)) if average_duration is not None else None,
        "feedback_counts": feedback_counts,
        "recent_activity": recent_activity,
        "url_intelligence": url_intelligence,
        "ml_monitoring": {
            "model_name": "TF-IDF + Logistic Regression",
            "model_version": settings.ml_model_version,
            "experimental": True,
            "prediction_status_counts": model_predictions,
            "predicted_class_counts": predicted_classes,
            "evaluation": _offline_evaluation_metrics(),
            "disclaimer": "This isolated advisory does not change the deterministic score, findings, verification, or recommendations.",
        },
    }


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _url_intelligence_counts_from_grouped(db: Session, grouped, start_at: datetime, end_exclusive: datetime) -> dict[str, Any]:
    # Kept separate so overview can reuse the grouped provider query without a second read.
    providers: dict[str, dict[str, int]] = {
        "google_safe_browsing": {"checks": 0, "malicious": 0, "clean_no_known_threat": 0, "failures": 0, "skipped": 0},
        "virustotal": {"checks": 0, "malicious": 0, "clean_no_known_threat": 0, "failures": 0, "skipped": 0},
    }
    status_counts: dict[str, int] = {}
    malicious = clean = failed = skipped = 0
    failure_statuses = {"failed", "timed_out", "unavailable"}
    for raw_provider, status, verdict, count in grouped:
        raw_lower = str(raw_provider).strip().lower()
        provider_key = URL_PROVIDER_ALIASES.get(raw_lower.replace("-", "_"), URL_PROVIDER_ALIASES.get(raw_lower, raw_lower.replace(" ", "_")))
        item = providers.setdefault(provider_key, {"checks": 0, "malicious": 0, "clean_no_known_threat": 0, "failures": 0, "skipped": 0})
        count = int(count)
        item["checks"] += count
        status_counts[str(status)] = status_counts.get(str(status), 0) + count
        if status == "completed" and verdict is True:
            malicious += count
            item["malicious"] += count
        elif status == "completed" and verdict is False:
            clean += count
            item["clean_no_known_threat"] += count
        elif status == "skipped":
            skipped += count
            item["skipped"] += count
        elif status in failure_statuses:
            failed += count
            item["failures"] += count

    findings_expr = Investigation.report_json["findings"]
    url_reports = db.execute(select(findings_expr).where(*_date_predicate(start_at, end_exclusive))).scalars()
    suspicious_findings = 0
    for findings in url_reports:
        if isinstance(findings, list):
            suspicious_findings += sum(
                1 for finding in findings
                if isinstance(finding, dict) and finding.get("indicator") in URL_HEURISTIC_INDICATORS
            )
    return {
        "malicious_results": malicious,
        "suspicious_url_findings": suspicious_findings,
        "clean_no_known_threat_results": clean,
        "provider_failures": failed,
        "skipped_lookups": skipped,
        "status_counts": status_counts,
        "providers": providers,
        "clean_result_caveat": "No known threat found; not verified safe.",
    }
