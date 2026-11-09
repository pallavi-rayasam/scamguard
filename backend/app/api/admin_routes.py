"""Administrator-only management and health APIs; no mutation endpoints are exposed."""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Literal
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, cast, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.admin_metrics import UNCATEGORIZED, date_range_bounds
from app.core.config import settings
from app.core.security import admin_user
from app.db.session import get_db
from app.models.entities import AgentRun, Investigation, User

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _date_filter(start_at, end_exclusive):
    return (Investigation.created_at >= start_at, Investigation.created_at < end_exclusive)


def _classification_expression():
    return func.lower(Investigation.report_json["classification"].as_string())


def _scam_detection_expression():
    return Investigation.category.is_not(None) & func.lower(Investigation.category).not_in(UNCATEGORIZED)


def _json_array_length(db: Session, key: str):
    if db.get_bind().dialect.name == "postgresql":
        return func.coalesce(func.json_array_length(Investigation.report_json[key]), 0)
    return func.coalesce(func.json_array_length(Investigation.report_json, f"$.{key}"), 0)


@router.get("/investigations")
def list_admin_investigations(
    q: str | None = Query(default=None, max_length=100),
    classification: Literal["all", "scam", "legitimate", "uncertain", "no_pattern"] = "all",
    risk_level: str | None = Query(default=None, max_length=16),
    from_date: date | None = None,
    to_date: date | None = None,
    sort_by: Literal["created_at", "risk_score", "risk_level", "category"] = "created_at",
    sort_direction: Literal["asc", "desc"] = "desc",
    page: int = Query(default=1, ge=1, le=100000),
    page_size: int = Query(default=20, ge=1, le=100),
    _: User = Depends(admin_user),
    db: Session = Depends(get_db),
) -> dict:
    try:
        start, end, start_at, end_exclusive = date_range_bounds(from_date, to_date)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    filters = list(_date_filter(start_at, end_exclusive))
    if q and q.strip():
        term = f"%{q.strip()}%"
        filters.append(
            cast(Investigation.id, String).ilike(term)
            | Investigation.input_type.ilike(term)
            | Investigation.category.ilike(term)
            | Investigation.risk_level.ilike(term)
        )
    if risk_level:
        filters.append(Investigation.risk_level == risk_level)
    classification_value = _classification_expression()
    if classification == "scam":
        filters.append(_scam_detection_expression())
    elif classification == "no_pattern":
        filters.append(~_scam_detection_expression())
    elif classification in {"legitimate", "uncertain"}:
        filters.append(classification_value == classification)

    total = int(db.scalar(select(func.count()).select_from(Investigation).where(*filters)) or 0)
    sort_columns = {
        "created_at": Investigation.created_at,
        "risk_score": Investigation.risk_score,
        "risk_level": Investigation.risk_level,
        "category": Investigation.category,
    }
    sort_column = sort_columns[sort_by]
    order = sort_column.asc() if sort_direction == "asc" else sort_column.desc()
    rows = db.execute(
        select(
            Investigation.id,
            Investigation.input_type,
            Investigation.category,
            Investigation.risk_score,
            Investigation.risk_level,
            Investigation.created_at,
            classification_value.label("classification"),
            _json_array_length(db, "findings").label("finding_count"),
            _json_array_length(db, "urls").label("url_count"),
        )
        .where(*filters)
        .order_by(order, Investigation.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    items = []
    for row in rows:
        explicit_classification = row.classification
        if explicit_classification in {"scam", "legitimate", "uncertain"}:
            classification_label = explicit_classification
            classification_source = "stored_explicit_classification"
        elif row.category and row.category.strip().casefold() not in UNCATEGORIZED:
            classification_label = "scam_detected"
            classification_source = "deterministic_category_match"
        else:
            classification_label = "not_classified"
            classification_source = "no_ground_truth_label_recorded"
        items.append({
            "id": str(row.id),
            "input_type": row.input_type,
            "category": row.category,
            "risk_score": row.risk_score,
            "risk_level": row.risk_level,
            "created_at": row.created_at,
            "classification": classification_label,
            "classification_source": classification_source,
            "finding_count": int(row.finding_count or 0),
            "url_count": int(row.url_count or 0),
        })
    return {
        "items": items,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": (total + page_size - 1) // page_size,
        "date_range": {"from_date": start.isoformat(), "to_date": end.isoformat()},
        "privacy_note": "Investigation text, user identity, URL paths, and evidence excerpts are not returned.",
    }


@router.get("/investigations/{investigation_id}")
def get_admin_investigation(
    investigation_id: UUID,
    _: User = Depends(admin_user),
    db: Session = Depends(get_db),
) -> dict:
    row = db.execute(
        select(
            Investigation.id,
            Investigation.input_type,
            Investigation.category,
            Investigation.risk_score,
            Investigation.risk_level,
            Investigation.created_at,
            Investigation.report_json,
        ).where(Investigation.id == investigation_id)
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    report = row.report_json if isinstance(row.report_json, dict) else {}
    raw_findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    findings = [
        {"indicator": item.get("indicator"), "source": item.get("source"), "verification_level": item.get("verification_level")}
        for item in raw_findings if isinstance(item, dict)
    ]
    raw_providers = report.get("threat_intel_results") if isinstance(report.get("threat_intel_results"), list) else []
    providers = [
        {"provider": item.get("provider"), "status": item.get("status"), "is_malicious": item.get("is_malicious")}
        for item in raw_providers if isinstance(item, dict)
    ]
    runs = db.scalars(
        select(AgentRun).where(AgentRun.investigation_id == investigation_id).order_by(AgentRun.created_at.asc())
    ).all()
    ml_prediction = report.get("ml_prediction") if isinstance(report.get("ml_prediction"), dict) else {}
    safe_ml = {key: ml_prediction.get(key) for key in ("status", "predicted_class", "model_version")}
    return {
        "id": str(row.id),
        "input_type": row.input_type,
        "category": row.category,
        "risk_score": row.risk_score,
        "risk_level": row.risk_level,
        "created_at": row.created_at,
        "findings": findings,
        "providers": providers,
        "agents": [
            {"name": run.agent_name, "status": run.status, "duration_ms": run.duration_ms, "tools_used": run.tools_used or []}
            for run in runs
        ],
        "ml_prediction": safe_ml if safe_ml.get("status") else None,
        "recommendation_count": len(report.get("recommendations", [])) if isinstance(report.get("recommendations"), list) else 0,
        "url_count": len(report.get("urls", [])) if isinstance(report.get("urls"), list) else 0,
        "privacy_note": "Source message, account identity, provider details, URL values, and evidence excerpts are intentionally omitted.",
    }


def _configured_status(configured: bool, *, selected: bool = True) -> str:
    if not configured:
        return "unavailable" if selected else "not_configured"
    return "configured" if selected else "unverified"


@router.get("/system-health")
def admin_system_health(
    _: User = Depends(admin_user),
    db: Session = Depends(get_db),
) -> dict:
    try:
        db.execute(select(1)).scalar_one()
        database_status = "operational"
    except SQLAlchemyError:
        database_status = "unavailable"

    scanner_status = "unverified"
    if settings.url_scanner_url:
        try:
            response = httpx.get(
                f"{settings.url_scanner_url.rstrip('/')}/health",
                timeout=httpx.Timeout(connect=1.0, read=1.0, write=1.0, pool=1.0),
                follow_redirects=False,
            )
            scanner_status = "operational" if response.status_code == 200 else "unavailable"
        except httpx.HTTPError:
            scanner_status = "unavailable"

    llm_selected = settings.llm_provider == "groq"
    services = [
        {"id": "backend", "name": "FastAPI backend", "status": "operational", "verification": "request_served"},
        {"id": "database", "name": "PostgreSQL database", "status": database_status, "verification": "select_1"},
        {"id": "url_scanner", "name": "URL scanner", "status": scanner_status, "verification": "health_endpoint" if settings.url_scanner_url else "not_configured"},
        {"id": "groq", "name": "Groq LLM provider", "status": _configured_status(bool(settings.groq_api_key), selected=llm_selected), "verification": "not_probed", "selected": llm_selected},
        {"id": "google_safe_browsing", "name": "Google Safe Browsing", "status": "configured" if settings.google_safe_browsing_key else "not_configured", "verification": "not_probed"},
        {"id": "virustotal", "name": "VirusTotal", "status": "configured" if settings.virustotal_api_key else "not_configured", "verification": "not_probed"},
    ]
    return {
        "services": services,
        "provider_note": "Third-party providers are not called by this dashboard; configured keys do not establish live availability.",
        "checked_at": datetime.now(timezone.utc),
    }
