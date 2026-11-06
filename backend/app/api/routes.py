from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.agents.workflow import investigate
from app.core.config import settings
from app.core.security import admin_user, current_user, csrf_token, enforce_csrf, hash_password, issue_access_token, verify_password
from app.db.session import get_db
from app.detection.normalize import load_categories
from app.models.entities import AgentRun, AuditLog, Evidence, ExtractedURL, Feedback, Investigation, Recommendation, ThreatIntelResult, User
from app.schemas.common import FeedbackRequest, InvestigationRequest, LoginRequest, RegisterRequest, UserResponse

router = APIRouter(prefix="/api")


def _set_session(response: Response, user: User) -> None:
    token = issue_access_token(user.id)
    response.set_cookie("scamguard_session", token, httponly=True, secure=settings.cookie_secure, samesite="lax", max_age=8 * 60 * 60, path="/")


@router.get("/auth/csrf")
def get_csrf(response: Response) -> dict:
    token = csrf_token()
    response.set_cookie("scamguard_csrf", token, httponly=False, secure=settings.cookie_secure, samesite="lax", max_age=8 * 60 * 60, path="/")
    return {"csrf_token": token}


@router.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> User:
    enforce_csrf(request)
    if len(settings.secret_key) < 32:
        raise HTTPException(status_code=503, detail="Authentication is not configured")
    user = User(email=payload.email.strip().lower(), password_hash=hash_password(payload.password))
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="An account with this email already exists") from None
    _set_session(response, user)
    return user


@router.post("/auth/login", response_model=UserResponse)
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> User:
    enforce_csrf(request)
    if len(settings.secret_key) < 32:
        raise HTTPException(status_code=503, detail="Authentication is not configured")
    user = db.scalar(select(User).where(User.email == payload.email.strip().lower()))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    _set_session(response, user)
    return user


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response) -> Response:
    enforce_csrf(request)
    response.delete_cookie("scamguard_session", path="/")
    response.delete_cookie("scamguard_csrf", path="/")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/auth/me", response_model=UserResponse)
def me(user: User = Depends(current_user)) -> User:
    return user


@router.post("/investigations/text", status_code=status.HTTP_201_CREATED)
def create_text_investigation(
    payload: InvestigationRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> dict:
    enforce_csrf(request)
    report = investigate(payload.text, payload.input_type)
    # The workflow returns only redacted text to prevent sensitive input from reaching persistence.
    # Preserve the sanitized submitted text separately from the public-facing report.
    from app.detection.normalize import normalize_text, redact_sensitive, redact_urls_in_text, extract_urls
    normalized = normalize_text(payload.text)
    safe, _ = redact_sensitive(normalized)
    safe = redact_urls_in_text(safe, extract_urls(normalized))
    investigation = Investigation(
        user_id=user.id,
        input_type=payload.input_type,
        redacted_content=safe[:12000],
        category=report["category"],
        risk_score=report["risk_score"],
        risk_level=report["risk_level"],
        report_json=report,
    )
    db.add(investigation)
    db.flush()
    for run in report.get("agents", []):
        db.add(AgentRun(
            investigation_id=investigation.id,
            agent_name=run["agent_name"],
            status=run["status"],
            duration_ms=run.get("duration_ms", 0),
            tools_used=run.get("tools_used", []),
            error=run.get("error"),
        ))
        for evidence in run.get("evidence", []):
            timestamp = evidence.get("timestamp")
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except ValueError:
                    timestamp = datetime.now(timezone.utc)
            db.add(Evidence(
                investigation_id=investigation.id,
                source=evidence.get("source", run["agent_name"]),
                verification_level=evidence.get("verification_level", "heuristic"),
                detail=evidence.get("detail", "")[:2000],
                observed_at=timestamp or datetime.now(timezone.utc),
            ))
    url_scans = {item.get("origin"): item for item in report.get("url_scans", []) if item.get("origin")}
    for url in report.get("urls", []):
        db.add(ExtractedURL(
            investigation_id=investigation.id,
            url=url,
            findings=url_scans.get(url, {"network_fetch":"not_configured"}),
        ))
    for intel in report.get("threat_intel_results", []):
        db.add(ThreatIntelResult(
            investigation_id=investigation.id,
            provider=intel["provider"],
            status=intel["status"],
            is_malicious=intel.get("is_malicious"),
            detail=intel.get("detail", "")[:1000],
        ))
    for advice in report.get("recommendations", []):
        db.add(Recommendation(investigation_id=investigation.id, advice_type="general", text=advice))
    db.add(AuditLog(actor_id=user.id, event="investigation.created", metadata_json={"investigation_id": str(investigation.id), "input_type": payload.input_type}))
    db.commit()
    db.refresh(investigation)
    return {"id": investigation.id, **report, "created_at": investigation.created_at}


@router.get("/investigations")
def list_investigations(
    q: str | None = Query(default=None, max_length=80),
    risk_level: str | None = Query(default=None, pattern="^(Low|Moderate|High|Critical)$"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    statement = select(Investigation).where(Investigation.user_id == user.id)
    if q:
        statement = statement.where(Investigation.redacted_content.ilike(f"%{q}%"))
    if risk_level:
        statement = statement.where(Investigation.risk_level == risk_level)
    rows = db.scalars(statement.order_by(Investigation.created_at.desc()).limit(limit).offset(offset)).all()
    return {"items": [{"id": row.id, "category": row.category, "risk_score": row.risk_score, "risk_level": row.risk_level, "created_at": row.created_at} for row in rows], "limit": limit, "offset": offset}


def _owned_investigation(investigation_id: UUID, user: User, db: Session) -> Investigation:
    row = db.get(Investigation, investigation_id)
    if not row or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return row


@router.get("/investigations/{investigation_id}")
def get_investigation(investigation_id: UUID, user: User = Depends(current_user), db: Session = Depends(get_db)) -> dict:
    row = _owned_investigation(investigation_id, user, db)
    return {"id": row.id, "created_at": row.created_at, "redacted_content": row.redacted_content, **row.report_json}


@router.get("/investigations/{investigation_id}/report")
def get_report(investigation_id: UUID, user: User = Depends(current_user), db: Session = Depends(get_db)) -> dict:
    row = _owned_investigation(investigation_id, user, db)
    return {"id": row.id, "created_at": row.created_at, **row.report_json}


@router.get("/investigations/{investigation_id}/status")
def investigation_status(investigation_id: UUID, user: User = Depends(current_user), db: Session = Depends(get_db)) -> dict:
    row = _owned_investigation(investigation_id, user, db)
    return {"id": row.id, "status": "completed", "created_at": row.created_at}


@router.delete("/investigations/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_investigation(investigation_id: UUID, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    enforce_csrf(request)
    row = _owned_investigation(investigation_id, user, db)
    db.add(AuditLog(actor_id=user.id, event="investigation.deleted", metadata_json={"investigation_id": str(row.id)}))
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/me/data", status_code=status.HTTP_204_NO_CONTENT)
def delete_my_data(request: Request, response: Response, user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    enforce_csrf(request)
    db.execute(delete(AuditLog).where(AuditLog.actor_id == user.id))
    db.delete(user)
    db.commit()
    response.delete_cookie("scamguard_session", path="/")
    response.delete_cookie("scamguard_csrf", path="/")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.post("/feedback", status_code=status.HTTP_201_CREATED)
def submit_feedback(payload: FeedbackRequest, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> dict:
    enforce_csrf(request)
    _owned_investigation(payload.investigation_id, user, db)
    from app.detection.normalize import redact_sensitive, redact_urls_in_text, extract_urls, normalize_text
    comment = None
    if payload.comment:
        comment, _ = redact_sensitive(normalize_text(payload.comment))
        comment = redact_urls_in_text(comment, extract_urls(comment))[:1000]
    feedback = Feedback(user_id=user.id, investigation_id=payload.investigation_id, rating=payload.rating, comment=comment)
    db.add(feedback)
    db.commit()
    return {"id": feedback.id, "rating": feedback.rating, "created_at": feedback.created_at}


@router.get("/dashboard/statistics")
def dashboard_statistics(user: User = Depends(current_user), db: Session = Depends(get_db)) -> dict:
    count = db.scalar(select(func.count()).select_from(Investigation).where(Investigation.user_id == user.id)) or 0
    by_risk = db.execute(select(Investigation.risk_level, func.count()).where(Investigation.user_id == user.id).group_by(Investigation.risk_level)).all()
    return {"total_investigations": count, "risk_distribution": {key: value for key, value in by_risk}}


@router.get("/scam-categories")
def scam_categories() -> list[dict]:
    return [{"code": item["code"], "name": item["name"], "language": item["language"]} for item in load_categories()]


@router.get("/scam-awareness")
def scam_awareness() -> dict:
    return {
        "language": "en",
        "items": [
            {"title":"Never share OTPs or UPI PINs", "body":"Banks and payment providers do not need your OTP or UPI PIN to receive money."},
            {"title":"Verify through official channels", "body":"Find the organisation's contact details independently instead of using a link or number in a suspicious message."},
            {"title":"Act quickly after a loss", "body":"Contact your bank immediately. In India, call 1930 or report at cybercrime.gov.in."},
        ],
    }


@router.get("/admin/analytics")
def admin_analytics(_: User = Depends(admin_user), db: Session = Depends(get_db)) -> dict:
    total = db.scalar(select(func.count()).select_from(Investigation)) or 0
    failures = db.scalar(select(func.count()).select_from(AgentRun).where(AgentRun.status.in_(["failed", "timed_out", "unavailable"]))) or 0
    return {"total_investigations": total, "agent_failures": failures}


@router.get("/admin/system-health")
def admin_system_health(_: User = Depends(admin_user)) -> dict:
    return {"api":"available", "database":"not_checked", "openai":"configured" if settings.openai_api_key else "not_configured", "threat_intel":"configured" if settings.google_safe_browsing_key or settings.virustotal_api_key else "not_configured"}
