"""Internal HTTP service for SSRF-safe URL investigation."""
from __future__ import annotations

from collections import defaultdict, deque
from threading import Lock
import time

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from url_scanner.analysis import analyze_url
from url_scanner.config import settings
from url_scanner.intel import check_reputation
from url_scanner.ssrf_guard import (
    MAX_BODY_BYTES,
    MAX_URL_LENGTH,
    FetchUnavailable,
    SSRFBlocked,
    safe_fetch,
    validate_target,
)


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)


app = FastAPI(title="ScamGuard URL Scanner", version="0.1.0", description="Internal SSRF-guarded URL structure and reputation service.")
SAFE_GET_CONTENT_TYPES = {"text/html", "text/plain", "application/xhtml+xml"}


def _provider_lookup_skipped(reason: str) -> list[dict]:
    return [
        {"provider": provider, "status": "skipped", "is_malicious": None, "reason": reason}
        for provider in ("google_safe_browsing", "virustotal")
    ]


class ScannerRateLimitMiddleware:
    """Small per-process backstop; the service is intended to stay on the compose network."""
    def __init__(self, app):
        self.app = app
        self._lock = Lock()
        self._events: dict[str, deque[float]] = defaultdict(deque)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") not in {"/scan", "/analyze", "/reputation"}:
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        key = client[0] if client else "unknown"
        now = time.monotonic()
        with self._lock:
            bucket = self._events[key]
            while bucket and now - bucket[0] >= 60:
                bucket.popleft()
            if len(bucket) >= 30:
                response = JSONResponse({"status": "unavailable", "reason": "scanner_rate_limited"}, status_code=429)
                await response(scope, receive, send)
                return
            bucket.append(now)
        await self.app(scope, receive, send)


app.add_middleware(ScannerRateLimitMiddleware)


def _score(findings: list[dict]) -> tuple[int, str]:
    highest: dict[str, int] = {}
    for item in findings:
        indicator = item.get("indicator", "unknown")
        highest[indicator] = max(highest.get(indicator, 0), int(item.get("score_weight", 0)))
    score = min(100, sum(highest.values()))
    level = "Critical" if score >= 75 else "High" if score >= 50 else "Moderate" if score >= 25 else "Low"
    return score, level


def scan_url(url: str, include_intel: bool = True) -> dict:
    findings = analyze_url(url)
    try:
        target = validate_target(url)
    except SSRFBlocked as exc:
        return {
            "status": "blocked",
            "reason": exc.code,
            "origin": None,
            "fetch": {"status": "blocked", "reason": exc.code},
            "findings": findings,
            "threat_intel_results": _provider_lookup_skipped(exc.code),
            "risk_score": _score(findings)[0],
            "risk_level": _score(findings)[1],
        }
    except FetchUnavailable as exc:
        return {
            "status": "unavailable", "reason": exc.code, "origin": None,
            "fetch": {"status": "unavailable", "reason": exc.code}, "findings": findings,
            "threat_intel_results": _provider_lookup_skipped(exc.code),
            "risk_score": _score(findings)[0], "risk_level": _score(findings)[1],
        }

    try:
        fetched = safe_fetch(url, method="HEAD")
        if fetched.http_status in {405, 501}:
            content_type = (fetched.content_type or "").split(";", 1)[0].strip().lower()
            if content_type in SAFE_GET_CONTENT_TYPES and (fetched.content_length is None or fetched.content_length <= MAX_BODY_BYTES):
                fetched = safe_fetch(url, method="GET", max_bytes=MAX_BODY_BYTES)
            else:
                fetched = type(fetched)("head_unsupported", fetched.origin, fetched.http_status, fetched.content_type, 0, False, fetched.redirect_count, fetched.content_length)
        fetch_result = {
            "status": fetched.status,
            "http_status": fetched.http_status,
            "content_type": fetched.content_type,
            "body_bytes": fetched.body_bytes,
            "body_truncated": fetched.body_truncated,
            "redirect_count": fetched.redirect_count,
            "final_origin": fetched.origin,
        }
    except SSRFBlocked as exc:
        return {
            "status": "blocked", "reason": exc.code, "origin": target.origin,
            "fetch": {"status": "blocked", "reason": exc.code}, "findings": findings,
            "threat_intel_results": _provider_lookup_skipped(exc.code),
            "risk_score": _score(findings)[0], "risk_level": _score(findings)[1],
        }
    except FetchUnavailable as exc:
        fetch_result = {"status": "unavailable", "reason": exc.code}

    intel_results = check_reputation(target.url) if include_intel else []
    for result in intel_results:
        if result.get("is_malicious") is True:
            findings.append({
                "indicator": f"threat_intel:{result['provider']}",
                "detail": f"{result['provider']} reported a known threat for this URL.",
                "verification_level": "verified",
                "source": result["provider"],
                "score_weight": 40,
            })

    score, level = _score(findings)
    return {
        "status": "completed" if fetch_result["status"] == "completed" else "unavailable",
        "reason": None if fetch_result["status"] == "completed" else fetch_result.get("reason", fetch_result["status"]),
        "origin": target.origin,
        "fetch": fetch_result,
        "findings": findings,
        "threat_intel_results": intel_results,
        "risk_score": score,
        "risk_level": level,
    }


@app.get("/health")
def health() -> dict:
    return {
        "status": "available",
        "service": "url-scanner",
        "provider_configuration": {
            "google_safe_browsing": "configured" if settings.google_safe_browsing_key else "not_configured",
            "virustotal": "configured" if settings.virustotal_api_key else "not_configured",
        },
    }


@app.post("/analyze")
def analyze(payload: ScanRequest) -> dict:
    """Run URL structure and guarded fetch checks without reputation providers."""
    return scan_url(payload.url, include_intel=False)


@app.post("/reputation")
def reputation(payload: ScanRequest) -> dict:
    """Revalidate a public target, then return reputation-provider outcomes."""
    try:
        target = validate_target(payload.url)
    except SSRFBlocked as exc:
        return {
            "status": "blocked",
            "reason": exc.code,
            "origin": None,
            "threat_intel_results": _provider_lookup_skipped(exc.code),
        }
    except FetchUnavailable as exc:
        return {
            "status": "unavailable",
            "reason": exc.code,
            "origin": None,
            "threat_intel_results": _provider_lookup_skipped(exc.code),
        }
    return {
        "status": "completed",
        "reason": None,
        "origin": target.origin,
        "threat_intel_results": check_reputation(target.url),
    }

@app.post("/scan")
def scan(payload: ScanRequest) -> dict:
    return scan_url(payload.url)
