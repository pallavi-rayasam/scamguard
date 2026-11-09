"""Bounded Safe Browsing and VirusTotal lookups with explicit unavailable states."""
from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import base64
import hashlib
import logging
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit, urlunsplit

import httpx

from url_scanner.config import settings

GOOGLE_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
VIRUSTOTAL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
_CACHE: OrderedDict[tuple[str, str], tuple[float, dict]] = OrderedDict()
_CACHE_LOCK = threading.Lock()
_CACHE_MAX_ENTRIES = 2048
_MAX_RETRY_AFTER_SECONDS = 0.5
logger = logging.getLogger(__name__)


def _lookup_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("A validated HTTP(S) URL is required")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    default = 443 if parsed.scheme.lower() == "https" else 80
    authority = f"{host}:{port}" if port and port != default else host
    return urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", parsed.query, ""))


def _key(provider: str, url: str) -> tuple[str, str]:
    return provider, hashlib.sha256(url.encode("utf-8")).hexdigest()


def _unavailable(provider: str, reason: str, retry_count: int = 0) -> dict:
    return {
        "provider": provider,
        "status": "unavailable",
        "is_malicious": None,
        "reason": reason,
        "failure_category": reason,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "cached": False,
        "retry_count": retry_count,
    }


def _cache_get(provider: str, url: str) -> dict | None:
    now = time.monotonic()
    with _CACHE_LOCK:
        key = _key(provider, url)
        item = _CACHE.get(key)
        if not item:
            return None
        expires, result = item
        if now >= expires:
            _CACHE.pop(key, None)
            return None
        _CACHE.move_to_end(key)
        return {**result, "cached": True}


def _cache_set(provider: str, url: str, result: dict) -> dict:
    with _CACHE_LOCK:
        _CACHE[_key(provider, url)] = (time.monotonic() + min(max(settings.cache_ttl_seconds, 1), 3600), result)
        _CACHE.move_to_end(_key(provider, url))
        while len(_CACHE) > _CACHE_MAX_ENTRIES:
            _CACHE.popitem(last=False)
    return result


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def _retry_delay(response: httpx.Response) -> float:
    raw = response.headers.get("Retry-After", "")
    try:
        suggested = float(raw)
    except (TypeError, ValueError):
        suggested = 0.2
    return max(0.0, min(suggested, _MAX_RETRY_AFTER_SECONDS))


def _provider_error_signals(response: httpx.Response) -> str:
    """Read error fields only for classification; never return or log provider text."""
    try:
        payload = response.json()
    except (ValueError, TypeError):
        return ""
    if not isinstance(payload, dict):
        return ""
    error = payload.get("error")
    if not isinstance(error, dict):
        return ""
    values = []
    for key in ("code", "status", "reason", "type", "message"):
        value = error.get(key)
        if isinstance(value, str):
            values.append(value)
    for key in ("details", "errors"):
        entries = error.get(key)
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict):
                    for field in ("code", "status", "reason", "type", "message"):
                        value = entry.get(field)
                        if isinstance(value, str):
                            values.append(value)
    return " ".join(values).casefold()


def _http_failure_reason(response: httpx.Response) -> str:
    status_code = response.status_code
    signals = _provider_error_signals(response)
    if status_code == 402:
        return "quota_exhausted"
    if status_code in {400, 403, 429}:
        if any(marker in signals for marker in (
            "quota", "resource_exhausted", "daily limit", "dailylimit", "billing", "credit_balance",
        )):
            return "quota_exhausted"
        if any(marker in signals for marker in (
            "rate_limit", "ratelimit", "too_many_requests", "toomanyrequests",
        )):
            return "rate_limited"
    if status_code == 429:
        return "rate_limited"
    if status_code in {401, 403} or any(marker in signals for marker in (
        "api_key_invalid", "invalid api key", "authenticationrequired", "unauthorized", "unauthenticated",
    )):
        return "authentication_failed"
    if status_code >= 500:
        return "provider_outage"
    return "provider_rejected_request"


def _unavailable_with_diagnostic(
    provider: str,
    reason: str,
    retry_count: int = 0,
    http_status: int | None = None,
    exception_type: str | None = None,
    failure_category: str | None = None,
) -> dict:
    category = failure_category or reason
    diagnostic = {
        "event": "threat_intel_provider_unavailable",
        "provider": provider,
        "failure_category": category,
        "retry_count": retry_count,
    }
    if http_status is not None:
        diagnostic["http_status"] = http_status
    if exception_type is not None:
        diagnostic["exception_type"] = exception_type
    logger.warning("threat_intel_provider_unavailable %s", diagnostic)
    result = _unavailable(provider, reason, retry_count)
    result["failure_category"] = category
    result["diagnostic"] = {
        "category": category,
        "retry_count": retry_count,
        **({"http_status": http_status} if http_status is not None else {}),
        **({"exception_type": exception_type} if exception_type is not None else {}),
    }
    if http_status is not None:
        result["http_status"] = http_status
    return result


def _network_failure_reason(exc: httpx.HTTPError) -> str:
    """Classify transport failures by exception type, never by logging its text."""
    pending: list[BaseException] = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ssl.SSLError):
            return "tls_failure"
        if isinstance(current, socket.gaierror):
            return "dns_failure"
        for linked in (current.__cause__, current.__context__):
            if isinstance(linked, BaseException):
                pending.append(linked)
    if isinstance(exc, httpx.TimeoutException):
        return "timed_out"
    return "network_failure"


def _malformed_response(provider: str, retry_count: int, http_status: int | None = None) -> dict:
    return _unavailable_with_diagnostic(
        provider,
        "invalid_response",
        retry_count,
        http_status,
        failure_category="malformed_response",
    )


def _call(provider: str, url: str, api_key: str, endpoint: str) -> dict:
    if not api_key:
        return _unavailable_with_diagnostic(provider, "not_configured")
    lookup_url = _lookup_url(url)
    cached = _cache_get(provider, lookup_url)
    if cached:
        return cached
    url_id = base64.urlsafe_b64encode(lookup_url.encode("utf-8")).decode("ascii").rstrip("=")
    request_url = f"{endpoint}/{url_id}" if provider == "virustotal" else endpoint
    attempts = 2
    for attempt in range(attempts):
        try:
            with httpx.Client(timeout=5.0, follow_redirects=False) as client:
                if provider == "google_safe_browsing":
                    response = client.post(
                        request_url,
                        params={"key": api_key},
                        json={
                            "client": {"clientId": "scamguard-project", "clientVersion": "0.1.0"},
                            "threatInfo": {
                                "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"],
                                "platformTypes": ["ANY_PLATFORM"],
                                "threatEntryTypes": ["URL"],
                                "threatEntries": [{"url": lookup_url}],
                            },
                        },
                    )
                else:
                    response = client.get(request_url, headers={"x-apikey": api_key})
            if response.status_code == 429 or response.status_code >= 500:
                if attempt == 0:
                    time.sleep(_retry_delay(response))
                    continue
                reason = _http_failure_reason(response)
                return _unavailable_with_diagnostic(provider, reason, attempt, response.status_code)
            if 400 <= response.status_code < 500 and not (provider == "virustotal" and response.status_code == 404):
                return _unavailable_with_diagnostic(
                    provider,
                    _http_failure_reason(response),
                    attempt,
                    response.status_code,
                )
            if provider == "virustotal" and response.status_code == 404:
                result = {
                    "provider": provider, "status": "completed", "is_malicious": None,
                    "reason": "no_report", "checked_at": datetime.now(timezone.utc).isoformat(),
                    "cached": False, "retry_count": attempt,
                }
                return _cache_set(provider, lookup_url, result)
            response.raise_for_status()
            try:
                payload = response.json()
            except (ValueError, TypeError):
                return _malformed_response(provider, attempt, response.status_code)
            if not isinstance(payload, dict):
                return _malformed_response(provider, attempt, response.status_code)
            if provider == "google_safe_browsing":
                matches = payload.get("matches", [])
                if not isinstance(matches, list):
                    return _malformed_response(provider, attempt, response.status_code)
                malicious = bool(matches)
            else:
                data = payload.get("data")
                attributes = data.get("attributes") if isinstance(data, dict) else None
                stats = attributes.get("last_analysis_stats") if isinstance(attributes, dict) else None
                if not isinstance(stats, dict):
                    return _malformed_response(provider, attempt, response.status_code)
                malicious_count = stats.get("malicious")
                if isinstance(malicious_count, bool) or not isinstance(malicious_count, int) or malicious_count < 0:
                    return _malformed_response(provider, attempt, response.status_code)
                malicious = malicious_count > 0
            result = {
                "provider": provider, "status": "completed", "is_malicious": malicious,
                "reason": "known_threat" if malicious else "no_known_threat",
                "checked_at": datetime.now(timezone.utc).isoformat(), "cached": False,
                "retry_count": attempt,
            }
            return _cache_set(provider, lookup_url, result)
        except httpx.TimeoutException as exc:
            if attempt + 1 == attempts:
                return _unavailable_with_diagnostic(
                    provider, "timed_out", attempt, exception_type=type(exc).__name__
                )
        except httpx.HTTPStatusError as exc:
            if attempt + 1 == attempts:
                return _unavailable_with_diagnostic(
                    provider,
                    _http_failure_reason(exc.response),
                    attempt,
                    exc.response.status_code,
                    type(exc).__name__,
                )
        except httpx.HTTPError as exc:
            if attempt + 1 == attempts:
                reason = _network_failure_reason(exc)
                return _unavailable_with_diagnostic(
                    provider, reason, attempt, exception_type=type(exc).__name__
                )
        except (TypeError, KeyError, AttributeError) as exc:
            if attempt + 1 == attempts:
                return _unavailable_with_diagnostic(
                    provider,
                    "invalid_response",
                    attempt,
                    exception_type=type(exc).__name__,
                    failure_category="malformed_response",
                )
    return _unavailable_with_diagnostic(provider, "request_failed", attempts - 1)


def query_google_safe_browsing(url: str) -> dict:
    return _call("google_safe_browsing", url, settings.google_safe_browsing_key, GOOGLE_ENDPOINT)


def query_virustotal(url: str) -> dict:
    return _call("virustotal", url, settings.virustotal_api_key, VIRUSTOTAL_ENDPOINT)


def check_reputation(url: str) -> list[dict]:
    """Return two explicit provider states; no configured provider means unavailable."""
    return [query_google_safe_browsing(url), query_virustotal(url)]
