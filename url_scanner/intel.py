"""Bounded Safe Browsing and VirusTotal lookups with explicit unavailable states."""
from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import base64
import hashlib
import threading
import time
from urllib.parse import urlsplit

import httpx

from url_scanner.config import settings

GOOGLE_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
VIRUSTOTAL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
_CACHE: OrderedDict[tuple[str, str], tuple[float, dict]] = OrderedDict()
_CACHE_LOCK = threading.Lock()
_CACHE_MAX_ENTRIES = 2048
_MAX_RETRY_AFTER_SECONDS = 0.5


def _origin_only(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("A validated HTTP(S) origin is required")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    default = 443 if parsed.scheme.lower() == "https" else 80
    authority = f"{host}:{port}" if port and port != default else host
    return f"{parsed.scheme.lower()}://{authority}"


def _key(provider: str, origin: str) -> tuple[str, str]:
    return provider, hashlib.sha256(origin.encode("utf-8")).hexdigest()


def _unavailable(provider: str, reason: str, retry_count: int = 0) -> dict:
    return {
        "provider": provider,
        "status": "unavailable",
        "is_malicious": None,
        "reason": reason,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "cached": False,
        "retry_count": retry_count,
    }


def _cache_get(provider: str, origin: str) -> dict | None:
    now = time.monotonic()
    with _CACHE_LOCK:
        key = _key(provider, origin)
        item = _CACHE.get(key)
        if not item:
            return None
        expires, result = item
        if now >= expires:
            _CACHE.pop(key, None)
            return None
        _CACHE.move_to_end(key)
        return {**result, "cached": True}


def _cache_set(provider: str, origin: str, result: dict) -> dict:
    with _CACHE_LOCK:
        _CACHE[_key(provider, origin)] = (time.monotonic() + min(max(settings.cache_ttl_seconds, 1), 3600), result)
        _CACHE.move_to_end(_key(provider, origin))
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


def _call(provider: str, origin: str, api_key: str, endpoint: str) -> dict:
    if not api_key:
        return _unavailable(provider, "not_configured")
    safe_origin = _origin_only(origin)
    cached = _cache_get(provider, safe_origin)
    if cached:
        return cached
    url_id = base64.urlsafe_b64encode(safe_origin.encode("utf-8")).decode("ascii").rstrip("=")
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
                                "threatEntries": [{"url": safe_origin}],
                            },
                        },
                    )
                else:
                    response = client.get(request_url, headers={"x-apikey": api_key})
            if response.status_code == 429 or response.status_code >= 500:
                if attempt == 0:
                    time.sleep(_retry_delay(response))
                    continue
                reason = "rate_limited" if response.status_code == 429 else "upstream_error"
                return _unavailable(provider, reason, retry_count=attempt)
            if 400 <= response.status_code < 500 and not (provider == "virustotal" and response.status_code == 404):
                return _unavailable(provider, "provider_rejected_request", retry_count=attempt)
            if provider == "virustotal" and response.status_code == 404:
                result = {
                    "provider": provider, "status": "completed", "is_malicious": None,
                    "reason": "no_report", "checked_at": datetime.now(timezone.utc).isoformat(),
                    "cached": False, "retry_count": attempt,
                }
                return _cache_set(provider, safe_origin, result)
            response.raise_for_status()
            payload = response.json()
            if provider == "google_safe_browsing":
                malicious = bool(payload.get("matches", []))
            else:
                stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0)) > 0
            result = {
                "provider": provider, "status": "completed", "is_malicious": malicious,
                "reason": "known_threat" if malicious else "no_known_threat",
                "checked_at": datetime.now(timezone.utc).isoformat(), "cached": False,
                "retry_count": attempt,
            }
            return _cache_set(provider, safe_origin, result)
        except httpx.TimeoutException:
            if attempt + 1 == attempts:
                return _unavailable(provider, "timed_out", retry_count=attempt)
        except (httpx.HTTPError, ValueError, TypeError, KeyError):
            if attempt + 1 == attempts:
                return _unavailable(provider, "request_failed", retry_count=attempt)
    return _unavailable(provider, "request_failed", retry_count=attempts - 1)


def query_google_safe_browsing(origin: str) -> dict:
    return _call("google_safe_browsing", origin, settings.google_safe_browsing_key, GOOGLE_ENDPOINT)


def query_virustotal(origin: str) -> dict:
    return _call("virustotal", origin, settings.virustotal_api_key, VIRUSTOTAL_ENDPOINT)


def check_reputation(origin: str) -> list[dict]:
    """Return two explicit provider states; no configured provider means unavailable."""
    return [query_google_safe_browsing(origin), query_virustotal(origin)]
