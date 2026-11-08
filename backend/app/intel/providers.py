"""Bounded, real threat-intel lookups. No configured key means an explicit skip."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import time

import httpx

from app.core.config import settings
from app.detection.normalize import normalize_url_for_scan

_CACHE: dict[tuple[str, str], tuple[datetime, dict]] = {}
_TTL = timedelta(minutes=5)


def _cache_key(provider: str, url: str) -> tuple[str, str]:
    return provider, hashlib.sha256(url.encode("utf-8")).hexdigest()


def _cached(provider: str, url: str) -> dict | None:
    entry = _CACHE.get(_cache_key(provider, url))
    if not entry:
        return None
    expires, result = entry
    if datetime.now(timezone.utc) >= expires:
        _CACHE.pop(_cache_key(provider, url), None)
        return None
    return {**result, "cached": True}


def _store(provider: str, url: str, result: dict) -> dict:
    _CACHE[_cache_key(provider, url)] = (datetime.now(timezone.utc) + _TTL, result)
    return result


def _unavailable(provider: str, detail: str, status: str = "skipped") -> dict:
    return {"provider": provider, "status": status, "is_malicious": None, "detail": detail, "checked_at": datetime.now(timezone.utc).isoformat(), "cached": False}


def query_google_safe_browsing(url: str) -> dict:
    provider = "google_safe_browsing"
    if not settings.google_safe_browsing_key:
        return _unavailable(provider, "API key not configured; lookup skipped.")
    url = normalize_url_for_scan(url)
    if not url:
        return _unavailable(provider, "Invalid HTTP(S) URL; lookup skipped.")
    cached = _cached(provider, url)
    if cached:
        return cached
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    body = {
        "client": {"clientId": "scamguard-project", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    for attempt in range(2):
        try:
            with httpx.Client(timeout=5.0, follow_redirects=False) as client:
                response = client.post(endpoint, params={"key": settings.google_safe_browsing_key}, json=body)
            if (response.status_code == 429 or response.status_code >= 500) and attempt == 0:
                time.sleep(0.2)
                continue
            response.raise_for_status()
            matches = response.json().get("matches", [])
            malicious = bool(matches)
            detail = (
                f"Google Safe Browsing reported {len(matches)} matching threat entry/entries."
                if malicious else "No known threat found; not verified safe."
            )
            result = {"provider": provider, "status": "completed", "is_malicious": malicious, "detail": detail, "checked_at": datetime.now(timezone.utc).isoformat(), "cached": False}
            return _store(provider, url, result)
        except httpx.TimeoutException:
            if attempt == 1:
                return _unavailable(provider, "Provider timed out after one bounded retry.", "timed_out")
        except (httpx.HTTPError, ValueError):
            if attempt == 1:
                return _unavailable(provider, "Provider request failed; no reputation conclusion available.", "failed")
    return _unavailable(provider, "Provider request failed; no reputation conclusion available.", "failed")


def query_virustotal(url: str) -> dict:
    provider = "virustotal"
    if not settings.virustotal_api_key:
        return _unavailable(provider, "API key not configured; lookup skipped.")
    url = normalize_url_for_scan(url)
    if not url:
        return _unavailable(provider, "Invalid HTTP(S) URL; lookup skipped.")
    cached = _cached(provider, url)
    if cached:
        return cached
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    for attempt in range(2):
        try:
            with httpx.Client(timeout=5.0, follow_redirects=False) as client:
                response = client.get(endpoint, headers={"x-apikey": settings.virustotal_api_key})
            if (response.status_code == 429 or response.status_code >= 500) and attempt == 0:
                time.sleep(0.2)
                continue
            if response.status_code == 404:
                result = {"provider": provider, "status": "completed", "is_malicious": None, "detail": "No report available; not verified safe.", "checked_at": datetime.now(timezone.utc).isoformat(), "cached": False}
                return _store(provider, url, result)
            response.raise_for_status()
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = int(stats.get("malicious", 0))
            malicious = malicious_count > 0
            detail = (
                f"VirusTotal recorded {malicious_count} malicious engine verdict(s)."
                if malicious else "No known threat found; not verified safe."
            )
            result = {"provider": provider, "status": "completed", "is_malicious": malicious, "detail": detail, "checked_at": datetime.now(timezone.utc).isoformat(), "cached": False}
            return _store(provider, url, result)
        except httpx.TimeoutException:
            if attempt == 1:
                return _unavailable(provider, "Provider timed out after one bounded retry.", "timed_out")
        except (httpx.HTTPError, ValueError, TypeError):
            if attempt == 1:
                return _unavailable(provider, "Provider request failed; no reputation conclusion available.", "failed")
    return _unavailable(provider, "Provider request failed; no reputation conclusion available.", "failed")


def check_url_reputation(url: str) -> list[dict]:
    """Look up the full normalized URL; fragments are omitted and cache keys are hashed."""
    return [query_google_safe_browsing(url), query_virustotal(url)]
