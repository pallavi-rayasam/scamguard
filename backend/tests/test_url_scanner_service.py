from pathlib import Path
import socket
import sys

from fastapi.testclient import TestClient
import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from url_scanner import analysis, intel, main  # noqa: E402
from url_scanner.ssrf_guard import FetchUnavailable, SafeFetchResult, SSRFBlocked  # noqa: E402


def clear_scanner_rate_limit_events():
    layer = main.app.middleware_stack
    while layer is not None:
        if isinstance(layer, main.ScannerRateLimitMiddleware):
            layer._events.clear()
            return
        layer = getattr(layer, "app", None)


def test_url_analysis_flags_http_shortener_punycode_and_seeded_typos():
    findings = analysis.analyze_url("http://onlinesbii.bit.ly/login")
    indicators = {item["indicator"] for item in findings}
    assert {"url_http_not_https", "url_shortener", "url_brand_lookalike"} <= indicators

    punycode = analysis.analyze_url("https://xn--e1afmkfd.example/")
    assert "url_punycode" in {item["indicator"] for item in punycode}


def test_exact_trusted_domain_and_https_do_not_trigger_lookalike_or_tls_finding():
    findings = analysis.analyze_url("https://login.uidai.gov.in/secure")
    assert "url_http_not_https" not in {item["indicator"] for item in findings}
    assert "url_brand_lookalike" not in {item["indicator"] for item in findings}


def test_unconfigured_providers_are_explicitly_unavailable_without_network(monkeypatch):
    monkeypatch.setattr(intel.settings, "google_safe_browsing_key", "")
    monkeypatch.setattr(intel.settings, "virustotal_api_key", "")
    monkeypatch.setattr(intel.httpx, "Client", lambda **kwargs: (_ for _ in ()).throw(AssertionError("network must not be used")))

    results = intel.check_reputation("https://example.com")

    assert [result["status"] for result in results] == ["unavailable", "unavailable"]
    assert {result["reason"] for result in results} == {"not_configured"}


def test_provider_queries_only_the_origin_and_caches_completed_results(monkeypatch):
    intel.clear_cache()
    monkeypatch.setattr(intel.settings, "google_safe_browsing_key", "test-google-key")
    requests = []

    class Response:
        status_code = 200
        headers = {}

        def json(self):
            return {"matches": []}

        def raise_for_status(self):
            return None

    class Client:
        def __init__(self, **kwargs):
            assert kwargs == {"timeout": 5.0, "follow_redirects": False}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, params, json):
            requests.append((url, params, json))
            return Response()

    monkeypatch.setattr(intel.httpx, "Client", Client)
    origin_with_path = "https://example.com/pay?token=private"
    first = intel.query_google_safe_browsing(origin_with_path)
    second = intel.query_google_safe_browsing(origin_with_path)

    assert first["status"] == "completed" and first["is_malicious"] is False
    assert second["cached"] is True
    assert len(requests) == 1
    assert requests[0][2]["threatInfo"]["threatEntries"] == [{"url": "https://example.com"}]
    assert "token=private" not in str(requests[0])


def test_provider_429_is_retried_once_then_returns_rate_limited(monkeypatch):
    intel.clear_cache()
    monkeypatch.setattr(intel.settings, "virustotal_api_key", "test-vt-key")
    delays = []
    calls = []

    class Response:
        status_code = 429
        headers = {"Retry-After": "30"}

        def raise_for_status(self):
            return None

        def json(self):
            return {}

    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url, headers):
            calls.append((url, headers))
            return Response()

    monkeypatch.setattr(intel.httpx, "Client", Client)
    monkeypatch.setattr(intel.time, "sleep", delays.append)
    result = intel.query_virustotal("https://example.com/path?private=1")

    assert result["status"] == "unavailable"
    assert result["reason"] == "rate_limited"
    assert result["retry_count"] == 1
    assert len(calls) == 2
    assert delays == [intel._MAX_RETRY_AFTER_SECONDS]
    assert all("example.com" not in url for url, _ in calls)


def test_provider_timeout_retries_once_and_returns_unavailable(monkeypatch):
    intel.clear_cache()
    monkeypatch.setattr(intel.settings, "google_safe_browsing_key", "test-google-key")
    calls = []

    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, *args, **kwargs):
            calls.append(1)
            raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(intel.httpx, "Client", Client)
    result = intel.query_google_safe_browsing("https://example.com")

    assert result["status"] == "unavailable"
    assert result["reason"] == "timed_out"
    assert result["retry_count"] == 1
    assert len(calls) == 2


def test_virustotal_known_threat_response_is_parsed_from_origin_only(monkeypatch):
    import base64
    intel.clear_cache()
    monkeypatch.setattr(intel.settings, "virustotal_api_key", "test-vt-key")
    requests = []

    class Response:
        status_code = 200
        headers = {}

        def json(self):
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 2}}}}

        def raise_for_status(self):
            return None

    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url, headers):
            requests.append((url, headers))
            return Response()

    monkeypatch.setattr(intel.httpx, "Client", Client)
    result = intel.query_virustotal("https://example.com/private?account=123")
    encoded_origin = requests[0][0].rsplit("/", 1)[-1]

    assert base64.urlsafe_b64decode(encoded_origin + "==").decode() == "https://example.com"
    assert requests[0][1] == {"x-apikey": "test-vt-key"}
    assert result["status"] == "completed"
    assert result["is_malicious"] is True


def test_dns_failure_is_unavailable_and_skips_provider_lookups(monkeypatch):
    monkeypatch.setattr(main, "validate_target", lambda _: (_ for _ in ()).throw(FetchUnavailable("dns_resolution_failed")))
    monkeypatch.setattr(main, "check_reputation", lambda _: (_ for _ in ()).throw(AssertionError("unvalidated target must not be queried")))

    result = main.scan_url("https://lookup-failed.example")

    assert result["status"] == "unavailable"
    assert result["reason"] == "dns_resolution_failed"
    assert all(item["status"] == "unavailable" for item in result["threat_intel_results"])


def test_analyze_endpoint_accepts_legitimate_multi_address_dns(monkeypatch):
    addresses = [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
        "149.112.112.112", "93.184.216.34", "208.67.222.222", "208.67.220.220",
    ]
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))
        for address in addresses
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda hostname, port, type: records)
    monkeypatch.setattr(
        main,
        "safe_fetch",
        lambda _url, method, **kwargs: SafeFetchResult(
            "completed", "https://many-addresses.example", 200, "text/html", 0, False, 0
        ),
    )

    with TestClient(main.app) as client:
        response = client.post("/analyze", json={"url": "https://many-addresses.example/"})

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert response.json()["origin"] == "https://many-addresses.example"


def test_analyze_endpoint_blocks_mixed_public_private_dns_answers(monkeypatch):
    addresses = [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
        "149.112.112.112", "93.184.216.34", "208.67.222.222", "208.67.220.220",
        "169.254.169.254",
    ]
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))
        for address in addresses
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda hostname, port, type: records)
    monkeypatch.setattr(
        main,
        "safe_fetch",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("blocked DNS target must not be fetched")),
    )

    with TestClient(main.app) as client:
        response = client.post("/analyze", json={"url": "https://mixed-addresses.example/"})

    assert response.status_code == 200
    assert response.json()["status"] == "blocked"
    assert response.json()["reason"] == "dns_returned_non_public_address"


def test_scanner_blocks_private_targets_without_calling_reputation(monkeypatch):
    monkeypatch.setattr(main, "check_reputation", lambda _: (_ for _ in ()).throw(AssertionError("must not query reputation")))

    result = main.scan_url("http://127.0.0.1/admin")

    assert result["status"] == "blocked"
    assert result["reason"] == "non_public_address"
    assert all(item["status"] == "unavailable" for item in result["threat_intel_results"])


def test_scanner_falls_back_to_capped_get_when_head_is_unsupported(monkeypatch):
    target = type("Target", (), {"origin": "https://example.com"})()
    calls = []
    monkeypatch.setattr(main, "validate_target", lambda _: target)

    def fake_fetch(url, method, **kwargs):
        calls.append((method, kwargs))
        if method == "HEAD":
            return SafeFetchResult("completed", target.origin, 405, "text/plain", 0, False, 0)
        return SafeFetchResult("completed", target.origin, 200, "text/html", 65536, True, 0)

    monkeypatch.setattr(main, "safe_fetch", fake_fetch)
    monkeypatch.setattr(main, "check_reputation", lambda _: [
        {"provider": "google_safe_browsing", "status": "unavailable", "is_malicious": None},
        {"provider": "virustotal", "status": "unavailable", "is_malicious": None},
    ])

    result = main.scan_url("https://example.com/path?query=private")

    assert calls[0][0] == "HEAD"
    assert calls[1] == ("GET", {"max_bytes": main.MAX_BODY_BYTES})
    assert result["fetch"]["body_bytes"] == 65536
    assert result["fetch"]["body_truncated"] is True
    assert "body" not in result["fetch"]


@pytest.mark.parametrize("content_type,content_length", [("application/pdf", 100), ("text/html", 100_000)])
def test_scanner_never_gets_binary_or_oversize_content(monkeypatch, content_type, content_length):
    target = type("Target", (), {"origin": "https://example.com"})()
    calls = []
    monkeypatch.setattr(main, "validate_target", lambda _: target)
    monkeypatch.setattr(main, "safe_fetch", lambda url, method, **kwargs: (
        calls.append(method) or SafeFetchResult("completed", target.origin, 405, content_type, 0, False, 0, content_length)
    ))
    monkeypatch.setattr(intel, "check_reputation", lambda _: [])

    result = main.scan_url("https://example.com/file")

    assert calls == ["HEAD"]
    assert result["status"] == "unavailable"
    assert result["fetch"]["status"] == "head_unsupported"


def test_redirect_guard_failure_skips_provider_queries(monkeypatch):
    target = type("Target", (), {"origin": "https://example.com"})()
    monkeypatch.setattr(main, "validate_target", lambda _: target)
    monkeypatch.setattr(main, "safe_fetch", lambda *args, **kwargs: (_ for _ in ()).throw(SSRFBlocked("non_public_address")))
    monkeypatch.setattr(main, "check_reputation", lambda _: (_ for _ in ()).throw(AssertionError("must not query reputation")))

    result = main.scan_url("https://example.com/start")

    assert result["status"] == "blocked"
    assert result["reason"] == "non_public_address"


def test_scanner_service_rate_limits_requests_from_one_client():
    from url_scanner.main import ScannerRateLimitMiddleware, app

    with TestClient(app) as client:
        layer = app.middleware_stack
        guard = None
        while layer is not None:
            if isinstance(layer, ScannerRateLimitMiddleware):
                guard = layer
                break
            layer = getattr(layer, "app", None)
        if guard:
            guard._events.clear()
        statuses = [client.post("/scan", json={"url": "http://127.0.0.1/"}).status_code for _ in range(31)]
    assert statuses[:30] == [200] * 30
    assert statuses[30] == 429

def test_analyze_endpoint_does_not_query_reputation_providers(monkeypatch):
    target = type("Target", (), {"origin": "https://example.com"})()
    monkeypatch.setattr(main, "validate_target", lambda _: target)
    monkeypatch.setattr(
        main,
        "safe_fetch",
        lambda _url, method, **kwargs: SafeFetchResult("completed", target.origin, 200, "text/html", 0, False, 0),
    )
    monkeypatch.setattr(
        main,
        "check_reputation",
        lambda _: (_ for _ in ()).throw(AssertionError("analysis node must not query reputation")),
    )

    result = main.analyze(main.ScanRequest(url="https://example.com/"))

    assert result["status"] == "completed"
    assert result["origin"] == target.origin
    assert result["threat_intel_results"] == []


def test_reputation_endpoint_revalidates_before_provider_lookup(monkeypatch):
    target = type("Target", (), {"origin": "https://example.com"})()
    queried = []
    monkeypatch.setattr(main, "validate_target", lambda url: target)
    monkeypatch.setattr(main, "check_reputation", lambda origin: (
        queried.append(origin) or [{"provider": "google_safe_browsing", "status": "unavailable", "is_malicious": None}]
    ))

    result = main.reputation(main.ScanRequest(url="https://example.com/"))

    assert queried == [target.origin]
    assert result["status"] == "completed"
    assert result["threat_intel_results"][0]["status"] == "unavailable"


def test_reputation_endpoint_accepts_public_ipv4_with_ipv6_unspecified_answer(monkeypatch):
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("20.193.173.92", 80)),
        (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::", 80, 0, 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda hostname, port, type: records)
    monkeypatch.setattr(main, "check_reputation", lambda origin: [
        {"provider": "google_safe_browsing", "status": "completed", "is_malicious": False, "reason": "no_known_threat"},
    ])

    with TestClient(main.app) as client:
        clear_scanner_rate_limit_events()
        response = client.post("/reputation", json={"url": "http://testsafebrowsing.appspot.com/"})

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert response.json()["origin"] == "http://testsafebrowsing.appspot.com"
    assert response.json()["threat_intel_results"][0]["status"] == "completed"


def test_reputation_endpoint_rejects_only_ipv6_unspecified_answer(monkeypatch):
    records = [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::", 80, 0, 0))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda hostname, port, type: records)
    monkeypatch.setattr(
        main,
        "check_reputation",
        lambda _origin: (_ for _ in ()).throw(AssertionError("no usable public DNS address must not be queried")),
    )

    with TestClient(main.app) as client:
        clear_scanner_rate_limit_events()
        response = client.post("/reputation", json={"url": "http://unspecified-only.example/"})

    assert response.status_code == 200
    assert response.json()["status"] == "blocked"
    assert response.json()["reason"] == "dns_no_usable_addresses"


def test_reputation_endpoint_blocks_public_private_dns_mix(monkeypatch):
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("20.193.173.92", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.168.1.20", 80)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda hostname, port, type: records)
    monkeypatch.setattr(
        main,
        "check_reputation",
        lambda _origin: (_ for _ in ()).throw(AssertionError("mixed DNS answers must not reach providers")),
    )

    with TestClient(main.app) as client:
        clear_scanner_rate_limit_events()
        response = client.post("/reputation", json={"url": "http://mixed-public-private.example/"})

    assert response.status_code == 200
    assert response.json()["status"] == "blocked"
    assert response.json()["reason"] == "dns_returned_non_public_address"


def test_reputation_endpoint_blocks_private_target_before_provider_lookup(monkeypatch):
    monkeypatch.setattr(
        main,
        "validate_target",
        lambda _url: (_ for _ in ()).throw(SSRFBlocked("non_public_address")),
    )
    monkeypatch.setattr(
        main,
        "check_reputation",
        lambda _: (_ for _ in ()).throw(AssertionError("private target must not be queried")),
    )

    result = main.reputation(main.ScanRequest(url="http://127.0.0.1/"))

    assert result["status"] == "blocked"
    assert all(item["status"] == "unavailable" for item in result["threat_intel_results"])
