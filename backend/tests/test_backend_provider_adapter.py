import base64
from dataclasses import replace

import httpx
import pytest

from app.intel import providers


@pytest.mark.parametrize("provider", ["google_safe_browsing", "virustotal"])
def test_backend_provider_fallback_preserves_path_query_and_excludes_fragment(monkeypatch, caplog, provider):
    full_url = "https://fallback.example/account/verify?case=7&next=%2Fhome#client-fragment"
    lookup_url = "https://fallback.example/account/verify?case=7&next=%2Fhome"
    requests = []

    monkeypatch.setattr(
        providers,
        "settings",
        replace(
            providers.settings,
            google_safe_browsing_key="test-google-key",
            virustotal_api_key="test-vt-key",
        ),
    )

    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            if provider == "google_safe_browsing":
                return {"matches": []}
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}

    class Client:
        def __init__(self, **kwargs):
            assert kwargs == {"timeout": 5.0, "follow_redirects": False}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, endpoint, params, json):
            requests.append(json["threatInfo"]["threatEntries"][0]["url"])
            return Response()

        def get(self, endpoint, headers):
            encoded = endpoint.rsplit("/", 1)[-1]
            requests.append(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode())
            return Response()

    monkeypatch.setattr(providers.httpx, "Client", Client)
    query = (
        providers.query_google_safe_browsing
        if provider == "google_safe_browsing"
        else providers.query_virustotal
    )

    result = query(full_url)

    assert requests == [lookup_url]
    assert result["status"] == "completed"
    assert result["is_malicious"] is False
    assert "case=7" not in str(result)
    assert "test-google-key" not in caplog.text
    assert "test-vt-key" not in caplog.text
