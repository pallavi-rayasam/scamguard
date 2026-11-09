from datetime import datetime, timezone
from io import BytesIO

import pytest
from pypdf import PdfReader

from app.reports.pdf import build_investigation_pdf, resolve_report_time_zone


CREATED_AT = datetime(2026, 11, 7, 14, 14, tzinfo=timezone.utc)


def pdf_text(report: dict, time_zone: str | None = "UTC") -> str:
    pdf = build_investigation_pdf(report, CREATED_AT, time_zone)
    assert pdf.startswith(b"%PDF-")
    return "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(pdf)).pages)


@pytest.mark.parametrize(
    ("time_zone", "timestamp"),
    [
        ("Asia/Kolkata", "2026-11-07 19:44:00 IST"),
        ("Asia/Calcutta", "2026-11-07 19:44:00 IST"),
        ("UTC", "2026-11-07 14:14:00 UTC"),
        ("America/New_York", "2026-11-07 09:14:00 EST"),
    ],
)
def test_pdf_preserves_the_instant_and_formats_valid_iana_zones(time_zone, timestamp):
    text = pdf_text({}, time_zone)
    assert timestamp in text
    assert f"Times shown in {time_zone}." in text
    assert CREATED_AT == datetime(2026, 11, 7, 14, 14, tzinfo=timezone.utc)


@pytest.mark.parametrize("time_zone", [None, "", "Not/AZone"])
def test_missing_empty_and_invalid_zones_fall_back_to_utc_without_blocking_pdf(time_zone):
    resolved, used_fallback = resolve_report_time_zone(time_zone)
    assert (resolved, used_fallback) == ("UTC", True)
    text = pdf_text({}, time_zone)
    assert "2026-11-07 14:14:00 UTC" in text
    assert "Times shown in UTC." in text


def test_pdf_contains_report_details_and_tolerates_missing_optional_data():
    report = {
        "risk_score": 51,
        "risk_level": "Moderate",
        "category": "fake_kyc",
        "findings": [{"indicator": "kyc_pressure", "verification_level": "heuristic", "detail": "Account restricted today."}],
        "evidence": [{"source": "message", "verification_level": "verified", "timestamp": "not-a-timestamp", "detail": "Verified deterministic check."}],
        "urls": ["https://example.test/path"],
        "url_scans": [{"origin": "https://example.test/path", "status": "completed"}],
        "threat_intel_results": [{"provider": "Safe Browsing", "status": "completed", "is_malicious": False, "detail": "No match."}],
        "agents": [{"agent_name": "RiskAssessment", "status": "completed", "duration_ms": 12, "tools_used": []}],
        "explanation": "The message threatens account restrictions.",
        "explanation_source": "deterministic_fallback",
        "recommendations": ["Use the official bank app."],
        "limitations": ["No external threat was verified."],
        "ml_prediction": {
            "status": "completed", "predicted_class": "scam", "model_version": "message-text-v1",
            "calibrated_probability": None, "calibration_status": "not_justified",
        },
    }
    text = pdf_text(report, "UTC")
    for expected in (
        "Moderate", "fake_kyc", "kyc_pressure", "Verified deterministic check.",
        "Timestamp unavailable", "The message threatens account restrictions.",
        "deterministic fallback", "Safe Browsing", "no known threat found; not verified safe",
        "message-text-v1", "Use the official bank app.", "No external threat was verified.",
    ):
        assert expected in text

    sparse_text = pdf_text({"findings": None, "evidence": None, "urls": None, "url_scans": None,
                            "threat_intel_results": None, "agents": None, "recommendations": None,
                            "limitations": None, "explanation": None, "ml_prediction": None}, "UTC")
    assert "No indicators were recorded." in sparse_text
    assert "No provider results were recorded." in sparse_text
