from app.detection.normalize import extract_urls, redact_sensitive
from app.detection.rules import classify_message
from app.detection.scoring import risk_level, score_findings
from app.detection.url_checks import inspect_url


def test_sensitive_values_are_redacted_before_storage():
    redacted, labels = redact_sensitive("Share OTP 123456 and UPI PIN 4321")
    assert "123456" not in redacted
    assert "4321" not in redacted
    assert "otp" in labels
    assert "credential" in labels


def test_url_extraction_drops_paths_and_query_values():
    assert extract_urls("Check https://example.in/login?session=secret now") == ["https://example.in"]


def test_classification_uses_seeded_indian_scam_patterns():
    result = classify_message("Your KYC will expire. Complete KYC immediately or your account will be blocked.")
    assert result["category"] == "fake_kyc"
    assert result["findings"]


def test_weighted_score_thresholds_are_deterministic():
    findings = [
        {"indicator":"otp_request", "score_weight":32},
        {"indicator":"urgent_threat", "score_weight":18},
    ]
    score, level, _ = score_findings(findings)
    assert score == 50
    assert level == "High"
    assert risk_level(24) == "Low"
    assert risk_level(25) == "Moderate"
    assert risk_level(75) == "Critical"


def test_url_scanner_does_not_treat_http_as_safe():
    findings = inspect_url("http://unknown-example.in")
    assert any(item["indicator"] == "url_not_https" for item in findings)
