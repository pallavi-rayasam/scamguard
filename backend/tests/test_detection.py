import pytest

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


def test_classification_leaves_unmatched_harmless_text_uncategorized():
    result = classify_message("Hi, are we meeting at 5pm?")
    assert result["category"] is None
    assert result["findings"] == []


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


SCAM_REGRESSIONS = [
    (
        "prize-claim-pressure",
        "URGENT This is our 2nd attempt to contact U. Your £900 prize from YESTERDAY is still awaiting collection. To claim CALL NOW",
        "lottery_fraud",
        {"prize_won", "claim_collect", "call_now", "urgency"},
    ),
    (
        "customs-fee-link",
        "Your parcel is held at customs. Pay Rs 1200 clearance fee at the link to release it.",
        "courier_scam",
        {"parcel_courier", "authority_customs", "pay_penalty_fee", "off_platform_link"},
    ),
    (
        "prohibited-item-police-penalty",
        "Your parcel contains a prohibited item. Pay a penalty now or police will arrest you.",
        "courier_scam",
        {"parcel_courier", "prohibited_illegal", "pay_penalty_fee", "authority_customs", "coercive_threat"},
    ),
]


@pytest.mark.parametrize("name,message,category,signals", SCAM_REGRESSIONS, ids=[case[0] for case in SCAM_REGRESSIONS])
def test_signal_family_scam_regressions_are_categorized_and_explain_signals(name, message, category, signals):
    result = classify_message(message)
    score, level, _ = score_findings(result["findings"])

    assert result["category"] == category
    assert signals <= set(result["matched_signals"])
    assert score >= 50
    assert level == "High"
    assert any(f"Combined signals" in item["detail"] for item in result["findings"])


@pytest.mark.parametrize(
    "message,expected_level,expected_score",
    [
        ("Prize winner: claim your reward, CALL NOW.", "Moderate", 25),
        ("Prize winner: claim your reward, CALL NOW, use the link to collect.", "High", 50),
    ],
    ids=["two-strong-signals-moderate", "three-strong-signals-high"],
)
def test_combination_strength_controls_score(message, expected_level, expected_score):
    result = classify_message(message)
    score, level, _ = score_findings(result["findings"])

    assert result["category"] == "lottery_fraud"
    assert score == expected_score
    assert level == expected_level


LEGITIMATE_LOOKALIKES = [
    pytest.param("Congratulations, your bookstore raffle prize is ready. Collect it at the service desk before 30 June. No fee is due.", id="legit-prize-service-desk"),
    pytest.param("You won 500 reward points in our loyalty app. Redeem them in the app whenever convenient; no calls or fees.", id="legit-loyalty-reward"),
    pytest.param("Competition winner announcement: your prize is reserved for pickup in our office. Customer support hours are on our website.", id="legit-competition-pickup"),
    pytest.param("The library summer reading prize can be collected from the front desk during opening hours.", id="legit-library-prize"),
    pytest.param("Your bank rewards coupon is available in the verified mobile app; there is no fee and no need to call anyone.", id="legit-bank-reward"),
    pytest.param("Courier update: your parcel is undergoing routine customs review; no payment or further action is required.", id="legit-customs-review-no-fee"),
    pytest.param("Your parcel clearance fee was already paid at checkout; track it in our official app.", id="legit-parcel-fee-already-paid"),
    pytest.param("The customs clearance charge for this shipment has been waived. Delivery will continue tomorrow.", id="legit-customs-fee-waived"),
    pytest.param("Your parcel is at customs; use the official carrier tracking app to follow its progress. No fee is due.", id="legit-customs-tracking"),
    pytest.param("Shipping and customs charges were included in your order total. Your courier parcel is on its way.", id="legit-customs-prepaid"),
    pytest.param("Courier policy: prohibited items are returned to sender at no charge; police are not involved.", id="legit-prohibited-return-policy"),
    pytest.param("Customs guidance says restricted items may be held for review and returned without a penalty.", id="legit-restricted-item-guidance"),
    pytest.param("Delivery update: an item is not allowed under carrier policy, so the parcel will be returned. No payment is requested.", id="legit-carrier-return"),
    pytest.param("The courier explained that illegal goods are referred for review only when required by law; this notice asks for no payment.", id="legit-courier-policy-notice"),
    pytest.param("Your package was delayed for prohibited-item review. The inspection charge is covered by the sender.", id="legit-covered-review"),
    pytest.param("Reminder: your electricity bill of Rs 1200 is due on 15 July. Pay it through the utility's official app.", id="legit-bill-reminder"),
    pytest.param("Bank alert: a debit of Rs 850 at the grocery store was approved. Contact us through the number on your card if this was not you.", id="legit-bank-transaction-alert"),
    pytest.param("Your verification code is 482913. Do not share this code with anyone, including bank staff.", id="legit-otp-do-not-share-after"),
    pytest.param("Do not share the OTP with anyone. Your bank will never ask you to send it by phone or message.", id="legit-otp-do-not-share-before"),
    pytest.param("Your mobile bill payment is due next week; view the statement in the provider app. No action is needed today.", id="legit-mobile-bill-reminder"),
]


@pytest.mark.parametrize("message", LEGITIMATE_LOOKALIKES)
def test_legitimate_signal_lookalikes_remain_low_and_uncategorized(message):
    result = classify_message(message)
    score, level, _ = score_findings(result["findings"])

    assert level == "Low", (message, score, result["findings"])
    assert result["category"] is None, (message, result["findings"])
