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
    if category == "loan_scam":
        assert "upfront_job_fee" not in result["matched_signals"]
    assert score >= 50
    assert level == "High"
    assert any(f"Combined signals" in item["detail"] for item in result["findings"])


@pytest.mark.parametrize(
    "message,expected_level,expected_score",
    [
        ("Prize winner: claim your reward, CALL NOW.", "Moderate", 30),
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


KYC_PHISHING_MESSAGE = (
    "Your bank KYC is incomplete and your account will be restricted today. Verify immediately "
    "through the link below to avoid suspension: abcd.com . Do not delay."
)


def test_kyc_phishing_regression_explains_each_score_contribution():
    result = classify_message(KYC_PHISHING_MESSAGE)
    score, level, scored_findings = score_findings(result["findings"])
    weights = {finding["indicator"]: finding["score_weight"] for finding in scored_findings}

    assert result["category"] == "fake_kyc"
    assert {"kyc_verification", "account_restriction", "verify_link", "bank_government_claim", "unverified_domain", "urgency"} <= set(result["matched_signals"])
    assert weights["urgent_threat"] == 18
    assert weights["signal_combination:fake_kyc"] == 30
    assert weights["unverified_domain_urgency"] == 0
    assert weights["unverified_bank_domain"] == 8
    assert score == 56
    assert level in {"Moderate", "High"}


def test_kyc_restriction_and_link_alone_reach_moderate():
    result = classify_message("KYC verification is incomplete. Your account will be restricted. Verify through this link: notice.example.org")
    score, level, _ = score_findings(result["findings"])

    assert result["category"] == "fake_kyc"
    assert score >= 25
    assert level == "Moderate"


def test_unverified_domain_and_urgency_combo_has_a_thirty_point_floor():
    result = classify_message("Urgent: check abcd.com today for your delivery update.")
    score, level, scored_findings = score_findings(result["findings"])

    assert {"unverified_domain", "urgency"} <= set(result["matched_signals"])
    assert next(item for item in scored_findings if item["indicator"] == "unverified_domain_urgency")["score_weight"] == 30
    assert score == 30
    assert level == "Moderate"


KYC_LEGITIMATE_LOOKALIKES = [
    pytest.param(
        "Security notice from your bank: we will never send links. Do not click links; open the banking app directly to review your account.",
        id="bank-says-do-not-click-links",
    ),
    pytest.param(
        "Reminder: please update your KYC at a branch or in the official app by 30 June. Your account remains active and unrestricted.",
        id="genuine-kyc-no-link-no-threat",
    ),
    pytest.param(
        "Your monthly bank statement is ready in the official mobile app. No verification is needed and your account access is unchanged.",
        id="statement-ready-notice",
    ),
    pytest.param(
        "Your bank KYC record was refreshed; no action is needed. Do not reply to this message.",
        id="kyc-record-refreshed",
    ),
    pytest.param(
        "Annual identity review reminder: bring your documents to a branch if needed. We will not send a web link or restrict account access.",
        id="annual-identity-review-in-branch",
    ),
]


@pytest.mark.parametrize("message", KYC_LEGITIMATE_LOOKALIKES)
def test_genuine_kyc_and_bank_lookalikes_remain_low(message):
    result = classify_message(message)
    score, level, _ = score_findings(result["findings"])

    assert level == "Low", (message, score, result["findings"])
    assert result["category"] is None, (message, result["findings"])


ADDITIONAL_SCAM_REGRESSIONS = [
    pytest.param(
        "This is an urgent notice from the cyber investigation department. Your identity has been linked to a criminal case. Stay on this call and follow our instructions or a warrant will be issued.",
        "digital_arrest",
        {"authority_investigation", "criminal_case_claim", "stay_on_call", "warrant_threat"},
        id="cyber-investigation-stay-on-call-warrant",
    ),
    pytest.param(
        "Congratulations! You have been shortlisted for a work-from-home position with a salary of Rs. 45,000 per month. Pay a refundable registration fee of Rs. 1,499 today to confirm your offer.",
        "job_fraud",
        {"job_offer", "salary_offer", "upfront_job_fee", "pay_penalty_fee"},
        id="shortlisted-work-from-home-refundable-fee",
    ),
    pytest.param(
        "Your electricity connection will be disconnected tonight because of an unpaid bill. Call 1234567895 immediately and complete the payment to prevent disconnection.",
        "electricity_bill_scam",
        {"utility_service", "utility_disconnection", "call_now", "pay_penalty_fee", "urgency"},
        id="electricity-disconnection-call-payment",
    ),
    pytest.param(
        "You are pre-approved for an instant loan without documents. Install SmartWQ, allow access to your contacts, photos, and messages, and pay a processing charge to release the amount.",
        "loan_scam",
        {"loan_offer", "loan_app_install", "sensitive_app_permissions", "loan_processing_charge", "pay_penalty_fee"},
        id="preapproved-loan-app-invasive-permissions-charge",
    ),
]


@pytest.mark.parametrize("message,category,signals", ADDITIONAL_SCAM_REGRESSIONS)
def test_additional_scam_families_trigger_a_strong_combination(message, category, signals):
    result = classify_message(message)
    score, level, scored_findings = score_findings(result["findings"])

    assert result["category"] == category
    assert signals <= set(result["matched_signals"])
    assert score >= 30
    assert level in {"Moderate", "High"}
    assert any(item["indicator"] == f"signal_combination:{category}" for item in scored_findings)


ADDITIONAL_LEGITIMATE_LOOKALIKES = [
    pytest.param("Police-station notice: submit a copy of the FIR at reception by appointment. No payment or phone call is required.", id="police-station-fir-filing"),
    pytest.param("Your police complaint has been recorded. Visit the station desk during public hours; official updates are posted at reception.", id="police-complaint-receipt"),
    pytest.param("A warrant was served through the court; bring identification to the listed hearing. No payment or call is requested.", id="court-warrant-hearing-notice"),
    pytest.param("The cyber investigation department posted its office hours and case lookup instructions. Visit the office for assistance.", id="cyber-office-hours"),
    pytest.param("Police station public notice: file copies are available at the front desk. Report concerns in person; no payment is due.", id="police-station-document-collection"),
    pytest.param("Shortlisted for a position with a salary of Rs. 45,000 per month. The written offer is attached; no registration or training fee is charged.", id="genuine-shortlist-no-fee"),
    pytest.param("Your work-from-home interview is scheduled for Friday. The salary range is in the role description; no payment is required at any stage.", id="genuine-work-from-home-interview"),
    pytest.param("Official job offer: annual salary and start date are listed in the signed letter. Payroll onboarding begins after hiring; no refundable deposit is requested.", id="signed-job-offer-no-deposit"),
    pytest.param("Shortlisted candidate: please attend an interview to discuss the monthly salary and benefits. There is no application fee.", id="interview-and-salary-no-fee"),
    pytest.param("The employer confirms your selection, monthly pay, and start date. No application, registration, training fee, or refundable deposit is charged.", id="employer-selection-no-upfront-fee"),
    pytest.param("Your electricity bill is due today. Pay through the utility's official app; service will not be disconnected before the due date.", id="utility-bill-due-no-disconnection-threat"),
    pytest.param("Gas bill reminder: please pay by the date on your statement in the official app. Your service continues normally.", id="gas-bill-reminder"),
    pytest.param("Water account statement is ready. Payment has been received and no disconnection is planned.", id="water-payment-received"),
    pytest.param("Electricity meter reading is scheduled for next week. No bill is due yet and service remains active.", id="electricity-meter-reading"),
    pytest.param("Autopay confirmation: your electricity payment was processed. We will not disconnect service; view the receipt in the utility app.", id="utility-autopay-confirmed"),
    pytest.param("A pre-approved personal loan offer is available in the bank app. Review the terms; no fee is requested and no extra app needs to be installed.", id="bank-preapproved-loan-no-fee"),
    pytest.param("Official loan app notice: the app never requests access to contacts, photos, or messages. Review your application in the bank's established app.", id="official-loan-app-permission-notice"),
    pytest.param("Your instant loan application is under review; check status in the official app. No document-access permission or processing fee is needed.", id="loan-status-no-permission-fee"),
    pytest.param("Install the official bank app for statements. It does not request contact or message permissions; your existing loan account is unchanged.", id="bank-app-install-no-invasive-permission"),
    pytest.param("Pre-approved loan status: your bank has approved the application. Accept in its established app; no processing or release fee is charged.", id="loan-approved-official-app-no-release-fee"),
    pytest.param("Reminder: your bank account statement is ready. View it in the official app; no call, payment, or access change is required.", id="bank-statement-reminder"),
    pytest.param("Utility notice: your electricity account remains active. The bill and due date are available in the official customer portal.", id="electricity-account-active"),
]


@pytest.mark.parametrize("message", ADDITIONAL_LEGITIMATE_LOOKALIKES)
def test_additional_genuine_lookalikes_remain_low_and_uncategorized(message):
    result = classify_message(message)
    score, level, _ = score_findings(result["findings"])

    assert level == "Low", (message, score, result["findings"])
    assert result["category"] is None, (message, result["findings"])
