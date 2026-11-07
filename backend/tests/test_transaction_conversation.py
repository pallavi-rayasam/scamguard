import pytest

from app.detection.conversation import analyze_conversation
from app.detection.transaction import assess_pre_transaction


SCAM_TRANSACTIONS = [
    ("advance-fee-job", "Congratulations, you got the job. Pay a registration fee before the offer letter.", "advance_fee_job_fraud"),
    ("interview-processing-fee", "Transfer the processing fee to confirm your interview slot.", "advance_fee_job_fraud"),
    ("placement-security-deposit", "Deposit a security amount to secure this placement.", "advance_fee_job_fraud"),
    ("training-fee-before-joining", "Pay the training fee before joining the company.", "advance_fee_job_fraud"),
    ("job-advance-fee", "Send an advance fee to release the salary for this new job.", "advance_fee_job_fraud"),
    ("upi-collect-request", "Approve the UPI collect request to receive your refund.", "upi_collect_request"),
    ("collect-request", "A collect request is waiting. Accept it to receive the parcel refund.", "upi_collect_request"),
    ("digital-arrest", "You are under digital arrest. Transfer money now to avoid custody.", "digital_arrest_payment"),
    ("cbi-arrest-threat", "A CBI officer says pay now or an arrest warrant will be issued.", "digital_arrest_payment"),
    ("police-payment-threat", "Police will arrest you unless you pay the settlement immediately.", "digital_arrest_payment"),
    ("otp-for-refund", "Send me your OTP to process the refund.", "credential_harvest_request"),
    ("upi-pin-for-credit", "Tell me your UPI PIN so I can credit your account.", "credential_harvest_request"),
    ("verification-code-for-courier", "Forward the verification code to release the courier.", "credential_harvest_request"),
    ("urgent-account-block", "Transfer the amount immediately or your bank account will be blocked.", "coercive_payment_pressure"),
    ("prize-release-pressure", "Pay the release charge today only to receive your prize.", "coercive_payment_pressure"),
]

LEGITIMATE_TRANSACTIONS = [
    ("normal-job-offer", "Your job offer is attached. No registration or training fee is required.", ""),
    ("job-posting-no-fee", "We never charge applicants a placement fee.", ""),
    ("genuine-bank-otp", "Your bank login OTP is 482913. Do not share it with anyone.", ""),
    ("bank-debit-notice", "INR 450 was debited from your account at a grocery store.", ""),
    ("electricity-bill", "Your electricity bill is due next week. Pay through the official app when convenient.", ""),
    ("monthly-rent", "Monthly rent is due on the fifth. Please use the usual bank transfer.", ""),
    ("known-shop-collect", "The shop sent a UPI collect request for my lunch. I checked the order and paid INR 240.", "upi_collect_request"),
    ("upi-transfer-complete", "Your UPI transfer of INR 900 to the saved contact was successful.", ""),
    ("courier-tracking", "Your courier parcel will arrive between 2 and 5 pm. Track it in the official app.", ""),
    ("salary-credit", "Salary was credited to your account today.", ""),
    ("grocery-invoice", "The supermarket invoice for your purchase is ready.", ""),
    ("tuition-portal", "The school fee invoice is available in the official parent portal.", ""),
    ("bank-refund", "Your bank refund has been initiated. It will appear in your account in three days.", ""),
    ("insurance-reminder", "Your insurance premium is due in ten days. Use the insurer's official app.", ""),
    ("colleague-expense", "I paid for the shared cab. Your share is INR 180, whenever convenient.", ""),
]


@pytest.mark.parametrize("case,text,expected_indicator", SCAM_TRANSACTIONS, ids=[case[0] for case in SCAM_TRANSACTIONS])
def test_pre_transaction_scam_examples_raise_the_expected_heuristic(case, text, expected_indicator):
    result = assess_pre_transaction(
        description=text,
        claimed_recipient="Unverified contact",
        reason="Payment request",
        amount=2500,
    )
    assert expected_indicator in {item["indicator"] for item in result["findings"]}
    assert result["risk_score"] > 0
    assert result["advisory_only"] is True


@pytest.mark.parametrize("case,text,expected_indicator", LEGITIMATE_TRANSACTIONS, ids=[case[0] for case in LEGITIMATE_TRANSACTIONS])
def test_pre_transaction_legitimate_examples_remain_advisory(case, text, expected_indicator):
    result = assess_pre_transaction(
        description=text,
        claimed_recipient="Known merchant",
        reason="Routine payment",
        amount=250,
    )
    indicators = {item["indicator"] for item in result["findings"]}
    if expected_indicator:
        assert expected_indicator in indicators
    else:
        assert not indicators
    assert result["risk_level"] in {"Low", "Moderate"}
    assert result["recipient_identity_check"] == "not_performed"
    assert result["payment_initiated"] is False
    assert "does not verify account-holder identity" in result["advisory"]


SCAM_CONVERSATIONS = [
    ("repeated-job-payment", ["Please pay the registration fee now.", "Transfer it today to secure the job."], "repeated_payment_requests"),
    ("repeated-upi-collect", ["I sent the UPI collect request.", "Please approve the UPI collect request."], "repeated_payment_requests"),
    ("bank-otp-theft", ["I am from bank support. Send me your OTP."], "credential_request"),
    ("upi-pin-theft", ["Tell me your UPI PIN to receive the refund."], "credential_request"),
    ("forward-code", ["Forward the one-time password to verify the parcel."], "credential_request"),
    ("rising-deadline-pressure", ["Please verify the case.", "Act urgently today.", "Pay immediately or the account will be blocked."], "escalating_pressure"),
    ("bank-to-cbi-identity-switch", ["I am from SBI bank support.", "I am a CBI officer and will arrest you."], "inconsistent_identity_claims"),
    ("repeated-money-demands", ["Please send money to this UPI ID.", "Send the amount now to release the package."], "repeated_payment_requests"),
    ("document-fee-loop", ["Pay the processing charge.", "Pay again for document clearance."], "repeated_payment_requests"),
    ("verification-code-question", ["What is your verification code?"], "credential_request"),
    ("account-threat-escalates", ["There is an account issue.", "Your account may be blocked.", "Police will arrest you unless you pay."], "escalating_pressure"),
    ("personal-account-deposit", ["Kindly deposit the fee.", "Transfer the fee to my personal account."], "repeated_payment_requests"),
    ("courier-to-bank-identity-switch", ["I am from the courier team.", "I am from bank support; send your OTP."], "inconsistent_identity_claims"),
    ("urgent-pin-request", ["Tell me your UPI PIN immediately or lose the refund."], "credential_request"),
    ("repeated-payment-and-threat", ["Pay the clearance fee now.", "Transfer more money immediately or face legal action."], "repeated_payment_requests"),
]

LEGITIMATE_CONVERSATIONS = [
    ("bank-otp-do-not-share", ["Bank: Your login OTP is 482913. Do not share it with anyone."], ""),
    ("bank-debit-alert", ["Bank: INR 450 was debited at the grocery store."], ""),
    ("courier-delivery-update", ["Courier: Your parcel will arrive between 2 and 5 pm."], ""),
    ("official-bank-safety-note", ["Bank: We will never ask you to share an OTP or PIN."], ""),
    ("job-offer-no-fee", ["HR: Your offer letter is ready. We do not charge applicants any fee."], ""),
    ("family-lunch-split", ["Ravi: I paid for lunch. Your share is INR 200 whenever convenient."], ""),
    ("single-merchant-payment", ["Shop: Please pay INR 250 at the counter when you collect the order."], ""),
    ("insurance-due-date", ["Insurer: Your premium is due in ten days. Use the official app."], ""),
    ("school-invoice", ["School: The invoice is posted in the parent portal."], ""),
    ("successful-upi-payment", ["Bank: Your UPI transfer to the saved contact succeeded."], ""),
    ("routine-invoice-reminder", ["Vendor: Please settle invoice 189 by Friday."], ""),    ("gentle-electricity-bill-reminder", ["Bank: Your electricity bill is due Friday.", "Bank: Friendly reminder: please pay through the official app when convenient."], ""),
    ("bill-reminder-paid", ["Bank: Your water bill is due next week.", "Bank: Your payment has been received. Thank you."], ""),
    ("courier-no-payment-needed", ["Courier: Delivery is scheduled for tomorrow. No action is needed."], ""),
    ("bank-role-consistent", ["Caller: I am from SBI support.", "Caller: I am calling from SBI about the service request."], ""),
    ("hospital-billing", ["Clinic: Your appointment is confirmed. The bill is available at reception."], ""),
    ("otp-security-reminder", ["Bank: Your OTP is 123456. Never disclose it to callers."], ""),
]


@pytest.mark.parametrize("case,texts,expected_indicator", SCAM_CONVERSATIONS, ids=[case[0] for case in SCAM_CONVERSATIONS])
def test_conversation_scam_examples_raise_the_expected_sequence_signal(case, texts, expected_indicator):
    result = analyze_conversation([{"sender": "caller", "text": text} for text in texts])
    assert expected_indicator in {item["indicator"] for item in result["findings"]}


@pytest.mark.parametrize("case,texts,expected_indicator", LEGITIMATE_CONVERSATIONS, ids=[case[0] for case in LEGITIMATE_CONVERSATIONS])
def test_conversation_legitimate_examples_avoid_high_risk_sequence_signals(case, texts, expected_indicator):
    messages = []
    for text in texts:
        sender, _, content = text.partition(":")
        messages.append({"sender": sender, "text": content.strip() if _ else text})
    indicators = {item["indicator"] for item in analyze_conversation(messages)["findings"]}
    assert not indicators.intersection({
        "credential_request",
        "repeated_payment_requests",
        "escalating_pressure",
        "inconsistent_identity_claims",
    })
    if expected_indicator:
        assert expected_indicator in indicators