"""Advisory-only pre-transaction scam indicators."""
from __future__ import annotations

import re

from app.detection.scoring import score_findings


_JOB_TERMS = re.compile(r"\b(?:job|employment|career|placement|interview|joining|recruitment|salary)\b", re.I)
_FEE_TERMS = re.compile(r"\b(?:registration|processing|security|training|joining|application|interview)\s+(?:fee|deposit|charge)\b|\bsecurity\s+amount\b|\badvance\s+fee\b", re.I)
_FEE_NEGATION = re.compile(r"\b(?:no|never|not|without|don't|do not)\b.{0,35}\b(?:fee|fees|deposit|charge)\b", re.I)
_COLLECT_REQUEST = re.compile(r"\b(?:upi\s+)?collect\s+request\b|\bapprove\s+(?:the\s+)?(?:upi\s+)?collect\b", re.I)
_DIGITAL_ARREST = re.compile(r"\bdigital arrest\b|\b(?:police|cbi|cyber cell|ed officer)\b.{0,70}\b(?:arrest|warrant|transfer|pay|freeze)\b", re.I)
_CREDENTIAL_REQUEST = re.compile(
    r"\b(?:share|send|tell|read|forward|give|provide|enter|confirm)\s+(?:me\s+)?"
    r"(?:your\s+|the\s+)?(?:otp|one[- ]time password|verification code|security code|upi pin|pin|password|passcode|cvv)\b",
    re.I,
)
_SAFE_CREDENTIAL_NOTICE = re.compile(
    r"\b(?:do not|don't|never|must not|should not)\s+(?:share|send|tell|forward|disclose)\b"
    r".{0,55}\b(?:otp|one[- ]time password|verification code|security code|upi pin|pin|password|passcode|cvv)\b",
    re.I,
)
_PAYMENT_TERMS = re.compile(r"\b(?:pay|payment|transfer|deposit|fee|collect request|money)\b", re.I)
_PRESSURE = re.compile(r"\b(?:immediately|right now|within\s+\d+\s+minutes?|last warning|arrest|warrant|account will be blocked|today only)\b", re.I)


def _finding(indicator: str, detail: str, weight: int) -> dict:
    return {
        "indicator": indicator,
        "detail": detail,
        "verification_level": "heuristic",
        "source": "pre_transaction_rules",
        "score_weight": weight,
    }


def assess_pre_transaction(
    *,
    description: str,
    claimed_recipient: str = "",
    reason: str = "",
    amount=None,
    related_chat: str = "",
) -> dict:
    """Score textual risk signals without checking recipient ownership or initiating payment."""
    text = " ".join(part for part in (description, reason, related_chat) if part).lower()
    findings: list[dict] = []

    fee_negated = bool(_FEE_NEGATION.search(text))
    if _JOB_TERMS.search(text) and _FEE_TERMS.search(text) and not fee_negated:
        findings.append(_finding(
            "advance_fee_job_fraud",
            "The request links a job, interview, or placement to an advance fee or deposit.",
            32,
        ))

    if _COLLECT_REQUEST.search(text):
        findings.append(_finding(
            "upi_collect_request",
            "The request mentions a UPI collect request; approving one can authorize a debit, so check the payee and amount in your UPI app.",
            18,
        ))

    if _DIGITAL_ARREST.search(text) and _PAYMENT_TERMS.search(text):
        findings.append(_finding(
            "digital_arrest_payment",
            "The message combines an authority or arrest threat with a request for payment or transfer.",
            36,
        ))

    credential_text = text
    for match in _SAFE_CREDENTIAL_NOTICE.finditer(credential_text):
        start, end = match.span()
        credential_text = credential_text[:start] + (" " * (end - start)) + credential_text[end:]
    if _CREDENTIAL_REQUEST.search(credential_text):
        findings.append(_finding(
            "credential_harvest_request",
            "The request asks for an OTP, PIN, password, or verification code.",
            32,
        ))

    if _PRESSURE.search(text) and _PAYMENT_TERMS.search(text):
        findings.append(_finding(
            "coercive_payment_pressure",
            "The payment request uses urgent deadlines, threats, or immediate pressure.",
            18,
        ))

    score, level, _ = score_findings(findings)
    recommendations = [
        "Verify the claimed recipient using contact details you find independently.",
        "Never share an OTP, UPI PIN, password, or full card details to receive money.",
        "Check the payee and amount in your own bank or UPI app before approving a payment.",
    ]
    advisory = (
        "Advisory only. The claimed recipient is user-provided; this assessment does not verify "
        "account-holder identity or account ownership, and it does not initiate payments."
    )
    return {
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
        "recommendations": recommendations,
        "advisory": advisory,
        "advisory_only": True,
        "recipient_identity_check": "not_performed",
        "claimed_recipient_provided": bool(claimed_recipient.strip()),
        "amount_provided": amount is not None,
        "payment_initiated": False,
    }