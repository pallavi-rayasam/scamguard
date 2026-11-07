"""Deterministic sequence-level analysis for scam conversations."""
from __future__ import annotations

import re
from collections import defaultdict


_PAYMENT_REQUEST = re.compile(
    r"\b(?:(?:please|kindly)\s+)?(?:pay|send|transfer|deposit)\s+"
    r"(?:(?:me|it|again|more|the|a|an|your|this|that)\s+){0,3}"
    r"(?:money|amount|fee|payment|charge|deposit|registration|processing|document|clearance|job|₹|inr|[a-z]{2,})\b"
    r"|\b(?:i\s+)?(?:sent|created|raised)\s+(?:the|a)\s+(?:upi\s+)?collect\s+request\b"
    r"|\b(?:approve|accept)\s+(?:the\s+|this\s+)?(?:upi\s+)?collect\s+request\b",
    re.IGNORECASE,
)
_CREDENTIAL_REQUEST = re.compile(
    r"\b(?:share|send|tell|read|forward|give|provide|enter|confirm)\s+(?:me\s+)?"
    r"(?:your\s+|the\s+)?(?:otp|one[- ]time password|verification code|security code|upi pin|pin|password|passcode|cvv)\b"
    r"|\bwhat(?:'s| is)\s+(?:your\s+)?(?:otp|upi pin|pin|password|verification code)\b",
    re.IGNORECASE,
)
_NEGATED_CREDENTIAL_REQUEST = re.compile(
    r"\b(?:do not|don't|never|must not|should not)\s+(?:share|send|tell|forward|disclose)\b"
    r".{0,55}\b(?:otp|one[- ]time password|verification code|security code|upi pin|pin|password|passcode|cvv)\b",
    re.IGNORECASE,
)
_PRESSURE_PATTERNS = (
    (3, re.compile(r"\b(?:arrest|warrant|digital arrest|police action|legal action|will be disconnected)\b", re.I)),
    (2, re.compile(r"\b(?:immediately|right now|within\s+\d+\s+minutes?|last warning|do not delay|act now|account (?:may|will) be blocked)\b", re.I)),
    (1, re.compile(r"\b(?:urgent(?:ly)?|today only|by today|deadline|soon)\b", re.I)),
)
_IDENTITY_PREFIX = re.compile(
    r"\b(?:i am|i'm|this is|we are|we're|calling from|speaking from|representative (?:of|from)|officer from)\b",
    re.I,
)
_IDENTITY_ALIASES = {
    "bank": ("sbi", "state bank of india", "hdfc", "icici", "axis bank", "bank support", "bank manager"),
    "law_enforcement": ("police", "cbi", "cyber cell", "ed officer", "enforcement directorate"),
    "regulator": ("rbi", "uidai", "income tax department", "government officer"),
    "courier": ("courier", "customs", "india post", "dhl", "fedex"),
    "employer": ("recruiter", "hr team", "hiring team", "placement office"),
}


def parse_conversation_text(text: str) -> list[dict[str, str]]:
    """Parse ordered newline-delimited chat, recognizing optional 'Sender: text' labels."""
    messages: list[dict[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.match(r"^([^:]{1,80}):\s*(.+)$", line)
        if match:
            messages.append({"sender": match.group(1).strip(), "text": match.group(2).strip()})
        else:
            messages.append({"sender": "participant", "text": line})
    return messages


def _is_credential_request(text: str) -> bool:
    safe_spans = [match.span() for match in _NEGATED_CREDENTIAL_REQUEST.finditer(text)]
    if not safe_spans:
        return bool(_CREDENTIAL_REQUEST.search(text))
    remaining = list(text)
    for start, end in safe_spans:
        remaining[start:end] = " " * (end - start)
    return bool(_CREDENTIAL_REQUEST.search("".join(remaining)))


def _pressure_level(text: str) -> int:
    for level, pattern in _PRESSURE_PATTERNS:
        if pattern.search(text):
            return level
    return 0


def _identity_claim(text: str) -> str | None:
    lowered = text.lower()
    for prefix in _IDENTITY_PREFIX.finditer(lowered):
        segment = lowered[prefix.end():prefix.end() + 70]
        for identity, aliases in _IDENTITY_ALIASES.items():
            if any(re.search(rf"\b{re.escape(alias)}\b", segment) for alias in aliases):
                return identity
    return None


def analyze_conversation(messages: list[dict[str, str]]) -> dict:
    """Find repeated asks, credential theft, pressure escalation, and identity changes."""
    clean_messages = [
        {
            "sender": str(item.get("sender", "participant")).strip().lower() or "participant",
            "text": str(item.get("text", "")).strip(),
        }
        for item in messages
        if str(item.get("text", "")).strip()
    ]
    findings: list[dict] = []

    payment_messages = [item for item in clean_messages if _PAYMENT_REQUEST.search(item["text"])]
    if len(payment_messages) >= 2:
        findings.append({
            "indicator": "repeated_payment_requests",
            "detail": "The conversation contains repeated requests to send, transfer, deposit, or approve money.",
            "verification_level": "heuristic",
            "source": "conversation_sequence_rules",
            "score_weight": 18,
        })

    if any(_is_credential_request(item["text"]) for item in clean_messages):
        findings.append({
            "indicator": "credential_request",
            "detail": "A message asks the recipient to share an OTP, PIN, password, or verification code.",
            "verification_level": "heuristic",
            "source": "conversation_sequence_rules",
            "score_weight": 32,
        })

    levels = [_pressure_level(item["text"]) for item in clean_messages]
    previous_max = 0
    escalated = False
    for level in levels:
        if previous_max > 0 and level > previous_max and level >= 2:
            escalated = True
        previous_max = max(previous_max, level)
    if escalated:
        findings.append({
            "indicator": "escalating_pressure",
            "detail": "The conversation escalates from urgency to immediate pressure or threats.",
            "verification_level": "heuristic",
            "source": "conversation_sequence_rules",
            "score_weight": 18,
        })

    claims_by_sender: dict[str, set[str]] = defaultdict(set)
    for item in clean_messages:
        claim = _identity_claim(item["text"])
        if claim:
            claims_by_sender[item["sender"]].add(claim)
    if any(len(claims) > 1 for claims in claims_by_sender.values()):
        findings.append({
            "indicator": "inconsistent_identity_claims",
            "detail": "The same conversation participant claims different organization or authority roles.",
            "verification_level": "heuristic",
            "source": "conversation_sequence_rules",
            "score_weight": 24,
        })

    return {"findings": findings, "message_count": len(clean_messages)}