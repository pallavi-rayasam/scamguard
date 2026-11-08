import re
from collections import Counter

from app.detection.normalize import load_categories

CATEGORIES = load_categories()

INDICATOR_WEIGHTS = {
    "credential_request": 30,
    "otp_request": 32,
    "financial_action": 24,
    "urgent_threat": 18,
    "reward_bait": 18,
    "remote_access": 28,
    "unusual_payment": 24,
    "sensitive_data_request": 20,
}

INDICATOR_PHRASES = {
    "credential_request": ["share your password", "send your password", "share your pin", "tell me your pin", "enter your upi pin"],
    "otp_request": ["share the otp", "tell me the otp", "send otp", "share otp", "verification code"],
    "financial_action": ["transfer the amount", "pay now", "send money", "scan this qr", "collect request", "pay registration fee"],
    "urgent_threat": ["immediately", "within 10 minutes", "account will be blocked", "will be disconnected", "digital arrest", "arrest warrant"],
    "reward_bait": ["you have won", "claim your prize", "guaranteed returns", "double your money", "free gift"],
    "remote_access": ["screen sharing", "install anydesk", "install remote support", "share your screen"],
    "unusual_payment": ["gift card", "crypto wallet", "personal upi", "pay outside the app"],
    "sensitive_data_request": ["aadhaar number", "pan number", "card number", "bank details", "date of birth"],
}

FAMILY_NAMES = {
    "authority_customs": "authority or customs reference",
    "parcel_courier": "parcel or courier context",
    "prohibited_illegal": "prohibited or illegal item claim",
    "prize_won": "prize or winnings claim",
    "claim_collect": "claim or collection request",
    "pay_penalty_fee": "payment, penalty, or fee language",
    "call_now": "urgent call request",
    "urgency": "time pressure or repeated attempt",
    "off_platform_link": "link-based action",
    "coercive_threat": "arrest or legal threat",
}

# These are explicitly contextual combinations. Context words alone never add
# risk; a combination also needs an active demand/action signal.
SIGNAL_PATTERNS = {
    "authority_customs": re.compile(r"\b(?:customs?|police|law enforcement|border authorities|authorit(?:y|ies))\b", re.I),
    "parcel_courier": re.compile(r"\b(?:parcel|courier|shipment|package|delivery)\b", re.I),
    "prohibited_illegal": re.compile(r"\b(?:prohibited|illegal|restricted|banned|contraband)\b", re.I),
    "prize_won": re.compile(r"\b(?:prize|won|winnings?|jackpot|reward)\b", re.I),
    "claim_collect": re.compile(r"\b(?:claim|collect(?:ion|ed|ing)?|release)\b", re.I),
    "pay_penalty_fee": re.compile(r"\b(?:pay(?:ment|able)?|fees?|penalt(?:y|ies)|clearance|charges?)\b", re.I),
    "call_now": re.compile(r"\b(?:call|phone)\s+(?:me\s+)?(?:now|immediately|right away)\b|\b(?:call|phone)\s+now\b", re.I),
    "urgency": re.compile(r"\b(?:urgent(?:ly)?|immediately|right now|final (?:notice|warning|attempt)|(?:second|2nd|third|3rd) attempt|\d+(?:st|nd|rd|th) attempt|within \d+ (?:minutes?|hours?|days?))\b", re.I),
    "off_platform_link": re.compile(r"\b(?:at|via|through|use|click|open|visit)\s+(?:the\s+)?link\b|\b(?:link|url)\s+(?:below|to|for)\b|https?://|\bwww\.", re.I),
    "coercive_threat": re.compile(r"\b(?:arrest(?:ed)?|jail|prosecut(?:e|ion)|face charges|legal action|police will)\b", re.I),
}

_PAYMENT_NOT_REQUESTED = re.compile(
    r"\b(?:no|without)\s+(?:any\s+)?(?:payment|fees?|charges?|penalties?)\b|"
    r"\bwithout\s+a\s+(?:fee|charge|penalty)\b|"
    r"\b(?:fees?|charges?|penalties?|payment|clearance)\b.{0,35}\b(?:already paid|paid|prepaid|settled|waived|included|covered|not due|not required)\b|"
    r"\b(?:already paid|paid in advance|prepaid|settled|waived|included|covered)\b.{0,35}\b(?:fees?|charges?|penalties?|payment|clearance)\b|"
    r"\b(?:do not|don't|never)\s+pay\b",
    re.I,
)
_OTP_ADVICE_BEFORE = re.compile(
    r"\b(?:do not|don't|never|not)\s+(?:ever\s+)?(?:ask|share|send|tell|provide|disclose|give|reveal)\b"
    r"(?:\W+\w+){0,5}\W*$|\bnever ask.{0,30}\b(?:share|send|tell|provide|disclose|give|reveal)\b(?:\W+\w+){0,2}\W*$",
    re.I,
)
_OTP_ADVICE_AFTER = re.compile(
    r"\b(?:do not|don't|never)\s+(?:ever\s+)?share\s+(?:this\s+)?(?:otp|code|verification code)\b|"
    r"\b(?:do not|don't|never)\s+(?:ever\s+)?share\s+it\b",
    re.I,
)


def _active_matches(text: str, pattern: re.Pattern[str], *, payment: bool = False) -> list[str]:
    found = []
    for match in pattern.finditer(text):
        local_context = text[max(0, match.start() - 45):min(len(text), match.end() + 45)]
        if payment and _PAYMENT_NOT_REQUESTED.search(local_context):
            continue
        found.append(match.group(0))
    return found


def _advisory_negated(text: str, start: int, end: int) -> bool:
    context = text[max(0, start - 70):end]
    after = text[end:end + 90]
    return bool(_OTP_ADVICE_BEFORE.search(context) or _OTP_ADVICE_AFTER.search(after))


def classify_message(text: str) -> dict:
    lowered = text.lower()
    matched_indicators = []
    for key, phrases in INDICATOR_PHRASES.items():
        matched = []
        for phrase in phrases:
            for match in re.finditer(re.escape(phrase), lowered):
                if key == "otp_request" and _advisory_negated(lowered, match.start(), match.end()):
                    continue
                matched.append(phrase)
                break
        if matched:
            matched_indicators.append({
                "indicator": key,
                "detail": "Potential indicator: " + ", ".join(matched[:3]),
                "verification_level": "heuristic",
                "source": "deterministic_message_rules",
                "score_weight": INDICATOR_WEIGHTS[key],
            })

    configured_families = {
        family
        for category_config in CATEGORIES
        for family in category_config.get("signal_families", [])
    }
    signal_matches = {
        name: _active_matches(lowered, pattern, payment=name == "pay_penalty_fee")
        for name, pattern in SIGNAL_PATTERNS.items()
        if name in configured_families
    }
    active_signals = {name for name, matches in signal_matches.items() if matches}
    findings = list(matched_indicators)
    for name in sorted(active_signals):
        examples = ", ".join(dict.fromkeys(signal_matches[name][:3]))
        findings.append({
            "indicator": f"signal:{name}",
            "detail": f"Signal matched: {FAMILY_NAMES[name]} ({examples}).",
            "verification_level": "heuristic",
            "source": "deterministic_signal_families",
            "score_weight": 0,
        })

    category_names = {entry["code"]: entry["name"] for entry in CATEGORIES}
    category_hits: Counter[str] = Counter()
    for category in CATEGORIES:
        for phrase in category.get("patterns", []):
            matches = list(re.finditer(re.escape(phrase.lower()), lowered))
            if category["code"] == "otp_theft":
                matches = [match for match in matches if not _advisory_negated(lowered, match.start(), match.end())]
            if matches:
                category_hits[category["code"]] += 1

    for category_config in CATEGORIES:
        category_code = category_config["code"]
        combo = category_config.get("signal_combination")
        if not combo:
            continue
        combo_strong = set(combo.get("strong", []))
        combo_actions = set(combo.get("action_required", []))
        if combo["context"] not in active_signals:
            continue
        if "qualifying_context" in combo and not active_signals.intersection(combo["qualifying_context"]):
            continue
        if not active_signals.intersection(combo_actions):
            continue
        strong_signals = sorted(active_signals.intersection(combo_strong))
        if len(strong_signals) < combo.get("minimum_signals", 2):
            continue
        category_hits[category_code] += 1
        score_weight = 50 if len(strong_signals) >= combo.get("high_signals", 3) else 25
        names = ", ".join(FAMILY_NAMES[name] for name in strong_signals)
        findings.append({
            "indicator": f"signal_combination:{category_code}",
            "detail": f"Combined signals ({len(strong_signals)}): {names}.",
            "verification_level": "heuristic",
            "source": "deterministic_signal_combinations",
            "score_weight": score_weight,
        })

    for code, count in category_hits.items():
        findings.append({
            "indicator": f"category:{code}",
            "detail": f"Message matches {count} seeded pattern(s) for {category_names[code]}.",
            "verification_level": "heuristic",
            "source": "seeded_scam_patterns" if not any(entry["code"] == code and "signal_combination" in entry for entry in CATEGORIES) else "deterministic_signal_combinations",
            "score_weight": 0 if any(entry["code"] == code and "signal_combination" in entry for entry in CATEGORIES) else 8,
        })

    category = category_hits.most_common(1)[0][0] if category_hits else None
    return {"category": category, "findings": findings, "matched_signals": sorted(active_signals)}
