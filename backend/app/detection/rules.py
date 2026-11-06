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


def classify_message(text: str) -> dict:
    lowered = text.lower()
    matched_indicators = []
    for key, phrases in INDICATOR_PHRASES.items():
        matched = [phrase for phrase in phrases if phrase in lowered]
        if matched:
            matched_indicators.append({
                "indicator": key,
                "detail": "Potential indicator: " + ", ".join(matched[:3]),
                "verification_level": "heuristic",
                "source": "deterministic_message_rules",
                "score_weight": INDICATOR_WEIGHTS[key],
            })

    category_hits: Counter[str] = Counter()
    category_names = {entry["code"]: entry["name"] for entry in CATEGORIES}
    for category in CATEGORIES:
        for phrase in category.get("patterns", []):
            if phrase.lower() in lowered:
                category_hits[category["code"]] += 1
    category = category_hits.most_common(1)[0][0] if category_hits else "other_suspicious"

    findings = list(matched_indicators)
    for code, count in category_hits.items():
        findings.append({
            "indicator": f"category:{code}",
            "detail": f"Message matches {count} seeded pattern(s) for {category_names[code]}.",
            "verification_level": "heuristic",
            "source": "seeded_scam_patterns",
            "score_weight": 8,
        })

    return {"category": category, "findings": findings}
