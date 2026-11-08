import re
from collections import Counter
from urllib.parse import urlsplit

from app.detection.normalize import extract_urls, load_categories, load_trusted_domains

CATEGORIES = load_categories()
TRUSTED_DOMAINS = load_trusted_domains()

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
    "kyc_verification": "KYC or account verification request",
    "account_restriction": "account restriction or suspension threat",
    "verify_link": "verification or update requested through a link",
    "bank_government_claim": "bank or government identity claim",
    "unverified_domain": "domain not in the trusted-domain list",
    "authority_investigation": "police or cyber-investigation authority claim",
    "criminal_case_claim": "criminal case or investigation allegation",
    "warrant_threat": "warrant or arrest threat",
    "stay_on_call": "instruction to remain on a call",
    "job_offer": "job or work-from-home offer",
    "salary_offer": "salary or monthly pay promise",
    "upfront_job_fee": "registration, training, or refundable job fee",
    "utility_service": "electricity, water, gas, or utility service",
    "utility_disconnection": "utility disconnection threat",
    "loan_offer": "pre-approved or instant loan offer",
    "loan_app_install": "instruction to install a loan app",
    "sensitive_app_permissions": "request for contacts, photos, or messages access",
    "loan_processing_charge": "loan processing or release charge",
    "credential_data_request": "request for sensitive identity or financial details",
    "remote_support_app_install": "request to install remote-access or support software",
    "wallet_payment_to_unlock": "payment of coins or funds to activate or unlock a wallet benefit",
    "upi_payment_to_receive": "UPI payment requested to unlock or receive something",
    "guaranteed_return_claim": "guaranteed or unusually high investment return claim",
    "upfront_benefit_fee": "upfront or refundable fee/deposit tied to a job, loan, or prize",
    "online_relationship_money_request": "urgent money request from someone met online",
}

# These are explicitly contextual combinations. Context words alone never add
# risk; a combination also needs an active demand/action signal.
SIGNAL_PATTERNS = {
    "authority_customs": re.compile(r"\b(?:customs?|police|law enforcement|border authorities|authorit(?:y|ies))\b", re.I),
    "parcel_courier": re.compile(r"\b(?:parcel|courier|shipment|package|delivery)\b", re.I),
    "prohibited_illegal": re.compile(r"\b(?:prohibited|illegal|banned|contraband)\b|\brestricted\s+(?:item|goods|package|substance)\b", re.I),
    "prize_won": re.compile(r"\b(?:prize|won|winnings?|jackpot|reward)\b", re.I),
    "claim_collect": re.compile(r"\b(?:claim|collect(?:ion|ed|ing)?|release)\b", re.I),
    "pay_penalty_fee": re.compile(r"\b(?:pay(?:ment|able)?|fees?|penalt(?:y|ies)|clearance|charges?)\b", re.I),
    "call_now": re.compile(r"\b(?:call|phone)\s+(?:(?:\+?\d[\d -]{5,15}|(?:me|us|the number|this number|our helpline))\s+)?(?:now|immediately|right away)\b|\b(?:call|phone)\s+now\b", re.I),
    "urgency": re.compile(r"\b(?:urgent(?:ly)?|immediately|right now|today|do not delay|don't delay|final (?:notice|warning|attempt)|(?:second|2nd|third|3rd) attempt|\d+(?:st|nd|rd|th) attempt|within \d+ (?:minutes?|hours?|days?))\b", re.I),
    "off_platform_link": re.compile(r"\b(?:at|via|through|use|click|open|visit)\s+(?:the\s+)?link\b|\b(?:link|url)\s+(?:below|to|for)\b|https?://|\bwww\.", re.I),
    "coercive_threat": re.compile(r"\b(?:arrest(?:ed)?|jail|prosecut(?:e|ion)|face charges|legal action|police will)\b", re.I),
    "kyc_verification": re.compile(r"\b(?:kyc|know your customer|identity verification|customer verification|verify your account|verify account|account verification)\b", re.I),
    "account_restriction": re.compile(r"\b(?:restrict(?:ed|ion)?|suspend(?:ed|sion)?|block(?:ed|ing)?|freeze|frozen|access limited)\b", re.I),
    "verify_link": re.compile(r"\b(?:verify|update|confirm|complete)\b.{0,55}\b(?:via|through|using|at|on)\s+(?:(?:the|this|a|an)\s+)?(?:web\s+)?(?:link|url)\b|\b(?:link|url)\b.{0,35}\b(?:to\s+(?:verify|update|confirm)|for\s+(?:verification|kyc|account update))\b", re.I),
    "bank_government_claim": re.compile(r"\b(?:bank|banking|rbi|uidai|government|income tax department|tax department)\b", re.I),
    "authority_investigation": re.compile(r"\b(?:cyber investigation department|cyber crime department|cybercrime department|investigation department|investigation officer|cyber cell|police|law enforcement)\b", re.I),
    "criminal_case_claim": re.compile(r"\b(?:criminal case|criminal complaint|under investigation|identity.{0,25}linked to.{0,30}(?:case|crime)|linked to.{0,20}(?:criminal case|crime))\b", re.I),
    "warrant_threat": re.compile(r"\b(?:warrant(?: will be issued| has been issued)?|issue an arrest warrant|arrest warrant)\b", re.I),
    "stay_on_call": re.compile(r"\b(?:stay|remain|keep|continue)\s+(?:on|in)\s+(?:this\s+)?(?:call|line)\b|\bdo not hang up\b", re.I),
    "job_offer": re.compile(r"\b(?:job offer|work[- ]from[- ]home|position|shortlisted|vacancy|employment|recruit(?:ing|ment)?|part[- ]time|product reviewers?|tasks?)\b", re.I),
    "salary_offer": re.compile(r"\b(?:salary|per month|monthly pay|monthly salary|remuneration)\b|\bearn(?:ing)?\b.{0,50}\b(?:per day|daily|per month|monthly)\b", re.I),
    "upfront_job_fee": re.compile(r"\b(?:registration|application|training|security)\s+(?:fee|charge|deposit)\b|\brefundable\b.{0,35}\b(?:fee|charge|deposit)\b|\b(?:upfront|advance)\s+(?:fee|charge|deposit)\b", re.I),
    "utility_service": re.compile(r"\b(?:electricity|power|water|gas|utility)\b", re.I),
    "utility_disconnection": re.compile(r"\b(?:disconnect(?:ed|ion)?|power will be cut|service will be shut off|connection will be discontinued|cut off|shut off)\b", re.I),
    "loan_offer": re.compile(r"\b(?:pre[- ]approved|preapproved|instant loan|loan offer|loan without documents|personal loan)\b", re.I),
    "loan_app_install": re.compile(r"\binstall\s+(?:(?:the|an?)\s+)?(?:(?:official|bank|loan|mobile)\s+)?(?:[\w.-]+\s+)?app\b|\binstall\s+[A-Z][A-Za-z0-9_-]{2,}\b", re.I),
    "sensitive_app_permissions": re.compile(r"\b(?:allow|grant|give|enable|access)\b.{0,40}\b(?:contacts|photos|messages)\b|\b(?:contacts|photos|messages)\b.{0,25}\b(?:permission|access)\b", re.I),
    "loan_processing_charge": re.compile(r"\b(?:processing|release|disbursal|upfront)\s+(?:fee|charge|payment)\b", re.I),
    "credential_data_request": re.compile(r"\b(?:send|submit|provide|enter|share|upload|type|email|text|reply)\b.{0,100}\b(?:card(?:\s+(?:number|details?))?|cvv|cvc|pin|password|passcode|aadhaar|pan|bank details|account details|date of birth|full address|payment details)\b", re.I),
    "remote_support_app_install": re.compile(r"\binstall\b.{0,70}\b(?:remote access|remote support|screen[- ]sharing|remote[- ]control|anydesk|teamviewer|quickassist)\b|\b(?:remote access|remote support|screen[- ]sharing|remote[- ]control)\s+(?:app|software|tool)\b.{0,30}\binstall\b", re.I),
    "wallet_payment_to_unlock": re.compile(r"\b(?:send|transfer|deposit|pay)\b.{0,100}\b(?:coins?|crypto|funds?|money)\b.{0,100}\b(?:wallet|crypto wallet)\b.{0,100}\b(?:unlock|activate|receive|release|claim|membership)\b|\b(?:send|transfer|deposit|pay)\b.{0,100}\b(?:wallet|crypto wallet)\b.{0,100}\b(?:coins?|crypto|funds?|money)\b.{0,100}\b(?:unlock|activate|receive|release|claim|membership)\b", re.I),
    "upi_payment_to_receive": re.compile(r"\b(?:send|transfer|pay)\b.{0,100}\b(?:upi(?:\s+(?:id|address))?)\b.{0,100}\b(?:unlock|activate|receive|release|claim)\b|\b(?:unlock|activate|receive|release|claim)\b.{0,100}\b(?:send|transfer|pay)\b.{0,100}\b(?:upi(?:\s+(?:id|address))?)\b", re.I),
    "guaranteed_return_claim": re.compile(r"\bguaranteed\b.{0,60}\b(?:returns?|profit|yield)\b|\bguaranteed\b.{0,35}\b\d{1,3}(?:\.\d+)?\s*%\s*(?:daily|per day|weekly|monthly|returns?|profit|yield)\b|\b(?:1[5-9]|[2-9]\d|100)(?:\.\d+)?\s*%\s*(?:daily|per day|weekly|monthly)\b", re.I),
    "upfront_benefit_fee": re.compile(r"\b(?:job|work|position|employment|recruit(?:ing|ment)?|reviewers?|tasks?|loan|prize|winnings?|offer|membership)\b.{0,150}\b(?:refundable|upfront|registration|onboarding|application|processing|training|release|security)\b.{0,60}\b(?:fees?|deposit|charge)\b|\b(?:refundable|upfront|registration|onboarding|application|processing|training|release|security)\b.{0,60}\b(?:fees?|deposit|charge)\b.{0,150}\b(?:job|work|position|employment|recruit(?:ing|ment)?|reviewers?|tasks?|loan|prize|winnings?|offer|membership)\b", re.I),
    "online_relationship_money_request": re.compile(r"(?=.*\b(?:met online|met on (?:a )?(?:dating app|dating site)|online friend|dating app)\b)(?=.*\b(?:urgent(?:ly)?|emergency|hospital|medical|today|right now|immediately)\b)(?=.*\b(?:send|transfer|borrow|lend|need|money|cash|amount|deposit)\b).+", re.I),
}

_PAYMENT_NOT_REQUESTED = re.compile(
    r"\b(?:no|without)\s+(?:any\s+)?(?:payment|fees?|charges?|penalties?|deposits?)\b|"
    r"\b(?:no|without)\b(?:\W+\w+){0,8}\W*(?:payment|fees?|charges?|penalties?|deposits?)\b|"
    r"\bwithout\s+a\s+(?:fee|charge|penalty)\b|"
    r"\b(?:fees?|charges?|penalties?|deposits?|payment|clearance)\b.{0,35}\b(?:already paid|paid|prepaid|settled|waived|included|covered|deducted|not due|not required)\b|"
    r"\b(?:already paid|paid in advance|prepaid|settled|waived|included|covered|deducted)\b.{0,35}\b(?:fees?|charges?|penalties?|deposits?|payment|clearance)\b|"
    r"\b(?:do not|don't|never)\s+pay\b",
    re.I,
)
_NEGATED_SERVICE_THREAT = re.compile(
    r"\b(?:no|not|never|won't|will not|isn't|is not|remains?|remain)\b.{0,24}\b(?:restrict(?:ed|ion)?|suspend(?:ed|sion)?|block(?:ed|ing)?|disconnect(?:ed|ion)?|cut off|shut off)\b",
    re.I,
)
_NEGATED_REQUEST = re.compile(
    r"\b(?:do not|don't|never|avoid|will never|will not)\b.{0,90}\b(?:ask|send|transfer|deposit|pay|install|share|provide|enter|upload|type|email|text|reply)\b",
    re.I,
)
_NEGATED_SENSITIVE_REQUEST = re.compile(
    r"\b(?:do not|don't|never|will never|will not)\b.{0,90}\b(?:ask|send|share|provide|enter|upload|type|email|text|reply|disclose|reveal)\b",
    re.I,
)
_NEGATED_RETURN_CLAIM = re.compile(
    r"\b(?:do not|don't|never|avoid|beware|warning|not)\b.{0,80}\b(?:guaranteed|assured|risk[- ]free|returns?|profit|yield)\b",
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


def _active_matches(
    text: str,
    pattern: re.Pattern[str],
    *,
    payment: bool = False,
    service_threat: bool = False,
    request: bool = False,
    sensitive_request: bool = False,
    return_claim: bool = False,
) -> list[str]:
    found = []
    for match in pattern.finditer(text):
        local_context = text[max(0, match.start() - 45):min(len(text), match.end() + 45)]
        if payment and _PAYMENT_NOT_REQUESTED.search(local_context):
            continue
        if service_threat and _NEGATED_SERVICE_THREAT.search(local_context):
            continue
        if request and _NEGATED_REQUEST.search(local_context):
            continue
        if sensitive_request and _NEGATED_SENSITIVE_REQUEST.search(local_context):
            continue
        if return_claim and _NEGATED_RETURN_CLAIM.search(local_context):
            continue
        if return_claim and _is_normal_bank_fixed_rate(text):
            continue
        found.append(match.group(0))
    return found


def _is_normal_bank_fixed_rate(text: str) -> bool:
    has_bank_deposit = re.search(r"\b(?:fixed deposit|term deposit|bank deposit|bank fd)\b", text, re.I)
    modest_annual_rate = re.search(r"\b\d{1,2}(?:\.\d+)?\s*%\s*(?:annual|per annum|p\.a\.?|yearly)\b", text, re.I)
    high_rate = re.search(r"\b(?:1[5-9]|[2-9]\d|100)(?:\.\d+)?\s*%\b", text, re.I)
    return bool(has_bank_deposit and modest_annual_rate and not high_rate)


def _advisory_negated(text: str, start: int, end: int) -> bool:
    context = text[max(0, start - 70):end]
    after = text[end:end + 90]
    return bool(_OTP_ADVICE_BEFORE.search(context) or _OTP_ADVICE_AFTER.search(after))


def _unverified_domains(text: str) -> list[str]:
    unverified = []
    for url in extract_urls(text):
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
        if not host:
            continue
        if any(host == trusted or host.endswith("." + trusted) for trusted in TRUSTED_DOMAINS):
            continue
        if host not in unverified:
            unverified.append(host)
    return unverified


def _points_to_floor(findings: list[dict], floor: int) -> int:
    highest_by_indicator: dict[str, int] = {}
    for finding in findings:
        indicator = finding.get("indicator", "unknown")
        highest_by_indicator[indicator] = max(highest_by_indicator.get(indicator, 0), finding.get("score_weight", 0))
    return max(0, floor - sum(highest_by_indicator.values()))


def classify_message(text: str) -> dict:
    lowered = text.lower()
    matched_indicators = []
    for key, phrases in INDICATOR_PHRASES.items():
        matched = []
        for phrase in phrases:
            for match in re.finditer(re.escape(phrase), lowered):
                if key == "otp_request" and _advisory_negated(lowered, match.start(), match.end()):
                    continue
                context = lowered[max(0, match.start() - 90):min(len(lowered), match.end() + 90)]
                if key in {"credential_request", "sensitive_data_request"} and _NEGATED_SENSITIVE_REQUEST.search(context):
                    continue
                if key == "remote_access" and _NEGATED_REQUEST.search(context):
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
        name: _active_matches(
            lowered,
            pattern,
            payment=name in {"pay_penalty_fee", "upfront_job_fee", "upfront_benefit_fee"},
            service_threat=name in {"account_restriction", "utility_disconnection"},
            request=name in {"remote_support_app_install", "wallet_payment_to_unlock", "upi_payment_to_receive", "online_relationship_money_request"},
            sensitive_request=name == "credential_data_request",
            return_claim=name == "guaranteed_return_claim",
        )
        for name, pattern in SIGNAL_PATTERNS.items()
        if name in configured_families
    }
    if "unverified_domain" in configured_families:
        signal_matches["unverified_domain"] = _unverified_domains(text)
    active_signals = {name for name, matches in signal_matches.items() if matches}
    global_signals = {"urgency", "unverified_domain", "pay_penalty_fee", "call_now", "off_platform_link"}
    family_contexts: dict[str, set[str]] = {}
    contexts: set[str] = set()
    for category_config in CATEGORIES:
        combos = ([category_config["signal_combination"]] if category_config.get("signal_combination") else [])
        combos.extend(category_config.get("additional_signal_combinations", []))
        for combo in combos:
            context = combo["context"]
            contexts.add(context)
            for family in category_config.get("signal_families", []):
                family_contexts.setdefault(family, set()).add(context)
    active_contexts = active_signals.intersection(contexts)
    active_signals = {
        signal
        for signal in active_signals
        if signal in global_signals
        or signal in active_contexts
        or bool(family_contexts.get(signal, set()).intersection(active_contexts))
    }
    duplicate_indicators = {
        "credential_data_request": {"sensitive_data_request"},
        "remote_support_app_install": {"remote_access"},
        "wallet_payment_to_unlock": {"financial_action", "unusual_payment"},
        "upi_payment_to_receive": {"financial_action", "unusual_payment"},
        "guaranteed_return_claim": {"reward_bait"},
        "upfront_benefit_fee": {"financial_action"},
        "online_relationship_money_request": {"financial_action"},
    }
    suppressed_indicators = {indicator for family in active_signals for indicator in duplicate_indicators.get(family, set())}
    matched_indicators = [item for item in matched_indicators if item["indicator"] not in suppressed_indicators]
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
    seeded_category_hits: Counter[str] = Counter()
    for category in CATEGORIES:
        for phrase in category.get("patterns", []):
            matches = list(re.finditer(re.escape(phrase.lower()), lowered))
            if category["code"] == "otp_theft":
                matches = [match for match in matches if not _advisory_negated(lowered, match.start(), match.end())]
            if matches:
                category_hits[category["code"]] += 1
                seeded_category_hits[category["code"]] += 1

    for category_config in CATEGORIES:
        category_code = category_config["code"]
        combos = ([category_config["signal_combination"]] if category_config.get("signal_combination") else [])
        combos.extend(category_config.get("additional_signal_combinations", []))
        for combo in combos:
            combo_strong = set(combo.get("strong", []))
            combo_actions = set(combo.get("action_required", []))
            if combo["context"] not in active_signals:
                continue
            if "qualifying_context" in combo and not active_signals.intersection(combo["qualifying_context"]):
                continue
            if combo_actions and not active_signals.intersection(combo_actions):
                continue
            strong_signals = sorted(active_signals.intersection(combo_strong))
            if len(strong_signals) < combo.get("minimum_signals", 2):
                continue
            category_hits[category_code] = max(category_hits[category_code], 1)
            score_weight = 50 if len(strong_signals) >= combo.get("high_signals", 3) else 30
            names = ", ".join(FAMILY_NAMES[name] for name in strong_signals)
            findings.append({
                "indicator": f"signal_combination:{category_code}",
                "detail": f"Combined signals ({len(strong_signals)}): {names}.",
                "verification_level": "heuristic",
                "source": "deterministic_signal_combinations",
                "score_weight": score_weight,
            })

    if {"unverified_domain", "urgency"} <= active_signals:
        findings.append({
            "indicator": "unverified_domain_urgency",
            "detail": "An unverified domain appears alongside time pressure; combined evidence reaches at least 30 points.",
            "verification_level": "heuristic",
            "source": "deterministic_signal_combinations",
            "score_weight": _points_to_floor(findings, 30),
        })
    if {"unverified_domain", "bank_government_claim"} <= active_signals:
        findings.append({
            "indicator": "unverified_bank_domain",
            "detail": "A bank or government identity is claimed alongside a domain not in the trusted-domain list.",
            "verification_level": "heuristic",
            "source": "deterministic_signal_combinations",
            "score_weight": 8,
        })

    for code, count in category_hits.items():
        seeded_count = seeded_category_hits.get(code, 0)
        detail = (
            f"Message matches {seeded_count} seeded pattern(s) for {category_names[code]}."
            if seeded_count
            else f"Message matches a configured signal combination for {category_names[code]}."
        )
        findings.append({
            "indicator": f"category:{code}",
            "detail": detail,
            "verification_level": "heuristic",
            "source": "seeded_scam_patterns" if seeded_count else "deterministic_signal_combinations",
            "score_weight": 8 if seeded_count else 0,
        })

    category = category_hits.most_common(1)[0][0] if category_hits else None
    return {"category": category, "findings": findings, "matched_signals": sorted(active_signals)}
