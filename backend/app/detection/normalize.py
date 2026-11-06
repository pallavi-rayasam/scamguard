import json
import re
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[3]
URL_RE = re.compile(
    r"(?i)(?:https?://|www\.)[^\s<>\"']+|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:in|com|net|org|info|co|io|app|site|xyz|online)(?:/[^\s<>\"']*)?"
)
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)")
OTP_RE = re.compile(r"(?i)\b(?:otp|one[- ]time password|verification code|security code)\s*(?:is|:|=|-)?\s*\d{4,8}\b")
SECRET_RE = re.compile(r"(?i)\b(?:upi\s*pin|pin|password|passcode|cvv|cvc)\s*(?:is|:|=|-)?\s*[a-z0-9@#$!]{3,24}\b")


def normalize_text(text: str) -> str:
    text = text.replace("\u200b", "").replace("\ufeff", "")
    return re.sub(r"\s+", " ", text).strip()


def redact_sensitive(text: str) -> tuple[str, list[str]]:
    redactions: list[str] = []

    def replace(pattern: re.Pattern[str], label: str, value: str) -> str:
        result, count = pattern.subn(value, text)
        if count:
            redactions.append(label)
        return result

    redacted = OTP_RE.sub("[REDACTED OTP]", text)
    if redacted != text:
        redactions.append("otp")
    before_secret = redacted
    redacted = SECRET_RE.sub("[REDACTED CREDENTIAL]", redacted)
    if redacted != before_secret:
        redactions.append("credential")
    before_card = redacted
    redacted = CARD_RE.sub("[REDACTED CARD NUMBER]", redacted)
    if redacted != before_card:
        redactions.append("card_number")
    # Remove common bare OTP mentions with a following 4–8 digit value.
    bare_otp = re.compile(r"(?i)\b(?:otp|code)\s+(?:is\s+)?\d{4,8}\b")
    if bare_otp.search(redacted):
        redacted = bare_otp.sub("[REDACTED OTP]", redacted)
        redactions.append("otp")
    # Avoid exposing duplicated redaction labels in the audit record.
    return normalize_text(redacted), sorted(set(redactions))


def extract_urls(text: str) -> list[str]:
    values: list[str] = []
    for match in URL_RE.findall(text):
        candidate = match.rstrip(".,;:!?)]}")
        if candidate.lower().startswith("www."):
            candidate = "https://" + candidate
        candidate = privacy_safe_url(candidate)
        if candidate and candidate not in values:
            values.append(candidate)
    return values[:3]


def privacy_safe_url(raw_url: str) -> str:
    """Keep only scheme, host, and optional port; drop userinfo, path, query and fragment."""
    candidate = raw_url if raw_url.lower().startswith(("http://", "https://")) else "https://" + raw_url
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        if not host:
            return ""
        host = host.lower().rstrip(".")
        port = parsed.port
        authority = f"{host}:{port}" if port else host
        return f"{parsed.scheme.lower()}://{authority}"
    except ValueError:
        return ""


def redact_urls_in_text(text: str, urls: list[str]) -> str:
    """Replace submitted URLs with privacy-safe origins before persistence/model use."""
    redacted = text
    for match in URL_RE.findall(text):
        trimmed = match.rstrip(".,;:!?)]}")
        safe = privacy_safe_url(trimmed)
        replacement = f"[URL origin: {safe}]" if safe else "[REDACTED URL]"
        redacted = redacted.replace(trimmed, replacement)
    return redacted


def load_categories() -> list[dict]:
    source = ROOT / "data" / "seed" / "scam_categories.json"
    with source.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def load_trusted_domains() -> list[str]:
    source = ROOT / "data" / "seed" / "trusted_domains.json"
    with source.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def load_organization_domains() -> dict[str, list[str]]:
    source = ROOT / "data" / "seed" / "organization_domains.json"
    with source.open("r", encoding="utf-8") as stream:
        return json.load(stream)
