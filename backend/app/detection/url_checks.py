from difflib import SequenceMatcher
from urllib.parse import urlsplit

from app.detection.normalize import load_trusted_domains

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "cutt.ly", "shorturl.at"}
TRUSTED_DOMAINS = load_trusted_domains()


def inspect_url(raw_url: str) -> list[dict]:
    normalized = raw_url.strip()
    if not normalized.lower().startswith(("http://", "https://")):
        normalized = "https://" + normalized
    parsed = urlsplit(normalized)
    host = (parsed.hostname or "").lower().rstrip(".")
    findings: list[dict] = []
    if parsed.scheme != "https":
        findings.append({"indicator":"url_not_https", "detail":"URL does not use HTTPS.", "verification_level":"heuristic", "source":"url_structure_check", "score_weight":8})
    if not host or "." not in host or any(char.isspace() for char in host):
        findings.append({"indicator":"malformed_url", "detail":"URL host could not be parsed as a normal domain.", "verification_level":"heuristic", "source":"url_structure_check", "score_weight":14})
    if host in SHORTENERS:
        findings.append({"indicator":"url_shortener", "detail":"URL uses a known link-shortening domain, so the final destination is not visible here.", "verification_level":"heuristic", "source":"url_structure_check", "score_weight":8})
    if host.startswith("xn--") or ".xn--" in host:
        findings.append({"indicator":"punycode_domain", "detail":"URL contains a Punycode domain label.", "verification_level":"heuristic", "source":"url_structure_check", "score_weight":14})
    if host.count(".") >= 4:
        findings.append({"indicator":"deep_subdomain", "detail":"URL contains several subdomain labels.", "verification_level":"heuristic", "source":"url_structure_check", "score_weight":8})
    for trusted in TRUSTED_DOMAINS:
        if host == trusted or host.endswith("." + trusted):
            break
        if SequenceMatcher(None, host, trusted).ratio() >= 0.84:
            findings.append({"indicator":"lookalike_domain", "detail":f"Domain resembles a trusted domain ({trusted}) but is not an exact match.", "verification_level":"heuristic", "source":"url_structure_check", "score_weight":22})
            break
    return findings
