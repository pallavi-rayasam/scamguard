"""Local URL structure checks; these findings are heuristics, not verdicts."""
from __future__ import annotations

from difflib import SequenceMatcher
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

SHORTENER_HOSTS = {
    "bit.ly", "bitly.ws", "tinyurl.com", "tiny.cc", "t.co", "goo.gl",
    "cutt.ly", "rb.gy", "is.gd", "rebrand.ly", "lnkd.in", "ow.ly",
    "buff.ly", "shorturl.at",
}
_MULTI_LABEL_SUFFIXES = {"co.in", "org.in", "net.in", "gov.in", "ac.in"}
_ORG_PATH = Path(__file__).resolve().parents[1] / "data" / "seed" / "organization_domains.json"


def _trusted_domains() -> set[str]:
    try:
        data = json.loads(_ORG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    return {domain.lower().rstrip(".") for domains in data.values() for domain in domains}


def _registered_label(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else labels[0]


def _typosquatted_brand(host: str, trusted: set[str]) -> str | None:
    if any(host == domain or host.endswith("." + domain) for domain in trusted):
        return None
    candidate_labels = re.findall(r"[a-z0-9]+", host)
    for trusted_domain in sorted(trusted):
        brand = _registered_label(trusted_domain)
        for token in candidate_labels:
            if len(brand) >= 3 and token == brand:
                return brand
            if len(brand) >= 4 and len(token) >= 4 and SequenceMatcher(None, token, brand).ratio() >= 0.82:
                return brand
    return None


def analyze_url(url: str) -> list[dict]:
    """Flag shorteners, non-HTTPS URLs, Punycode, deep subdomains and seeded brand lookalikes."""
    parsed = urlsplit(url.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return []
    try:
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return [{
            "indicator": "invalid_idn",
            "detail": "The hostname could not be converted to a valid IDN form.",
            "verification_level": "heuristic",
            "source": "url_domain_heuristic",
            "score_weight": 12,
        }]

    findings: list[dict] = []
    def add(indicator: str, detail: str, weight: int) -> None:
        findings.append({
            "indicator": indicator,
            "detail": detail,
            "verification_level": "heuristic",
            "source": "url_domain_heuristic",
            "score_weight": weight,
        })

    if parsed.scheme.lower() != "https":
        add("url_http_not_https", "The URL uses HTTP without transport encryption.", 10)
    if any(host == item or host.endswith("." + item) for item in SHORTENER_HOSTS):
        add("url_shortener", "The hostname is a known URL-shortening service; its destination is not established by this check.", 14)
    if "xn--" in host:
        add("url_punycode", "The hostname contains an IDN Punycode label; inspect it carefully for lookalike characters.", 12)
    if len(host.split(".")) > 4:
        add("url_deep_subdomain", "The hostname has several subdomain labels, which can obscure the registered domain.", 6)
    brand = _typosquatted_brand(host, _trusted_domains())
    if brand:
        add("url_brand_lookalike", f"The hostname resembles or uses the seeded {brand.upper()} brand outside its trusted domain.", 22)
    return findings
