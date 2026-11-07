def risk_level(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Moderate"
    return "Low"


def score_findings(findings: list[dict]) -> tuple[int, str, list[dict]]:
    highest_by_indicator: dict[str, dict] = {}
    for finding in findings:
        key = finding.get("indicator", "unknown")
        current = highest_by_indicator.get(key)
        if not current or finding.get("score_weight", 0) > current.get("score_weight", 0):
            highest_by_indicator[key] = finding
    score = min(100, sum(item.get("score_weight", 0) for item in highest_by_indicator.values()))
    return score, risk_level(score), list(highest_by_indicator.values())


def evidence_strength(findings: list[dict]) -> str:
    """Describe corroboration strength; heuristics and LLM output are not verified evidence."""
    if any(item.get("verification_level") == "verified" for item in findings):
        return "Strong"
    if any(item.get("verification_level") == "heuristic" for item in findings):
        return "Limited"
    return "Weak"
