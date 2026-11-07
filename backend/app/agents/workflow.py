"""Deterministic LangGraph orchestration for independent investigation stages."""
from collections import Counter
from datetime import datetime, timezone
import operator
import time
from typing import Annotated, TypedDict
from concurrent.futures import ThreadPoolExecutor

from langgraph.graph import END, START, StateGraph
import httpx

from app.agents.contracts import AgentResult
from app.core.config import settings
from app.detection.normalize import extract_urls, load_organization_domains, normalize_text, privacy_safe_url, redact_sensitive, redact_urls_in_text
from app.detection.rules import classify_message
from app.detection.scoring import evidence_strength, score_findings
from app.detection.url_checks import inspect_url
from app.intel.providers import check_url_reputation
from app.llm.provider import get_explanation_provider

ORG_TO_DOMAINS = load_organization_domains()
ORG_TOKENS = (*ORG_TO_DOMAINS.keys(), "police", "electricity board")


class WorkflowState(TypedDict, total=False):
    input_text: str
    input_type: str
    normalized_text: str
    redacted_text: str
    redactions: list[str]
    urls: list[str]
    category: str
    findings: Annotated[list[dict], operator.add]
    runs: Annotated[list[dict], operator.add]
    intel_results: Annotated[list[dict], operator.add]
    recommendation: list[str]
    explanation: str
    url_scan_results: list[dict]
    score: int
    risk_level: str
    report: dict


def _run(agent_name: str, status: str, started: float, findings: list[dict] | None = None, tools: list[str] | None = None, error: str | None = None) -> dict:
    result = AgentResult(
        status=status,
        findings=findings or [],
        evidence=[
            {"source": f.get("source", agent_name), "timestamp": datetime.now(timezone.utc), "verification_level": f.get("verification_level", "heuristic"), "detail": f.get("detail", "")}
            for f in (findings or [])
        ],
        tools_used=tools or [],
        duration_ms=max(0, int((time.monotonic() - started) * 1000)),
        error=error,
    )
    return {"agent_name": agent_name, **result.model_dump(mode="json")}


def guarded_agent(names: list[str], function):
    """Contain one stage failure and keep the rest of the graph runnable."""
    def invoke(state: WorkflowState) -> dict:
        started = time.monotonic()
        try:
            return function(state)
        except (httpx.TimeoutException, TimeoutError):
            return {"runs": [_run(name, "timed_out", started, [], [], "Agent timed out.") for name in names]}
        except Exception as exc:
            return {"runs": [_run(name, "failed", started, [], [], type(exc).__name__) for name in names]}
    return invoke


def prepare(state: WorkflowState) -> dict:
    started = time.monotonic()
    original = normalize_text(state.get("input_text", ""))
    urls = [privacy_safe_url(item) for item in extract_urls(original)]
    urls = [url for url in urls if url]
    redacted, redactions = redact_sensitive(original)
    redacted = redact_urls_in_text(redacted, urls)
    return {
        "normalized_text": original,
        "redacted_text": redacted,
        "redactions": redactions,
        "urls": urls,
        "findings": [],
        "runs": [_run("NormalizeAndRedact", "completed", started, [], ["pattern_redaction"])],
    }


def router(state: WorkflowState) -> dict:
    started = time.monotonic()
    return {"runs": [_run("DeterministicRouter", "completed", started, [], ["input_type_and_entity_router"])]}


def route_agents(state: WorkflowState) -> list[str]:
    # Each node is a small execution wrapper. Inapplicable agents return an explicit skipped
    # result, which keeps the parallel barrier deterministic and makes the audit trail complete.
    return ["message_agent", "url_agent", "impersonation_agent", "conversation_agent"]


def _scan_url_service(url: str) -> dict:
    """Call the internal URL scanner without following its redirects at the HTTP layer."""
    endpoint = settings.url_scanner_url.rstrip("/") + "/analyze"
    try:
        with httpx.Client(timeout=60.0, follow_redirects=False) as client:
            response = client.post(endpoint, json={"url": url})
        if response.status_code == 429:
            return {
                "status": "unavailable", "reason": "scanner_rate_limited", "findings": [],
                "threat_intel_results": [
                    {"provider": provider, "status": "unavailable", "is_malicious": None, "reason": "scanner_rate_limited"}
                    for provider in ("google_safe_browsing", "virustotal")
                ],
            }
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict) or result.get("status") not in {"completed", "blocked", "unavailable"}:
            raise ValueError("Invalid scanner service response")
        return result
    except httpx.TimeoutException:
        reason = "scanner_timed_out"
    except (httpx.HTTPError, ValueError):
        reason = "scanner_unavailable"
    return {
        "status": "unavailable", "reason": reason, "findings": [],
        "threat_intel_results": [
            {"provider": provider, "status": "unavailable", "is_malicious": None, "reason": reason}
            for provider in ("google_safe_browsing", "virustotal")
        ],
    }


def _query_url_reputation_service(url: str) -> dict:
    """Ask the scanner's reputation stage to revalidate and query provider results."""
    endpoint = settings.url_scanner_url.rstrip("/") + "/reputation"
    providers = ("google_safe_browsing", "virustotal")
    try:
        with httpx.Client(timeout=15.0, follow_redirects=False) as client:
            response = client.post(endpoint, json={"url": url})
        if response.status_code == 429:
            reason = "scanner_rate_limited"
            return {
                "status": "unavailable",
                "reason": reason,
                "threat_intel_results": [
                    {"provider": provider, "status": "unavailable", "is_malicious": None, "reason": reason}
                    for provider in providers
                ],
            }
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict) or result.get("status") not in {"completed", "blocked", "unavailable"}:
            raise ValueError("Invalid scanner reputation response")
        return result
    except httpx.TimeoutException:
        reason = "scanner_timed_out"
    except (httpx.HTTPError, ValueError):
        reason = "scanner_unavailable"
    return {
        "status": "unavailable",
        "reason": reason,
        "threat_intel_results": [
            {"provider": provider, "status": "unavailable", "is_malicious": None, "reason": reason}
            for provider in providers
        ],
    }

def message_agent(state: WorkflowState) -> dict:
    started = time.monotonic()
    result = classify_message(state.get("normalized_text", ""))
    findings = result["findings"]
    return {"category": result["category"], "findings": findings, "runs": [_run("MessageAnalysis", "completed", started, findings, ["seeded_scam_patterns", "deterministic_message_rules"])]}


def url_agent(state: WorkflowState) -> dict:
    """Inspect URL structure and run the SSRF-guarded URL analysis stage."""
    started = time.monotonic()
    urls = state.get("urls", [])
    if not urls:
        return {
            "url_scan_results": [],
            "runs": [_run("URLInvestigation", "skipped", started, [], [], "No URL extracted.")],
        }

    findings: list[dict] = []
    scan_results: list[dict] = []
    tools = ["url_structure_check"]
    status = "completed"
    error = None
    if settings.url_scanner_url:
        tools.append("internal_url_scanner")
        with ThreadPoolExecutor(max_workers=max(1, min(6, len(urls)))) as pool:
            scan_results = list(pool.map(_scan_url_service, urls))
        for result in scan_results:
            findings.extend(result.get("findings", []))
        if scan_results and all(result.get("status") == "unavailable" for result in scan_results):
            reasons = {result.get("reason", "scanner_unavailable") for result in scan_results}
            if any("timed_out" in reason or "timeout" in reason for reason in reasons):
                status, error = "timed_out", "The URL scanner timed out."
            else:
                status, error = "failed", "The URL scanner was unavailable."
    else:
        for url in urls:
            findings.extend(inspect_url(url))

    return {
        "findings": findings,
        "url_scan_results": scan_results,
        "runs": [_run("URLInvestigation", status, started, findings, tools, error)],
    }


def _provider_results_from_scan(scan_result: dict) -> list[dict]:
    results = scan_result.get("threat_intel_results", [])
    if results:
        return results
    reason = scan_result.get("reason", "target_not_publicly_validated")
    return [
        {"provider": provider, "status": "unavailable", "is_malicious": None, "reason": reason}
        for provider in ("google_safe_browsing", "virustotal")
    ]


def threat_intelligence_agent(state: WorkflowState) -> dict:
    """Query and reconcile reputation outcomes as a separate graph node."""
    started = time.monotonic()
    urls = state.get("urls", [])
    if not urls:
        return {"runs": [_run("ThreatIntelligence", "skipped", started, [], [], "No URL was available for lookup.")]}

    scan_results = state.get("url_scan_results", [])
    if settings.url_scanner_url:
        if not scan_results:
            return {
                "runs": [_run("ThreatIntelligence", "skipped", started, [], [], "No safe URL analysis result was available for reputation lookup.")],
            }
        def query_scan_result(scan_result: dict) -> dict:
            origin = scan_result.get("origin")
            if not origin:
                return {"threat_intel_results": _provider_results_from_scan(scan_result)}
            return _query_url_reputation_service(origin)

        with ThreadPoolExecutor(max_workers=max(1, min(6, len(scan_results)))) as pool:
            reputation_batches = list(pool.map(query_scan_result, scan_results))
        intel_results = [
            item
            for batch in reputation_batches
            for item in batch.get("threat_intel_results", [])
        ]
    else:
        with ThreadPoolExecutor(max_workers=max(1, min(6, len(urls)))) as pool:
            reputation_batches = list(pool.map(check_url_reputation, urls))
        intel_results = [item for batch in reputation_batches for item in batch]

    provider_statuses = {item.get("status") for item in intel_results}
    reasons = {item.get("reason", "") for item in intel_results}
    tools = sorted({
        item["provider"]
        for item in intel_results
        if item.get("provider") and item.get("status") != "skipped"
    })
    safe_skip_reasons = {
        "not_configured",
        "target_not_publicly_validated",
        "redirect_target_not_public",
    }
    if not intel_results or provider_statuses <= {"skipped"}:
        status = "skipped"
        error = "Threat-intel providers were not configured or no lookup was possible."
    elif "completed" in provider_statuses:
        status = "completed"
        error = "One or more provider results were unavailable." if provider_statuses & {"failed", "timed_out", "unavailable"} else None
    elif "timed_out" in provider_statuses or any("timed_out" in reason or "timeout" in reason for reason in reasons):
        status, error = "timed_out", "One or more threat-intel lookups timed out."
    elif provider_statuses <= {"skipped", "unavailable"} and all(
        item.get("status") == "skipped" or item.get("reason") in safe_skip_reasons
        for item in intel_results
    ):
        status, error = "skipped", "Reputation lookup was skipped because the target was not eligible or no key was configured."
    else:
        status, error = "failed", "One or more threat-intel providers were unavailable or failed."

    findings = []
    for result in intel_results:
        if result.get("status") != "completed":
            continue
        provider = result.get("provider", "threat_intel")
        malicious = result.get("is_malicious")
        findings.append({
            "indicator": f"threat_intel:{provider}" if malicious is True else f"threat_intel_status:{provider}",
            "detail": result.get("detail", "Provider returned no known-threat match; this does not establish safety."),
            "verification_level": "verified",
            "source": provider,
            "score_weight": 40 if malicious is True else 0,
        })

    return {
        "findings": findings,
        "intel_results": intel_results,
        "runs": [_run("ThreatIntelligence", status, started, findings, tools, error)],
    }

def impersonation_agent(state: WorkflowState) -> dict:
    started = time.monotonic()
    text = state.get("normalized_text", "").lower()
    domains = [url.split("//", 1)[-1].split(":", 1)[0].lower() for url in state.get("urls", [])]
    findings = []
    claims = [token for token in ORG_TOKENS if token in text]
    if claims and domains:
        for claim in claims:
            expected = ORG_TO_DOMAINS.get(claim)
            matches = expected and any(host == domain or host.endswith("." + domain) for host in domains for domain in expected)
            if expected and not matches:
                findings.append({"indicator":"claimed_org_domain_mismatch", "detail":f"The message mentions {claim.upper()}, but the supplied URL does not match its trusted-domain seed.", "verification_level":"heuristic", "source":"trusted_domain_comparison", "score_weight":18})
            elif not expected:
                findings.append({"indicator":"claimed_org_unlisted", "detail":f"The claimed organization ({claim}) is not covered by the current trusted-domain seed; verify independently.", "verification_level":"heuristic", "source":"trusted_domain_comparison", "score_weight":4})
    return {"findings": findings, "runs": [_run("Impersonation", "completed", started, findings, ["trusted_domain_seed"])]}


def conversation_agent(state: WorkflowState) -> dict:
    started = time.monotonic()
    if state.get("input_type") != "conversation":
        return {"runs": [_run("ConversationAnalysis", "skipped", started, [], [], "Input mode is not conversation.")]}
    text = state.get("normalized_text", "").lower()
    findings = []
    payment_terms = sum(text.count(term) for term in ("pay", "transfer", "send money", "deposit"))
    if payment_terms >= 3:
        findings.append({"indicator":"repeated_payment_pressure", "detail":"The conversation repeatedly references payment or transfer requests.", "verification_level":"heuristic", "source":"conversation_pattern_rules", "score_weight":18})
    if text.count("otp") >= 2 or text.count("pin") >= 2:
        findings.append({"indicator":"repeated_credential_pressure", "detail":"Credential or OTP requests appear repeatedly in the conversation.", "verification_level":"heuristic", "source":"conversation_pattern_rules", "score_weight":24})
    return {"findings": findings, "runs": [_run("ConversationAnalysis", "completed", started, findings, ["conversation_pattern_rules"])]}


def reconcile(state: WorkflowState) -> dict:
    started = time.monotonic()
    results: dict[str, set[bool]] = {}
    for item in state.get("intel_results", []):
        if item.get("status") == "completed" and item.get("is_malicious") is not None:
            results.setdefault(item["provider"], set()).add(bool(item["is_malicious"]))
    values = [item.get("is_malicious") for item in state.get("intel_results", []) if item.get("status") == "completed" and item.get("is_malicious") is not None]
    findings = []
    if True in values and False in values:
        findings.append({"indicator":"intel_provider_conflict", "detail":"Configured threat-intel providers returned conflicting reputation results.", "verification_level":"heuristic", "source":"reconciliation", "score_weight":8})
    return {"findings": findings, "runs": [_run("VerifyAndReconcile", "completed", started, findings, ["conflict_check"])]}


def risk_assessment(state: WorkflowState) -> dict:
    started = time.monotonic()
    findings = state.get("findings", [])
    score, level, _ = score_findings(findings)
    category = state.get("category", "other_suspicious")
    return {"score": score, "risk_level": level, "runs": [_run("RiskAssessment", "completed", started, [], ["weighted_indicator_scorer"]) ]}


def recommend(state: WorkflowState) -> dict:
    started = time.monotonic()
    level = state.get("risk_level", "Low")
    advice = ["Do not share passwords, one-time codes, UPI PINs, or full card details.", "Verify the request through the organization's official app or contact details you find independently."]
    if level in ("High", "Critical"):
        advice.insert(0, "Pause before responding or paying, and contact your bank through its official channel if money or credentials may be at risk.")
        advice.append("If money has already been lost in India, contact your bank immediately and call 1930 or report at cybercrime.gov.in.")
    elif level == "Moderate":
        advice.insert(0, "Pause and independently verify the sender before opening links or making a payment.")
    return {"recommendation": advice, "runs": [_run("Recommendation", "completed", started, [], ["risk_guidance_rules"])]}


def explain(state: WorkflowState) -> dict:
    started = time.monotonic()
    provider = get_explanation_provider()
    if not provider:
        return {"explanation": "", "runs": [_run("LLMExplanation", "skipped", started, [], [], "OpenAI provider is not configured; deterministic report remains available.")]}
    summary = {"category": state.get("category"), "risk_score": state.get("score"), "risk_level": state.get("risk_level"), "indicators": [item.get("detail") for item in state.get("findings", [])]}
    try:
        explanation = provider.explain(state.get("redacted_text", ""), summary)
        finding = {"indicator":"llm_explanation", "detail":explanation, "verification_level":"llm_inferred", "source":"openai_responses_api", "score_weight":0}
        return {"explanation": explanation, "findings": [finding], "runs": [_run("LLMExplanation", "completed", started, [finding], ["openai_responses_api"])]}
    except (httpx.HTTPError, RuntimeError, ValueError) as exc:
        status = "timed_out" if isinstance(exc, httpx.TimeoutException) else "failed"
        return {"explanation": "", "runs": [_run("LLMExplanation", status, started, [], ["openai_responses_api"], type(exc).__name__)]}


def finalize(state: WorkflowState) -> dict:
    findings = state.get("findings", [])
    category_hits = Counter(item.get("indicator", "").split(":", 1)[1] for item in findings if item.get("indicator", "").startswith("category:"))
    category = state.get("category", "other_suspicious")
    if category_hits:
        category = category_hits.most_common(1)[0][0]
    intel_status = {item["provider"]: item["status"] for item in state.get("intel_results", [])}
    if not intel_status:
        intel_run = next((run for run in state.get("runs", []) if run["agent_name"] == "ThreatIntelligence"), None)
        if intel_run and intel_run["status"] in {"failed", "timed_out", "unavailable", "skipped"}:
            intel_status = {"providers": intel_run["status"]}
    report = {
        "category": category,
        "risk_score": state.get("score", 0),
        "risk_level": state.get("risk_level", "Low"),
        "score_is_probability": False,
        "model_confidence": "not_available",
        "evidence_strength": evidence_strength(findings),
        "data_availability": {
            "threat_intelligence": intel_status or {"google_safe_browsing":"not_queried", "virustotal":"not_queried"},
            "llm": next((run["status"] for run in reversed(state.get("runs", [])) if run["agent_name"] == "LLMExplanation"), "not_run"),
        },
        "findings": findings,
        "evidence": [e for run in state.get("runs", []) for e in run.get("evidence", [])],
        "agents": state.get("runs", []),
        "urls": state.get("urls", []),
        "threat_intel_results": state.get("intel_results", []),
        "url_scans": state.get("url_scan_results", []),
        "redactions": state.get("redactions", []),
        "recommendations": state.get("recommendation", []),
        "explanation": state.get("explanation", ""),
        "limitations": ["No known threat found does not mean a URL is safe.", "The weighted risk score is not a calibrated probability.", "URL paths and query strings are omitted before storage and threat-intel lookup."],
    }
    return {"report": report}


def build_workflow():
    graph = StateGraph(WorkflowState)
    graph.add_node("prepare", prepare)
    graph.add_node("router", router)
    graph.add_node("message_agent", guarded_agent(["MessageAnalysis"], message_agent))
    graph.add_node("url_agent", guarded_agent(["URLInvestigation"], url_agent))
    graph.add_node("threat_intelligence_agent", guarded_agent(["ThreatIntelligence"], threat_intelligence_agent))
    graph.add_node("impersonation_agent", guarded_agent(["Impersonation"], impersonation_agent))
    graph.add_node("conversation_agent", guarded_agent(["ConversationAnalysis"], conversation_agent))
    graph.add_node("reconcile", reconcile)
    graph.add_node("risk_assessment", risk_assessment)
    graph.add_node("recommend", recommend)
    graph.add_node("explain", guarded_agent(["LLMExplanation"], explain))
    graph.add_node("finalize", finalize)
    graph.add_edge(START, "prepare")
    graph.add_edge("prepare", "router")
    graph.add_conditional_edges("router", route_agents)
    graph.add_edge(["message_agent", "url_agent", "impersonation_agent", "conversation_agent"], "threat_intelligence_agent")
    graph.add_edge("threat_intelligence_agent", "reconcile")
    graph.add_edge("reconcile", "risk_assessment")
    graph.add_edge("risk_assessment", "recommend")
    graph.add_edge("recommend", "explain")
    graph.add_edge("explain", "finalize")
    graph.add_edge("finalize", END)
    return graph.compile()


_WORKFLOW = build_workflow()


def investigate(text: str, input_type: str) -> dict:
    result = _WORKFLOW.invoke({"input_text": text, "input_type": input_type, "findings": [], "runs": [], "intel_results": []})
    return result["report"]
