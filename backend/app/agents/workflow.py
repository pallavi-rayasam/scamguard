"""Deterministic LangGraph orchestration for independent investigation stages."""
from collections import Counter
from datetime import datetime, timezone
import json
import logging
import operator
import re
import time
from typing import Annotated, TypedDict
from concurrent.futures import ThreadPoolExecutor

from langgraph.graph import END, START, StateGraph
import httpx

from app.agents.contracts import AgentResult
from app.core.config import settings
from app.detection.normalize import extract_urls_for_scan, load_organization_domains, normalize_text, privacy_safe_url, redact_sensitive, redact_urls_in_text
from app.detection.rules import classify_message
from app.detection.scoring import evidence_strength, score_findings
from app.detection.conversation import analyze_conversation, parse_conversation_text
from app.detection.transaction import assess_pre_transaction
from app.detection.url_checks import inspect_url
from app.intel.providers import check_url_reputation
from app.llm.provider import get_explanation_provider

ORG_TO_DOMAINS = load_organization_domains()
ORG_TOKENS = (*ORG_TO_DOMAINS.keys(), "police", "electricity board")
THREAT_INTEL_PROVIDERS = ("google_safe_browsing", "virustotal")
THREAT_INTEL_STATUSES = {"completed", "skipped", "failed", "timed_out", "unavailable"}
logger = logging.getLogger(__name__)


class WorkflowState(TypedDict, total=False):
    input_text: str
    input_type: str
    normalized_text: str
    redacted_text: str
    redactions: list[str]
    urls: list[str]
    category: str | None
    findings: Annotated[list[dict], operator.add]
    runs: Annotated[list[dict], operator.add]
    intel_results: Annotated[list[dict], operator.add]
    recommendation: list[str]
    explanation: str
    url_scan_results: list[dict]
    score: int
    risk_level: str
    report: dict
    conversation_messages: list[dict]
    transaction_context: dict
    transaction_advisory: dict


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
        except (httpx.TimeoutException, TimeoutError) as exc:
            if "LLMExplanation" in names:
                _log_llm_failure(exc, "timed_out")
            return {"runs": [_run(name, "timed_out", started, [], [], "Agent timed out.") for name in names]}
        except Exception as exc:
            if "LLMExplanation" in names:
                _log_llm_failure(exc, "failed")
            return {"runs": [_run(name, "failed", started, [], [], type(exc).__name__) for name in names]}
    return invoke


def _log_llm_failure(exc: Exception, status: str) -> None:
    """Log provider diagnostics without exception text, request content, or credentials."""
    fields: dict[str, object] = {
        "event": "llm_provider_failure",
        "provider": settings.llm_provider,
        "status": status,
        "exception_type": type(exc).__name__,
    }
    if isinstance(exc, ValueError):
        # Only emit a fixed category. Exception text from parsers/model output can
        # contain submitted content, so it is intentionally never copied to logs.
        category = getattr(exc, "diagnostic_category", None)
        allowed_categories = {
            "response_json_invalid",
            "response_shape_invalid",
            "choices_missing",
            "response_truncated",
            "message_content_missing",
            "structured_output_invalid",
            "evidence_quote_mismatch",
        }
        fields["failure_category"] = category if category in allowed_categories else "invalid_provider_response"
    if isinstance(exc, httpx.ReadTimeout):
        fields["failure_category"] = "read_timeout"
    elif isinstance(exc, httpx.ConnectTimeout):
        fields["failure_category"] = "connect_timeout"
    elif isinstance(exc, httpx.ConnectError):
        fields["failure_category"] = "connection_failure"
    elif isinstance(exc, TimeoutError):
        fields["failure_category"] = "overall_timeout"

    if isinstance(exc, httpx.HTTPStatusError):
        response = exc.response
        fields["http_status"] = response.status_code
        try:
            payload = response.json()
        except ValueError:
            payload = None
        error = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(error, dict):
            provider_fields: dict[str, str] = {}
            for key in ("type", "status", "code", "param"):
                value = error.get(key)
                if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.\-\[\]]{1,80}", value):
                    fields[f"provider_error_{key}"] = value
                    provider_fields[key] = value.casefold()
            # Classify common provider failures using response metadata in memory only. Never
            # log the provider message, which could contain echoed request material.
            provider_message = error.get("message")
            provider_message = provider_message.casefold() if isinstance(provider_message, str) else ""
            provider_status = provider_fields.get("status", "")
            provider_code = provider_fields.get("code", "")
            provider_type = provider_fields.get("type", "")
            model_error = "model" in (provider_code + " " + provider_message) and any(
                term in provider_code + " " + provider_message
                for term in ("not found", "does not exist", "unavailable", "invalid")
            )
            if response.status_code in {401, 403} or provider_status in {"unauthenticated", "permission_denied"} or (
                response.status_code == 400 and "api key" in provider_message
                and any(term in provider_message for term in ("invalid", "not valid", "expired"))
            ):
                fields["failure_category"] = "authentication_failure"
            elif response.status_code == 404 or provider_status == "not_found" or model_error:
                fields["failure_category"] = "model_or_endpoint_not_found"
            elif response.status_code == 402:
                fields["failure_category"] = "quota_exhausted"
            elif response.status_code == 429:
                classification = " ".join((provider_type, provider_status, provider_code, provider_message))
                if any(term in classification for term in ("quota", "billing", "credit", "daily limit")):
                    fields["failure_category"] = "quota_exhausted"
                elif any(term in classification for term in ("rate limit", "rate_limit", "too many requests", "per minute")):
                    fields["failure_category"] = "rate_limited"
                else:
                    fields["failure_category"] = "quota_or_rate_limit"
        elif response.status_code == 429:
            fields["failure_category"] = "quota_or_rate_limit"
        elif response.status_code in {401, 403}:
            fields["failure_category"] = "authentication_failure"
        elif response.status_code == 402:
            fields["failure_category"] = "quota_exhausted"
        elif response.status_code == 404:
            fields["failure_category"] = "model_or_endpoint_not_found"
        elif response.status_code == 429:
            fields["failure_category"] = "quota_or_rate_limit"
        elif response.status_code >= 500:
            fields["failure_category"] = "provider_unavailable"
    logger.warning("llm_provider_failure %s", json.dumps(fields, sort_keys=True))


def prepare(state: WorkflowState) -> dict:
    started = time.monotonic()
    original = normalize_text(state.get("input_text", ""))
    urls = extract_urls_for_scan(original)
    redacted, redactions = redact_sensitive(original)
    redacted = redact_urls_in_text(redacted, [privacy_safe_url(url) for url in urls])
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


def _unavailable_reputation_response(reason: str, origin: str | None = None) -> dict:
    return {
        "status": "unavailable",
        "reason": reason,
        "origin": origin,
        "threat_intel_results": [
            {"provider": provider, "status": "unavailable", "is_malicious": None, "reason": reason}
            for provider in THREAT_INTEL_PROVIDERS
        ],
    }


def _normalize_reputation_response(payload: object, expected_origin: str) -> dict:
    """Validate the scanner response and return exactly one explicit result per provider."""
    if not isinstance(payload, dict):
        return _unavailable_reputation_response("invalid_scanner_response", expected_origin)
    overall_status = payload.get("status")
    if not isinstance(overall_status, str) or overall_status not in {"completed", "blocked", "unavailable"}:
        return _unavailable_reputation_response("invalid_scanner_response", expected_origin)
    if payload.get("origin") != expected_origin:
        return _unavailable_reputation_response("scanner_origin_mismatch", expected_origin)
    if overall_status != "completed":
        return _unavailable_reputation_response(
            payload.get("reason") if isinstance(payload.get("reason"), str) else f"scanner_{overall_status}",
            expected_origin,
        )

    raw_results = payload.get("threat_intel_results")
    if not isinstance(raw_results, list):
        return _unavailable_reputation_response("invalid_scanner_response", expected_origin)

    grouped: dict[str, list[dict]] = {provider: [] for provider in THREAT_INTEL_PROVIDERS}
    for item in raw_results:
        if isinstance(item, dict):
            provider = item.get("provider")
            if isinstance(provider, str) and provider in grouped:
                grouped[provider].append(item)

    normalized: list[dict] = []
    for provider in THREAT_INTEL_PROVIDERS:
        candidates = grouped[provider]
        if len(candidates) != 1:
            reason = "scanner_provider_result_missing" if not candidates else "scanner_provider_result_ambiguous"
            normalized.append({"provider": provider, "status": "unavailable", "is_malicious": None, "reason": reason})
            continue

        item = candidates[0]
        provider_status = item.get("status")
        malicious = item.get("is_malicious")
        valid_malicious = malicious is None or isinstance(malicious, bool)
        if (
            not isinstance(provider_status, str)
            or provider_status not in THREAT_INTEL_STATUSES
            or not valid_malicious
            or (provider_status != "completed" and malicious is not None)
            or (provider == "google_safe_browsing" and provider_status == "completed" and not isinstance(malicious, bool))
        ):
            normalized.append({"provider": provider, "status": "unavailable", "is_malicious": None, "reason": "invalid_scanner_response"})
            continue

        normalized_item = {
            "provider": provider,
            "status": provider_status,
            "is_malicious": malicious,
        }
        for key in ("reason", "detail", "checked_at", "cached", "retry_count"):
            value = item.get(key)
            if isinstance(value, (str, bool, int)):
                normalized_item[key] = value
        normalized.append(normalized_item)

    return {
        "status": "completed",
        "reason": None,
        "origin": expected_origin,
        "threat_intel_results": normalized,
    }


def _query_url_reputation_service(url: str, expected_origin: str) -> dict:
    """Ask the scanner's reputation stage to revalidate and query provider results."""
    endpoint = settings.url_scanner_url.rstrip("/") + "/reputation"
    try:
        with httpx.Client(timeout=15.0, follow_redirects=False) as client:
            response = client.post(endpoint, json={"url": url})
        if response.status_code == 429:
            return _unavailable_reputation_response("scanner_rate_limited", expected_origin)
        response.raise_for_status()
        return _normalize_reputation_response(response.json(), expected_origin)
    except httpx.TimeoutException:
        reason = "scanner_timed_out"
    except (httpx.HTTPError, ValueError):
        reason = "scanner_unavailable"
    return _unavailable_reputation_response(reason, expected_origin)

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

    if state.get("input_type") == "screenshot":
        findings = [finding for url in urls for finding in inspect_url(url)]
        scan_results = [
            {"origin": url, "status": "skipped", "reason": "screenshot_extracted_link_not_opened", "findings": []}
            for url in urls
        ]
        return {
            "findings": findings,
            "url_scan_results": scan_results,
            "runs": [_run("URLInvestigation", "completed", started, findings, ["url_structure_check"])],
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


def threat_intelligence_agent(state: WorkflowState) -> dict:
    """Query and reconcile reputation outcomes as a separate graph node."""
    started = time.monotonic()
    urls = state.get("urls", [])
    if not urls:
        return {"runs": [_run("ThreatIntelligence", "skipped", started, [], [], "No URL was available for lookup.")]}

    if state.get("input_type") == "screenshot":
        return {
            "runs": [_run("ThreatIntelligence", "skipped", started, [], [], "External lookups are disabled for screenshot-extracted links.")],
        }

    scan_results = state.get("url_scan_results", [])
    if settings.url_scanner_url:
        scan_requests = [
            (url, scan_results[index] if index < len(scan_results) else None)
            for index, url in enumerate(urls)
        ]

        def query_scan_result(scan_request: tuple[str, dict | None]) -> dict:
            url, scan_result = scan_request
            expected_origin = privacy_safe_url(url)
            if not isinstance(scan_result, dict):
                return _unavailable_reputation_response("scanner_analysis_result_missing", expected_origin)
            scan_origin = scan_result.get("origin")
            if not scan_origin:
                reason = scan_result.get("reason") if isinstance(scan_result.get("reason"), str) else "target_not_publicly_validated"
                return _unavailable_reputation_response(reason, expected_origin)
            if scan_origin != expected_origin:
                return _unavailable_reputation_response("scanner_origin_mismatch", expected_origin)
            return _query_url_reputation_service(url, expected_origin)

        with ThreadPoolExecutor(max_workers=max(1, min(6, len(scan_requests)))) as pool:
            reputation_batches = list(pool.map(query_scan_result, scan_requests))
        intel_results = [
            {**item, "origin": privacy_safe_url(url)}
            for (url, _scan_result), batch in zip(scan_requests, reputation_batches, strict=True)
            for item in batch.get("threat_intel_results", [])
        ]
    else:
        with ThreadPoolExecutor(max_workers=max(1, min(6, len(urls)))) as pool:
            reputation_batches = list(pool.map(check_url_reputation, urls))
        intel_results = [
            {**item, "origin": privacy_safe_url(url)}
            for url, batch in zip(urls, reputation_batches)
            for item in batch
        ]

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
        if result.get("status") != "completed" or result.get("is_malicious") is not True:
            continue
        provider = result.get("provider", "threat_intel")
        findings.append({
            "indicator": f"threat_intel:{provider}",
            "detail": result.get("detail", "Provider confirmed a known-threat match."),
            "verification_level": "verified",
            "source": provider,
            "score_weight": 40,
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
    input_type = state.get("input_type")
    messages = state.get("conversation_messages") or []
    if not messages and input_type == "conversation":
        messages = parse_conversation_text(state.get("normalized_text", ""))
    if not messages or input_type not in {"conversation", "transaction"}:
        return {"runs": [_run("ConversationAnalysis", "skipped", started, [], [], "No conversation sequence was supplied.")]}
    analysis = analyze_conversation(messages)
    findings = analysis["findings"]
    return {"findings": findings, "runs": [_run("ConversationAnalysis", "completed", started, findings, ["conversation_sequence_rules"])]}

def reconcile(state: WorkflowState) -> dict:
    started = time.monotonic()
    results_by_origin: dict[str | None, set[bool]] = {}
    for item in state.get("intel_results", []):
        if item.get("status") == "completed" and item.get("is_malicious") is not None:
            results_by_origin.setdefault(item.get("origin"), set()).add(bool(item["is_malicious"]))
    findings = []
    if any({True, False} <= verdicts for verdicts in results_by_origin.values()):
        findings.append({"indicator":"intel_provider_conflict", "detail":"Configured threat-intel providers returned conflicting reputation results.", "verification_level":"heuristic", "source":"reconciliation", "score_weight":8})
    return {"findings": findings, "runs": [_run("VerifyAndReconcile", "completed", started, findings, ["conflict_check"])]}


def risk_assessment(state: WorkflowState) -> dict:
    started = time.monotonic()
    findings = state.get("findings", [])
    transaction_context = state.get("transaction_context")
    transaction_advisory = None
    transaction_findings: list[dict] = []
    if transaction_context is not None:
        transaction = assess_pre_transaction(**transaction_context)
        transaction_findings = transaction["findings"]
        findings = findings + transaction_findings
        transaction_advisory = {
            "advisory_only": True,
            "advisory": transaction["advisory"],
            "recipient_identity_check": transaction["recipient_identity_check"],
            "claimed_recipient_provided": transaction["claimed_recipient_provided"],
            "amount_provided": transaction["amount_provided"],
            "payment_initiated": False,
            "risk_score": transaction["risk_score"],
            "risk_level": transaction["risk_level"],
            "recommendations": transaction["recommendations"],
        }
        transaction_run = _run("PreTransactionRisk", "completed", started, transaction_findings, ["pre_transaction_rules"])
    else:
        transaction_run = _run("PreTransactionRisk", "skipped", started, [], [], "Input is not a pre-transaction request.")
    score, level, _ = score_findings(findings)
    return {
        "findings": transaction_findings,
        "score": score,
        "risk_level": level,
        "transaction_advisory": transaction_advisory,
        "runs": [transaction_run, _run("RiskAssessment", "completed", started, [], ["weighted_indicator_scorer"])],
    }

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
        return {"explanation": "", "runs": [_run("LLMExplanation", "skipped", started, [], [], "Configured LLM provider is not available; deterministic report remains available.")]}
    provider_tool = {
        "openai": "openai_responses_api",
        "gemini": "gemini_interactions_api",
        "groq": "groq_chat_completions_api",
    }.get(settings.llm_provider, f"{settings.llm_provider}_api")
    summary = {
        "category": state.get("category"),
        "risk_score": state.get("score"),
        "risk_level": state.get("risk_level"),
        "indicators": [
            indicator[:100]
            for item in state.get("findings", [])
            if isinstance((indicator := item.get("indicator")), str)
        ][:20],
    }
    try:
        explanation = provider.explain(state.get("redacted_text", ""), summary)
        finding = {"indicator":"llm_explanation", "detail":explanation, "verification_level":"llm_inferred", "source":provider_tool, "score_weight":0}
        return {"explanation": explanation, "findings": [finding], "runs": [_run("LLMExplanation", "completed", started, [finding], [provider_tool])]}
    except (httpx.HTTPError, RuntimeError, ValueError, TimeoutError) as exc:
        status = "timed_out" if isinstance(exc, (httpx.TimeoutException, TimeoutError)) else "failed"
        _log_llm_failure(exc, status)
        return {"explanation": "", "runs": [_run("LLMExplanation", status, started, [], [provider_tool], type(exc).__name__)]}


def finalize(state: WorkflowState) -> dict:
    findings = state.get("findings", [])
    category_hits = Counter(item.get("indicator", "").split(":", 1)[1] for item in findings if item.get("indicator", "").startswith("category:"))
    category = state.get("category")
    if category_hits:
        category = category_hits.most_common(1)[0][0]
    intel_status = {item["provider"]: item["status"] for item in state.get("intel_results", [])}
    if not intel_status:
        intel_run = next((run for run in state.get("runs", []) if run["agent_name"] == "ThreatIntelligence"), None)
        if intel_run and intel_run["status"] in {"failed", "timed_out", "unavailable", "skipped"}:
            intel_status = {"providers": intel_run["status"]}
    limitations = [
        "No known threat found does not mean a URL is safe.",
        "The weighted risk score is not a calibrated probability.",
        "URL paths and query parameters are sent to reputation providers for URL-specific checks; fragments are excluded and full URLs are omitted from the report.",
    ]
    if state.get("input_type") == "screenshot":
        limitations.append("Screenshot-extracted URLs receive structural checks only; they are not opened or sent to external reputation providers.")
    report_urls = list(dict.fromkeys(
        safe_url
        for url in state.get("urls", [])
        if (safe_url := privacy_safe_url(url))
    ))
    report = {
        "input_type": state.get("input_type"),
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
        "urls": report_urls,
        "threat_intel_results": state.get("intel_results", []),
        "url_scans": state.get("url_scan_results", []),
        "redactions": state.get("redactions", []),
        "recommendations": state.get("recommendation", []),
        "transaction_advisory": state.get("transaction_advisory"),
        "explanation": state.get("explanation", ""),
        "limitations": limitations,
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


def investigate(text: str, input_type: str, *, conversation_messages: list[dict] | None = None, transaction_context: dict | None = None) -> dict:
    result = _WORKFLOW.invoke({"input_text": text, "input_type": input_type, "conversation_messages": conversation_messages or [], "transaction_context": transaction_context, "findings": [], "runs": [], "intel_results": []})
    return result["report"]
