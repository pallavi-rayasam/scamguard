"""Build a compact PDF from the persisted investigation report snapshot."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from io import BytesIO
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


def _plain(value: object) -> str:
    return escape(str(value if value is not None else "")).replace("\n", "<br/>")


def _local_timestamp(value: object, time_zone: str) -> str:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            value = None
    if not isinstance(value, datetime):
        return "Timestamp unavailable"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    try:
        zone = ZoneInfo(time_zone)
    except ZoneInfoNotFoundError as exc:
        raise ValueError("Unknown IANA time zone") from exc
    return value.astimezone(zone).strftime("%Y-%m-%d %H:%M:%S %Z")


def build_investigation_pdf(report: dict, created_at: datetime, time_zone: str = "UTC") -> bytes:
    """Render an export from stored report data without recomputing the investigation."""
    buffer = BytesIO()
    page_width, page_height = A4
    styles = getSampleStyleSheet()
    title = ParagraphStyle("ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=19, leading=23, textColor=colors.HexColor("#17324d"), spaceAfter=5 * mm)
    heading = ParagraphStyle("ReportHeading", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=colors.HexColor("#176b63"), spaceBefore=5 * mm, spaceAfter=2 * mm, keepWithNext=True)
    body = ParagraphStyle("ReportBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=9, leading=12, spaceAfter=1.4 * mm, wordWrap="LTR")
    small = ParagraphStyle("ReportSmall", parent=body, fontSize=8, leading=10)
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=19 * mm,
        leftMargin=19 * mm,
        topMargin=17 * mm,
        bottomMargin=18 * mm,
        title="ScamGuard Investigation Report",
        author="ScamGuard",
        subject="Stored advisory investigation report",
    )
    story = [
        Paragraph("ScamGuard Investigation Report", title),
        Paragraph(f"Created: {_plain(_local_timestamp(created_at, time_zone))}", small),
        Spacer(1, 2 * mm),
        Paragraph("Summary", heading),
        Paragraph(f"<b>Risk score:</b> {_plain(report.get('risk_score', 'Unavailable'))} / 100", body),
        Paragraph(f"<b>Risk level:</b> {_plain(report.get('risk_level', 'Unavailable'))}", body),
        Paragraph(f"<b>Category:</b> {_plain(report.get('category') or 'No scam pattern detected')}", body),
        Paragraph(f"<b>Input type:</b> {_plain(report.get('input_type', 'Unavailable'))}", body),
    ]

    story.append(Paragraph("Indicators and verification", heading))
    findings = report.get("findings") or []
    if findings:
        for item in findings:
            story.append(Paragraph(
                f"<b>{_plain(item.get('indicator', 'Indicator'))}</b> "
                f"[{_plain(item.get('verification_level', 'unspecified'))}]",
                body,
            ))
            story.append(Paragraph(_plain(item.get("detail", "")), small))
    else:
        story.append(Paragraph("No indicators were recorded.", body))

    story.append(Paragraph("Evidence timeline (local time)", heading))
    evidence = report.get("evidence") or []
    if evidence:
        for item in evidence:
            timestamp = item.get("timestamp", item.get("observed_at"))
            story.append(Paragraph(
                f"<b>{_plain(item.get('source', 'Evidence'))}</b> "
                f"[{_plain(item.get('verification_level', 'unspecified'))}] - "
                f"{_plain(_local_timestamp(timestamp, time_zone))}",
                small,
            ))
    else:
        story.append(Paragraph("No timestamped evidence records were stored.", body))

    story.append(Paragraph("URL and provider status", heading))
    urls = report.get("urls") or []
    url_scans = {item.get("origin"): item for item in report.get("url_scans") or [] if isinstance(item, dict) and item.get("origin")}
    if urls:
        for url in urls:
            scan = url_scans.get(url, {})
            state = scan.get("status", "not checked")
            reason = scan.get("reason")
            suffix = f" - {_plain(reason)}" if reason else ""
            story.append(Paragraph(f"<b>URL:</b> {_plain(url)} | <b>Analysis:</b> {_plain(state)}{suffix}", small))
    else:
        story.append(Paragraph("No URLs were extracted.", body))
    providers = report.get("threat_intel_results") or []
    if providers:
        for result in providers:
            story.append(Paragraph(
                f"<b>{_plain(result.get('provider', 'Provider'))}:</b> "
                f"{_plain(result.get('status', 'unavailable'))}"
                + (f" - {_plain(result.get('reason'))}" if result.get("reason") else ""),
                small,
            ))
    else:
        story.append(Paragraph("No provider results were recorded.", body))

    story.append(Paragraph("Agent audit", heading))
    agents = report.get("agents") or []
    if agents:
        for agent in agents:
            tools = ", ".join(str(tool) for tool in (agent.get("tools_used") or [])) or "none"
            error = f" | Error: {_plain(agent.get('error'))}" if agent.get("error") else ""
            story.append(Paragraph(
                f"<b>{_plain(agent.get('agent_name', 'Agent'))}</b> - "
                f"{_plain(agent.get('status', 'unavailable'))}; "
                f"{_plain(agent.get('duration_ms', 0))} ms; "
                f"Tools: {_plain(tools)}{error}",
                small,
            ))
    else:
        story.append(Paragraph("No agent audit records were stored.", body))

    story.append(Paragraph("Recommendations", heading))
    recommendations = report.get("recommendations") or []
    if recommendations:
        for index, recommendation in enumerate(recommendations, 1):
            story.append(Paragraph(f"{index}. {_plain(recommendation)}", body))
    else:
        story.append(Paragraph("No recommendations were stored.", body))

    story.append(Paragraph("Limitations", heading))
    limitations = report.get("limitations") or []
    if limitations:
        for item in limitations:
            story.append(Paragraph(f"- {_plain(item)}", body))
    else:
        story.append(Paragraph("No limitations were stored in the report snapshot.", body))

    def footer(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#d7e1e8"))
        canvas.line(document.leftMargin, 13 * mm, page_width - document.rightMargin, 13 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#5a6d7c"))
        canvas.drawString(document.leftMargin, 8.5 * mm, "ScamGuard - advisory report")
        canvas.drawRightString(page_width - document.rightMargin, 8.5 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
