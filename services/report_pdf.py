"""Read-only, monochrome case report export. No model calls or audit mutations."""

from io import BytesIO
import json
from pathlib import Path
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer


def build_report_pdf(case_id, incident, alerts, flows, state):
    record = state.get("record") or {}
    regular, bold = "Helvetica", "Helvetica-Bold"
    if any("\u3400" <= c <= "\u9fff" for c in json.dumps(state, ensure_ascii=False)):
        font = Path("C:/Windows/Fonts/msyh.ttc")
        if font.exists():
            if "ReportCJK" not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont("ReportCJK", str(font), subfontIndex=0))
                pdfmetrics.registerFont(
                    TTFont("ReportCJKBold", "C:/Windows/Fonts/msyhbd.ttc", subfontIndex=0)
                )
                pdfmetrics.registerFontFamily(
                    "ReportCJK",
                    normal="ReportCJK",
                    bold="ReportCJKBold",
                    italic="ReportCJK",
                    boldItalic="ReportCJKBold",
                )
            regular, bold = "ReportCJK", "ReportCJKBold"
        else:
            pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
            regular = bold = "STSong-Light"
    output = BytesIO()
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportBody",
            fontName=regular,
            fontSize=10,
            leading=15,
            spaceAfter=7,
            textColor=colors.black,
            splitLongWords=True,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ReportHeading",
            fontName=bold,
            fontSize=13,
            leading=18,
            spaceBefore=16,
            spaceAfter=8,
            keepWithNext=True,
        )
    )
    styles.add(
        ParagraphStyle(name="ReportSmall", parent=styles["ReportBody"], fontSize=8, leading=12)
    )
    styles["Title"].fontName = bold
    styles["Title"].textColor = colors.black
    story = []

    def clean(value):
        return (
            escape(str(value if value is not None else "Not recorded"))
            .replace("\n", "<br/>")
            .replace("→", "-&gt;")
            .replace("—", "-")
            .replace("·", " / ")
        )

    def para(value, small=False):
        story.append(Paragraph(clean(value), styles["ReportSmall" if small else "ReportBody"]))

    def field(label, value):
        story.append(Paragraph(f"<b>{clean(label)}:</b> {clean(value)}", styles["ReportBody"]))

    def heading(value):
        story.append(Paragraph(clean(value), styles["ReportHeading"]))

    def evidence(ids, label="Evidence"):
        if ids:
            field(label, ", ".join(ids))

    story.append(Paragraph("Triage report", styles["Title"]))
    field("Case", case_id)
    field(
        "Report status",
        "Saved snapshot" if state.get("status") in ("saved", "resolved") else "Draft - not saved",
    )
    if state.get("event_id"):
        field("Record ID", state["event_id"])
        field("Saved at (UTC)", state.get("saved_at"))
    field("Rule signal", incident.get("type"))
    field(
        "Communication path",
        f"{incident.get('source_ip', '-')} -> {incident.get('destination_ip', '-')}",
    )
    field(
        "Observed (dataset clock)",
        f"{incident.get('window_start', '-')} to {incident.get('window_end', '-')}",
    )
    field("Review priority", (record.get("review_priority") or {}).get("level"))

    heading("1. AI assessment")
    field("Verdict", record.get("ai_verdict") or "No verified AI result")
    field("Confidence", record.get("ai_confidence"))
    para(record.get("ai_summary") or record.get("ai_error") or "No AI assessment recorded.")
    if record.get("ai_limitations"):
        field("Limitations", record["ai_limitations"])
    for index, finding in enumerate(record.get("ai_findings") or [], 1):
        field(f"Finding {index}", finding.get("observation"))
        evidence(finding.get("evidence_ids"))

    heading("2. Supporting evidence")
    evidence(record.get("ai_evidence_ids"), "Assessment evidence")
    field(
        "Available evidence",
        f"{len(alerts)} alerts / {incident.get('flow_count', 0):,} matched flows / {len(flows)} sample flows",
    )
    for mapping in record.get("ai_mappings") or []:
        field(
            "MITRE ATT&CK proposal",
            f"{mapping.get('technique_id', 'Unmapped')} - {mapping.get('reason', '')}",
        )
        evidence([mapping["evidence_id"]] if mapping.get("evidence_id") else [], "Mapping evidence")
    para(
        "Rule matches and technique mappings are evidence-based signals, not confirmation of a successful attack."
    )

    heading("3. Recommended steps and analyst decisions")
    steps = record.get("investigation_steps") or []
    if not steps:
        para("No investigation steps recorded.")
    for index, step in enumerate(steps, 1):
        field(f"Step {index}", step.get("text"))
        field("Review decision", step.get("decision") or "Not reviewed")
        if step.get("reason"):
            field("Reason", step["reason"])
        if step.get("remark"):
            field("Approval remark", step["remark"])
        evidence(step.get("evidence_ids"))
        for event in step.get("events") or []:
            payload = event.get("payload") or {}
            field(
                "Activity",
                f"{event.get('ts', '-')} / {event.get('actor', '-')} / {event.get('event', '-')} / {payload.get('decision') or payload.get('note') or ''}",
            )

    heading("4. Investigation notes")
    notes = record.get("investigation_notes") or []
    if not notes:
        para("No investigation notes included in this report.")
    for note in notes:
        field("Recorded by / at (UTC)", f"{note.get('analyst', '-')} / {note.get('time', '-')}")
        para(note.get("text"))
        if note.get("evidence_id"):
            evidence([note["evidence_id"]])

    heading("5. Analyst review")
    review = record.get("analyst_review") or {}
    field("Decision", review.get("status") or record.get("ai_decision") or "Awaiting review")
    field("Reviewer", review.get("analyst") or "Not reviewed")
    field("Reviewed at (UTC)", review.get("at"))
    field("Review note", review.get("note") or "No note recorded")

    heading("6. AI activity and validation")
    field("Run ID", record.get("ai_run_id"))
    metadata = record.get("ai_run_metadata") or {}
    field(
        "Started / completed (UTC)",
        f"{metadata.get('started_at', '-')} / {metadata.get('completed_at', '-')}",
    )
    field(
        "Evidence validation",
        {True: "Passed", False: "Failed"}.get(
            (record.get("ai_validation") or {}).get("ok"), "Not recorded"
        ),
    )
    if metadata.get("duration_ms") is not None:
        field("Duration", f"{metadata['duration_ms'] / 1000:.2f} seconds")
    for call in (record.get("ai_investigation") or {}).get("tool_calls") or []:
        para(
            f"{call.get('tool', '-')} / {'Completed' if call.get('ok') else 'Blocked' if call.get('blocked') else 'Failed'} / {call.get('result_count', '-')} records"
        )

    heading("7. Activity trail")
    events = record.get("activity") or []
    if not events:
        para("No activity recorded in this report.")
    for event in events:
        payload = event.get("payload") or {}
        para(
            f"{event.get('ts', '-')} / {event.get('actor', '-')} / {event.get('event', '-')}",
            small=True,
        )
        detail = (
            payload.get("note")
            or payload.get("reason")
            or " / ".join(
                str(payload[key])
                for key in ("tool", "decision", "error_code")
                if payload.get(key) is not None
            )
        )
        if detail:
            para(detail, small=True)
        if event.get("event_id"):
            para(
                f"Event ID: {event['event_id']} / Hash: {event.get('hash', 'Not recorded')}",
                small=True,
            )

    heading("Appendix A. Alert evidence")
    for alert in alerts:
        field(
            alert.get("alert_id", "Alert"),
            f"{alert.get('timestamp', '-')} / {alert.get('rule_basis', 'No rule basis recorded')}",
        )

    heading("Appendix B. Sample flow evidence")
    para(
        "These are the available case samples, not the complete set of matched raw flows. Times use the dataset clock."
    )
    for flow in flows:
        para(
            f"{flow.get('flow_id', '-')} / {flow.get('timestamp', '-')} / {flow.get('source_ip', '-')}:{flow.get('source_port', '-')} -> {flow.get('destination_ip', '-')}:{flow.get('destination_port', '-')} / {flow.get('packet_count', '-')} packets",
            small=True,
        )

    def footer(canvas, doc):
        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(20 * mm, 12 * mm, str(case_id))
        canvas.drawRightString(A4[0] - 20 * mm, 12 * mm, f"Page {doc.page}")

    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm,
        title=f"Triage report - {case_id}",
        author="SOC Desk",
    )
    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
