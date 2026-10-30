"""PDF report rendering."""
import json
from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def render_scan_report_pdf(report: dict[str, Any]) -> bytes:
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"Scan Report {report['scan']['id']}",
        author="007 Security Scanner",
    )
    styles = getSampleStyleSheet()
    styles["Title"].alignment = TA_CENTER
    styles.add(ParagraphStyle(
        "ReportSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        wordWrap="CJK",
    ))
    styles.add(ParagraphStyle(
        "ReportTableHeader",
        parent=styles["ReportSmall"],
        textColor=colors.white,
        fontName="Helvetica-Bold",
    ))
    story: list[Any] = []

    def paragraph(value: Any, style: str = "BodyText") -> Paragraph:
        text = escape(str(value if value is not None else ""))
        return Paragraph(text.replace("\n", "<br/>"), styles[style])

    def section(title: str) -> None:
        story.extend((Spacer(1, 8), paragraph(title, "Heading2")))

    def table(headers: list[str], rows: list[list[Any]], widths: list[float]) -> None:
        data = [[paragraph(value, "ReportTableHeader") for value in headers]]
        data.extend(
            [[value if isinstance(value, Paragraph) else paragraph(value, "ReportSmall") for value in row]
             for row in rows]
        )
        if len(data) == 1:
            data.append([paragraph("None", "ReportSmall") for _ in headers])
        report_table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        report_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#18324b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5df")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f5f8")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(report_table)

    page_width = A4[0] - 36 * mm
    story.extend([
        paragraph("Security Scan Report", "Title"),
        Spacer(1, 8),
        paragraph(f"Target: {report['target']['name']}", "Heading2"),
        paragraph(f"Base URL: {report['target']['base_url']}"),
    ])
    section("Scan summary")
    scan = report["scan"]
    table(
        ["Scan ID", "Status", "Started", "Finished"],
        [[scan["id"], scan["status"], scan["started_at"], scan["finished_at"] or "Not finished"]],
        [page_width * 0.12, page_width * 0.14, page_width * 0.37, page_width * 0.37],
    )
    story.extend((Spacer(1, 5), paragraph(f"Summary: {scan['summary']}")))

    section("Stages")
    table(
        ["Stage", "Status", "Error"],
        [[stage["name"], stage["status"], stage.get("error") or ""] for stage in report["stages"]],
        [page_width * 0.3, page_width * 0.18, page_width * 0.52],
    )

    section("Inventory snapshots")
    snapshots = report["inventory_snapshots"]
    for snapshot in snapshots:
        story.append(paragraph(
            f"{snapshot['endpoint_count']} endpoints · captured {snapshot['created_at']}",
            "Heading3",
        ))
        endpoints = json.dumps(snapshot["endpoints"], ensure_ascii=True, indent=2)
        story.append(paragraph(endpoints, "ReportSmall"))
        story.append(Spacer(1, 4))
    if not snapshots:
        story.append(paragraph("No inventory snapshots."))

    section("Audit events")
    table(
        ["Event", "Decision", "Details", "Created"],
        [[event["event_type"], event["decision"], event["details"], event["created_at"]]
         for event in report["audit_events"]],
        [page_width * 0.18, page_width * 0.14, page_width * 0.4, page_width * 0.28],
    )

    section("Findings")
    findings = report["findings"]
    if not findings:
        story.append(paragraph("No findings recorded for this scan."))
    for finding in findings:
        story.append(paragraph(f"{finding['title']} (#{finding['id']})", "Heading3"))
        table(
            ["Severity", "Category", "Confidence", "Status", "Verified"],
            [[finding["severity"], finding["category"], finding["confidence"], finding["status"], str(finding["verified"])]],
            [page_width * 0.2] * 5,
        )
        story.extend([
            paragraph(f"Affected endpoint: {finding['affected_endpoint']}"),
            paragraph(f"Business impact: {finding['business_impact']}"),
            paragraph(f"Owner: {finding['owner']}"),
            paragraph("Reproduction steps:", "Heading4"),
        ])
        story.extend(paragraph(f"{index}. {step}") for index, step in enumerate(finding["reproduction_steps"], 1))
        story.append(paragraph("Evidence:", "Heading4"))
        if finding["evidence"]:
            table(
                ["Kind", "Summary", "Redacted"],
                [[item["kind"], item["summary"], str(item["redacted"])] for item in finding["evidence"]],
                [page_width * 0.18, page_width * 0.62, page_width * 0.2],
            )
        else:
            story.append(paragraph("No evidence recorded."))
        story.extend([
            paragraph("Remediation:", "Heading4"),
            paragraph(finding["remediation"]),
        ])

    document.build(story)
    return buffer.getvalue()


def render_executive_report_pdf(report: dict[str, Any]) -> bytes:
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"Executive Security Report - Target {report['target_id']}",
        author="007 Security Scanner",
    )
    styles = getSampleStyleSheet()
    styles["Title"].alignment = TA_CENTER
    styles.add(ParagraphStyle(
        "ExecutiveReportSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        wordWrap="CJK",
    ))
    styles.add(ParagraphStyle(
        "ExecutiveReportTableHeader",
        parent=styles["ExecutiveReportSmall"],
        textColor=colors.white,
        fontName="Helvetica-Bold",
    ))
    page_width = A4[0] - 36 * mm
    story: list[Any] = []

    def paragraph(value: Any, style: str = "BodyText") -> Paragraph:
        text = escape(str(value if value is not None else ""))
        return Paragraph(text.replace("\n", "<br/>"), styles[style])

    def section(title: str) -> None:
        story.extend((Spacer(1, 8), paragraph(title, "Heading2")))

    def table(headers: list[str], rows: list[list[Any]], widths: list[float]) -> None:
        data = [[paragraph(value, "ExecutiveReportTableHeader") for value in headers]]
        data.extend(
            [[paragraph(value, "ExecutiveReportSmall") for value in row] for row in rows]
        )
        if len(data) == 1:
            data.append([paragraph("None", "ExecutiveReportSmall") for _ in headers])
        report_table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        report_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#18324b")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5df")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f5f8")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(report_table)

    story.extend([
        paragraph("Executive Security Report", "Title"),
        Spacer(1, 8),
        paragraph(f"Target {report['target_id']} · Generated {report['generated_at']}"),
    ])
    section("Risk overview")
    table(
        ["Risk score", "Vulnerabilities", "Risk scale"],
        [[report["risk_score"], report["vulnerability_count"], report["risk_scale"]]],
        [page_width * 0.18, page_width * 0.22, page_width * 0.6],
    )

    section("Severity counts")
    table(
        ["Severity", "Findings"],
        [[severity.title(), count] for severity, count in report["severity_counts"].items()],
        [page_width * 0.5, page_width * 0.5],
    )

    section("Most affected business flows")
    table(
        ["Flow", "Findings", "Critical", "High"],
        [[flow["flow"], flow["vulnerabilities"], flow["critical"], flow["high"]]
         for flow in report["top_vulnerable_business_flows"]],
        [page_width * 0.4, page_width * 0.2, page_width * 0.2, page_width * 0.2],
    )

    section("Remediation")
    remediation = report["remediation"]
    table(
        ["Open findings", "Tickets", "Resolved", "Mean resolution days"],
        [[
            remediation["open_findings"],
            remediation["tickets"],
            remediation["tickets_resolved"],
            remediation["mean_ticket_resolution_days"] if remediation["mean_ticket_resolution_days"] is not None else "N/A",
        ]],
        [page_width * 0.22, page_width * 0.18, page_width * 0.2, page_width * 0.4],
    )

    section("Remediation guidance")
    if report["guidance"]:
        story.extend(
            paragraph(f"{index}. {guidance}")
            for index, guidance in enumerate(report["guidance"], 1)
        )
    else:
        story.append(paragraph("No remediation guidance available."))

    document.build(story)
    return buffer.getvalue()
