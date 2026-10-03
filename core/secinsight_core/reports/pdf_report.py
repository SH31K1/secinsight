from __future__ import annotations

from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from secinsight_core.models import ScanResult
from secinsight_core.scoring import score_scan

_SEVERITY_COLORS = {
    "critical": colors.HexColor("#b91c1c"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#2563eb"),
    "info": colors.HexColor("#6b7280"),
}

_GRADE_COLORS = {
    "A": colors.HexColor("#16a34a"),
    "B": colors.HexColor("#65a30d"),
    "C": colors.HexColor("#ca8a04"),
    "D": colors.HexColor("#ea580c"),
    "F": colors.HexColor("#b91c1c"),
}


def _escape(text: str | None) -> str:
    if not text:
        return "-"
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def write_pdf_report(scan: ScanResult, out_path: str, mode: str = "pro", ai_summary_text: str | None = None) -> str:
    score = score_scan(scan)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("SITitle", parent=styles["Title"], textColor=colors.HexColor("#0f172a"))
    h2 = ParagraphStyle("SIH2", parent=styles["Heading2"], spaceBefore=14, spaceAfter=6)
    body = ParagraphStyle("SIBody", parent=styles["Normal"], fontSize=9.5, leading=13)
    small = ParagraphStyle("SISmall", parent=styles["Normal"], fontSize=8.5, textColor=colors.HexColor("#4b5563"))

    doc = SimpleDocTemplate(out_path, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    story = []

    story.append(Paragraph("SecInsight AI — Security Report", title_style))
    story.append(
        Paragraph(
            f"Tool: {scan.meta.tool.upper()} &middot; Target: {_escape(scan.meta.target)} &middot; "
            f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} &middot; Mode: {mode.capitalize()}",
            small,
        )
    )
    story.append(Spacer(1, 14))

    grade_color = _GRADE_COLORS.get(score.grade, colors.grey)
    score_table = Table(
        [[Paragraph(f"<b>{score.score}</b>/100", ParagraphStyle("sc", parent=body, fontSize=20, textColor=grade_color)),
          Paragraph(f"Grade <b>{score.grade}</b>", ParagraphStyle("gr", parent=body, fontSize=16, textColor=grade_color)),
          Paragraph(_escape(score.summary), body)]],
        colWidths=[1.3 * inch, 1.3 * inch, 4.4 * inch],
    )
    score_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 10))

    counts_row = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        counts_row.append(Paragraph(f"<b>{sev.upper()}</b>: {score.counts.get(sev, 0)}",
                                     ParagraphStyle("cnt", parent=body, textColor=colors.white, alignment=1)))
    counts_table = Table([counts_row], colWidths=[1.4 * inch] * 5)
    counts_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), _SEVERITY_COLORS["critical"]),
        ("BACKGROUND", (1, 0), (1, 0), _SEVERITY_COLORS["high"]),
        ("BACKGROUND", (2, 0), (2, 0), _SEVERITY_COLORS["medium"]),
        ("BACKGROUND", (3, 0), (3, 0), _SEVERITY_COLORS["low"]),
        ("BACKGROUND", (4, 0), (4, 0), _SEVERITY_COLORS["info"]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(counts_table)
    story.append(Spacer(1, 16))

    if mode == "student":
        story.append(Paragraph("What does this mean?", h2))
        story.append(Paragraph(
            "This report uses Student Mode: plain-English explanations. Critical/High findings mean an "
            "attacker could likely break in or steal data - fix these first. Medium/Low are still worth "
            "fixing. Informational items are context, not vulnerabilities.",
            body,
        ))

    story.append(Paragraph(f"Findings ({len(scan.findings)})", h2))
    table_data = [["Severity", "Title", "Host", "CVE"]]
    for f in scan.sorted_findings():
        host = (f.host or "-") + (f":{f.port}" if f.port else "")
        table_data.append([
            Paragraph(f.severity.value.upper(), ParagraphStyle("s", parent=small, textColor=colors.white)),
            Paragraph(_escape(f.title), small),
            Paragraph(_escape(host), small),
            Paragraph(_escape(f.cve), small),
        ])

    if len(table_data) > 1:
        t = Table(table_data, colWidths=[0.8 * inch, 3.1 * inch, 1.8 * inch, 1.2 * inch], repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        for i, f in enumerate(scan.sorted_findings(), start=1):
            style.append(("BACKGROUND", (0, i), (0, i), _SEVERITY_COLORS[f.severity.value]))
        t.setStyle(TableStyle(style))
        story.append(t)
    else:
        story.append(Paragraph("No findings reported.", body))

    if ai_summary_text:
        story.append(PageBreak())
        story.append(Paragraph("AI Summary", h2))
        for para in ai_summary_text.split("\n"):
            if para.strip():
                story.append(Paragraph(_escape(para), body))
            else:
                story.append(Spacer(1, 6))

    doc.build(story)
    return out_path
