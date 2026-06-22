"""
Phase 2 exports: professional PDF, JSON, SARIF 2.1.0.
"""

from __future__ import annotations

import json
import re
from io import BytesIO
from typing import Any

from platform_core import SEVERITY_LABELS

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def build_json_export(
    *,
    brand: dict,
    scan_url: str,
    hostname: str,
    generated_at: str,
    report: str,
    summary: dict | None,
    executive: dict | None,
    sections: list[dict],
    remediation: list[dict],
    recommendations: list[str],
    metrics: dict | None = None,
    record_id: str = "",
) -> dict[str, Any]:
    findings = []
    for sec in sections:
        level = sec.get("severity_level") or "info"
        if level == "info" and "[MISSING]" not in (sec.get("text") or "") and "[ERROR]" not in (sec.get("text") or ""):
            continue
        findings.append(
            {
                "id": sec.get("slug"),
                "title": sec.get("title"),
                "category": sec.get("category"),
                "severity": level,
                "severity_label": sec.get("severity_label"),
                "cwe_ids": sec.get("cwe_ids", []),
                "compliance_refs": sec.get("compliance_refs", []),
                "preview": (sec.get("text") or "")[:500],
            }
        )

    return {
        "schema_version": "2.0",
        "tool": {"name": brand.get("full", "ReconSight"), "vendor": brand.get("full", "ReconSight")},
        "generated_at": generated_at,
        "record_id": record_id,
        "target": {"url": scan_url, "hostname": hostname},
        "summary": summary,
        "executive": executive,
        "metrics": metrics or {},
        "severity_counts": (executive or {}).get("severity_counts", {}),
        "findings": findings,
        "remediation": remediation,
        "recommendations": recommendations,
        "sections": [
            {
                "title": s.get("title"),
                "slug": s.get("slug"),
                "severity_level": s.get("severity_level"),
                "cwe_ids": s.get("cwe_ids", []),
                "text": s.get("text"),
            }
            for s in sections
        ],
        "raw_report": report,
    }


def build_csv_export(
    *,
    scan_url: str,
    hostname: str,
    generated_at: str,
    summary: dict | None,
    sections: list[dict],
    executive: dict | None = None,
) -> str:
    """CSV summary + findings for spreadsheets / SIEM import."""
    import csv
    from io import StringIO

    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ReconSight Export", generated_at])
    writer.writerow(["Target", scan_url or hostname])
    if summary:
        writer.writerow(["Score", summary.get("score")])
        writer.writerow(["Status", summary.get("status")])
    if executive:
        writer.writerow(["Risk Level", executive.get("risk_level")])
    writer.writerow([])
    writer.writerow(["Title", "Category", "Severity", "CWE", "Preview"])
    for sec in sections:
        level = sec.get("severity_level") or sec.get("severity", "info")
        preview = (sec.get("text") or "").replace("\n", " ").strip()[:200]
        writer.writerow(
            [
                sec.get("title", ""),
                sec.get("category", ""),
                sec.get("severity_label", level),
                ";".join(sec.get("cwe_ids", [])),
                preview,
            ]
        )
    return buf.getvalue()


def build_sarif_export(
    *,
    brand: dict,
    scan_url: str,
    generated_at: str,
    sections: list[dict],
) -> dict[str, Any]:
    results = []
    for idx, sec in enumerate(sections):
        level = sec.get("severity_level") or "info"
        text = sec.get("text") or ""
        if level == "info" and "[MISSING]" not in text and "[WARNING]" not in text and "[ERROR]" not in text:
            continue
        rule_id = sec.get("slug") or f"section-{idx}"
        cwe_ids = sec.get("cwe_ids", [])
        result = {
            "ruleId": rule_id,
            "ruleIndex": idx,
            "level": _SARIF_LEVEL.get(level, "note"),
            "message": {"text": f"{sec.get('title')}: {(text[:240] + '…') if len(text) > 240 else text}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": scan_url or "/"},
                    }
                }
            ],
            "properties": {
                "severity_level": level,
                "severity_label": sec.get("severity_label"),
                "category": sec.get("category"),
            },
        }
        if cwe_ids:
            result["properties"]["tags"] = cwe_ids
            result["taxa"] = [{"id": cid, "toolComponent": {"name": "CWE"}} for cid in cwe_ids]
        results.append(result)

    rules = []
    seen = set()
    for r in results:
        rid = r["ruleId"]
        if rid in seen:
            continue
        seen.add(rid)
        rules.append(
            {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": rid.replace("-", " ").title()},
                "defaultConfiguration": {"level": r["level"]},
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": brand.get("full", "ReconSight"),
                        "informationUri": "https://github.com/",
                        "version": "2.0",
                        "rules": rules,
                    }
                },
                "invocations": [{"startTimeUtc": generated_at, "executionSuccessful": True}],
                "results": results,
            }
        ],
    }


def build_professional_pdf(
    buffer: BytesIO,
    *,
    brand: dict,
    hostname: str,
    scan_url: str,
    generated_at: str,
    executive: dict | None,
    summary: dict | None,
    sections: list[dict],
    remediation: list[dict],
    report: str,
) -> None:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=50,
        leftMargin=50,
        topMargin=50,
        bottomMargin=50,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Title"],
        fontSize=22,
        spaceAfter=12,
        alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        "CoverSub",
        parent=styles["Normal"],
        fontSize=11,
        textColor=colors.HexColor("#475569"),
        alignment=TA_CENTER,
        spaceAfter=6,
    )
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13, spaceBefore=14, spaceAfter=8)
    body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9, leading=12)
    small = ParagraphStyle("Small", parent=styles["Normal"], fontSize=8, leading=10, textColor=colors.grey)

    story = []
    name = brand.get("full", "ReconSight")

    # —— Cover page ——
    story.append(Spacer(1, 1.2 * inch))
    story.append(Paragraph(name, title_style))
    story.append(Paragraph("Security Assessment Report", subtitle_style))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(f"<b>Target:</b> {hostname or scan_url or '—'}", subtitle_style))
    story.append(Paragraph(f"<b>Generated:</b> {generated_at}", subtitle_style))
    if executive:
        story.append(Spacer(1, 0.4 * inch))
        story.append(
            Paragraph(
                f'<font size="28"><b>{executive.get("score", "—")}</b></font> / 100',
                ParagraphStyle("Score", parent=subtitle_style, fontSize=14),
            )
        )
        story.append(
            Paragraph(
                f'Risk level: <b>{executive.get("risk_level", "—")}</b>',
                subtitle_style,
            )
        )
    story.append(PageBreak())

    # —— Severity table ——
    story.append(Paragraph("Severity distribution", h2))
    if executive:
        counts = executive.get("severity_counts", {})
        sev_data = [["Severity", "Count"]]
        for level in ("critical", "high", "medium", "low", "info"):
            sev_data.append([SEVERITY_LABELS.get(level, level.title()), str(counts.get(level, 0))])
        t = Table(sev_data, colWidths=[2.5 * inch, 1.2 * inch])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d9488")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ]
            )
        )
        story.append(t)
        story.append(Spacer(1, 0.2 * inch))

    # —— Executive summary ——
    story.append(Paragraph("Executive summary", h2))
    if executive:
        for bullet in executive.get("bullets", []):
            story.append(Paragraph(f"• {_escape_xml(bullet)}", body))
        story.append(Spacer(1, 0.15 * inch))

    # —— Findings table with CWE ——
    story.append(Paragraph("Priority findings (with CWE references)", h2))
    find_rows = [["Severity", "Finding", "CWE"]]
    added = 0
    for sec in sections:
        level = sec.get("severity_level") or "info"
        if level == "info" and "[MISSING]" not in (sec.get("text") or ""):
            continue
        cwe = ", ".join(sec.get("cwe_ids", [])[:3]) or "—"
        find_rows.append(
            [
                sec.get("severity_label", level.title()),
                (sec.get("title") or "")[:48],
                cwe,
            ]
        )
        added += 1
        if added >= 25:
            break
    if len(find_rows) > 1:
        ft = Table(find_rows, colWidths=[1.1 * inch, 3.2 * inch, 1.5 * inch])
        ft.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(ft)
    else:
        story.append(Paragraph("No elevated findings recorded.", body))
    story.append(PageBreak())

    # —— Remediation ——
    if remediation:
        story.append(Paragraph("Remediation plan", h2))
        for item in remediation[:12]:
            story.append(
                Paragraph(
                    f'<b>[{item.get("priority_label", "Medium")}]</b> {_escape_xml(item.get("text", ""))}',
                    body,
                )
            )
        story.append(PageBreak())

    # —— Appendix: raw report ——
    story.append(Paragraph("Appendix — Full scan output", h2))
    for line in report.splitlines():
        if not line.strip():
            story.append(Spacer(1, 4))
            continue
        safe = _escape_xml(line[:120])
        story.append(Paragraph(safe, small))
        if len(story) > 800:
            break

    doc.build(story)


def _escape_xml(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
