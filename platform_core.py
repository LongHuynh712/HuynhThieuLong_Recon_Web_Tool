"""
ReconSight platform helpers: severity taxonomy, executive summary, remediation.
Preserves legacy severity aliases (high/medium/info) while adding CVSS-style levels.
"""

from __future__ import annotations

import re
from typing import Any

SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")

SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

# Legacy map for filters that used high/medium/info only
LEGACY_SEVERITY_MAP = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "info",
    "info": "info",
}


def classify_section_severity(text: str, title: str = "") -> str:
    """Return one of: critical, high, medium, low, info."""
    combined = f"{title}\n{text}"
    upper = combined.upper()

    if "[ERROR]" in combined or "SEVERITY: HIGH" in upper:
        # Critical when sensitive artifacts or secrets are found; do not
        # escalate purely on presence of administrative paths (discovery).
        if re.search(r"\[FOUND\].*(?:backup|\.env|\.git|password|secret|api[_-]?key)", combined, re.I):
            return "critical"
        return "high"

    # Treat admin/login discovery as informational by default; only mark
    # critical when explicit sensitive artifacts (backup/.env/.git) are found.
    if re.search(r"\[FOUND\].*(?:backup|\.env|\.git)", combined, re.I):
        return "critical"

    if "[WARNING]" in combined or "SEVERITY: MEDIUM" in upper:
        return "medium"

    if "[MISSING]" in combined:
        key = title.lower()
        if any(
            w in key
            for w in (
                "ssl",
                "tls",
                "hsts",
                "csp",
                "security header",
                "content-security",
                "x-frame",
            )
        ):
            return "medium"
        return "low"

    if "[FOUND]" in combined and "[MISSING]" not in combined and "[WARNING]" not in combined:
        return "info"

    return "info"


def legacy_severity(level: str) -> str:
    return LEGACY_SEVERITY_MAP.get(level, "info")


def count_severities(sections: list[dict]) -> dict[str, int]:
    counts = {k: 0 for k in SEVERITY_LEVELS}
    for section in sections:
        level = section.get("severity_level") or section.get("severity", "info")
        if level in counts:
            counts[level] += 1
        else:
            counts["info"] += 1
    return counts


def build_executive_summary(
    report: str,
    sections: list[dict],
    summary: dict | None,
    recommendations: list[str],
    target_hostname: str = "",
) -> dict[str, Any]:
    summary = summary or {}
    severity_counts = count_severities(sections)
    security_score = int(summary.get("security_score", summary.get("score", 0)) or 0)
    quality_score = int(summary.get("quality_score", 100) or 100)

    if severity_counts["critical"] > 0 or security_score < 50:
        risk_level = "Critical"
        risk_class = "risk-critical"
    elif severity_counts["high"] > 0 or security_score < 65:
        risk_level = "High"
        risk_class = "risk-high"
    elif severity_counts["medium"] > 2 or security_score < 80:
        risk_level = "Elevated"
        risk_class = "risk-medium"
    elif security_score < 90:
        risk_level = "Moderate"
        risk_class = "risk-low"
    else:
        risk_level = "Low"
        risk_class = "risk-good"

    top_findings = []
    priority_order = ("critical", "high", "medium", "low", "info")
    for level in priority_order:
        for section in sections:
            sl = section.get("severity_level") or section.get("severity", "info")
            if sl == level and len(top_findings) < 6:
                preview = (section.get("text") or "")[:120].replace("\n", " ").strip()
                top_findings.append(
                    {
                        "title": section.get("title", "Finding"),
                        "severity_level": sl,
                        "severity_label": SEVERITY_LABELS.get(sl, sl.title()),
                        "preview": preview or "See detailed report section.",
                        "cwe_ids": section.get("cwe_ids", []),
                    }
                )

    bullets = []
    if summary.get("error"):
        bullets.append(f"{summary['error']} issue(s) require immediate attention.")
    if summary.get("missing"):
        bullets.append(f"{summary['missing']} security control(s) are missing or misconfigured.")
    if "Site is not HTTPS" in report:
        bullets.append("Transport encryption (HTTPS) is not properly enforced.")
    if severity_counts["critical"]:
        bullets.append(
            f"{severity_counts['critical']} critical exposure(s) detected (sensitive paths or severe misconfig)."
        )
    if not bullets:
        bullets.append("No critical blockers detected; continue monitoring and hardening.")

    return {
        "risk_level": risk_level,
        "risk_class": risk_class,
        "score": security_score,
        "security_score": security_score,
        "quality_score": quality_score,
        "security_grade": summary.get("security_grade", "—"),
        "quality_grade": summary.get("quality_grade", "—"),
        "status": summary.get("status", "—"),
        "hostname": target_hostname or "Target",
        "section_count": len(sections),
        "severity_counts": severity_counts,
        "top_findings": top_findings,
        "bullets": bullets[:5],
        "recommendations_count": len(recommendations),
    }


def build_remediation_plan(recommendations: list[str], sections: list[dict]) -> list[dict]:
    """Structured remediation items with priority derived from context."""
    items = []
    for idx, text in enumerate(recommendations[:15]):
        priority = "medium"
        lower = text.lower()
        if any(w in lower for w in ("https", "ssl", "tls", "hsts", "csp", "admin", "backup", ".env")):
            priority = "high"
        elif any(w in lower for w in ("alt", "meta", "sitemap", "robots")):
            priority = "low"
        items.append(
            {
                "id": idx + 1,
                "text": text,
                "priority": priority,
                "priority_label": {"high": "High", "medium": "Medium", "low": "Low"}.get(priority, "Medium"),
            }
        )

    for section in sections:
        level = section.get("severity_level") or section.get("severity", "info")
        if level not in ("critical", "high"):
            continue
        title = section.get("title", "")
        if any(i.get("text", "").startswith(title) for i in items):
            continue
        items.append(
            {
                "id": len(items) + 1,
                "text": f"Review and remediate findings in: {title}",
                "priority": "high" if level == "critical" else "medium",
                "priority_label": "High" if level == "critical" else "Medium",
            }
        )
        if len(items) >= 18:
            break

    return items[:18]


def enrich_sections(sections: list[dict]) -> list[dict]:
    """Add severity_level and legacy severity for templates/filters."""
    for section in sections:
        level = classify_section_severity(section.get("text", ""), section.get("title", ""))
        section["severity_level"] = level
        section["severity_label"] = SEVERITY_LABELS.get(level, level.title())
        section["severity"] = legacy_severity(level)
    return sections


def enrich_check_cards(cards: list[dict], sections: list[dict]) -> list[dict]:
    by_slug = {s.get("slug"): s for s in sections}
    by_title = {s.get("title"): s for s in sections}
    for card in cards:
        sec = by_slug.get(card.get("slug")) or by_title.get(card.get("title"))
        if sec:
            card["severity_level"] = sec.get("severity_level", "info")
            card["severity_label"] = sec.get("severity_label", "Info")
    return cards
