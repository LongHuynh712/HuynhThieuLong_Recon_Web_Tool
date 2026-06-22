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
    """Return one of: critical, high, medium, low, info.

    Severity classification follows OWASP principles:
    - Discovery and informational findings are INFO
    - Missing security controls are MEDIUM
    - Dangerous exposures are HIGH
    - Exposed secrets/sensitive data are CRITICAL (with evidence)
    """
    combined = f"{title}\n{text}"
    lower = combined.lower()

    # Google Dork suggestions are informational regardless of content
    if "google dork" in lower or "dork suggestion" in lower:
        return "info"

    # CRITICAL: Exposed sensitive artifacts with evidence
    # Must have [FOUND] and actual exposure (not just a Google dork suggestion)
    if "[FOUND]" in combined:
        # Use word boundaries to avoid false positives like ".github"
        if re.search(r"\.git\b|\.env\b|\bbackup\b", lower):
            return "critical"
        if re.search(r"password.*(?:in\s+url|in\s+html|client-side|hardcoded)|secret.*(?:key|token|password)|api[_-]?key.*(?:exposed|found|leak)|aws[_-]?key|private[_-]?key|jwt.*secret|database.*password|production.*backup", lower):
            return "critical"

    if "[ERROR]" in combined:
        if re.search(r"backup|\.env|\.git|password|secret|api[_-]?key", lower):
            return "critical"
        return "high"

    # HIGH: Dangerous exposures
    high_patterns = [
        r"directory\s+listing",
        r"index\s+of\s+/",
        r"backup\.(?:zip|tar|tar\.gz|sql)",
        r"\.sql\b",
        r"\.bak\b",
        r"dangerous\s+cors|wildcard.*allow-origin|cors.*\*",
        r"tls.*(?:v1\.0|v1\.1|sslv2|sslv3)",
        r"weak\s+(?:tls|ssl|cipher)",
        r"default\s+credentials?",
        r"(?:admin|administrator|dashboard).*(?:public|accessible|unprotected)",
        r"(?:auth|authorization).*bypass",
        r"(?:account|user).*takeover"
    ]
    for pattern in high_patterns:
        if re.search(pattern, lower):
            return "high"

    if "[WARNING]" in combined:
        if re.search(r"tls.*(?:v1\.0|v1\.1|weak|insecure)|dangerous\s+cors|permissive\s+cors", lower):
            return "high"
        return "medium"

    # MEDIUM: Missing security controls
    if "[MISSING]" in combined:
        key = title.lower()
        security_keywords = [
            "ssl", "tls", "hsts", "csp", "security header",
            "x-frame-options", "x-content-type-options", "referrer-policy",
            "secure cookie", "httponly", "samesite",
            "security.txt", "dnssec"
        ]
        for sk in security_keywords:
            if sk in key:
                return "medium"

        # Missing optional/SEO items are not medium
        optional_keywords = [
            "robots.txt", "sitemap.xml", "seo", "meta description",
            "open graph", "social tags", "favicon", "viewport", "alt text"
        ]
        for ok in optional_keywords:
            if ok in key:
                return "info"

        return "low"

    # INFO: Discovery, informational findings, positive controls
    if "[FOUND]" in combined:
        return "info"

    if "[INFO]" in combined:
        return "info"

    # Discovery patterns default to info
    discovery_keywords = [
        "server header", "x-powered-by", "via", "fingerprint", "technology",
        "subdomain", "admin path", "common path", "entry point", "execution path",
        "architecture", "framework", "cms", "api contract", "data flow",
        "email", "phone", "social link", "whois", "dns", "txt record",
        "google dork", "search engine", "cache", "wayback", "comment", "metadata",
        "robots.txt", "sitemap.xml", "sitemap quality"
    ]
    for keyword in discovery_keywords:
        if keyword in lower:
            return "info"

    return "info"


def determine_risk_tier(severity_counts: dict) -> tuple[str, str]:
    """Determine risk tier and CSS class based on severity counts.

    Rules:
    - Critical Risk: >=1 Critical finding
    - High Risk: >=2 High findings
    - Elevated Risk: multiple (>=2) Medium findings, or 1 High + 1+ Medium
    - Moderate Risk: 1 High, or 1 Medium
    - Low Risk: no Critical/High/Medium findings
    """
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    medium = severity_counts.get("medium", 0)

    if critical > 0:
        return "Critical", "risk-critical"
    if high >= 2:
        return "High", "risk-high"
    if medium >= 2:
        return "Elevated", "risk-medium"
    if high == 1 or medium == 1:
        return "Moderate", "risk-low"
    return "Low", "risk-good"


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

    # Determine risk tier using the new rules based on severity counts
    risk_level, risk_class = determine_risk_tier(severity_counts)

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
