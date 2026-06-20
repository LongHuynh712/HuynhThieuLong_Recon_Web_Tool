"""
Weighted risk scoring (Phase 4).
"""

from __future__ import annotations

from typing import Any

_SEVERITY_WEIGHT = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 1,
}

_CRITICALITY_MULT = {
    "low": 0.85,
    "normal": 1.0,
    "high": 1.2,
    "critical": 1.45,
}

QUALITY_SECTION_KEYWORDS = (
    "page title",
    "meta description",
    "open graph",
    "og:",
    "favicon",
    "viewport",
    "seo",
    "image alt",
    "canonical",
    "social tags",
    "linked pages",
    "sitemap quality",
)

INFORMATIONAL_SECTION_KEYWORDS = (
    "robots",
    "sitemap",
    "technology",
    "fingerprint",
    "subdomains",
    "admin paths discovery",
    "common paths discovery",
    "execution paths",
    "architecture",
    "api contract",
    "data flow",
    "search engine",
    "content leakage",
    "forms",
    "parameters",
)

SECURITY_SECTION_KEYWORDS = (
    "security",
    "ssl",
    "tls",
    "hsts",
    "csp",
    "http headers",
    "http security",
    "security.txt",
    "cookies",
    "http methods",
    "backup",
    "sensitive",
    "firewall",
    "dns records",
    "whois",
    "network info",
    ".env",
    ".git",
    # 'administrator', 'login', and 'admin' are discovery/enum indicators
    # and are handled as informational by default. Keep highly sensitive
    # keywords such as ".env" and ".git" here.
    "backup",
    "config",
)


def classify_section_impact(section: dict[str, Any]) -> str:
    title = (section.get("title") or "").lower()
    text = (section.get("text") or "").lower()

    for keyword in QUALITY_SECTION_KEYWORDS:
        if keyword in title or keyword in text:
            return "quality"

    for keyword in INFORMATIONAL_SECTION_KEYWORDS:
        if keyword in title or keyword in text:
            return "informational"

    for keyword in SECURITY_SECTION_KEYWORDS:
        if keyword in title or keyword in text:
            return "security"

    return "security"


def count_security_severities(sections: list[dict]) -> dict[str, int]:
    counts = {k: 0 for k in _SEVERITY_WEIGHT}
    for sec in sections:
        if classify_section_impact(sec) != "security":
            continue
        level = sec.get("severity_level") or sec.get("severity", "info")
        if level in counts:
            counts[level] += 1
        else:
            counts["info"] += 1
    return counts


def compute_security_score(sections: list[dict]) -> int:
    critical = 0
    high = 0
    medium = 0
    low = 0

    for sec in sections:
        if classify_section_impact(sec) != "security":
            continue
        level = sec.get("severity_level") or sec.get("severity", "info")
        if level == "critical":
            critical += 1
        elif level == "high":
            high += 1
        elif level == "medium":
            medium += 1
        elif level == "low":
            low += 1

    score = 100
    score -= min(50, critical * 25)
    score -= min(36, high * 12)
    score -= min(18, medium * 6)
    score -= min(8, low * 2)
    return max(0, min(100, score))


def compute_quality_score(sections: list[dict]) -> int:
    issues = 0
    for sec in sections:
        if classify_section_impact(sec) != "quality":
            continue
        if sec.get("severity_level") in ("critical", "high", "medium", "low"):
            issues += 1
        elif "[MISSING]" in (sec.get("text") or "") or "[WARNING]" in (sec.get("text") or ""):
            issues += 1

    score = 100 - min(60, issues * 10)
    return max(0, min(100, score))


def score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def compute_weighted_risk(
    sections: list[dict],
    summary: dict | None,
    *,
    asset_criticality: str = "normal",
) -> dict[str, Any]:
    summary = summary or {}
    base_score = int(summary.get("security_score", summary.get("score", 0)) or 0)

    raw_risk = 0
    breakdown = []
    for sec in sections:
        level = sec.get("severity_level") or sec.get("severity", "info")
        w = _SEVERITY_WEIGHT.get(level, 1)
        if level in ("critical", "high", "medium") or "[MISSING]" in (sec.get("text") or ""):
            raw_risk += w
            breakdown.append(
                {
                    "title": sec.get("title"),
                    "severity": level,
                    "weight": w,
                }
            )

    mult = _CRITICALITY_MULT.get(asset_criticality, 1.0)
    weighted_risk_points = round(raw_risk * mult, 1)
    max_points = 100
    risk_index = min(100, round(weighted_risk_points * 1.8))
    composite_score = max(0, min(100, round(base_score - (risk_index * 0.35))))

    if risk_index >= 70:
        tier = "Critical"
        tier_class = "risk-critical"
    elif risk_index >= 50:
        tier = "High"
        tier_class = "risk-high"
    elif risk_index >= 30:
        tier = "Elevated"
        tier_class = "risk-medium"
    elif risk_index >= 15:
        tier = "Moderate"
        tier_class = "risk-low"
    else:
        tier = "Low"
        tier_class = "risk-good"

    top_drivers = sorted(breakdown, key=lambda x: -x["weight"])[:5]

    return {
        "base_score": base_score,
        "composite_score": composite_score,
        "risk_index": risk_index,
        "risk_tier": tier,
        "risk_class": tier_class,
        "asset_criticality": asset_criticality,
        "criticality_multiplier": mult,
        "weighted_risk_points": weighted_risk_points,
        "top_drivers": top_drivers,
        "interpretation": (
            f"Composite {composite_score}/100 after weighting {len(top_drivers)} risk driver(s) "
            f"at {asset_criticality} asset criticality."
        ),
    }
