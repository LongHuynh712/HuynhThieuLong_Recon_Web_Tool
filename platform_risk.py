"""
Weighted risk scoring (Phase 4).
"""

from __future__ import annotations

from typing import Any
import re

# Import from platform_core for tier determination and severity counting
from platform_core import count_severities, determine_risk_tier

_SEVERITY_WEIGHT = {
    "critical": 20,
    "high": 10,
    "medium": 5,
    "low": 1,
    "info": 0,
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
    "metadata",
    "social",
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


# --- Positive control detection helpers ---

def _has_strong_tls(sections: list[dict]) -> bool:
    """Check if TLS 1.2 or 1.3 is supported and no weak protocols."""
    all_text = " ".join(
        sec.get("text", "").lower()
        for sec in sections
        if "ssl" in sec.get("title", "").lower() or "tls" in sec.get("title", "").lower()
    )
    if not all_text:
        return False
    has_strong = re.search(r"tls\s+(?:1\.2|1\.3)", all_text) is not None
    has_weak = re.search(r"tls\s+(?:1\.0|1\.1)|sslv[23]", all_text) is not None
    return has_strong and not has_weak


def _has_full_security_headers(sections: list[dict]) -> bool:
    """Check for presence of all five key security headers: CSP, HSTS, XFO, XCTO, Referrer-Policy."""
    headers = {
        "content-security-policy": False,
        "strict-transport-security": False,
        "x-frame-options": False,
        "x-content-type-options": False,
        "referrer-policy": False,
    }
    all_text = " ".join(
        sec.get("text", "").lower()
        for sec in sections
        if "http" in sec.get("title", "").lower() or "header" in sec.get("title", "").lower()
    )
    for hdr in headers:
        if re.search(fr"\[found\].*{hdr}|{hdr}:", all_text):
            headers[hdr] = True
    return all(headers.values())


def _has_secure_cookies(sections: list[dict]) -> bool:
    """Check if cookies have Secure and HttpOnly flags."""
    all_text = " ".join(
        sec.get("text", "").lower()
        for sec in sections
        if "cookie" in sec.get("title", "").lower()
    )
    if not all_text:
        return False
    has_secure = re.search(r"secure", all_text) and re.search(r"\[found\].*secure", all_text) is not None
    has_httponly = re.search(r"httponly", all_text) and re.search(r"\[found\].*httponly", all_text) is not None
    return has_secure and has_httponly


def _has_waf_cdn(sections: list[dict]) -> bool:
    """Detect WAF or CDN presence."""
    all_text = " ".join(sec.get("text", "").lower() for sec in sections)
    indicators = [
        "cloudflare", "akamai", "fastly", "aws waf", "azure front door",
        "imperva", "incapsula", "sucuri", "barracuda", "mod_security",
        "waf", "web application firewall", "cdn", "x-cdn", "x-waf"
    ]
    return any(ind in all_text for ind in indicators)


def _has_valid_cert(sections: list[dict]) -> bool:
    """Check for a valid SSL/TLS certificate."""
    all_text = " ".join(
        sec.get("text", "").lower()
        for sec in sections
        if "ssl" in sec.get("title", "").lower() or "tls" in sec.get("title", "").lower()
    )
    if not all_text:
        return False
    valid_phrases = ["certificate valid", "trusted certificate", "ssl certificate verified", "certificate ok"]
    invalid_phrases = ["certificate expired", "self-signed", "untrusted", "certificate invalid"]
    has_valid = any(phrase in all_text for phrase in valid_phrases)
    has_invalid = any(phrase in all_text for phrase in invalid_phrases)
    return has_valid and not has_invalid


def compute_security_score(sections: list[dict]) -> int:
    """Compute security score (0-100) using OWASP-style weighting.

    Deductions:
    - Critical: -25
    - High: -10
    - Medium: -3
    - Low: -1

    Bonuses:
    - Strong TLS (1.2/1.3): +5
    - Full security headers (CSP, HSTS, XFO, XCTO, Referrer-Policy): +5
    - Secure cookies (Secure+HttpOnly): +5
    - WAF/CDN detected: +3
    - Valid certificate: +3

    Score is clamped to 0-100.
    """
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
    score -= critical * 25
    score -= high * 10
    score -= medium * 3
    score -= low * 1

    # Bonuses for positive security controls
    if _has_strong_tls(sections):
        score += 5
    if _has_full_security_headers(sections):
        score += 5
    if _has_secure_cookies(sections):
        score += 5
    if _has_waf_cdn(sections):
        score += 3
    if _has_valid_cert(sections):
        score += 3

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
    has_critical = False
    has_high = False
    
    for sec in sections:
        level = sec.get("severity_level") or sec.get("severity", "info")
        w = _SEVERITY_WEIGHT.get(level, 0)
        
        if level == "critical":
            has_critical = True
        elif level == "high":
            has_high = True
            
        if level in ("critical", "high", "medium", "low"):
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

    risk_index = min(100, round(weighted_risk_points * 1.8))

    # Cap risk index at 69 (High) if there are no Critical findings
    if not has_critical and risk_index >= 70:
        risk_index = 69

    # Cap risk index at 49 (Elevated/Medium) if there are no Critical or High findings
    if not has_high and not has_critical and risk_index >= 50:
        risk_index = 49

    composite_score = max(0, min(100, round(base_score - (risk_index * 0.35))))

    # Determine risk tier based on severity counts (new rules)
    severity_counts = count_severities(sections)
    risk_level, risk_class = determine_risk_tier(severity_counts)

    top_drivers = sorted(breakdown, key=lambda x: -x["weight"])[:5]

    return {
        "base_score": base_score,
        "composite_score": composite_score,
        "risk_index": risk_index,
        "risk_tier": risk_level,
        "risk_class": risk_class,
        "asset_criticality": asset_criticality,
        "criticality_multiplier": mult,
        "weighted_risk_points": weighted_risk_points,
        "top_drivers": top_drivers,
        "interpretation": (
            f"Composite {composite_score}/100 after weighting {len(top_drivers)} risk driver(s) "
            f"at {asset_criticality} asset criticality."
        ),
    }
