"""
Compare two scan history records (Phase 2).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any


def _section_fingerprint(section: dict) -> str:
    title = (section.get("title") or "").strip().lower()
    slug = section.get("slug") or title
    level = section.get("severity_level") or section.get("severity", "info")
    # Key signals only (ignore timestamps)
    signals = []
    text = section.get("text") or ""
    for tag in ("[ERROR]", "[WARNING]", "[MISSING]", "[FOUND]"):
        signals.append(f"{tag}:{text.count(tag)}")
    sig = "|".join(signals)
    raw = f"{slug}|{level}|{sig}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _section_map(sections: list[dict]) -> dict[str, dict]:
    by_slug: dict[str, dict] = {}
    for s in sections:
        key = s.get("slug") or s.get("title", "")
        by_slug[key] = s
    return by_slug


def compare_scan_records(
    baseline: dict,
    current: dict,
) -> dict[str, Any]:
    """
    baseline = older scan, current = newer scan.
    """
    base_score = int(baseline.get("score", 0) or 0)
    cur_score = int(current.get("score", 0) or 0)
    score_delta = cur_score - base_score

    base_sections = baseline.get("_parsed_sections") or []
    cur_sections = current.get("_parsed_sections") or []

    base_fp = {_section_fingerprint(s): s for s in base_sections}
    cur_fp = {_section_fingerprint(s): s for s in cur_sections}
    base_slug = _section_map(base_sections)
    cur_slug = _section_map(cur_sections)

    new_findings = []
    resolved = []
    changed = []

    for slug, sec in cur_slug.items():
        if slug not in base_slug:
            new_findings.append(_brief(sec, "new_section"))
            continue
        old = base_slug[slug]
        old_level = old.get("severity_level") or old.get("severity", "info")
        new_level = sec.get("severity_level") or sec.get("severity", "info")
        if old_level != new_level or _section_fingerprint(old) != _section_fingerprint(sec):
            changed.append(
                {
                    "title": sec.get("title"),
                    "slug": slug,
                    "from_severity": old_level,
                    "to_severity": new_level,
                    "score_impact": _severity_rank(new_level) - _severity_rank(old_level),
                }
            )

    for slug, sec in base_slug.items():
        if slug not in cur_slug:
            resolved.append(_brief(sec, "removed_section"))
        elif slug in cur_slug:
            old = sec
            new = cur_slug[slug]
            old_level = old.get("severity_level") or old.get("severity", "info")
            new_level = new.get("severity_level") or new.get("severity", "info")
            if _severity_rank(new_level) < _severity_rank(old_level):
                resolved.append(_brief(old, "improved"))

    trend = "improved" if score_delta > 0 else "degraded" if score_delta < 0 else "unchanged"

    return {
        "baseline": {
            "id": baseline.get("id"),
            "url": baseline.get("url"),
            "timestamp": baseline.get("timestamp"),
            "score": base_score,
        },
        "current": {
            "id": current.get("id"),
            "url": current.get("url"),
            "timestamp": current.get("timestamp"),
            "score": cur_score,
        },
        "score_delta": score_delta,
        "trend": trend,
        "new_findings": new_findings[:20],
        "resolved": resolved[:20],
        "changed": changed[:20],
        "summary_text": _summary_text(score_delta, trend, len(new_findings), len(resolved), len(changed)),
    }


def _severity_rank(level: str) -> int:
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return order.get(level, 1)


def _brief(section: dict, kind: str) -> dict:
    return {
        "kind": kind,
        "title": section.get("title"),
        "slug": section.get("slug"),
        "severity_level": section.get("severity_level") or section.get("severity", "info"),
        "severity_label": section.get("severity_label", ""),
        "cwe_ids": section.get("cwe_ids", []),
    }


def _summary_text(delta: int, trend: str, new_n: int, res_n: int, ch_n: int) -> str:
    parts = [f"Score change: {delta:+d} ({trend})."]
    if new_n:
        parts.append(f"{new_n} new issue(s).")
    if res_n:
        parts.append(f"{res_n} resolved/improved.")
    if ch_n:
        parts.append(f"{ch_n} changed section(s).")
    return " ".join(parts)
