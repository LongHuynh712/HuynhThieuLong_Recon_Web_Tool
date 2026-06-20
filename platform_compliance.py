"""
CWE / compliance reference mapping for findings (Phase 2).
"""

from __future__ import annotations

import re
from typing import Any

# (pattern in title+text, CWE ids, short labels)
_CWE_RULES: list[tuple[str, list[str], list[str]]] = [
    (
        r"content-security-policy|\[missing\].*csp|csp",
        ["CWE-693", "CWE-1021"],
        ["Protection Mechanism Failure", "Improper Restriction of Rendered UI Layers"],
    ),
    (
        r"hsts|strict-transport",
        ["CWE-319", "CWE-523"],
        ["Cleartext Transmission of Sensitive Information"],
    ),
    (
        r"ssl|tls|certificate|https",
        ["CWE-295", "CWE-326"],
        ["Improper Certificate Validation", "Inadequate Encryption Strength"],
    ),
    (
        r"x-frame-options|clickjack",
        ["CWE-1021"],
        ["Improper Restriction of Rendered UI Layers"],
    ),
    (
        r"x-content-type|nosniff",
        ["CWE-693"],
        ["Protection Mechanism Failure"],
    ),
    (
        r"referrer-policy",
        ["CWE-200"],
        ["Exposure of Sensitive Information"],
    ),
    (
        r"admin|dashboard|cpanel|/manage|login",
        ["CWE-200", "CWE-284"],
        ["Information Exposure", "Improper Access Control"],
    ),
    (
        r"backup|\.env|\.git|config\.php",
        ["CWE-538", "CWE-200"],
        ["Insertion of Sensitive Information into Log/File", "Information Exposure"],
    ),
    (
        r"enumeration|sensitive path",
        ["CWE-200", "CWE-548"],
        ["Information Exposure", "Exposure Through Directory Listing"],
    ),
    (
        r"cookie|set-cookie",
        ["CWE-614", "CWE-1004"],
        ["Sensitive Cookie Without Secure Attribute"],
    ),
    (
        r"http methods|put|delete|trace",
        ["CWE-650", "CWE-749"],
        ["Trusting HTTP Permission Methods"],
    ),
    (
        r"robots|sitemap|seo|meta description|title",
        ["CWE-1059"],
        ["Incomplete Documentation"],
    ),
]


def resolve_cwe_refs(title: str, text: str) -> dict[str, Any]:
    combined = f"{title}\n{text}".lower()
    cwe_ids: list[str] = []
    labels: list[str] = []
    for pattern, ids, descs in _CWE_RULES:
        if re.search(pattern, combined, re.I):
            for cid in ids:
                if cid not in cwe_ids:
                    cwe_ids.append(cid)
            for label in descs:
                if label not in labels:
                    labels.append(label)
    refs = [{"type": "CWE", "id": cid, "url": f"https://cwe.mitre.org/data/definitions/{cid.split('-')[1]}.html"} for cid in cwe_ids]
    return {
        "cwe_ids": cwe_ids,
        "cwe_labels": labels[:4],
        "compliance_refs": refs,
    }


def attach_compliance_refs(sections: list[dict]) -> list[dict]:
    for section in sections:
        refs = resolve_cwe_refs(section.get("title", ""), section.get("text", ""))
        section.update(refs)
    return sections
