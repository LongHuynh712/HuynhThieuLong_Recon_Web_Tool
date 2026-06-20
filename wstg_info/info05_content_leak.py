# [WSTG-INFO-05] Bổ sung theo OWASP WSTG 4.1
"""Review webpage content for information leakage."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Comment

from wstg_info._helpers import fetch_page, normalize_target_url
from webcheck_checks import extract_js_secrets

LEAK_PATTERNS = {
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "stripe_live": r"sk_live_[A-Za-z0-9]{20,}",
    "bearer_token": r"Bearer\s+[A-Za-z0-9._\-]{20,}",
    "private_ip": r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    "internal_path": r"(?:/internal/|/private/|/admin/|/backup/|/config/)[\w./\-]+",
    "todo_fixme": r"(?i)\b(TODO|FIXME|HACK|XXX)\b[^\n]{0,120}",
}


def scan_page_content_leak(url: str) -> dict:
    base = normalize_target_url(url)
    response = fetch_page(base)
    if not response:
        raise ConnectionError(f"Cannot connect to {url}")

    html = response.text or ""
    soup = BeautifulSoup(html, "html.parser")

    comments = [str(c).strip() for c in soup.find_all(string=lambda t: isinstance(t, Comment)) if str(c).strip()]

    meta_tags = []
    for tag in soup.find_all("meta"):
        meta_tags.append({
            "name": tag.get("name") or tag.get("property") or tag.get("http-equiv") or "meta",
            "content": (tag.get("content") or "")[:200],
        })

    script_srcs = []
    for script in soup.find_all("script", src=True):
        src = urljoin(base, script["src"])
        host = urlparse(base).netloc
        if urlparse(src).netloc == host or not urlparse(src).netloc:
            script_srcs.append(src)

    findings = {key: sorted(set(re.findall(pattern, html, re.I)))[:20] for key, pattern in LEAK_PATTERNS.items()}
    js_report = extract_js_secrets(html)

    report = "\n========== WSTG-INFO-05 CONTENT LEAKAGE (SUPPLEMENT) ==========\n"
    report += f"[FOUND] HTML comments: {len(comments)}\n"
    for c in comments[:10]:
        report += f" - {c[:120]}\n"
    report += f"\n[FOUND] Meta tags: {len(meta_tags)}\n"
    for m in meta_tags[:12]:
        report += f" - {m['name']}: {m['content'][:80]}\n"
    report += f"\n[FOUND] Internal script sources: {len(script_srcs)}\n"
    for src in script_srcs[:15]:
        report += f" - {src}\n"
    report += "\n[PATTERN MATCHES]\n"
    for key, values in findings.items():
        if values:
            report += f" - {key}: {len(values)} match(es)\n"
    if js_report:
        report += "\n" + js_report.strip()

    return {
        "wstg_id": "WSTG-INFO-05",
        "comments": comments[:20],
        "meta_tags": meta_tags[:30],
        "script_srcs": script_srcs[:30],
        "pattern_matches": findings,
        "js_secrets_report": js_report.strip() if js_report else "",
        "report": report.strip(),
    }
