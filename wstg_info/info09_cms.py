# [WSTG-INFO-09] Bổ sung theo OWASP WSTG 4.1
"""Fingerprint CMS / web application product."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from wstg_info._helpers import fetch_page, normalize_target_url

CMS_SIGNATURES = {
    "WordPress": {
        "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/", "/readme.html"],
        "generator": r"wordpress",
    },
    "Joomla": {
        "paths": ["/administrator/", "/media/system/js/core.js"],
        "generator": r"joomla",
    },
    "Drupal": {
        "paths": ["/core/misc/drupal.js", "/sites/default/files/"],
        "generator": r"drupal",
    },
    "Magento": {
        "paths": ["/skin/frontend/", "/media/catalog/"],
        "generator": r"magento",
    },
}


def _extract_generator(html: str) -> str | None:
    soup = BeautifulSoup(html, "html.parser")
    tag = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
    if tag and tag.get("content"):
        return tag["content"].strip()
    return None


def fingerprint_cms(url: str) -> dict:
    base = normalize_target_url(url)
    response = fetch_page(base)
    if not response:
        raise ConnectionError(f"Cannot connect to {url}")

    html = response.text or ""
    generator = _extract_generator(html)
    matches = []

    for cms, sig in CMS_SIGNATURES.items():
        signals = []
        if generator and re.search(sig["generator"], generator, re.I):
            signals.append(f"generator:{generator}")
        for path in sig["paths"]:
            probe = fetch_page(urljoin(base, path.lstrip("/")))
            if probe and probe.status_code in (200, 301, 302, 401, 403):
                signals.append(f"path:{path}")
        if signals:
            version = None
            if cms == "WordPress":
                readme = fetch_page(urljoin(base, "readme.html"))
                if readme and readme.status_code == 200:
                    m = re.search(r"Version\s+([0-9.]+)", readme.text or "", re.I)
                    if m:
                        version = m.group(1)
            matches.append({"cms": cms, "signals": signals, "version": version})

    best = matches[0]["cms"] if matches else "Unknown"

    report = "\n========== WSTG-INFO-09 CMS FINGERPRINT (SUPPLEMENT) ==========\n"
    report += f"[INFO] Meta generator: {generator or 'Not present'}\n"
    if matches:
        for m in matches:
            line = f"[FOUND] {m['cms']}: {', '.join(m['signals'])}"
            if m.get("version"):
                line += f" (version hint: {m['version']})"
            report += line + "\n"
    else:
        report += "[INFO] No CMS signature matched strongly\n"
    report += f"[RESULT] Best guess: {best}\n"

    return {
        "wstg_id": "WSTG-INFO-09",
        "generator": generator,
        "matches": matches,
        "best_guess": best,
        "report": report.strip(),
    }
