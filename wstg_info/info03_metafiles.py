# [WSTG-INFO-03] Bổ sung theo OWASP WSTG 4.1
"""Review webserver metafiles — robots, sitemap, security.txt, humans.txt."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from wstg_info._helpers import SENSITIVE_PATH_HINTS, fetch_page, normalize_target_url

META_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/humans.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
)


def _parse_robots_disallow(text: str) -> list[str]:
    paths = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue
        key, value = parts[0].strip().lower(), parts[1].strip()
        if key in ("disallow", "allow") and value:
            paths.append(value)
    return paths


def _flag_sensitive(paths: list[str]) -> list[dict]:
    flagged = []
    for path in paths:
        lower = path.lower()
        hits = [hint for hint in SENSITIVE_PATH_HINTS if hint in lower]
        if hits:
            flagged.append({"path": path, "hints": hits})
    return flagged


def fetch_metafiles(url: str) -> dict:
    base = normalize_target_url(url)
    parsed = urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    files = []
    sensitive_paths = []
    for path in META_PATHS:
        target = urljoin(origin + "/", path.lstrip("/"))
        resp = fetch_page(target)
        entry = {"path": path, "url": target, "status": None, "found": False, "preview": ""}
        if resp:
            entry["status"] = resp.status_code
            if resp.status_code == 200:
                body = (resp.text or "").strip()
                if body and "<html" not in body[:200].lower():
                    entry["found"] = True
                    entry["preview"] = body[:500]
                    if path.endswith("robots.txt"):
                        robots_paths = _parse_robots_disallow(body)
                        sensitive_paths.extend(_flag_sensitive(robots_paths))
        files.append(entry)

    report = "\n========== WSTG-INFO-03 METAFILES (SUPPLEMENT) ==========\n"
    for item in files:
        if item["found"]:
            report += f"[FOUND] {item['path']} (HTTP {item['status']})\n"
        elif item["status"]:
            report += f"[INFO] {item['path']} → HTTP {item['status']}\n"
        else:
            report += f"[MISSING] {item['path']}\n"
    if sensitive_paths:
        report += "\n[SENSITIVE PATHS FROM ROBOTS.TXT]\n"
        for sp in sensitive_paths:
            report += f" - {sp['path']} ({', '.join(sp['hints'])})\n"

    return {
        "wstg_id": "WSTG-INFO-03",
        "files": files,
        "sensitive_paths": sensitive_paths,
        "report": report.strip(),
    }
