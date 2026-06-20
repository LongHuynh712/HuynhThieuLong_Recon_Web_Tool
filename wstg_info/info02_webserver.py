# [WSTG-INFO-02] Bổ sung theo OWASP WSTG 4.1
"""Fingerprint web server via headers and intentional error-page banner probing."""

from __future__ import annotations

import uuid
from urllib.parse import urljoin

from wstg_info._helpers import fetch_page, normalize_target_url

ERROR_BANNERS = {
    "apache": ("Apache", ["Apache/", "mod_ssl", "mod_php"]),
    "nginx": ("Nginx", ["nginx/", "openresty"]),
    "iis": ("Microsoft IIS", ["Microsoft-IIS", "IIS Windows Server"]),
    "litespeed": ("LiteSpeed", ["LiteSpeed", "lsws"]),
    "cloudflare": ("Cloudflare", ["cloudflare", "cf-ray"]),
}


def fingerprint_webserver(url: str) -> dict:
    base = normalize_target_url(url)
    response = fetch_page(base)
    if not response:
        raise ConnectionError(f"Cannot connect to {url}")

    headers = {k: v for k, v in response.headers.items()}
    server = headers.get("Server", "Unknown")
    powered = headers.get("X-Powered-By", "")
    via = headers.get("Via", "")

    error_path = f"/reconsight-wstg-probe-{uuid.uuid4().hex[:8]}"
    error_resp = fetch_page(urljoin(base, error_path))
    error_status = error_resp.status_code if error_resp else None
    error_body = (error_resp.text or "")[:2000] if error_resp else ""
    error_headers = dict(error_resp.headers) if error_resp else {}

    matches = []
    haystack = " ".join([
        server, powered, via,
        error_body,
        " ".join(f"{k}:{v}" for k, v in error_headers.items()),
    ]).lower()

    for key, (name, signals) in ERROR_BANNERS.items():
        if any(sig.lower() in haystack for sig in signals):
            matches.append({"id": key, "name": name, "signals": [s for s in signals if s.lower() in haystack]})

    guess = matches[0]["name"] if matches else (server if server != "Unknown" else "Unknown")

    report = "\n========== WSTG-INFO-02 WEB SERVER FINGERPRINT (SUPPLEMENT) ==========\n"
    report += f"[FOUND] Server header: {server}\n"
    report += f"[INFO] X-Powered-By: {powered or 'Not present'}\n"
    report += f"[INFO] Via: {via or 'Not present'}\n"
    report += f"[PROBE] Error path: {error_path} → HTTP {error_status}\n"
    if matches:
        for m in matches:
            report += f"[FOUND] Likely web server: {m['name']} ({', '.join(m['signals'])})\n"
    else:
        report += "[INFO] No definitive error-page banner match\n"
    report += f"[RESULT] Best guess: {guess}\n"

    return {
        "wstg_id": "WSTG-INFO-02",
        "server_header": server,
        "x_powered_by": powered or None,
        "via": via or None,
        "error_probe": {"path": error_path, "status": error_status, "sample": error_body[:400]},
        "matches": matches,
        "best_guess": guess,
        "report": report.strip(),
    }
