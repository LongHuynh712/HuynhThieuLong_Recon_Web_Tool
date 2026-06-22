# [WSTG-INFO-08] Bổ sung theo OWASP WSTG 4.1
"""Fingerprint web application framework via cookies, headers, URL patterns."""

from __future__ import annotations

from urllib.parse import urljoin

from wstg_info._helpers import fetch_page, normalize_target_url

FRAMEWORK_SIGNATURES = {
    "Django": {"cookies": ["csrftoken", "sessionid"], "headers": [], "paths": ["/admin/login/"]},
    "Laravel": {"cookies": ["laravel_session", "XSRF-TOKEN"], "headers": [], "paths": ["/login"]},
    "Express/Node": {"cookies": ["connect.sid"], "headers": ["X-Powered-By: Express"], "paths": []},
    "ASP.NET": {"cookies": ["ASP.NET_SessionId", ".AspNetCore.Session"], "headers": ["X-AspNet-Version", "X-AspNetMvc-Version"], "paths": ["/Account/Login"]},
    "Spring": {"cookies": ["JSESSIONID"], "headers": [], "paths": ["/actuator/health"]},
    "Rails": {"cookies": ["_session_id"], "headers": ["X-Runtime"], "paths": ["/users/sign_in"]},
    "WordPress": {"cookies": [], "headers": [], "paths": ["/wp-json/", "/wp-login.php"]},
    "Next.js": {"cookies": [], "headers": [], "paths": ["/_next/static/"]},
}


def fingerprint_framework(url: str) -> dict:
    base = normalize_target_url(url)
    response = fetch_page(base)
    if not response:
        raise ConnectionError(f"Cannot connect to {url}")

    headers = {k.lower(): v for k, v in response.headers.items()}
    cookie_blob = (response.headers.get("Set-Cookie") or "").lower()
    html_lower = (response.text or "").lower()

    matches = []
    for name, sig in FRAMEWORK_SIGNATURES.items():
        signals = []
        for ck in sig["cookies"]:
            if ck.lower() in cookie_blob or ck.lower() in html_lower:
                signals.append(f"cookie:{ck}")
        for hdr in sig["headers"]:
            key = hdr.split(":", 1)[0].lower()
            if key in headers:
                signals.append(f"header:{key}")
        for path in sig["paths"]:
            probe = fetch_page(urljoin(base, path.lstrip("/")))
            if probe and probe.status_code in (200, 301, 302, 401, 403):
                signals.append(f"path:{path}")
        if signals:
            matches.append({"framework": name, "signals": signals})

    best = matches[0]["framework"] if matches else "Unknown"

    report = "\n========== WSTG-INFO-08 FRAMEWORK FINGERPRINT (SUPPLEMENT) ==========\n"
    if matches:
        for m in matches:
            report += f"[FOUND] {m['framework']}: {', '.join(m['signals'])}\n"
    else:
        report += "[INFO] No strong framework signature detected\n"
    report += f"[RESULT] Best guess: {best}\n"

    return {
        "wstg_id": "WSTG-INFO-08",
        "matches": matches,
        "best_guess": best,
        "report": report.strip(),
    }
