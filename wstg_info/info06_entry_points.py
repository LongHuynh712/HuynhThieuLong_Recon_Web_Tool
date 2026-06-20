# [WSTG-INFO-06] Bổ sung theo OWASP WSTG 4.1
"""Identify application entry points — forms, params, cookies, headers."""

from __future__ import annotations

from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup

from wstg_info._helpers import fetch_page, normalize_target_url


def extract_entry_points(url: str) -> dict:
    base = normalize_target_url(url)
    response = fetch_page(base)
    if not response:
        raise ConnectionError(f"Cannot connect to {url}")

    html = response.text or ""
    soup = BeautifulSoup(html, "html.parser")
    base_host = urlparse(base).netloc.lower()

    forms = []
    for form in soup.find_all("form"):
        action = urljoin(base, form.get("action") or base)
        method = (form.get("method") or "GET").upper()
        inputs = []
        for field in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": field.get("name") or field.get("id") or "unnamed",
                "type": field.get("type") or field.name,
            })
        forms.append({"action": action, "method": method, "inputs": inputs})

    query_params = []
    seen = set()
    for tag in soup.find_all("a", href=True):
        href = urljoin(base, tag["href"])
        parsed = urlparse(href)
        if parsed.query:
            params = parse_qs(parsed.query)
            for name in params:
                key = (href.split("?", 1)[0], name)
                if key not in seen:
                    seen.add(key)
                    query_params.append({"url": href.split("?", 1)[0], "param": name})

    cookies = []
    raw_cookie = response.headers.get("Set-Cookie", "")
    if raw_cookie:
        for chunk in raw_cookie.split(","):
            name = chunk.split("=", 1)[0].strip()
            if name and name.lower() not in ("path", "expires", "domain", "secure", "httponly", "samesite"):
                cookies.append(name)

    header_inputs = [h for h in response.headers if h.lower().startswith(("x-", "authorization", "cookie"))]

    report = "\n========== WSTG-INFO-06 ENTRY POINTS (SUPPLEMENT) ==========\n"
    report += f"[FOUND] Forms: {len(forms)}\n"
    for i, form in enumerate(forms[:20], 1):
        report += f" {i}. {form['method']} {form['action']} ({len(form['inputs'])} fields)\n"
    report += f"\n[FOUND] Query parameters: {len(query_params)}\n"
    for qp in query_params[:25]:
        report += f" - {qp['param']} @ {qp['url']}\n"
    report += f"\n[FOUND] Cookies set: {len(cookies)}\n"
    for c in cookies:
        report += f" - {c}\n"
    report += f"\n[INFO] Relevant headers: {', '.join(header_inputs[:12])}\n"

    return {
        "wstg_id": "WSTG-INFO-06",
        "forms": forms,
        "query_params": query_params,
        "cookies": cookies,
        "header_inputs": header_inputs,
        "report": report.strip(),
    }
