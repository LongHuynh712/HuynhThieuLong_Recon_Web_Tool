# [WSTG-INFO-10] Bổ sung theo OWASP WSTG 4.1
"""Map application architecture — CDN/WAF/LB detection + harmless WAF probe."""

from __future__ import annotations

import socket
from urllib.parse import urljoin

from wstg_info._helpers import fetch_page, hostname_from_url, normalize_target_url

CDN_WAF_HEADERS = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "server:cloudflare"],
    "Akamai": ["x-akamai-transformed", "akamaighost"],
    "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop", "via: cloudfront"],
    "Fastly": ["x-fastly-request-id", "x-served-by"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "Imperva/Incapsula": ["x-iinfo", "x-cdn: imperva"],
}

HARMLESS_WAF_PAYLOADS = (
    "?q=test' OR '1'='1",
    "?id=1 UNION SELECT NULL--",
    "/<script>alert(1)</script>",
)


def detect_architecture(url: str) -> dict:
    base = normalize_target_url(url)
    response = fetch_page(base)
    if not response:
        raise ConnectionError(f"Cannot connect to {url}")

    headers = {k.lower(): v for k, v in response.headers.items()}
    header_blob = " ".join(f"{k}: {v}".lower() for k, v in headers.items())

    cdn_matches = []
    for name, signals in CDN_WAF_HEADERS.items():
        hits = [s for s in signals if s.split(":", 1)[0].strip() in headers or s in header_blob]
        if hits:
            cdn_matches.append({"provider": name, "signals": hits})

    host = hostname_from_url(base)
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(host)
    except OSError:
        pass

    waf_blocks = []
    baseline_status = response.status_code
    for payload in HARMLESS_WAF_PAYLOADS:
        probe_url = urljoin(base, payload.lstrip("/") if payload.startswith("/") else payload)
        if not payload.startswith("/"):
            probe_url = base.rstrip("/") + payload
        probe = fetch_page(probe_url)
        if not probe:
            continue
        if probe.status_code in (403, 406, 429, 503):
            waf_blocks.append({"payload": payload, "status": probe.status_code})
        body = (probe.text or "").lower()
        if any(token in body for token in ("blocked", "forbidden", "access denied", "cloudflare", "sucuri", "incapsula")):
            waf_blocks.append({"payload": payload, "status": probe.status_code, "body_hint": True})

    lb_hints = []
    if any(k in headers for k in ("x-forwarded-for", "x-real-ip", "via")):
        lb_hints.append("Reverse proxy / load balancer headers present")

    report = "\n========== WSTG-INFO-10 ARCHITECTURE DETECTION (SUPPLEMENT) ==========\n"
    report += f"[INFO] Resolved IP: {resolved_ip or 'Unknown'}\n"
    if cdn_matches:
        for m in cdn_matches:
            report += f"[FOUND] CDN/WAF hint: {m['provider']} ({', '.join(m['signals'])})\n"
    else:
        report += "[INFO] No common CDN/WAF header signature matched\n"
    if lb_hints:
        for hint in lb_hints:
            report += f"[FOUND] {hint}\n"
    if waf_blocks:
        report += f"[FOUND] Possible WAF blocking behavior on {len(waf_blocks)} harmless probe(s)\n"
        for block in waf_blocks[:5]:
            report += f" - payload={block['payload']} status={block['status']}\n"
    else:
        report += "[INFO] No WAF block signature on harmless probes\n"

    return {
        "wstg_id": "WSTG-INFO-10",
        "resolved_ip": resolved_ip,
        "cdn_waf_matches": cdn_matches,
        "load_balancer_hints": lb_hints,
        "waf_probe_results": waf_blocks,
        "baseline_status": baseline_status,
        "report": report.strip(),
    }
