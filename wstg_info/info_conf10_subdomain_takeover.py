from __future__ import annotations

from urllib.parse import urlparse
from typing import Dict, List

from scanner import enumerate_subdomains, safe_request


TAKEOVER_SIGNATURES = {
    "s3": ["NoSuchBucket", "The specified bucket does not exist"],
    "github_pages": ["There isn't a GitHub Pages site here."],
    "heroku": ["No such app"],
    "azure": ["The specified resource does not exist"],
    "fastly": ["The requested URL is not configured"],
}


def detect_subdomain_takeover(url: str) -> Dict:
    """Detect likely subdomain takeover candidates for the given URL.

    This reuses the repository's `enumerate_subdomains` helper and then
    probes discovered hosts for common provider takeover signatures.
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")
    domain = parsed.hostname or parsed.path

    output = {
        "domain": domain,
        "candidates": [],
        "findings": [],
    }

    # Reuse enumerate_subdomains() which returns a human-readable report.
    raw = enumerate_subdomains(domain)
    # Parse lines starting with '- '
    subs: List[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("- "):
            subs.append(line[2:].strip())

    output["candidates"] = subs

    for host in subs:
        try:
            resp = safe_request(f"https://{host}")
            status = resp.status_code if resp else None
            body = (resp.text or "") if resp else ""
            sigs = []
            for provider, markers in TAKEOVER_SIGNATURES.items():
                for marker in markers:
                    if marker.lower() in body.lower():
                        sigs.append({"provider": provider, "marker": marker})
            if sigs:
                output["findings"].append({"host": host, "status": status, "signatures": sigs})
        except Exception:
            continue

    if not output["findings"]:
        output["note"] = "No obvious takeover signatures detected — manual follow-up recommended"

    return output
