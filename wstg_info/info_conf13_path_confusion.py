from __future__ import annotations

from typing import Dict, List
from urllib.parse import urljoin, urlparse

from scanner import safe_request, get_text_signature, is_similar_content


VARIANTS = ["", "/", "%2F", ".json", ".txt", ".bak"]


def test_path_confusion(url: str) -> Dict:
    """Test simple path confusion scenarios by comparing resource vs directory responses.

    The function probes a small set of candidate paths with different variants and
    flags cases where the server returns differing content or status codes that may
    indicate path-handling inconsistencies.
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")
    base = f"{parsed.scheme}://{parsed.netloc}"

    candidates = ["/index", "/admin", "/config", "/uploads/sample"]

    findings: List[Dict] = []

    for path in candidates:
        baseline_resp = safe_request(urljoin(base, path))
        baseline_text = get_text_signature(baseline_resp.text) if baseline_resp else ""
        baseline_status = baseline_resp.status_code if baseline_resp else None

        for v in VARIANTS:
            target = urljoin(base, path + v)
            resp = safe_request(target)
            status = resp.status_code if resp else None
            body_sig = get_text_signature(resp.text) if resp else ""

            if resp and status == 200 and baseline_resp:
                # If content differs significantly, report
                if not is_similar_content(baseline_text, body_sig):
                    findings.append({
                        "path": path,
                        "variant": v,
                        "target": target,
                        "baseline_status": baseline_status,
                        "status": status,
                        "note": "Different content for variant — potential path confusion"
                    })
            elif resp and baseline_resp is None and status in (200, 301, 302):
                findings.append({
                    "path": path,
                    "variant": v,
                    "target": target,
                    "baseline_status": baseline_status,
                    "status": status,
                    "note": "Variant reachable while baseline not — potential misrouting"
                })

    if not findings:
        return {"url": base, "note": "No obvious path confusion detected"}

    return {"url": base, "findings": findings}
