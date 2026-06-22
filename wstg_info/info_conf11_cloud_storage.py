from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse

from scanner import safe_request


STORAGE_PATTERNS = [
    r"s3[.-]([a-z0-9-]+)\.amazonaws\.com",
    r"amazonaws\.com",
    r"storage\.googleapis\.com",
    r"blob\.core\.windows\.net",
    r"cdn\.digitaloceanspaces\.com",
]


def discover_cloud_storage(url: str) -> Dict:
    """Discover obvious cloud storage hosts referenced by the target page.

    Returns candidate storage endpoints and whether basic unauthenticated listing
    appears to be possible (simple HEAD/GET heuristics).
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")
    base = f"{parsed.scheme}://{parsed.netloc}"

    results: List[Dict] = []

    resp = safe_request(base)
    text = resp.text if resp else ""

    # Find candidate hostnames in page
    candidates = set()
    for pattern in STORAGE_PATTERNS:
        for m in re.finditer(pattern, text, re.I):
            candidates.add(m.group(0))

    # Also search for direct links
    for m in re.findall(r"https?://[\w\.-]+\.(?:amazonaws\.com|googleapis\.com|core\.windows\.net)[/\w\-\.%&=?]*", text, re.I):
        candidates.add(m)

    for target in sorted(candidates):
        entry = {"target": target, "status": None, "public_listing": False, "notes": []}
        try:
            head = safe_request(target, method="HEAD")
            if head:
                entry["status"] = head.status_code
            # Try GET for XML listing indicators
            get = safe_request(target)
            body = (get.text or "") if get else ""
            if "<ListBucketResult>" in body or "ListBucketResult" in body:
                entry["public_listing"] = True
                entry["notes"].append("XML bucket listing detected")
            if "NoSuchBucket" in body or "The specified bucket does not exist" in body:
                entry["notes"].append("Bucket appears missing or misconfigured")
        except Exception:
            entry["notes"].append("Probe failed")

        results.append(entry)

    return {"url": base, "candidates": results}
