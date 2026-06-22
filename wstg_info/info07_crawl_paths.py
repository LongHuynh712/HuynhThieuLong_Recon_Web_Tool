# [WSTG-INFO-07] Bổ sung theo OWASP WSTG 4.1
"""Map execution paths — BFS crawl of internal links."""

from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from wstg_info._helpers import fetch_page, normalize_target_url

DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_PAGES = 25


def crawl_site(base_url: str, max_depth: int = DEFAULT_MAX_DEPTH, max_pages: int = DEFAULT_MAX_PAGES) -> dict:
    start = normalize_target_url(base_url)
    start_host = urlparse(start).netloc.lower()

    visited = {start: {"depth": 0, "parent": None}}
    edges = []
    queue = deque([(start, 0)])

    while queue and len(visited) < max_pages:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue
        resp = fetch_page(current)
        if not resp or not resp.text:
            continue
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = urljoin(current, tag["href"])
            parsed = urlparse(href)
            if parsed.scheme not in ("http", "https"):
                continue
            if parsed.netloc.lower() != start_host:
                continue
            clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
            if parsed.query:
                clean += "?" + parsed.query
            edges.append({"from": current, "to": clean})
            if clean not in visited and len(visited) < max_pages:
                visited[clean] = {"depth": depth + 1, "parent": current}
                queue.append((clean, depth + 1))

    tree = []
    for url, meta in sorted(visited.items(), key=lambda x: (x[1]["depth"], x[0])):
        tree.append({"url": url, "depth": meta["depth"], "parent": meta["parent"]})

    report = "\n========== WSTG-INFO-07 EXECUTION PATHS / CRAWL (SUPPLEMENT) ==========\n"
    report += f"[FOUND] Pages crawled: {len(visited)} (max_depth={max_depth}, max_pages={max_pages})\n"
    for node in tree:
        indent = "  " * node["depth"]
        report += f"{indent}- {node['url']}\n"

    return {
        "wstg_id": "WSTG-INFO-07",
        "start_url": start,
        "max_depth": max_depth,
        "max_pages": max_pages,
        "pages": tree,
        "edges": edges[:200],
        "report": report.strip(),
    }
