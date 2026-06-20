# [WSTG-INFO-01] Bổ sung theo OWASP WSTG 4.1
"""Search Engine Discovery — clickable dork URLs and cache/archive links."""

from __future__ import annotations

from urllib.parse import quote

from wstg_info._helpers import registered_domain_from_url


def build_search_engine_recon(url: str) -> dict:
    domain = registered_domain_from_url(url)
    base_google = "https://www.google.com/search?q="
    dorks = [
        {"label": "PDF documents", "query": f"site:{domain} filetype:pdf", "severity": "MEDIUM"},
        {"label": "Word documents", "query": f"site:{domain} filetype:doc OR filetype:docx", "severity": "MEDIUM"},
        {"label": "Excel spreadsheets", "query": f"site:{domain} filetype:xls OR filetype:xlsx", "severity": "MEDIUM"},
        {"label": "Admin pages", "query": f"site:{domain} inurl:admin", "severity": "MEDIUM"},
        {"label": "Login portals", "query": f"site:{domain} intitle:login", "severity": "MEDIUM"},
        {"label": "Backup files", "query": f"site:{domain} (backup OR backup.zip OR backup.sql)", "severity": "CRITICAL"},
        {"label": "Config files", "query": f"site:{domain} (config OR .env OR web.config)", "severity": "CRITICAL"},
        {"label": "Version control", "query": f'site:{domain} (".git" OR ".svn")', "severity": "CRITICAL"},
        {"label": "Dev/staging", "query": f"site:{domain} (staging OR dev OR test)", "severity": "MEDIUM"},
        {"label": "Credentials in pages", "query": f'site:{domain} (password OR username OR "api key")', "severity": "CRITICAL"},
    ]

    dork_links = [
        {
            "label": item["label"],
            "query": item["query"],
            "severity": item["severity"],
            "google_url": base_google + quote(item["query"]),
        }
        for item in dorks
    ]

    lookup_links = [
        {"label": "Google Search (site)", "url": base_google + quote(f"site:{domain}")},
        {"label": "Google Cache", "url": f"https://webcache.googleusercontent.com/search?q=cache:{domain}"},
        {"label": "Bing Cache", "url": f"https://cc.bingj.com/cache.aspx?q={quote(f'site:{domain}')}"},
        {"label": "Wayback Machine", "url": f"https://web.archive.org/web/*/{domain}/*"},
        {"label": "Google Dorking Helper", "url": base_google + quote(f"site:{domain} filetype:pdf")},
    ]

    report = "\n========== WSTG-INFO-01 SEARCH ENGINE RECON (SUPPLEMENT) ==========\n"
    report += f"Domain: {domain}\n\n[FOUND] {len(dork_links)} Google dork links (clickable)\n"
    for i, item in enumerate(dork_links, 1):
        report += f"{i}. [{item['severity']}] {item['label']}\n   Query: {item['query']}\n   URL: {item['google_url']}\n\n"
    report += "\n[CACHE & ARCHIVE LOOKUP]\n"
    for link in lookup_links:
        report += f" - {link['label']}: {link['url']}\n"

    return {
        "wstg_id": "WSTG-INFO-01",
        "domain": domain,
        "dorks": dork_links,
        "lookup_links": lookup_links,
        "report": report.strip(),
    }
