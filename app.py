# =========================
# FILE: app.py
# =========================

from flask import Flask, jsonify, render_template, request, make_response, redirect, url_for
from scanner import scan_target, get_whois_info, get_dns_records, get_registered_domain
from api_routes import api_bp
from api_handlers import API_REGISTRY
from module_docs import all_docs_payload, enrich_scan_modules, get_check_doc, resolve_doc_id
from platform_core import (
    build_executive_summary,
    build_remediation_plan,
    enrich_check_cards,
    enrich_sections,
)
from platform_compliance import attach_compliance_refs
from platform_compare import compare_scan_records
from platform_export import build_csv_export, build_json_export, build_professional_pdf, build_sarif_export
from schedule_service import (
    SCHEDULES_FILE,
    add_schedule,
    delete_schedule,
    load_schedules,
    start_scheduler,
    toggle_schedule,
)
from audit_service import audit_log, load_audit_entries
from workspace_service import (
    create_user,
    create_workspace,
    delete_user,
    delete_workspace,
    ensure_defaults,
    get_active_user,
    get_active_workspace_id,
    load_users,
    load_workspaces,
    set_active_user,
    set_active_workspace,
    verify_api_key,
)
from queue_service import (
    QUEUE_FILE,
    cancel_queue_item,
    enqueue_scan,
    list_queue,
    start_queue_worker,
)
from webhook_service import add_webhook, delete_webhook, dispatch_event, list_webhooks, toggle_webhook
from integration_service import load_integrations, notify_scan_complete, save_integrations
from health_service import build_health_status
from platform_risk import (
    compute_weighted_risk,
    compute_security_score,
    compute_quality_score,
    score_to_grade,
)
from platform_analytics import trend_analytics
from browser_service import (
    browser_scan,
    format_browser_cookies_report,
    format_screenshot_report,
    format_tech_hints_report,
    puppeteer_available,
)
import webbrowser
import threading
import time
import re
import socket
import urllib.parse
import json
import uuid
import requests
from io import BytesIO
from pathlib import Path

app = Flask(__name__)
app.register_blueprint(api_bp)
from wstg_routes import wstg_bp  # OWASP WSTG INFO supplement routes
app.register_blueprint(wstg_bp)

APP_BRAND = {
    "name": "Recon",
    "accent": "Sight",
    "full": "ReconSight",
    "page_title": "Công cụ trinh sát & phân tích website",
    "headline_line1": "Soi sáng website",
    "headline_line2": "của bạn từng lớp một",
    "subline_lead": "Thu thập OSINT, phân tích bảo mật và khám phá bề mặt tấn công trong vài phút —",
    "subline_emphasis": "trước khi kẻ tấn công làm điều đó.",
    "footer_tagline": "Công cụ trinh sát & kiểm tra bảo mật website",
}


def history_hostname(url):
    if not url:
        return "—"
    raw = str(url).strip()
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"
    parsed = urllib.parse.urlparse(raw)
    host = parsed.netloc or (parsed.path.split("/")[0] if parsed.path else raw)
    if host.startswith("www."):
        host = host[4:]
    return host or raw


SCAN_PRESETS = [
    {"id": "full", "label": "Toàn bộ", "icon": "⚡"},
    {"id": "security", "label": "Bảo mật", "icon": "🛡️"},
    {"id": "seo", "label": "SEO & Web", "icon": "📣"},
    {"id": "infra", "label": "Hạ tầng", "icon": "🌐"},
]


def history_chart_data(history):
    """Điểm số các lần quét gần đây (cũ → mới)."""
    items = list(reversed(history[:8]))
    return [
        {
            "label": history_hostname(item.get("url", "")),
            "score": int(item.get("score", 0) or 0),
        }
        for item in items
    ]


@app.context_processor
def inject_brand():
    return {
        "brand": APP_BRAND,
        "feature_docs": all_docs_payload(),
        "scan_presets": SCAN_PRESETS,
    }


@app.template_filter("history_host")
def history_host_filter(url):
    return history_hostname(url)


@app.template_filter("history_score_class")
def history_score_class_filter(score):
    try:
        value = int(score)
    except (TypeError, ValueError):
        return "score-low"
    if value >= 80:
        return "score-good"
    if value >= 50:
        return "score-mid"
    return "score-low"


HISTORY_FILE = Path("scan_history.json")
MAX_HISTORY_ITEMS = 15

SCAN_MODULES = [
    {
        "value": "security_headers",
        "label": "Headers & Security",
        "icon": "🛡️",
        "desc": "HTTP headers, HSTS, firewall, uptime",
        "tags": ["Headers", "HTTP Security", "HSTS", "Firewall"],
    },
    {
        "value": "ssl",
        "label": "SSL / TLS",
        "icon": "🔒",
        "desc": "Certificate, TLS version & cipher suite",
        "tags": ["SSL", "TLS"],
    },
    {
        "value": "cookies",
        "label": "Cookies",
        "icon": "🍪",
        "desc": "Set-Cookie analysis & session flags",
        "tags": ["Cookies"],
    },
    {
        "value": "fingerprint",
        "label": "Tech Stack",
        "icon": "⚙️",
        "desc": "Server fingerprint & technologies",
        "tags": ["Tech Stack", "Fingerprint"],
    },
    {
        "value": "robots",
        "label": "Crawl Rules",
        "icon": "🤖",
        "desc": "robots.txt, sitemap & security.txt",
        "tags": ["Robots.txt", "Sitemap", "Security.txt"],
    },
    {
        "value": "links",
        "label": "Linked Pages",
        "icon": "🔗",
        "desc": "Links, forms, redirects & JS endpoints",
        "tags": ["Linked Pages", "Redirects", "Forms"],
    },
    {
        "value": "seo",
        "label": "SEO & Social",
        "icon": "📣",
        "desc": "Meta tags, OpenGraph & Twitter cards",
        "tags": ["SEO", "Social Tags"],
    },
    {
        "value": "enumeration",
        "label": "Enumeration",
        "icon": "🎯",
        "desc": "Sensitive paths, methods & subdomains",
        "tags": ["Enumeration", "Subdomains"],
    },
    {
        "value": "browser",
        "label": "Browser (Puppeteer)",
        "icon": "📸",
        "desc": "Screenshot, JS cookies & tech hints",
        "tags": ["Screenshot", "Cookies"],
    },
    {
        "value": "assets",
        "label": "Assets & Trackers",
        "icon": "🧩",
        "desc": "Scripts, images, third-party services and trackers",
        "tags": ["Assets", "Tracking", "Third-Party"],
    },
    {
        "value": "network",
        "label": "Network Insight",
        "icon": "🌍",
        "desc": "IP, ASN, reverse DNS and hosting provider details",
        "tags": ["Network", "ASN", "Hosting"],
    },
    {
        "value": "email_security",
        "label": "Email Security",
        "icon": "✉️",
        "desc": "SPF, DMARC, DKIM and mail DNS checks",
        "tags": ["Email", "SPF", "DMARC", "DKIM"],
    },
    {
        "value": "whois_dns",
        "label": "DNS & WHOIS",
        "icon": "🌐",
        "desc": "DNS records, TXT, SPF/DMARC, WHOIS, IP",
        "tags": ["DNS", "WHOIS", "TXT", "Mail"],
    },
    {
        "value": "content_leakage",
        "label": "Content Leakage",
        "icon": "🔍",
        "desc": "Email, phone, API keys, secrets, comments",
        "tags": ["Information Leakage", "Content Analysis", "Secrets"],
    },
    {
        "value": "search_engine_recon",
        "label": "Search Engine Recon",
        "icon": "🔎",
        "desc": "Google Dorks, indexed URLs, documents, repositories",
        "tags": ["OSINT", "Search Engine", "Exposure"],
    },
    {
        "value": "enhanced_enumeration",
        "label": "Enhanced Enumeration",
        "icon": "🗂️",
        "desc": "Virtual hosts, admin paths, alternate ports, common paths",
        "tags": ["Enumeration", "Discovery", "Mapping"],
    },
    {
        "value": "entry_point_mapper",
        "label": "Entry Point Mapper",
        "icon": "📋",
        "desc": "Forms, parameters, HTTP headers, technology stack",
        "tags": ["Entry Points", "Mapping", "Analysis"],
    },
    {
        "value": "execution_paths",
        "label": "Execution Paths",
        "icon": "🔄",
        "desc": "Application workflow, entry/exit points, data flows",
        "tags": ["Execution Flow", "Workflow", "Analysis"],
    },
    {
        "value": "architecture_mapper",
        "label": "Architecture Mapper",
        "icon": "🏗️",
        "desc": "Microservices, APIs, databases, infrastructure components",
        "tags": ["Architecture", "Infrastructure", "Mapping"],
    },
    {
        "value": "framework_enhancement",
        "label": "Framework Enhancement",
        "icon": "⚙️",
        "desc": "Framework-specific vulnerabilities, version detection, API contracts",
        "tags": ["Framework", "Vulnerabilities", "API"],
    },
]

# Backward-compatible alias
SCAN_SECTION_OPTIONS = [{"value": m["value"], "label": m["label"]} for m in SCAN_MODULES]

# Feature list aligned with web-check.as93.net / web-check-master
FEATURE_CHECKS = [
    "Archive History", "Block List Check", "Carbon Footprint", "Cookies",
    "DNS Server", "DNS Records", "DNSSEC", "Site Features", "Firewall Types",
    "Get IP Address", "Headers", "HSTS", "HTTP Security", "Linked Pages",
    "Mail Config", "Email Security", "Network Info", "Open Ports", "Quality Check",
    "Global Rank", "Redirects", "Robots.txt", "Screenshot", "Security.txt",
    "Sitemap", "Social Tags", "SSL Certificate", "Uptime Status", "Tech Stack",
    "Known Threats", "TLS Version", "Trace Route", "TXT Records", "Whois Lookup",
    "Subdomains", "JS Endpoints", "Enumeration", "Forms", "SEO Metadata",
    "Assets & Trackers", "CSP Policy",
]

EXAMPLE_URLS = [
    "duck.com", "github.com", "google.com", "x.com",
    "bbc.co.uk", "wikipedia.org", "openai.com",
]

IMPLEMENTED_CHECKS = {
    "Headers", "HSTS", "HTTP Security", "SSL Certificate", "TLS Version",
    "DNS Records", "WHOIS Lookup", "Get IP Address", "Firewall Types",
    "Robots.txt", "Sitemap", "Linked Pages", "Redirects", "Social Tags",
    "Security.txt", "Tech Stack", "Uptime Status", "Subdomains", "JS Endpoints",
    "Enumeration", "Forms", "SEO Metadata", "TXT Records", "Cookies", "Mail Config",
    "Screenshot", "Email Security", "Network Info", "Assets & Trackers", "CSP Policy",
}

SCREENSHOT_URLS = [
    "https://pixelflare.cc/alicia/web-check/wc-ssl",
    "https://pixelflare.cc/alicia/web-check/wc-dns",
    "https://pixelflare.cc/alicia/web-check/wc-cookies",
    "https://pixelflare.cc/alicia/web-check/wc-robots",
    "https://pixelflare.cc/alicia/web-check/wc-headers",
    "https://pixelflare.cc/alicia/web-check/wc-quality",
    "https://pixelflare.cc/alicia/web-check/wc-location",
    "https://pixelflare.cc/alicia/web-check/wc-redirects",
    "https://pixelflare.cc/alicia/web-check/wc-firewall",
    "https://pixelflare.cc/alicia/web-check/wc-social",
    "https://pixelflare.cc/alicia/web-check/wc-screenshot",
    "https://pixelflare.cc/alicia/web-check/wc-tech",
    "https://pixelflare.cc/alicia/web-check/wc-hsts",
    "https://pixelflare.cc/alicia/web-check/wc-threats",
    "https://pixelflare.cc/alicia/web-check/wc-rank",
    "https://pixelflare.cc/alicia/web-check/wc-http",
]

API_JOB_LABELS = {
    "get-ip": "Get IP Address",
    "headers": "Headers",
    "http-security": "HTTP Security",
    "hsts": "HSTS",
    "ssl": "SSL Certificate",
    "tls-connection": "TLS Connection",
    "dns": "DNS Records",
    "whois": "Whois Lookup",
    "txt-records": "TXT Records",
    "mail-config": "Mail Config",
    "redirects": "Redirects",
    "social-tags": "Social Tags",
    "security-txt": "Security.txt",
    "firewall": "Firewall",
    "status": "Server Status",
    "robots-txt": "Robots.txt",
    "linked-pages": "Linked Pages",
    "cookies": "Cookies",
    "screenshot": "Screenshot",
    "tech-stack": "Tech Stack",
    "fingerprint": "Fingerprint",
}


def get_api_jobs():
    return [
        {"id": job_id, "label": API_JOB_LABELS.get(job_id, job_id.replace("-", " ").title())}
        for job_id in sorted(API_REGISTRY.keys())
    ]


CHECK_ICONS = {
    "headers": "📋", "security": "🛡️", "ssl": "🔒", "hsts": "🔐", "tls": "🔐",
    "fingerprint": "🔍", "robots": "🤖", "sitemap": "🗺️", "links": "🔗",
    "forms": "📝", "seo": "📈", "enumeration": "⚠️", "whois": "🌐", "dns": "📡",
    "subdomains": "🧩", "metadata": "📄", "methods": "⚙️", "cookies": "🍪",
    "social": "📣", "redirect": "↪️", "firewall": "🧱", "mail": "✉️", "txt": "📜",
    "screenshot": "📸", "browser": "🌐",
}


def load_history():
    if not HISTORY_FILE.exists():
        return []
    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_history(history):
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY_FILE.open("w", encoding="utf-8") as f:
        json.dump(history[-MAX_HISTORY_ITEMS:], f, ensure_ascii=False, indent=2)


def _parse_and_enrich_sections(report: str):
    sections = attach_compliance_refs(enrich_sections(parse_report(report)))
    for s in sections or []:
        try:
            s["doc_id"] = resolve_doc_id(s.get("slug", ""), s.get("title", ""))
        except Exception:
            # UI bổ sung doc_id, không ảnh hưởng nội dung scan.
            s["doc_id"] = "security_headers"
    return sections


def save_scan_to_history(
    url: str,
    scan_mode: str,
    selected_sections: list,
    report: str,
    sections: list,
    summary: dict,
    recommendations: list,
    metrics: dict,
    target_info: dict,
    scan_duration: float,
):
    section_titles = [s["title"] for s in sections]
    if section_titles:
        section_summary = ", ".join(section_titles[:3])
        if len(section_titles) > 3:
            section_summary += "..."
        if len(section_summary) > 80:
            section_summary = section_summary[:77].rstrip() + "..."
    else:
        section_summary = "Không có danh mục"

    history = load_history()
    new_record = {
        "id": str(uuid.uuid4()),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ts": time.time(),
        "workspace_id": get_active_workspace_id(),
        "url": url,
        "mode": scan_mode,
        "score": summary["score"],
        "security_score": summary.get("security_score", summary["score"]),
        "quality_score": summary.get("quality_score", 100),
        "security_grade": summary.get("security_grade", score_to_grade(summary.get("security_score", summary["score"]))),
        "quality_grade": summary.get("quality_grade", score_to_grade(summary.get("quality_score", 100))),
        "status": summary["status"],
        "missing": summary["missing"],
        "warning": summary["warning"],
        "error": summary["error"],
        "found": summary["found"],
        "redirects": summary["redirects"],
        "section_count": len(section_titles),
        "section_preview": section_summary,
        "report": report,
        "target_info": target_info,
        "recommendations": recommendations,
        "metrics": metrics,
        "scan_duration": scan_duration,
        "selected_sections": selected_sections,
    }
    history.append(new_record)
    save_history(history)
    _post_scan_hooks(new_record, sections, summary, recommendations)
    return new_record


def _post_scan_hooks(record: dict, sections: list, summary: dict, recommendations: list):
    """Webhooks, integrations, audit after scan saved."""
    ws = record.get("workspace_id", "")
    user = get_active_user()
    actor = user.get("name", "system") if user else "system"
    hostname = (record.get("target_info") or {}).get("hostname") or record.get("url", "")
    executive = build_executive_summary(
        record.get("report", ""),
        sections,
        summary,
        recommendations,
        hostname,
    )
    payload = {
        "record_id": record.get("id"),
        "url": record.get("url"),
        "hostname": hostname,
        "score": summary.get("score"),
        "status": summary.get("status"),
        "risk_level": executive.get("risk_level"),
        "workspace_id": ws,
        "timestamp": record.get("timestamp"),
    }
    audit_log("scan.complete", actor=actor, workspace_id=ws, detail=payload)
    try:
        dispatch_event("scan.complete", payload)
    except Exception:
        pass
    try:
        notify_scan_complete(payload)
    except Exception:
        pass


_GEOLOCATION_CACHE = {}

def lookup_ip_geolocation(ip: str):
    if not ip:
        return {}
    if ip in _GEOLOCATION_CACHE:
        return _GEOLOCATION_CACHE[ip]
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,regionName,city,lat,lon,timezone,isp,org,as,query"},
            timeout=6,
        )
        data = response.json()
        if response.status_code == 200 and data.get("status") == "success":
            result = {
                "query": data.get("query", ip),
                "country": data.get("country"),
                "region": data.get("regionName") or data.get("region"),
                "city": data.get("city"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "provider": data.get("isp") or data.get("org") or data.get("as"),
                "as": data.get("as"),
                "status": data.get("status"),
            }
        else:
            result = {
                "query": ip,
                "status": data.get("status", "fail"),
                "message": data.get("message", "Geolocation lookup failed"),
            }
    except Exception as exc:
        result = {"query": ip, "status": "error", "message": str(exc)}
    _GEOLOCATION_CACHE[ip] = result
    return result


def perform_scan(url: str, scan_mode: str = "full", selected_sections: list | None = None):
    """Run full server scan; returns dict used by UI, export, and scheduler."""
    if not url:
        return None
    if not url.startswith("http"):
        url = "https://" + url
    if not selected_sections:
        selected_sections = [option["value"] for option in SCAN_SECTION_OPTIONS]

    start_time = time.perf_counter()
    report = scan_target(url, scan_mode, selected_sections)
    browser_data = {}

    if "browser" in selected_sections:
        try:
            browser_data = browser_scan(url)
            if browser_data.get("screenshot"):
                report += format_screenshot_report()
                report += format_browser_cookies_report(browser_data.get("clientCookies", []))
                report += format_tech_hints_report(
                    browser_data.get("generators"),
                    browser_data.get("scriptSources"),
                )
            elif browser_data.get("error") or browser_data.get("skipped"):
                msg = browser_data.get("error") or browser_data.get("skipped")
                hint = browser_data.get("hint", "")
                report += f"\n========== SCREENSHOT ==========\n[WARNING] Puppeteer: {msg}\n"
                if hint:
                    report += f"{hint}\n"
        except Exception as e:
            # Browser module fails, mark as skipped but continue scan
            browser_data = {
                "status": "skipped",
                "module": "Browser (Puppeteer)",
                "reason": str(e)
            }
            report += f"\n========== SCREENSHOT ==========\n[WARNING] Puppeteer: {str(e)}\n"

    scan_duration = round(time.perf_counter() - start_time, 1)
    sections = _parse_and_enrich_sections(report)
    summary = build_summary(report)
    recommendations = generate_recommendations(report)
    metrics = extract_metrics(report)

    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or url
        ipaddr = socket.gethostbyname(hostname)
    except Exception:
        hostname = None
        ipaddr = None

    target_info = {"hostname": hostname, "ip": ipaddr}
    base_domain = get_registered_domain(hostname) if hostname else None
    try:
        whois_text = get_whois_info(base_domain) if hostname else ""
    except Exception as e:
        whois_text = f"WHOIS lookup error: {e}\n"
    try:
        dns_text = get_dns_records(hostname, ["A"]) if hostname else ""
        if base_domain and base_domain != hostname:
            dns_text += "\n"
            dns_text += get_dns_records(base_domain, ["MX", "NS", "TXT"])
    except Exception as e:
        dns_text = f"DNS lookup error: {e}\n"

    target_info["whois"] = whois_text
    target_info["dns"] = dns_text
    target_info["server"] = metrics.get("server")
    target_info["technology"] = metrics.get("technology")
    target_info["cdn"] = metrics.get("cdn")
    target_info["robots_found"] = metrics.get("robots_found")
    target_info["sitemap_found"] = metrics.get("sitemap_found")
    if ipaddr:
        target_info["geo"] = lookup_ip_geolocation(ipaddr)
    if browser_data.get("screenshot"):
        target_info["screenshot_b64"] = browser_data["screenshot"]
        target_info["browser_cookies"] = browser_data.get("clientCookies", [])

    return {
        "url": url,
        "scan_mode": scan_mode,
        "selected_sections": selected_sections,
        "report": report,
        "sections": sections,
        "summary": summary,
        "recommendations": recommendations,
        "metrics": metrics,
        "target_info": target_info,
        "scan_duration": scan_duration,
    }


def run_scheduled_scan(schedule: dict):
    modules = schedule.get("modules") or [option["value"] for option in SCAN_SECTION_OPTIONS]
    result = perform_scan(schedule.get("url", ""), schedule.get("scan_mode", "full"), modules)
    if result and result.get("summary"):
        record = save_scan_to_history(
            result["url"],
            result["scan_mode"],
            result["selected_sections"],
            result["report"],
            result["sections"],
            result["summary"],
            result["recommendations"],
            result["metrics"],
            result["target_info"],
            result["scan_duration"],
        )
        result["record_id"] = record.get("id")
    return result


def run_queued_scan(queue_item: dict):
    modules = queue_item.get("modules") or None
    if modules == []:
        modules = None
    ws = queue_item.get("workspace_id")
    if ws:
        set_active_workspace(ws)
    result = perform_scan(
        queue_item.get("url", ""),
        queue_item.get("scan_mode", "full"),
        modules,
    )
    if result and result.get("summary"):
        record = save_scan_to_history(
            result["url"],
            result["scan_mode"],
            result["selected_sections"],
            result["report"],
            result["sections"],
            result["summary"],
            result["recommendations"],
            result["metrics"],
            result["target_info"],
            result["scan_duration"],
        )
        result["record_id"] = record.get("id")
    return result


def _platform_context(extra: dict | None = None):
    ensure_defaults()
    history = load_history()
    ctx = {
        "workspaces": load_workspaces(),
        "users": load_users(),
        "active_workspace_id": get_active_workspace_id(),
        "active_user": get_active_user(),
        "scan_queue": list_queue(),
        "webhooks": list_webhooks(),
        "integrations": load_integrations(),
        "audit_entries": load_audit_entries(30),
        "health_snapshot": build_health_status(
            api_job_count=len(API_REGISTRY),
            puppeteer_check=puppeteer_available,
            scan_modules_count=len(SCAN_MODULES),
            history_file=HISTORY_FILE,
            schedules_file=SCHEDULES_FILE,
            queue_file=QUEUE_FILE,
        ),
        "trend_30": trend_analytics(history, 30),
        "trend_90": trend_analytics(history, 90),
    }
    queue = ctx["scan_queue"]
    ctx["dashboard_stats"] = {
        "history_count": len(history),
        "queue_pending": sum(1 for q in queue if q.get("status") == "pending"),
        "avg_score_30": ctx["trend_30"].get("average_score", 0),
        "health_status": ctx["health_snapshot"].get("status", "—"),
        "module_count": len(SCAN_MODULES),
        "api_count": len(API_REGISTRY),
    }
    if extra:
        ctx.update(extra)
    return ctx


def slugify(title):
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower().strip())
    return slug.strip("-")


def categorize(title):
    key = title.lower()
    if any(word in key for word in ["security", "header", "hsts", "fingerprint", "ssl", "http methods", "admin", "backup", "sensitive"]):
        return "Security"
    if any(word in key for word in ["seo", "mobile", "canonical", "image alt", "robots", "sitemap", "linked pages", "social", "redirect"]):
        return "SEO"
    if any(word in key for word in ["firewall", "security.txt", "http security", "server status", "get ip", "cookies", "tls connection", "mail config", "txt record"]):
        return "Security"
    if any(word in key for word in ["links", "forms", "http methods", "enumeration"]):
        return "Analysis"
    if any(word in key for word in ["meta", "page metadata", "fingerprint"]):
        return "Site Info"
    return "Other"


def get_section_severity(text):
    if "[ERROR]" in text or "Severity: HIGH" in text:
        return "high"
    if "[WARNING]" in text or "Severity: MEDIUM" in text:
        return "medium"
    return "info"


def parse_report(report):
    sections = []
    current = None

    for line in report.splitlines():
        if line.strip().startswith("=========="):
            if current:
                current["severity"] = get_section_severity(current["text"])
                sections.append(current)
            title = line.strip("= ")
            current = {
                "title": title,
                "text": "",
                "slug": slugify(title),
                "category": categorize(title),
                "severity": "info",
            }
        elif current is not None:
            current["text"] += line + "\n"

    if current:
        current["severity"] = get_section_severity(current["text"])
        sections.append(current)

    return enrich_sections(sections)


def extract_metrics(report):
    metrics = {
        "links": 0,
        "forms": 0,
        "subdomains": 0,
        "js_endpoints": 0,
        "security_headers_pct": 100,
        "tls_score": 100,
        "seo_score": 100,
        "enumeration_findings": 0,
        "server": "Unknown",
        "technology": "Unknown",
        "cdn": "None",
        "robots_found": False,
        "sitemap_found": False,
        "admin_findings": 0,
        "backup_findings": 0,
        "sensitive_findings": 0,
        "http_methods_allowed": 0,
        "whois_available": False,
        "dns_available": False,
        "https_enabled": False,
    }

    if not report:
        return metrics

    link_match = re.search(r"Total links found:\s*(\d+)", report, re.I)
    if link_match:
        metrics["links"] = int(link_match.group(1))

    form_match = re.search(r"Found\s*(\d+)\s*forms", report, re.I)
    if form_match:
        metrics["forms"] = int(form_match.group(1))

    if re.search(r"Site is not HTTPS|not https|expired|invalid", report, re.I):
        metrics["tls_score"] = 58

    if re.search(r"Page title is missing|Meta description is missing|No viewport meta tag detected", report, re.I):
        metrics["seo_score"] = 72

    if re.search(r"\[MISSING\].*(Content-Security-Policy|HSTS not configured|X-Frame-Options|X-Content-Type-Options|Referrer-Policy)", report, re.I):
        metrics["security_headers_pct"] = 78

    metrics["enumeration_findings"] = len(re.findall(r"\[FOUND\]", report, re.I))
    metrics["admin_findings"] = len(re.findall(r"\[FOUND\].*(?:/admin|administrator|/dashboard|/cpanel|/manage|/login)", report, re.I))
    metrics["backup_findings"] = len(re.findall(r"\[FOUND\].*(?:backup|\\.env|config\\.php\\.bak|index\\.old|backup\\.zip|backup\\.sql)", report, re.I))
    metrics["sensitive_findings"] = len(re.findall(r"\[FOUND\].*(?:\\.git/config|\\.svn/entries|web\\.config|crossdomain\\.xml|clientaccesspolicy\\.xml)", report, re.I))
    metrics["http_methods_allowed"] = len(re.findall(r"^(?:OPTIONS|PUT|DELETE|TRACE|PATCH):\s*(?:Allowed|Redirected|Not Allowed|Blocked)", report, re.I | re.M))

    if re.search(r"^Server:\s*(.+)$", report, re.I | re.M):
        metrics["server"] = re.search(r"^Server:\s*(.+)$", report, re.I | re.M).group(1).strip()

    if re.search(r"^Possible Technology:\s*(.+)$", report, re.I | re.M):
        metrics["technology"] = re.search(r"^Possible Technology:\s*(.+)$", report, re.I | re.M).group(1).strip()
    elif re.search(r"^Fingerprint:\s*(.+)$", report, re.I | re.M):
        metrics["technology"] = re.search(r"^Fingerprint:\s*(.+)$", report, re.I | re.M).group(1).strip()

    if "Cloudflare Detected" in report or "WAF/CDN: Cloudflare" in report:
        metrics["cdn"] = "Cloudflare"
    elif "Akamai Detected" in report or "Akamai" in report:
        metrics["cdn"] = "Akamai"
    elif "nginx" in metrics["server"].lower() or "Apache" in metrics["server"]:
        metrics["cdn"] = metrics["server"]

    metrics["subdomains"] = len(re.findall(r"^\s*-\s*[\w\.-]+\.[a-z]{2,}" , report, re.M))
    metrics["js_endpoints"] = len(re.findall(r"^\s*-\s*(?:https?://|/)[\w\./\?\=&%\-_:]+", report, re.M))
    metrics["robots_found"] = bool(re.search(r"robots\.txt", report, re.I)) and not re.search(r"robots\.txt.*(not reachable|returned \d+)", report, re.I)
    metrics["sitemap_found"] = bool(re.search(r"Found sitemap|Sitemap directives found in robots\.txt|/sitemap\.xml", report, re.I))
    metrics["whois_available"] = "WHOIS" in report
    metrics["dns_available"] = bool(re.search(r"DNS RECORDS|records for", report, re.I))
    metrics["https_enabled"] = not bool(re.search(r"Site is not HTTPS|not https", report, re.I))

    return metrics


def build_summary(report):
    missing = report.count("[MISSING]")
    warning = report.count("[WARNING]")
    error = report.count("[ERROR]")
    found = report.count("[FOUND]")
    redirects = report.count("Redirected")

    sections = parse_report(report)
    security_score = compute_security_score(sections)
    quality_score = compute_quality_score(sections)

    score = security_score
    status = "Good"
    if score < 65:
        status = "Needs Improvement"
    elif score < 85:
        status = "Fair"

    return {
        "score": score,
        "security_score": security_score,
        "quality_score": quality_score,
        "security_grade": score_to_grade(security_score),
        "quality_grade": score_to_grade(quality_score),
        "status": status,
        "missing": missing,
        "warning": warning,
        "error": error,
        "found": found,
        "redirects": redirects,
    }


def build_summary_from_record(record):
    report = record.get("report", "")
    if report:
        return build_summary(report)

    security_score = record.get("security_score", record.get("score", 0))
    quality_score = record.get("quality_score", 100)

    return {
        "score": record.get("score", security_score),
        "security_score": security_score,
        "quality_score": quality_score,
        "security_grade": record.get("security_grade", score_to_grade(security_score)),
        "quality_grade": record.get("quality_grade", score_to_grade(quality_score)),
        "status": record.get("status", ""),
        "missing": record.get("missing", 0),
        "warning": record.get("warning", 0),
        "error": record.get("error", 0),
        "found": record.get("found", 0),
        "redirects": record.get("redirects", 0),
    }


def header_enabled(report, header_name):
    missing = f"[MISSING] {header_name}"
    if missing in report:
        return False
    if f"[MISSING] {header_name.lower()}" in report.lower():
        return False
    return f"[FOUND] {header_name}" in report or f"{header_name}:" in report


def build_security_panels(report):
    hsts_ok = "[MISSING] HSTS" not in report and (
        "[FOUND] HSTS" in report or "Strict-Transport-Security" in report
    )
    return {
        "csp": header_enabled(report, "Content-Security-Policy"),
        "hsts": hsts_ok,
        "xfo": header_enabled(report, "X-Frame-Options"),
        "xcto": header_enabled(report, "X-Content-Type-Options"),
        "referrer": header_enabled(report, "Referrer-Policy"),
    }


def _clean_line(line):
    stripped = line.strip()
    if not stripped or stripped.startswith("=") or re.fullmatch(r"=+", stripped):
        return None
    return re.sub(r"^\[(FOUND|MISSING|WARNING|ERROR|INFO|POSSIBLE FALSE POSITIVE)\]\s*", "", stripped)


def _truncate_text(text, limit=72):
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= limit:
        return text
    if ":" in text and text.index(":") < 48:
        key, value = text.split(":", 1)
        key = key.strip()
        value = value.strip()
        if len(key) <= 40:
            remaining = max(20, limit - len(key) - 2)
            if len(value) > remaining:
                return f"{key}: {value[: remaining - 1]}…"
    return text[: limit - 1] + "…"


def section_preview(text, limit=72):
    if not text:
        return "No details available."

    found = text.count("[FOUND]")
    missing = text.count("[MISSING]")
    warnings = text.count("[WARNING]") + text.count("[ERROR]")

    stats = []
    if found:
        stats.append(f"{found} passed")
    if missing:
        stats.append(f"{missing} missing")
    if warnings:
        stats.append(f"{warnings} warnings")
    stats_text = ", ".join(stats)

    for line in text.splitlines():
        cleaned = _clean_line(line)
        if not cleaned:
            continue
        snippet = _truncate_text(cleaned, limit)
        if stats_text:
            return f"{stats_text} · {snippet}"
        return snippet

    return stats_text or "No details available."


def pick_icon(title):
    key = title.lower()
    for token, icon in CHECK_ICONS.items():
        if token in key:
            return icon
    return "📌"


def severity_to_status(severity):
    if severity in ("critical", "high"):
        return "fail"
    if severity == "medium":
        return "warn"
    return "pass"


def build_advisories(sections, recommendations):
    advisories = {"critical": [], "warning": [], "info": [], "pass": []}
    for section in sections:
        item = {"title": section["title"], "text": section_preview(section.get("text", ""))}
        level = section.get("severity_level", section.get("severity", "info"))
        if level in ("critical", "high"):
            advisories["critical"].append(item)
        elif level == "medium" or section.get("severity") == "medium":
            advisories["warning"].append(item)
        elif "[FOUND]" in section.get("text", "") and "[MISSING]" not in section.get("text", ""):
            advisories["pass"].append(item)
        else:
            advisories["info"].append(item)
    for rec in recommendations:
        advisories["info"].append({"title": "Recommendation", "text": rec})
    return advisories


def build_check_cards(sections):
    cards = []
    for section in sections:
        level = section.get("severity_level", section.get("severity", "info"))
        status = severity_to_status(level)
        doc_id = resolve_doc_id(section.get("slug", ""), section.get("title", ""))
        help = get_check_doc(section.get("slug", ""), section.get("title", ""))
        cards.append({
            "title": section["title"],
            "slug": section["slug"],
            "category": section.get("category", "Other"),
            "status": status,
            "severity_level": level,
            "severity_label": section.get("severity_label", level.title()),
            "status_label": {"fail": "Issue", "warn": "Warning", "pass": "OK"}.get(status, "OK"),
            "icon": pick_icon(section["title"]),
            "preview": section_preview(section.get("text", "")),
            "doc_id": doc_id,
            "help": help,
        })
    return cards


def generate_recommendations(report):
    recommendations = []

    if "[MISSING] Page title is missing" in report:
        recommendations.append("Bổ sung thẻ <title> hợp lệ cho trang để cải thiện định danh và SEO.")
    if "[MISSING] Meta description is missing" in report:
        recommendations.append("Thêm thẻ meta description 50-160 ký tự cho mỗi trang quan trọng.")
    if "Site is not HTTPS" in report:
        recommendations.append("Triển khai chứng chỉ SSL/TLS và chuyển toàn bộ truy cập sang HTTPS.")
    if "[MISSING] HSTS not configured" in report:
        recommendations.append("Cấu hình Strict-Transport-Security để ép buộc trình duyệt sử dụng HTTPS.")
    if "[MISSING] Content-Security-Policy" in report:
        recommendations.append("Thêm header Content-Security-Policy phù hợp để hạn chế nguồn thực thi và tải tài nguyên.")
    if "[MISSING] X-Frame-Options" in report:
        recommendations.append("Thêm X-Frame-Options: DENY hoặc SAMEORIGIN để phòng chống clickjacking.")
    if "[MISSING] X-Content-Type-Options" in report:
        recommendations.append("Thêm X-Content-Type-Options: nosniff để ngăn trình duyệt sniff MIME type.")
    if "[MISSING] Referrer-Policy" in report:
        recommendations.append("Khai báo Referrer-Policy phù hợp để giảm rò rỉ referrer khi chuyển hướng.")
    if "[MISSING] No viewport meta tag detected" in report:
        recommendations.append("Thêm thẻ meta viewport để tối ưu hiển thị trên thiết bị di động.")
    if "Images without alt text" in report or "missing alt" in report.lower():
        recommendations.append("Kiểm tra các thẻ <img> và bổ sung thuộc tính alt cho ảnh quan trọng.")
    if "[POSSIBLE FALSE POSITIVE]" in report or "returned homepage-like content" in report:
        recommendations.append("Xác định lại các đường dẫn enumeration và loại bỏ false positive trong kiểm thử.")
    if "Blocked" in report and "HTTP METHODS" in report:
        recommendations.append("Giới hạn phương thức HTTP không cần thiết để giảm mặt phẳng tấn công.")

    if re.search(r"X-Powered-By:\s*.+", report, re.I):
        recommendations.append("Ẩn header X-Powered-By hoặc cấu hình proxy để giảm rò rỉ thông tin nền tảng.")
    if "robots.txt not reachable" in report or re.search(r"robots.txt returned \d+", report, re.I):
        recommendations.append("Duy trì robots.txt nếu website cần index, hoặc chặn chính xác các đường dẫn nhạy cảm.")
    if "sitemap.xml not found" in report or ("Sitemap directives found" not in report and "robots.txt" in report):
        recommendations.append("Cung cấp sitemap.xml để giúp công cụ tìm kiếm lập chỉ mục chính xác.")
    if re.search(r"\[FOUND\].*(?:/admin|administrator|/dashboard|/cpanel|/manage|/login)", report, re.I):
        recommendations.append("Kiểm tra quyền truy cập quản trị và giới hạn truy cập cho các đường dẫn nhạy cảm được tìm thấy.")
    if re.search(r"\[FOUND\].*(?:backup|\\.env|config\\.php\\.bak|index\\.old|backup\\.zip|backup\\.sql)", report, re.I):
        recommendations.append("Loại bỏ hoặc bảo vệ các bản sao lưu, file cấu hình and tài nguyên nhạy cảm đã phát hiện.")

    if not recommendations:
        recommendations.append("Kiểm tra lại khi cập nhật nội dung mới và tiếp tục theo dõi các cấu hình bảo mật.")

    return recommendations


def build_results_context(record_id, asset_criticality=None):
    """Build template context for the results dashboard from a history record."""
    history = load_history()[::-1]
    record = next((item for item in history if item.get("id") == record_id), None)
    if not record:
        return None

    report = record.get("report", "")
    sections = _parse_and_enrich_sections(report)
    summary = build_summary_from_record(record)
    recommendations = record.get("recommendations", [])
    target_info = record.get("target_info", {})
    scan_mode = record.get("mode", "full")
    selected_sections = record.get(
        "selected_sections",
        [option["value"] for option in SCAN_SECTION_OPTIONS],
    )
    metrics = record.get("metrics", extract_metrics(report))
    scan_duration = record.get("scan_duration", 0.0)
    https_status = "Enabled" if metrics.get("https_enabled") else "Disabled"

    if asset_criticality is None:
        asset_criticality = request.args.get("criticality", "normal")
    if asset_criticality not in ("low", "normal", "high", "critical"):
        asset_criticality = "normal"

    hostname = (target_info or {}).get("hostname") or record.get("url", "")
    executive = build_executive_summary(report, sections, summary, recommendations, hostname)
    remediation = build_remediation_plan(recommendations, sections)
    risk_profile = compute_weighted_risk(sections, summary, asset_criticality=asset_criticality)

    return {
        "report": report,
        "sections": sections,
        "summary": summary,
        "recommendations": recommendations,
        "scan_mode": scan_mode,
        "scan_url": record.get("url", ""),
        "history": history,
        "target_info": target_info,
        "available_sections": SCAN_SECTION_OPTIONS,
        "scan_modules": enrich_scan_modules(SCAN_MODULES),
        "selected_sections": selected_sections,
        "metrics": metrics,
        "scan_duration": scan_duration,
        "https_status": https_status,
        "feature_checks": FEATURE_CHECKS,
        "example_urls": EXAMPLE_URLS,
        "screenshot_urls": SCREENSHOT_URLS,
        "check_cards": enrich_check_cards(build_check_cards(sections), sections) if sections else [],
        "security_panels": build_security_panels(report),
        "advisories": build_advisories(sections, recommendations) if sections else {},
        "implemented_checks": IMPLEMENTED_CHECKS,
        "puppeteer_available": puppeteer_available(),
        "api_jobs": get_api_jobs(),
        "history_chart": history_chart_data(history) if history else [],
        "executive": executive,
        "remediation": remediation,
        "scan_schedules": load_schedules(),
        "current_record_id": record_id,
        "risk_profile": risk_profile,
        "asset_criticality": asset_criticality,
    }


@app.route("/", methods=["GET"])
def index():
    """Landing page — scan interface only."""
    scan_url = request.args.get("url", "").strip()
    asset_criticality = request.args.get("criticality", "normal")
    if asset_criticality not in ("low", "normal", "high", "critical"):
        asset_criticality = "normal"

    return render_template(
        "home.html",
        scan_mode="full",
        scan_url=scan_url,
        selected_sections=[option["value"] for option in SCAN_SECTION_OPTIONS],
        scan_modules=enrich_scan_modules(SCAN_MODULES),
        example_urls=EXAMPLE_URLS,
        puppeteer_available=puppeteer_available(),
        api_jobs=get_api_jobs(),
        asset_criticality=asset_criticality,
        history=load_history()[::-1],
        **_platform_context(),
    )


@app.route("/scan", methods=["POST"])
def scan():
    """Run scan and redirect to the results dashboard."""
    url = request.form.get("url", "").strip()
    scan_mode = request.form.get("scanMode", "full").lower()
    if scan_mode not in ("full", "quick"):
        scan_mode = "full"

    selected_sections = request.form.getlist("scanSections")
    if not selected_sections:
        selected_sections = [option["value"] for option in SCAN_SECTION_OPTIONS]

    asset_criticality = request.form.get("assetCriticality", "normal")
    if asset_criticality not in ("low", "normal", "high", "critical"):
        asset_criticality = "normal"

    if not url:
        return redirect(url_for("index"))

    scan_result = perform_scan(url, scan_mode, selected_sections)
    if not scan_result or not scan_result.get("summary"):
        return redirect(url_for("index", url=url))

    report = scan_result["report"]
    sections = scan_result["sections"]
    for s in sections or []:
        try:
            s["doc_id"] = resolve_doc_id(s.get("slug", ""), s.get("title", ""))
        except Exception:
            s["doc_id"] = "security_headers"

    record = save_scan_to_history(
        scan_result["url"],
        scan_mode,
        selected_sections,
        report,
        sections,
        scan_result["summary"],
        scan_result["recommendations"],
        scan_result["metrics"],
        scan_result["target_info"],
        scan_result["scan_duration"],
    )
    return redirect(
        url_for("view_results", record_id=record["id"], criticality=asset_criticality)
    )


@app.route("/results/<record_id>", methods=["GET"])
def view_results(record_id):
    """Dedicated results dashboard for a completed scan."""
    ctx = build_results_context(record_id)
    if not ctx:
        return redirect(url_for("index"))
    return render_template("results.html", **ctx, **_platform_context())


@app.route("/history/<record_id>")
def view_history(record_id):
    """Backward-compatible bookmark URL — redirects to results page."""
    history = load_history()[::-1]
    record = next((item for item in history if item.get("id") == record_id), None)
    if record is None:
        return redirect(url_for("index"))
    return redirect(url_for("view_results", record_id=record_id), code=302)


@app.route("/api/health")
def api_health():
    return jsonify(
        build_health_status(
            api_job_count=len(API_REGISTRY),
            puppeteer_check=puppeteer_available,
            scan_modules_count=len(SCAN_MODULES),
            history_file=HISTORY_FILE,
            schedules_file=SCHEDULES_FILE,
            queue_file=QUEUE_FILE,
        )
    )


@app.route("/api/audit")
def api_audit():
    limit = min(200, int(request.args.get("limit", 50)))
    return jsonify({"entries": load_audit_entries(limit)})


@app.route("/api/workspaces", methods=["GET"])
def api_workspaces_list():
    return jsonify({"workspaces": load_workspaces(), "active": get_active_workspace_id()})


@app.route("/api/workspaces", methods=["POST"])
def api_workspaces_create():
    data = request.get_json(silent=True) or request.form
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    ws = create_workspace(name)
    audit_log("workspace.create", detail={"name": name, "id": ws.get("id")})
    return jsonify({"workspace": ws}), 201


@app.route("/api/workspaces/active", methods=["POST"])
def api_workspaces_active():
    data = request.get_json(silent=True) or request.form
    wid = (data.get("workspace_id") or "").strip()
    if not set_active_workspace(wid):
        return jsonify({"error": "workspace not found"}), 404
    audit_log("workspace.switch", detail={"workspace_id": wid})
    return jsonify({"active": wid})


@app.route("/api/workspaces/<workspace_id>", methods=["DELETE"])
def api_workspaces_delete(workspace_id):
    success, message = delete_workspace(workspace_id)
    if not success:
        return jsonify({"error": message}), 400 if "last" in message.lower() else 404
    audit_log("workspace.delete", detail={"workspace_id": workspace_id})
    return jsonify({"ok": True, "message": message})


@app.route("/api/users", methods=["GET"])
def api_users_list():
    return jsonify({"users": load_users(), "active": (get_active_user() or {}).get("id")})


@app.route("/api/users", methods=["POST"])
def api_users_create():
    data = request.get_json(silent=True) or request.form
    user = create_user(
        data.get("name", ""),
        data.get("email", ""),
        data.get("role", "analyst"),
    )
    audit_log("user.create", detail={"user_id": user.get("id"), "name": user.get("name")})
    return jsonify({"user": user}), 201


@app.route("/api/users/active", methods=["POST"])
def api_users_active():
    data = request.get_json(silent=True) or request.form
    uid = (data.get("user_id") or "").strip()
    if not set_active_user(uid):
        return jsonify({"error": "user not found"}), 404
    return jsonify({"active": uid})


@app.route("/api/users/<user_id>", methods=["DELETE"])
def api_users_delete(user_id):
    # Get the current user ID from the active user for self-deletion check
    active_user = get_active_user()
    deleting_user_id = active_user.get("id") if active_user else None

    success, message = delete_user(user_id, deleting_user_id)
    if not success:
        status = 400 if "last admin" in message.lower() or "your own" in message.lower() else 404
        return jsonify({"error": message}), status
    audit_log("user.delete", detail={"user_id": user_id})
    return jsonify({"ok": True, "message": message})


@app.route("/api/queue", methods=["GET"])
def api_queue_list():
    return jsonify({"queue": list_queue()})


@app.route("/api/queue", methods=["POST"])
def api_queue_add():
    data = request.get_json(silent=True) or request.form
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    entry, created = enqueue_scan(
        url,
        scan_mode=(data.get("scan_mode") or "full"),
        modules=data.get("modules"),
        workspace_id=get_active_workspace_id(),
        priority=int(data.get("priority", 0) or 0),
    )
    audit_log(
        "queue.enqueue",
        detail={"queue_id": entry.get("id"), "url": url, "created": created},
    )
    status = 201 if created else 200
    return jsonify({"item": entry, "created": created, "deduplicated": not created}), status


@app.route("/api/queue/<item_id>", methods=["DELETE"])
def api_queue_cancel(item_id):
    if cancel_queue_item(item_id):
        audit_log("queue.cancel", detail={"queue_id": item_id})
        return jsonify({"ok": True})
    return jsonify({"error": "not found or not pending"}), 404


@app.route("/api/webhooks", methods=["GET"])
def api_webhooks_list():
    return jsonify({"webhooks": list_webhooks()})


@app.route("/api/webhooks", methods=["POST"])
def api_webhooks_add():
    data = request.get_json(silent=True) or request.form
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    hook = add_webhook(url, label=(data.get("label") or ""))
    audit_log("webhook.create", detail={"id": hook.get("id")})
    return jsonify({"webhook": hook}), 201


@app.route("/api/webhooks/<hook_id>", methods=["DELETE"])
def api_webhooks_delete(hook_id):
    if delete_webhook(hook_id):
        return jsonify({"ok": True})
    return jsonify({"error": "not found"}), 404


@app.route("/api/webhooks/<hook_id>/toggle", methods=["POST"])
def api_webhooks_toggle(hook_id):
    hook = toggle_webhook(hook_id)
    if hook:
        return jsonify({"webhook": hook})
    return jsonify({"error": "not found"}), 404


@app.route("/api/integrations", methods=["GET"])
def api_integrations_get():
    return jsonify(load_integrations())


@app.route("/api/integrations", methods=["POST"])
def api_integrations_save():
    data = request.get_json(silent=True) or {}
    cfg = save_integrations(data)
    audit_log("integrations.update", detail={"channels": list(cfg.keys())})
    return jsonify(cfg)


@app.route("/api/analytics/trends")
def api_analytics_trends():
    days = int(request.args.get("days", 30))
    history = load_history()
    return jsonify(trend_analytics(history, days))


@app.route("/api/history/compare")
def api_history_compare():
    id_a = request.args.get("a", "").strip()
    id_b = request.args.get("b", "").strip()
    if not id_a or not id_b:
        return jsonify({"error": "Missing query params a and b"}), 400

    history = load_history()
    by_id = {item.get("id"): item for item in history}
    base = by_id.get(id_a)
    current = by_id.get(id_b)
    if not base or not current:
        return jsonify({"error": "Record not found"}), 404

    base_copy = dict(base)
    current_copy = dict(current)
    base_copy["_parsed_sections"] = _parse_and_enrich_sections(base.get("report", ""))
    current_copy["_parsed_sections"] = _parse_and_enrich_sections(current.get("report", ""))
    return jsonify(compare_scan_records(base_copy, current_copy))


@app.route("/api/schedules", methods=["GET"])
def api_schedules_list():
    return jsonify({"schedules": load_schedules()})


@app.route("/api/schedules", methods=["POST"])
def api_schedules_add():
    data = request.get_json(silent=True) or request.form
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    try:
        interval = float(data.get("interval_hours", 24))
    except (TypeError, ValueError):
        interval = 24
    scan_mode = (data.get("scan_mode") or "full").lower()
    modules = data.get("modules")
    if isinstance(modules, str):
        modules = [m.strip() for m in modules.split(",") if m.strip()]
    entry = add_schedule(
        url=url,
        interval_hours=interval,
        scan_mode=scan_mode,
        modules=modules if modules else None,
        label=(data.get("label") or "").strip(),
    )
    return jsonify({"schedule": entry}), 201


@app.route("/api/schedules/<schedule_id>", methods=["DELETE"])
def api_schedules_delete(schedule_id):
    if delete_schedule(schedule_id):
        return jsonify({"ok": True})
    return jsonify({"error": "not found"}), 404


@app.route("/api/schedules/<schedule_id>/toggle", methods=["POST"])
def api_schedules_toggle(schedule_id):
    entry = toggle_schedule(schedule_id)
    if entry:
        return jsonify({"schedule": entry})
    return jsonify({"error": "not found"}), 404


@app.route("/history/clear", methods=["POST"])
def clear_history():
    save_history([])
    return redirect(url_for("index"))


@app.route("/export", methods=["POST"])
def export_report():
    report = request.form.get("report", "")
    fmt = request.form.get("format", "txt")
    scan_url = request.form.get("scan_url", "").strip()
    sections = _parse_and_enrich_sections(report) if report else []
    summary = build_summary(report) if report else None
    recommendations = generate_recommendations(report) if report else []
    hostname = scan_url
    if scan_url:
        try:
            hostname = urllib.parse.urlparse(
                scan_url if scan_url.startswith("http") else f"https://{scan_url}"
            ).hostname or scan_url
        except Exception:
            hostname = scan_url
    executive = (
        build_executive_summary(report, sections, summary, recommendations, hostname)
        if report and summary
        else None
    )
    remediation = build_remediation_plan(recommendations, sections) if sections else []
    metrics = extract_metrics(report) if report else {}
    generated_at = time.strftime("%Y-%m-%d %H:%M:%S")
    record_id = request.form.get("record_id", "").strip()
    brand = APP_BRAND
    filename_base = brand["full"].lower()

    if fmt == "csv":
        csv_body = build_csv_export(
            scan_url=scan_url,
            hostname=hostname,
            generated_at=generated_at,
            summary=summary,
            sections=sections,
            executive=executive,
        )
        response = make_response(csv_body)
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = f"attachment; filename={filename_base}-report.csv"
        return response

    if fmt == "json":
        payload = build_json_export(
            brand=brand,
            scan_url=scan_url,
            hostname=hostname,
            generated_at=generated_at,
            report=report,
            summary=summary,
            executive=executive,
            sections=sections,
            remediation=remediation,
            recommendations=recommendations,
            metrics=metrics,
            record_id=record_id,
        )
        response = make_response(json.dumps(payload, ensure_ascii=False, indent=2))
        response.headers["Content-Type"] = "application/json; charset=utf-8"
        response.headers["Content-Disposition"] = f"attachment; filename={filename_base}-report.json"
        return response

    if fmt == "sarif":
        sarif = build_sarif_export(
            brand=brand,
            scan_url=scan_url or hostname,
            generated_at=generated_at,
            sections=sections,
        )
        response = make_response(json.dumps(sarif, ensure_ascii=False, indent=2))
        response.headers["Content-Type"] = "application/sarif+json; charset=utf-8"
        response.headers["Content-Disposition"] = f"attachment; filename={filename_base}-report.sarif.json"
        return response

    if fmt == "html":
        export_html = render_template(
            "export_report.html",
            report=report,
            brand=APP_BRAND,
            executive=executive,
            summary=summary,
            sections=sections,
            remediation=remediation,
            scan_url=scan_url,
            generated_at=generated_at,
        )
        response = make_response(export_html)
        response.headers["Content-Type"] = "text/html; charset=utf-8"
        response.headers["Content-Disposition"] = f"attachment; filename={APP_BRAND['full'].lower()}-report.html"
        return response

    if fmt == "pdf":
        try:
            buffer = BytesIO()
            build_professional_pdf(
                buffer,
                brand=brand,
                hostname=hostname,
                scan_url=scan_url,
                generated_at=generated_at,
                executive=executive,
                summary=summary,
                sections=sections,
                remediation=remediation,
                report=report,
            )
            buffer.seek(0)
            response = make_response(buffer.read())
            response.headers["Content-Type"] = "application/pdf"
            response.headers["Content-Disposition"] = f"attachment; filename={filename_base}-report.pdf"
            return response
        except Exception:
            error_text = "ReportLab không được cài đặt hoặc lỗi tạo PDF. Cài: pip install reportlab"
            export_html = render_template(
                "export.html", report=report, export_error=error_text
            )
            response = make_response(export_html)
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            return response

    # default to plain text
    response = make_response(report)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=webscan-report.txt"
    return response


def _open_browser(url, delay=1):
    time.sleep(delay)
    try:
        webbrowser.open(url)
    except Exception:
        pass


if __name__ == "__main__":
    ensure_defaults()
    start_scheduler(app, run_scheduled_scan)
    start_queue_worker(app, run_queued_scan)
    url = "http://127.0.0.1:5000/"
    threading.Thread(target=_open_browser, args=(url,), daemon=True).start()
    app.run(debug=True, use_reloader=False)