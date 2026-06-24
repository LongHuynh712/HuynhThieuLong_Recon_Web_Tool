# =========================
# FILE: scanner.py
# =========================

import cloudscraper
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import urllib3
import ssl
import socket
import logging
import re
import platform
import json
from datetime import datetime
from difflib import SequenceMatcher

from webcheck_checks import (
    check_http_security,
    trace_redirects,
    check_social_tags,
    check_security_txt,
    detect_firewall,
    check_server_status,
    get_ip_info,
    check_cookies,
    check_txt_records,
    check_tls_connection,
    check_mail_config,
    check_csp_policy,
    check_dnssec,
    discover_assets,
    extract_emails,
    extract_phone_numbers,
    detect_api_keys,
    detect_secrets,
    analyze_comments,
    extract_js_secrets,
    generate_google_dorks,
    analyze_search_engine_exposure,
    find_cached_pages,
    discover_exposed_documents,
    find_public_repositories,
    find_paste_references,
    discover_virtual_hosts,
    scan_common_admin_paths,
    discover_alternate_ports,
    find_common_paths,
    enumerate_forms,
    extract_parameters,
    analyze_http_headers,
    identify_technologies,
    trace_execution_paths,
    map_application_architecture,
    analyze_framework_vulnerabilities,
    detect_api_contracts,
    map_data_flows,
)

# OWASP assessors imports
from modules.api_security_assessor import APISecurityAssessor
from modules.input_validation_assessor import InputValidationAssessor
from modules.authentication_assessor import AuthenticationAssessor
from modules.client_side_assessor import ClientSideAssessor
from modules.business_logic_assessor import BusinessLogicAssessor
from modules.cryptography_assessor import CryptographyAssessor
from modules.session_assessor import SessionAssessor
from modules.authorization_assessor import AuthorizationAssessor
from modules.error_handler_assessor import ErrorHandlerAssessor
from modules.session_enhancement_assessor import SessionEnhancementAssessor

# Optional imports for WHOIS and DNS lookups
try:
    import whois as _whois
except Exception:
    _whois = None

try:
    import dns.resolver as _dns_resolver
except Exception:
    _dns_resolver = None

COMMON_SLD_DOMAINS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "net.au", "com.au", "edu.au",
    "co.nz", "gov.nz", "com.br", "net.br",
    "com.sg", "com.tr", "co.in", "net.in",
    "edu.vn", "gov.vn", "net.vn", "org.vn", "com.vn"
}

# Heavy domains - skip deep enumeration for performance
HEAVY_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "microsoft.com",
    "amazon.com", "apple.com", "netflix.com", "github.com",
    "linkedin.com", "twitter.com", "x.com", "instagram.com",
    "tiktok.com", "cloudflare.com", "akamai.com", "fastly.com",
    "wikipedia.org", "yahoo.com", "ebay.com", "reddit.com",
    "twitch.tv", "microsoftonline.com", "sharepoint.com"
}

def get_registered_domain(name):
    if not name:
        return name

    host = name.lower().strip().rstrip('.')
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return host

    parts = host.split('.')
    if len(parts) <= 2:
        return host

    if parts[0] == "www":
        return ".".join(parts[1:])

    suffix = ".".join(parts[-2:])
    if suffix in COMMON_SLD_DOMAINS and len(parts) >= 3:
        return ".".join(parts[-3:])

    return suffix

# SSL CONFIG
ssl._create_default_https_context = ssl._create_unverified_context
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# LOGGING
logging.basicConfig(
    filename="logs/scan.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# GLOBAL CONFIG
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

ADMIN_PATHS = [
    "/admin", "/administrator", "/dashboard",
    "/cpanel", "/manage", "/login", "/admin/login"
]

BACKUP_FILES = [
    "/backup.zip", "/backup.tar.gz", "/db.sql",
    "/.env", "/config.php.bak", "/index.old",
    "/website.zip", "/backup.sql"
]

SENSITIVE_FILES = [
    "/.git/config", "/.svn/entries",
    "/web.config", "/crossdomain.xml",
    "/clientaccesspolicy.xml"
]

HTTP_METHODS = ["OPTIONS", "PUT", "DELETE", "TRACE", "PATCH"]


# =========================
# REQUEST ENGINE
# =========================
def safe_request(url, method="GET"):
    try:
        scraper = cloudscraper.create_scraper(
            browser={
                "browser": "chrome",
                "platform": "windows",
                "mobile": False
            }
        )

        scraper.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0 Safari/537.36"
            )
        })

        logging.info(f"Connecting to {url} [{method}]")

        response = scraper.request(
            method=method,
            url=url,
            timeout=10,
            verify=True,
            allow_redirects=True
        )

        if not response.encoding or response.encoding.lower() in ["iso-8859-1", "latin-1"]:
            response.encoding = response.apparent_encoding or "utf-8"

        return response

    except Exception as e:
        logging.error(f"Request failed: {url} - {e}")
        return None


# =========================
# HEADER ANALYSIS
# =========================
def analyze_headers(response):
    result = "\n========== HEADERS ==========\n"

    for key, value in response.headers.items():
        result += f"{key}: {value}\n"

    return result


def get_text_signature(html):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\s+", " ", text)
    return text


def is_similar_content(base_text, candidate_text, threshold=0.92):
    if not base_text or not candidate_text:
        return False

    ratio = SequenceMatcher(None, base_text, candidate_text).ratio()
    return ratio >= threshold


def get_page_metadata(html):
    title = ""
    description = ""
    soup = BeautifulSoup(html, "html.parser")

    if soup.title and soup.title.string:
        title = soup.title.string.strip()

    desc = soup.find("meta", attrs={"name": "description"})
    if not desc:
        desc = soup.find("meta", attrs={"property": "og:description"})

    if desc and desc.get("content"):
        description = desc.get("content").strip()

    return title, description


def check_site_seo(title, description):
    result = "\n========== SEO METADATA =========="

    if title:
        result += f"Title: {title}\n"
        if len(title) < 30:
            result += "[WARNING] Title is short (recommended 30-70 characters).\n"
        elif len(title) > 70:
            result += "[WARNING] Title is too long (recommended 30-70 characters).\n"
    else:
        # Page title is primarily an SEO/quality issue — mark as Low by default
        result += "[MISSING] Page title is missing (Severity: LOW).\n"

    if description:
        result += f"Description: {description}\n"
        if len(description) < 50:
            result += "[WARNING] Meta description is short (recommended 50-160 characters).\n"
        elif len(description) > 160:
            result += "[WARNING] Meta description is too long (recommended 50-160 characters).\n"
    else:
        # Meta description is a quality/SEO finding — lower severity to Low
        result += "[MISSING] Meta description is missing (Severity: LOW).\n"

    return result


def check_mobile_friendly(html):
    result = "\n========== MOBILE FRIENDLY =========="
    soup = BeautifulSoup(html, "html.parser")
    viewport = soup.find("meta", attrs={"name": "viewport"})

    if viewport and viewport.get("content"):
        result += "[FOUND] Viewport meta tag is present.\n"
    else:
        # Viewport meta is quality/usability; treat as Low severity
        result += "[MISSING] No viewport meta tag detected (Severity: LOW).\n"

    apple = soup.find("meta", attrs={"name": "apple-mobile-web-app-capable"})
    if apple:
        result += "[FOUND] iOS mobile web app support meta is present.\n"

    return result


def check_canonical_link(html):
    result = "\n========== CANONICAL URL =========="
    soup = BeautifulSoup(html, "html.parser")
    canonical = soup.find("link", rel=lambda value: value and "canonical" in value.lower())

    if canonical and canonical.get("href"):
        result += f"[FOUND] Canonical URL: {canonical.get('href')}\n"
    else:
        result += "[MISSING] Canonical link is missing (Severity: INFO).\n"

    return result


def check_image_alt(html):
    result = "\n========== IMAGE ALT TEXT =========="
    soup = BeautifulSoup(html, "html.parser")
    images = soup.find_all("img")
    missing = [img for img in images if not img.get("alt") or not img.get("alt").strip()]
    result += f"Images found: {len(images)}\n"
    if missing:
        result += f"[WARNING] Images without alt text: {len(missing)}\n"
    else:
        result += "[FOUND] All images contain alt text.\n"

    return result


def check_ssl_certificate(url):
    result = "\n========== SSL CERTIFICATE =========="
    parsed = urlparse(url)

    if parsed.scheme != "https":
        return result + "Site is not HTTPS. SSL certificate check skipped.\n"

    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_after = cert.get("notAfter")
        if not_after:
            expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            remaining = (expire_date - datetime.utcnow()).days
            result += f"Expires: {expire_date} ({remaining} days remaining)\n"
            if remaining < 30:
                result += "[WARNING] SSL certificate expires soon.\n"
        else:
            result += "[WARNING] Cannot determine certificate expiration date.\n"

        if cert.get("subjectAltName"):
            result += f"SAN: {cert.get('subjectAltName')}\n"

    except Exception as e:
        result += f"[ERROR] SSL check failed: {e}\n"

    return result


def normalize_link(link, base_url):
    if not link:
        return None

    if link.startswith(("mailto:", "javascript:", "#")):
        return None

    target = urljoin(base_url, link)
    parsed = urlparse(target)
    if not parsed.scheme or not parsed.netloc:
        return None

    clean = parsed._replace(fragment="").geturl()
    if clean.endswith("/") and len(clean) > len(f"{parsed.scheme}://{parsed.netloc}/"):
        clean = clean.rstrip("/")

    return clean


def discover_js_endpoints(html, base_url):
    result = "\n========== JS ENDPOINTS =========="
    urls = set()
    soup = BeautifulSoup(html, "html.parser")

    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            normalized = normalize_link(src, base_url)
            if normalized:
                urls.add(normalized)
        elif script.string:
            text = script.string
            for match in re.findall(r"fetch\(\s*['\"]([^'\"]+)['\"]", text, re.I):
                urls.add(urljoin(base_url, match))
            for match in re.findall(r"axios\.(?:get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", text, re.I):
                urls.add(urljoin(base_url, match))
            for match in re.findall(r"\broute\s*[:=]\s*['\"]([^'\"]+)['\"]", text, re.I):
                urls.add(urljoin(base_url, match))

    if urls:
        for endpoint in sorted(urls):
            result += f"\n- {endpoint}"
    else:
        result += "\nNo JS endpoints detected."

    return result


def enumerate_subdomains(domain):
    result = "\n========== SUBDOMAINS =========="
    found = set()
    if not domain:
        return result + "\nNo domain provided."

    # Fast mode for large/heavy domains - skip brute-force enumeration
    is_heavy_domain = domain.lower() in HEAVY_DOMAINS

    if is_heavy_domain:
        result += f"\n[INFO] Domain '{domain}' detected as heavy - using fast passive mode only\n"
        result += "[INFO] Skipping common prefix brute force to avoid excessive requests\n"

    try:
        query_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = safe_request(query_url)
        if response and response.status_code == 200:
            try:
                entries = response.json()
                # Limit crt.sh results to prevent overwhelming output
                if isinstance(entries, list) and len(entries) > 100:
                    entries = entries[:100]
                    result += "[INFO] crt.sh results limited to first 100 entries for performance\n"
                for item in entries:
                    name = item.get("name_value")
                    if name:
                        for candidate in str(name).split("\n"):
                            if candidate.endswith(domain) and "*" not in candidate:
                                found.add(candidate.strip())
            except Exception:
                pass
    except Exception:
        pass

    # Only do common prefix brute force for non-heavy domains
    if not is_heavy_domain:
        common_prefixes = ["www", "api", "blog", "mail", "dev", "test", "admin", "cdn", "m", "portal"]
        for prefix in common_prefixes:
            candidate = f"{prefix}.{domain}"
            try:
                resp = safe_request(f"https://{candidate}")
                if resp and resp.status_code < 400:
                    found.add(candidate)
            except Exception:
                pass

    if found:
        for sub in sorted(found):
            result += f"\n- {sub}"
    else:
        result += "\nNo subdomains discovered."

    return result


def parse_robots_sitemaps(text):
    sitemaps = []
    for line in text.splitlines():
        parts = line.strip().split(":", 1)
        if len(parts) == 2 and parts[0].strip().lower() == "sitemap":
            sitemap_url = parts[1].strip()
            if sitemap_url:
                sitemaps.append(sitemap_url)
    return sitemaps


# =========================
# SECURITY HEADERS
# =========================
HEADER_SEVERITY = {
    # Strict-Transport-Security is high impact if missing on HTTPS sites.
    # Other headers improve hardening but are not automatically critical
    # for large public sites; prefer MEDIUM/LOW to avoid inflating scores.
    "Content-Security-Policy": "MEDIUM",
    "Strict-Transport-Security": "HIGH",
    "X-Frame-Options": "LOW",
    "X-Content-Type-Options": "LOW",
    "Referrer-Policy": "LOW",
}

def check_security_headers(response):
    result = "\n========== SECURITY HEADERS =========="

    for header in SECURITY_HEADERS:
        if header in response.headers:
            result += f"[FOUND] {header}: {response.headers[header]}\n"
        else:
            severity = HEADER_SEVERITY.get(header, "MEDIUM")
            result += f"[MISSING] {header} (Severity: {severity})\n"

    return result


# =========================
# HSTS TEST
# =========================
def test_hsts(response):
    result = "\n========== HSTS TEST ==========\n"

    hsts = response.headers.get("Strict-Transport-Security")

    if hsts:
        result += f"[FOUND] HSTS: {hsts}\n"
    else:
        result += "[MISSING] HSTS not configured (Severity: HIGH)\n"

    return result


# =========================
# FINGERPRINT
# =========================
def probe_url_path(url, path):
    target = urljoin(url, path)
    response = safe_request(target, method="HEAD")
    return response is not None and response.status_code in (200, 301, 302, 401, 403)


def fingerprint_target(response):
    result = "\n========== FINGERPRINT ==========\n"

    server = response.headers.get("Server", "Unknown")
    powered = response.headers.get("X-Powered-By", "Unknown")
    generator = response.headers.get("X-Generator", "")
    aspnet = response.headers.get("X-AspNet-Version", "")

    html = response.text or ""
    tech = "Unknown"
    confidence = "Low"
    hints = []

    server_lower = server.lower()
    html_lower = html.lower()
    generator_lower = generator.lower()
    powered_lower = powered.lower()

    if "amazonaws" in server_lower or "amazons3" in server_lower or "cloudfront" in server_lower:
        tech = "AmazonS3 / CloudFront"
        confidence = "High"
        hints.append("Server header indicates CDN/edge storage")

    if tech == "Unknown":
        if "wp-content" in html_lower or "wp-json" in html_lower or "wordpress" in html_lower:
            tech = "WordPress"
            confidence = "Medium"
        elif "drupal.settings" in html_lower or "drupal" in html_lower:
            tech = "Drupal"
            confidence = "Medium"
        elif "reactdom" in html_lower or 'id="root"' in html_lower or "__react_devtools_global_hook__" in html_lower:
            tech = "React"
            confidence = "Medium"
        elif "ng-app" in html_lower or "angular" in html_lower or "angularjs" in html_lower:
            tech = "Angular"
            confidence = "Medium"
        elif "__next_data__" in html_lower or "next/static" in html_lower or "nextjs" in html_lower:
            tech = "Next.js"
            confidence = "Medium"
        elif "__nuxt__" in html_lower or "nuxt.js" in html_lower:
            tech = "Nuxt.js"
            confidence = "Medium"
        elif "gatsby" in html_lower:
            tech = "Gatsby"
            confidence = "Medium"
        elif "vue" in html_lower or "vue.js" in html_lower:
            tech = "Vue.js"
            confidence = "Medium"
        elif "laravel" in html_lower:
            tech = "Laravel"
            confidence = "Medium"
        elif "asp.net" in html_lower or "x-aspnet-version" in response.headers:
            tech = "ASP.NET"
            confidence = "Medium"
        elif "nginx" in server_lower:
            tech = "Nginx"
            confidence = "Medium"
        elif "apache" in server_lower:
            tech = "Apache"
            confidence = "Medium"

    if powered != "Unknown" and tech == "Unknown":
        tech = powered
        confidence = "Low"

    joomla_signals = []
    if "joomla" in html_lower or "joomla" in generator_lower or "joomla" in powered_lower:
        joomla_signals.append("Joomla keyword in page or headers")
    if "/templates/" in html_lower:
        joomla_signals.append("Joomla templates path in HTML")
    if probe_url_path(response.url, "/administrator"):
        joomla_signals.append("/administrator path reachable")
    if probe_url_path(response.url, "/media/system/js"):
        joomla_signals.append("/media/system/js reachable")

    if len(joomla_signals) >= 2:
        tech = "Joomla"
        hints.extend(joomla_signals)
    elif joomla_signals:
        hints.append("Possible Joomla: " + ", ".join(joomla_signals))

    if generator and "joomla" not in generator_lower:
        hints.append(generator)

    if aspnet:
        hints.append(f"ASP.NET {aspnet}")

    result += f"Server: {server}\n"
    result += f"X-Powered-By: {powered if powered else 'Not present'}\n"
    if generator:
        result += f"X-Generator: {generator}\n"
    if aspnet:
        result += f"X-AspNet-Version: {aspnet}\n"

    result += f"Possible Technology: {tech}\n"
    result += f"Confidence: {confidence}\n"
    if hints and tech == "Unknown":
        result += f"Hints: {', '.join(hints)}\n"

    if "cloudflare" in server.lower():
        result += "WAF/CDN: Cloudflare Detected\n"
    elif "akamai" in server.lower():
        result += "WAF/CDN: Akamai Detected\n"

    return result


# =========================
# FILE CHECKERS
# =========================
def check_simple_file(url, path, title):
    result = f"\n========== {title} ==========\n"

    target = urljoin(url, path)
    response = safe_request(target)

    if response and response.status_code == 200:
        result += response.text[:500] + "\n"
    else:
        result += f"{path} not found\n"

    return result


def check_robots(url):
    target = urljoin(url, "/robots.txt")
    response = safe_request(target)
    result = "\n========== ROBOTS.TXT =========="

    if not response:
        return result + "\nrobots.txt not reachable\n", []
    if response.status_code != 200:
        return result + f"\nrobots.txt returned {response.status_code}.\n"

    result += response.text.strip() + "\n"
    sitemaps = parse_robots_sitemaps(response.text)
    if sitemaps:
        result += "\nSitemap directives found in robots.txt:\n"
        for sitemap in sitemaps:
            result += f"- {sitemap}\n"

    return result, sitemaps


def check_sitemap(url, sitemaps=None):
    result = "\n========== SITEMAP =========="

    if sitemaps:
        found_any = False
        for sitemap_target in sitemaps:
            response = safe_request(sitemap_target)
            if not response:
                result += f"\n{sitemap_target} not reachable\n"
                continue
            if response.status_code != 200:
                result += f"\n{sitemap_target} returned {response.status_code}.\n"
                continue
            details = response.text[:500].strip()
            result += f"\nFound sitemap at: {sitemap_target}\n"
            result += f"Sample content:\n{details}\n"
            found_any = True
        if not found_any:
            result += "\nSitemap directives were found, but none were reachable.\n"
        return result

    target = urljoin(url, "/sitemap.xml")
    response = safe_request(target)
    if not response:
        return result + "\n/sitemap.xml not found\n"
    if response.status_code != 200:
        return result + f"\n/sitemap.xml returned {response.status_code}.\n"

    details = response.text[:500].strip()
    return result + f"\nFound sitemap.xml. Sample content:\n{details}\n"


# =========================
# LINKS
# =========================
def crawl_links(base_url, html):
    result = "\n========== LINKS ==========\n"

    soup = BeautifulSoup(html, "html.parser")
    links = set()
    internal = set()
    external = set()
    base_host = urlparse(base_url).netloc.lower()

    for tag in soup.find_all("a", href=True):
        normalized = normalize_link(tag["href"], base_url)
        if not normalized:
            continue
        links.add(normalized)
        if base_host in urlparse(normalized).netloc.lower():
            internal.add(normalized)
        else:
            external.add(normalized)

    for link in list(links)[:30]:
        result += f"{link}\n"

    result += f"\nTotal links found: {len(links)}"
    result += f" (internal: {len(internal)}, external: {len(external)})\n"

    return result, soup, links


# =========================
# FORMS
# =========================
def detect_forms(soup):
    result = "\n========== FORMS ==========\n"

    forms = soup.find_all("form")
    result += f"Found {len(forms)} forms\n"

    for idx, form in enumerate(forms):
        result += f"\nForm #{idx+1}\n"
        result += f"Action: {form.get('action')}\n"
        result += f"Method: {form.get('method')}\n"

        for inp in form.find_all("input"):
            result += (
                f"Input Name: {inp.get('name')} | "
                f"Type: {inp.get('type')}\n"
            )
    if len(forms) == 0:
        body = soup.get_text().lower()
        if any(marker in str(soup) for marker in ['id="app"', 'id="root"', '__NEXT_DATA__', 'window.__INITIAL_STATE__']):
            result += "\nNote: Site appears to be a JS-rendered app, so static HTML may not contain forms.\n"
        elif re.search(r"<script|render\(|ReactDOM\.render", str(soup), re.I):
            result += "\nNote: No forms found in static HTML. The page appears to be a JS-rendered app.\n"
    return result


# =========================
# HTTP METHODS
# =========================
def test_http_methods(url):
    result = "\n========== HTTP METHODS ==========\n"

    for method in HTTP_METHODS:
        response = safe_request(url, method=method)

        if response is None:
            result += f"{method}: Blocked\n"
            continue

        status = response.status_code
        if status in (405, 501):
            result += f"{method}: Not Allowed ({status})\n"
        elif status in (403, 404):
            result += f"{method}: Blocked ({status})\n"
        elif 200 <= status < 300:
            result += f"{method}: Allowed ({status})\n"
        elif 300 <= status < 400:
            result += f"{method}: Redirected ({status})\n"
        else:
            result += f"{method}: {status}\n"

    return result


# =========================
# ENUMERATION
# =========================
def enumerate_paths(url, paths, title, baseline_text, severity="MEDIUM"):
    result = f"\n========== {title} =========="

    found = False

    for path in paths:
        target = urljoin(url, path)
        response = safe_request(target)

        if response and response.status_code == 200:
            candidate_text = get_text_signature(response.text)
            if response.url.rstrip("/") == url.rstrip("/") or is_similar_content(baseline_text, candidate_text):
                result += f"[POSSIBLE FALSE POSITIVE] {target} returned homepage-like content\n"
                continue

            result += f"[FOUND] {target} (Severity: {severity})\n"
            found = True

    if not found:
        result += "No findings.\n"

    return result


def check_admin_interfaces(url, baseline_text):
    return enumerate_paths(url, ADMIN_PATHS, "ADMIN INTERFACES", baseline_text, severity="INFO")


def check_backup_files(url, baseline_text):
    return enumerate_paths(url, BACKUP_FILES, "BACKUP FILES", baseline_text, severity="HIGH")


def check_sensitive_files(url, baseline_text):
    """Check for sensitive files and policy documents with appropriate severity."""
    result = "\n========== SENSITIVE FILES =========="
    found = False

    # Files with their severity levels
    files_with_severity = [
        ("/.git/config", "CRITICAL"),
        ("/.svn/entries", "CRITICAL"),
        ("/web.config", "HIGH"),
        ("/crossdomain.xml", "INFO"),
        ("/clientaccesspolicy.xml", "INFO"),
    ]

    for path, severity in files_with_severity:
        target = urljoin(url, path)
        response = safe_request(target)

        if response and response.status_code == 200:
            candidate_text = get_text_signature(response.text)
            if response.url.rstrip("/") == url.rstrip("/") or is_similar_content(baseline_text, candidate_text):
                # Possible false positive (homepage or similar)
                continue

            result += f"[FOUND] {target} (Severity: {severity})\n"
            found = True

    if not found:
        result += "No findings.\n"

    return result


# =========================
# MAIN SCAN ENGINE
# =========================
def scan_target(url, mode="full", selected_sections=None):
    section_groups = {
        "security_headers": {"headers", "hsts", "http_security", "firewall", "status", "csp"},
        "ssl": {"ssl", "hsts", "tls_connection"},
        "cookies": {"cookies"},
        "fingerprint": {"fingerprint"},
        "robots": {"robots", "sitemap", "security_txt"},
        "links": {"links", "forms", "js_endpoints", "redirects", "assets"},
        "seo": {"site_metadata", "seo", "mobile", "canonical", "image_alt", "social_tags"},
        "enumeration": {"http_methods", "admin", "backup", "sensitive", "subdomains"},
        "whois_dns": {"whois_dns", "get_ip", "txt_records", "mail_config", "dnssec", "network"},
        "email_security": {"mail_config"},
        "assets": {"assets"},
        "content_leakage": {"content_leakage"},
        "search_engine_recon": {"search_engine_recon"},
        "enhanced_enumeration": {"enhanced_enumeration"},
        "entry_point_mapper": {"entry_point_mapper"},
        "execution_paths": {"execution_paths"},
        "architecture_mapper": {"architecture_mapper"},
        "framework_enhancement": {"framework_enhancement"},
    }

    selected_sections = {section.lower() for section in (selected_sections or [])}
    active_sections = set()
    for section in selected_sections:
        active_sections.update(section_groups.get(section, {section}))
    all_sections = len(selected_sections) == 0

    def should_scan(key):
        return all_sections or key in active_sections

    full_report = ""
    full_report += f"\nScan Time: {datetime.now()}\n"
    full_report += f"Scan Mode: {mode.title()} Scan\n"

    response = safe_request(url)

    if not response:
        return "Cannot connect to target."

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    if should_scan("get_ip") and hostname:
        full_report += get_ip_info(hostname)
    if should_scan("network") and hostname:
        try:
            ip = socket.gethostbyname(hostname)
            full_report += check_network_info(ip)
        except Exception:
            full_report += "\n========== NETWORK INFO =========="
            full_report += "\nReverse DNS / ASN lookup failed.\n"

    if should_scan("status"):
        full_report += check_server_status(url, response)

    if should_scan("headers"):
        full_report += analyze_headers(response)
        full_report += check_security_headers(response)

    if should_scan("csp"):
        full_report += check_csp_policy(response)

    if should_scan("http_security"):
        full_report += check_http_security(response)

    if should_scan("firewall"):
        full_report += detect_firewall(response)

    if should_scan("hsts"):
        full_report += test_hsts(response)

    if should_scan("ssl"):
        full_report += check_ssl_certificate(url)

    if should_scan("tls_connection"):
        full_report += check_tls_connection(url)

    if should_scan("cookies"):
        full_report += check_cookies(response)

    soup = BeautifulSoup(response.text, "html.parser")

    if mode == "quick" and all_sections:
        full_report += detect_forms(soup)
        return full_report

    if should_scan("fingerprint"):
        full_report += fingerprint_target(response)

    robots_text, robots_sitemaps = ("", [])
    if should_scan("security_txt"):
        full_report += check_security_txt(url)

    if should_scan("robots") or should_scan("sitemap"):
        robots_text, robots_sitemaps = check_robots(url)
        if should_scan("robots"):
            full_report += robots_text
        if should_scan("sitemap"):
            full_report += check_sitemap(url, robots_sitemaps)

    if should_scan("redirects"):
        full_report += trace_redirects(url)

    if should_scan("links"):
        links_result, _, _ = crawl_links(url, response.text)
        full_report += links_result

    if should_scan("assets"):
        full_report += discover_assets(response.text, url)

    # ------------------------------------------------------------------
    # OWASP passive assessors execution
    # ------------------------------------------------------------------
    owasp_assessments = {}
    _assessors = [
        ("api_security", APISecurityAssessor),
        ("input_validation", InputValidationAssessor),
        ("authentication", AuthenticationAssessor),
        ("client_side", ClientSideAssessor),
        ("business_logic", BusinessLogicAssessor),
        ("cryptography", CryptographyAssessor),
        ("session", SessionAssessor),
        ("authorization", AuthorizationAssessor),
        ("error_handler", ErrorHandlerAssessor),
        ("session_enhancement", SessionEnhancementAssessor),
    ]
    for key, AssessorCls in _assessors:
        try:
            assessor = AssessorCls(url)
            owasp_assessments[key] = assessor.run_all_tests()
        except Exception as exc:  # pragma: no‑cover
            owasp_assessments[key] = {"error": str(exc)}
    # Append a JSON block to the report for visibility (optional)
    full_report += "\n========== OWASP ASSESSMENTS ==========\n"
    full_report += json.dumps(owasp_assessments, ensure_ascii=False, indent=2)


    if should_scan("js_endpoints"):
        full_report += discover_js_endpoints(response.text, url)

    title, description = get_page_metadata(response.text)
    if should_scan("site_metadata") and title:
        full_report += "\n========== PAGE METADATA =========="
        full_report += f"\nTitle: {title}\n"
        if description:
            full_report += f"Description: {description}\n"

    if should_scan("seo"):
        full_report += check_site_seo(title, description)

    if should_scan("mobile"):
        full_report += check_mobile_friendly(response.text)

    if should_scan("canonical"):
        full_report += check_canonical_link(response.text)

    if should_scan("image_alt"):
        full_report += check_image_alt(response.text)

    if should_scan("social_tags"):
        full_report += check_social_tags(response.text)

    if should_scan("content_leakage"):
        full_report += extract_emails(response.text, url)
        full_report += extract_phone_numbers(response.text)
        full_report += detect_api_keys(response.text)
        full_report += detect_secrets(response.text)
        full_report += analyze_comments(response.text)

    if should_scan("search_engine_recon"):
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or parsed.netloc
            if domain:
                full_report += generate_google_dorks(domain)
                full_report += analyze_search_engine_exposure(domain)
                full_report += find_cached_pages(domain)
                full_report += discover_exposed_documents(domain)
                full_report += find_public_repositories(domain)
                full_report += find_paste_references(domain)
        except Exception as e:
            full_report += f"\n[ERROR] Search engine reconnaissance failed: {e}\n"

    if should_scan("enhanced_enumeration"):
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or parsed.netloc
            if domain:
                # Fast mode for heavy domains - skip deep enumeration
                if domain.lower() in HEAVY_DOMAINS:
                    full_report += "\n[INFO] Domain is large/heavy - skipping deep enumeration for performance\n"
                    full_report += "[INFO] Use custom scan with specific sections for targeted analysis\n"
                else:
                    full_report += discover_virtual_hosts(domain)
                    full_report += scan_common_admin_paths(url)
                    full_report += discover_alternate_ports(domain)
                    full_report += find_common_paths(domain)
        except Exception as e:
            full_report += f"\n[ERROR] Enhanced enumeration failed: {e}\n"

    if should_scan("entry_point_mapper"):
        try:
            full_report += enumerate_forms(response.text, url)
            full_report += extract_parameters(response.text, url)
            full_report += analyze_http_headers(response.headers)
            full_report += identify_technologies(response.text, response.headers)
        except Exception as e:
            full_report += f"\n[ERROR] Entry point mapping failed: {e}\n"

    if should_scan("execution_paths"):
        try:
            full_report += trace_execution_paths(response.text, url)
            full_report += map_data_flows(response.text, url)
        except Exception as e:
            full_report += f"\n[ERROR] Execution paths analysis failed: {e}\n"

    if should_scan("architecture_mapper"):
        try:
            full_report += map_application_architecture(response.text, response.headers, url)
            full_report += detect_api_contracts(response.text, url)
        except Exception as e:
            full_report += f"\n[ERROR] Architecture mapping failed: {e}\n"

    if should_scan("framework_enhancement"):
        try:
            full_report += analyze_framework_vulnerabilities(response.text, response.headers, url)
        except Exception as e:
            full_report += f"\n[ERROR] Framework analysis failed: {e}\n"

    baseline_text = get_text_signature(response.text)
    if should_scan("forms"):
        full_report += detect_forms(soup)

    if should_scan("http_methods"):
        full_report += test_http_methods(url)

    if should_scan("admin"):
        full_report += check_admin_interfaces(url, baseline_text)

    if should_scan("backup"):
        full_report += check_backup_files(url, baseline_text)

    if should_scan("sensitive"):
        full_report += check_sensitive_files(url, baseline_text)

    if should_scan("subdomains"):
        try:
            parsed = urlparse(url)
            domain = parsed.hostname
            if domain:
                full_report += enumerate_subdomains(domain)
        except Exception:
            full_report += "\n========== SUBDOMAINS =========="
            full_report += "\nSubdomain enumeration failed.\n"

    if should_scan("whois_dns"):
        try:
            parsed = urlparse(url)
            domain = parsed.hostname
            if domain:
                base_domain = get_registered_domain(domain)
                try:
                    whois_info = get_whois_info(base_domain)
                    full_report += "\n========== WHOIS =========="
                    full_report += whois_info
                except Exception as e:
                    full_report += f"\n[ERROR] WHOIS lookup failed: {e}\n"

                try:
                    full_report += "\n========== DNS RECORDS =========="
                    full_report += get_dns_records(domain, ["A", "AAAA"])
                    if base_domain and base_domain != domain:
                        full_report += get_dns_records(base_domain, ["MX", "NS", "CNAME"])
                except Exception as e:
                    full_report += f"\n[ERROR] DNS lookup failed: {e}\n"

                if should_scan("dnssec"):
                    full_report += check_dnssec(domain)

                if should_scan("txt_records"):
                    full_report += check_txt_records(base_domain or domain)

                if should_scan("mail_config"):
                    full_report += check_mail_config(domain, base_domain)
        except Exception:
            pass

    return full_report


# =========================
# WHOIS + DNS HELPERS
# =========================
def get_whois_info(domain):
    if _whois is None:
        return "python-whois not installed. Install with: pip install python-whois\n"

    w = _whois.whois(domain)
    if not w:
        if platform.system() == "Windows":
            return "WHOIS command returned no output. On Windows, install the whois utility or use a Linux/macOS environment.\n"
        return "WHOIS lookup returned no output.\n"

    lines = []
    # Common fields
    for key in ("domain_name", "registrar", "whois_server", "referral_url", "email", "dnssec", "name_servers"):
        val = w.get(key)
        if val:
            lines.append(f"{key}: {val}\n")

    # dates
    for key in ("creation_date", "expiration_date", "updated_date"):
        val = w.get(key)
        if val:
            lines.append(f"{key}: {val}\n")

    if not lines:
        return "WHOIS returned no usable fields.\n"

    return "".join(lines)


def get_dns_records(domain, record_types=None):
    if _dns_resolver is None:
        return "dnspython not installed. Install with: pip install dnspython\n"

    if record_types is None:
        record_types = ["A", "MX", "NS", "TXT"]

    resolver = _dns_resolver.Resolver()
    out = []

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype, lifetime=5)
            out.append(f"{rtype} records for {domain}:\n")
            for r in answers:
                out.append(f" - {r.to_text()}\n")
        except Exception as e:
            out.append(f" - {rtype} lookup failed or no records ({e})\n")

    return "".join(out)


def check_network_info(ip):
    result = "\n========== NETWORK INFO =========="
    if not ip:
        return result + "\nNo IP address available.\n"

    try:
        reverse = socket.gethostbyaddr(ip)
        result += f"\nReverse DNS: {reverse[0]}\n"
    except Exception:
        result += "\nReverse DNS: not available\n"

    # Try ip-api.com first (more accurate for ASN/ISP), then ipinfo.io, then ipapi.co
    api_sources = [
        f"http://ip-api.com/json/{ip}/json",  # http to avoid https issues
        f"https://ipinfo.io/{ip}/json",
        f"https://ipapi.co/{ip}/json/",
    ]

    cdn_providers = {
        "cloudflare", "google", "akamai", "fastly", "amazonaws",
        "aws", "azure", "microsoft", "cdn", "edge"
    }

    location_data = {}
    cdn_detected = False

    for api_url in api_sources:
        try:
            response = safe_request(api_url)
            if response and response.status_code == 200:
                data = response.json()
                if data:
                    location_data.update(data)

                # Check for CDN/edge network indicators
                org = str(data.get("org", "") or data.get("company", "") or "").lower()
                isp = str(data.get("isp", "") or "").lower()
                asn = str(data.get("asn", "") or "").lower()

                for provider in cdn_providers:
                    if provider in org or provider in isp or provider in asn:
                        cdn_detected = True
                        break

                # Only return after successful fetch from first working source
                if data:
                    break
        except Exception:
            continue

    if location_data:
        # Build location string
        city = location_data.get("city")
        region = location_data.get("region") or location_data.get("regionName")
        country = location_data.get("country")
        if city or region or country:
            loc_parts = [x for x in [city, region, country] if x]
            result += f"Location: {', '.join(loc_parts)}\n"

        # Coordinates (from ip-api or ipinfo)
        lat = location_data.get("lat") or location_data.get("latitude")
        lon = location_data.get("lon") or location_data.get("longitude")
        if lat and lon:
            result += f"Coordinates: {lat}, {lon}\n"

        # ASN and organization
        asn = location_data.get("asn")
        if asn:
            result += f"ASN: {asn}\n"

        org = location_data.get("org") or location_data.get("company")
        if org:
            result += f"Organization: {org}\n"

        isp = location_data.get("isp")
        if isp and isp != org:
            result += f"ISP: {isp}\n"

        # CDN/Edge detection
        if cdn_detected:
            result += "\n[NOTE] CDN/Edge Network Detected - Location represents network edge, not origin server\n"

    else:
        result += "\nASN / hosting provider details unavailable from external services.\n"

    return result