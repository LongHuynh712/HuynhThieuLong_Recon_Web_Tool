# =========================
# FILE: scanner.py
# =========================

import cloudscraper
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import urllib3
import ssl
import logging
from datetime import datetime

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
            timeout=30,
            verify=True,
            allow_redirects=True
        )

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


# =========================
# SECURITY HEADERS
# =========================
def check_security_headers(response):
    result = "\n========== SECURITY HEADERS ==========\n"

    for header in SECURITY_HEADERS:
        if header in response.headers:
            result += f"[FOUND] {header}: {response.headers[header]}\n"
        else:
            result += f"[MISSING] {header}\n"

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
        result += "[MISSING] HSTS not configured\n"

    return result


# =========================
# FINGERPRINT
# =========================
def fingerprint_target(response):
    result = "\n========== FINGERPRINT ==========\n"

    server = response.headers.get("Server", "Unknown")
    powered = response.headers.get("X-Powered-By", "Unknown")

    result += f"Server: {server}\n"
    result += f"Technology: {powered}\n"

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
    return check_simple_file(url, "/robots.txt", "ROBOTS.TXT")


def check_sitemap(url):
    return check_simple_file(url, "/sitemap.xml", "SITEMAP.XML")


# =========================
# LINKS
# =========================
def crawl_links(base_url, html):
    result = "\n========== LINKS ==========\n"

    soup = BeautifulSoup(html, "html.parser")
    links = set()

    for tag in soup.find_all("a", href=True):
        links.add(urljoin(base_url, tag["href"]))

    for link in list(links)[:30]:
        result += f"{link}\n"

    result += f"\nTotal links found: {len(links)}\n"

    return result, soup


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

    return result


# =========================
# HTTP METHODS
# =========================
def test_http_methods(url):
    result = "\n========== HTTP METHODS ==========\n"

    for method in HTTP_METHODS:
        response = safe_request(url, method=method)

        if response:
            result += f"{method}: {response.status_code}\n"
        else:
            result += f"{method}: Failed\n"

    return result


# =========================
# ENUMERATION
# =========================
def enumerate_paths(url, paths, title):
    result = f"\n========== {title} ==========\n"

    found = False

    for path in paths:
        target = urljoin(url, path)
        response = safe_request(target)

        if response and response.status_code == 200:
            result += f"[FOUND] {target}\n"
            found = True

    if not found:
        result += "No findings.\n"

    return result


def check_admin_interfaces(url):
    return enumerate_paths(url, ADMIN_PATHS, "ADMIN INTERFACES")


def check_backup_files(url):
    return enumerate_paths(url, BACKUP_FILES, "BACKUP FILES")


def check_sensitive_files(url):
    return enumerate_paths(url, SENSITIVE_FILES, "SENSITIVE FILES")


# =========================
# MAIN SCAN ENGINE
# =========================
def scan_target(url):
    full_report = ""
    full_report += f"\nScan Time: {datetime.now()}\n"

    response = safe_request(url)

    if not response:
        return "Cannot connect to target."

    full_report += analyze_headers(response)
    full_report += check_security_headers(response)
    full_report += test_hsts(response)
    full_report += fingerprint_target(response)
    full_report += check_robots(url)
    full_report += check_sitemap(url)

    links_result, soup = crawl_links(url, response.text)
    full_report += links_result

    full_report += detect_forms(soup)
    full_report += test_http_methods(url)
    full_report += check_admin_interfaces(url)
    full_report += check_backup_files(url)
    full_report += check_sensitive_files(url)

    return full_report