# Checks ported from web-check (github.com/lissy93/web-check) — Python implementations

from __future__ import annotations

import re
import time
import socket
from collections import defaultdict
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from bs4 import BeautifulSoup

import cloudscraper


# Performance optimization settings
_REQUEST_TIMEOUT = 4.0  # Reduced from 20s to 4s
_CACHE = {}  # Request cache
_EARLY_EXIT_THRESHOLD = 3  # Exit after 3 consecutive timeouts
_MAX_CONCURRENT = 8  # Max concurrent requests
_MAX_DISCOVERIES = 150  # Limit discovered items (100-200 range)
_MAX_CRAWL_DEPTH = 2  # Default crawl depth limit

# Static asset extensions to skip (performance optimization)
STATIC_ASSET_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.svg', '.gif', '.woff', '.woff2',
    '.ttf', '.css', '.map', '.ico', '.bmp', '.webp', '.mp4',
    '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm', '.mp3',
    '.wav', '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z'
}

# Third-party domains to ignore (common CDNs, analytics, trackers)
THIRD_PARTY_DOMAINS = {
    'googleapis.com', 'gstatic.com', 'doubleclick.net',
    'googletagmanager.com', 'google-analytics.com', 'google.com',
    'facebook.net', 'facebook.com', 'twitter.com', 'x.com',
    'cdninstagram.com', 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com',
    'ajax.googleapis.com', 'fonts.googleapis.com', 'fonts.gstatic.com',
    'www.google-analytics.com', 'www.googletagmanager.com',
    'platform.twitter.com', 'syndication.twitter.com',
    'connect.facebook.net', 'static.xx.fbcdn.net'
}


def _fetch(url, allow_redirects=True, method="GET", timeout=None, metrics=None):
    """
    Fetch with timeout, caching, and cloudflare bypass
    Optional metrics tracking for performance monitoring
    """
    timeout = timeout or _REQUEST_TIMEOUT

    # Check cache first (deduplication)
    cache_key = (url, method, allow_redirects)
    if cache_key in _CACHE:
        if metrics:
            metrics.record_skipped(url, reason="cache")
        return _CACHE[cache_key]

    try:
        scraper = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "windows", "mobile": False}
        )
        scraper.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
            )
        })
        response = scraper.request(
            method=method,
            url=url,
            timeout=timeout,
            verify=False,
            allow_redirects=allow_redirects,
        )
        _CACHE[cache_key] = response
        if metrics:
            metrics.record_request(url, response.status_code)
        return response
    except socket.timeout:
        if metrics:
            metrics.record_timeout(url)
        return None
    except Exception as e:
        if metrics:
            metrics.record_error(url, str(e))
        return None


def _is_static_asset(url):
    """Check if URL points to a static asset that should be skipped"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    for ext in STATIC_ASSET_EXTENSIONS:
        if path.endswith(ext) or f'{ext}?' in path or f'{ext}#' in path:
            return True
    return False


def _is_third_party_domain(url, base_domain):
    """Check if URL belongs to a common third-party domain that should be ignored"""
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    # Remove port if present
    if ':' in hostname:
        hostname = hostname.split(':')[0]

    # Check if it's a subdomain of the base domain (should NOT be ignored)
    if hostname == base_domain or hostname.endswith('.' + base_domain):
        return False

    # Check against third-party list
    for third_party in THIRD_PARTY_DOMAINS:
        if third_party in hostname or hostname.endswith('.' + third_party):
            return True

    return False


class ScanMetrics:
    """Track performance metrics during scanning"""

    def __init__(self):
        self.start_time = time.time()
        self.requests_made = 0
        self.requests_skipped = 0
        self.skipped_reasons = defaultdict(int)
        self.discoveries = 0
        self.max_discoveries_reached = False
        self.timeout_count = 0
        self.concurrent_requests = 0
        self.max_concurrent = 0

    def record_request(self, url, status_code):
        """Record a successful request"""
        self.requests_made += 1

    def record_skipped(self, url, reason):
        """Record a skipped request"""
        self.requests_skipped += 1
        self.skipped_reasons[reason] += 1

    def record_timeout(self, url):
        """Record a timeout"""
        self.timeout_count += 1

    def record_error(self, url, error):
        """Record an error"""
        pass  # Not tracked separately for now

    def record_discovery(self):
        """Record a new finding"""
        self.discoveries += 1
        if self.discoveries >= _MAX_DISCOVERIES:
            self.max_discoveries_reached = True

    def should_continue(self):
        """Check if scanning should continue"""
        return not self.max_discoveries_reached

    def get_elapsed(self):
        """Get elapsed time in seconds"""
        return time.time() - self.start_time

    def get_summary(self):
        """Get performance summary"""
        elapsed = self.get_elapsed()
        return {
            "elapsed_seconds": round(elapsed, 2),
            "requests_made": self.requests_made,
            "requests_skipped": self.requests_skipped,
            "total_attempts": self.requests_made + self.requests_skipped,
            "discoveries": self.discoveries,
            "timeout_count": self.timeout_count,
            "skipped_breakdown": dict(self.skipped_reasons),
        }

MAX_REDIRECTS = 12

HTTP_SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "x-xss-protection": "X-XSS-Protection",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
    "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy",
}

SECURITY_TXT_PATHS = ["/.well-known/security.txt", "/security.txt"]


def _header_lookup(headers, name):
    lower = name.lower()
    for key, value in headers.items():
        if key.lower() == lower:
            return value
    return None


def check_http_security(response):
    result = "\n========== HTTP SECURITY ==========\n"
    headers = {k.lower(): v for k, v in response.headers.items()}
    missing = 0
    for key, label in HTTP_SECURITY_HEADERS.items():
        if key in headers:
            result += f"[FOUND] {label}\n"
        else:
            missing += 1
            result += f"[MISSING] {label} (Severity: MEDIUM)\n"
    result += f"\nSecurity headers present: {len(HTTP_SECURITY_HEADERS) - missing}/{len(HTTP_SECURITY_HEADERS)}\n"
    return result


def check_csp_policy(response):
    result = "\n========== CSP POLICY =========="
    header = _header_lookup(response.headers, "content-security-policy")

    if not header:
        # Missing CSP may increase attack surface but is not always
        # immediately exploitable on its own; use MEDIUM severity.
        result += "\n[MISSING] Content-Security-Policy header is not present (Severity: MEDIUM)\n"
        return result

    result += f"\n[FOUND] Content-Security-Policy: {header}\n"
    directives = [part.strip() for part in header.split(";") if part.strip()]
    parsed = {}
    for directive in directives:
        parts = directive.split(None, 1)
        name = parts[0].strip()
        value = parts[1].strip() if len(parts) > 1 else ""
        parsed[name] = value

    unsafe = []
    if "script-src" in parsed:
        if "'unsafe-inline'" in parsed["script-src"]:
            unsafe.append("script-src allows 'unsafe-inline'")
        if "'unsafe-eval'" in parsed["script-src"]:
            unsafe.append("script-src allows 'unsafe-eval'")
        if "*" in parsed["script-src"]:
            unsafe.append("script-src allows wildcard (*)")
    if "default-src" in parsed and "*" in parsed["default-src"]:
        unsafe.append("default-src allows wildcard (*)")

    if unsafe:
        for warning in unsafe:
            result += f"[WARNING] {warning}\n"
    else:
        result += "[FOUND] CSP policy directives appear restrictive\n"

    if "frame-ancestors" not in parsed:
        result += "[MISSING] frame-ancestors directive not found\n"
    if "base-uri" not in parsed:
        result += "[INFO] base-uri directive not found\n"

    return result


def trace_redirects(url):
    result = "\n========== REDIRECTS ==========\n"
    chain = [url]
    current = url
    for _ in range(MAX_REDIRECTS):
        try:
            resp = _fetch(current, allow_redirects=False)
            if not resp:
                break
            status = resp.status_code
            if status < 300 or status >= 400:
                result += f"Final status: {status}\n"
                break
            location = resp.headers.get("Location") or resp.headers.get("location")
            if not location:
                result += f"Redirect {status} without Location header\n"
                break
            next_url = urljoin(current, location)
            chain.append(next_url)
            current = next_url
        except Exception as exc:
            result += f"[ERROR] Redirect trace failed: {exc}\n"
            break

    for idx, hop in enumerate(chain):
        result += f"  {idx + 1}. {hop}\n"
    result += f"Total hops: {len(chain)}\n"
    return result


def check_social_tags(html):
    result = "\n========== SOCIAL TAGS ==========\n"
    soup = BeautifulSoup(html, "html.parser")
    head = soup.find("head")
    if not head:
        result += "[WARNING] No <head> element found\n"
        return result

    fields = {
        "title": soup.title.string.strip() if soup.title and soup.title.string else None,
        "description": _meta_content(soup, "description"),
        "og:title": _meta_property(soup, "og:title"),
        "og:description": _meta_property(soup, "og:description"),
        "og:image": _meta_property(soup, "og:image"),
        "twitter:card": _meta_name(soup, "twitter:card"),
        "twitter:title": _meta_name(soup, "twitter:title"),
        "canonical": _link_rel(soup, "canonical"),
    }
    found_any = False
    for key, value in fields.items():
        if value:
            found_any = True
            result += f"[FOUND] {key}: {value}\n"
        else:
            result += f"[MISSING] {key}\n"
    if not found_any:
        result += "[WARNING] No social / meta tags detected on page\n"
    return result


def _meta_content(soup, name):
    tag = soup.find("meta", attrs={"name": name})
    return tag.get("content") if tag and tag.get("content") else None


def _meta_property(soup, prop):
    tag = soup.find("meta", attrs={"property": prop})
    return tag.get("content") if tag and tag.get("content") else None


def _meta_name(soup, name):
    tag = soup.find("meta", attrs={"name": name})
    return tag.get("content") if tag and tag.get("content") else None


def _link_rel(soup, rel):
    tag = soup.find("link", rel=rel)
    return tag.get("href") if tag and tag.get("href") else None


def check_security_txt(url):
    result = "\n========== SECURITY.TXT ==========\n"
    parsed = urlparse(url if "://" in url else f"https://{url}")
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in SECURITY_TXT_PATHS:
        target = urljoin(base, path)
        resp = _fetch(target, allow_redirects=False)
        if not resp or resp.status_code != 200:
            continue
        text = (resp.text or "").strip()
        if not text or "<html" in text.lower()[:200]:
            continue
        result += f"[FOUND] security.txt at {path}\n"
        if "-----BEGIN PGP SIGNED MESSAGE-----" in text:
            result += "[FOUND] PGP signed\n"
        for line in text.splitlines()[:25]:
            if line.strip() and not line.startswith("#"):
                result += f"  {line}\n"
        return result

    result += "[MISSING] security.txt not found (/.well-known/security.txt or /security.txt)\n"
    return result


def detect_firewall(response):
    result = "\n========== FIREWALL ==========\n"
    headers = {k.lower(): v for k, v in response.headers.items()}
    server = (headers.get("server") or "").lower()
    powered = (headers.get("x-powered-by") or "").lower()
    cookie = (headers.get("set-cookie") or "").lower()

    checks = [
        ("cloudflare" in server or "cf-ray" in headers, "Cloudflare"),
        ("akamaighost" in server, "Akamai"),
        ("sucuri" in server or "x-sucuri-id" in headers, "Sucuri"),
        ("aws lambda" in powered, "AWS WAF"),
        ("ddos-guard" in server, "DDoS-Guard WAF"),
        ("qrator" in server, "QRATOR WAF"),
        ("_citrix_ns_id" in cookie, "Citrix NetScaler"),
    ]
    for matched, name in checks:
        if matched:
            result += f"[FOUND] WAF/CDN detected: {name}\n"
            return result
    result += "[INFO] No common WAF/CDN fingerprint in response headers\n"
    return result


def check_server_status(url, response):
    result = "\n========== SERVER STATUS ==========\n"
    start = time.perf_counter()
    elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
    if response is not None:
        elapsed_ms = max(elapsed_ms, 1)
        result += f"[FOUND] HTTP {response.status_code}\n"
        result += f"[FOUND] Response available (measured during scan)\n"
        if 200 <= response.status_code < 400:
            result += "[FOUND] Site appears UP\n"
        else:
            result += f"[WARNING] Non-success status (Severity: MEDIUM)\n"
    else:
        result += "[ERROR] Site unreachable\n"
    return result


def get_ip_info(hostname):
    import socket

    result = "\n========== GET IP ADDRESS ==========\n"
    try:
        ip = socket.gethostbyname(hostname)
        result += f"[FOUND] IPv4: {ip}\n"
    except Exception as exc:
        result += f"[ERROR] DNS lookup failed: {exc}\n"
    return result


def check_cookies(response):
    result = "\n========== COOKIES ==========\n"
    jar = getattr(response, "cookies", None)
    names = []
    if jar:
        for cookie in jar:
            names.append(cookie.name)
            secure = "Secure" if getattr(cookie, "secure", False) else "no Secure"
            httponly = "HttpOnly" if getattr(cookie, "has_nonstandard_attr", lambda x: False)("HttpOnly") or "HttpOnly" in str(cookie) else ""
            result += f"[FOUND] {cookie.name} ({secure})\n"
            if cookie.domain:
                result += f"  domain: {cookie.domain}\n"
            if cookie.path:
                result += f"  path: {cookie.path}\n"

    set_cookie = response.headers.get("Set-Cookie") or response.headers.get("set-cookie")
    if set_cookie and not names:
        parts = re.split(r", (?=[A-Za-z_][A-Za-z0-9_-]*=)", set_cookie)
        for part in parts[:20]:
            name = part.split("=", 1)[0].strip()
            if name:
                result += f"[FOUND] {name} (from Set-Cookie)\n"
                names.append(name)

    if not names:
        result += "[INFO] No cookies detected in response\n"
    else:
        result += f"\nTotal cookies: {len(names)}\n"
    return result


def check_txt_records(hostname):
    result = "\n========== TXT RECORDS ==========\n"
    try:
        import dns.resolver as dns_resolver
    except ImportError:
        result += "[ERROR] dnspython not installed\n"
        return result

    try:
        answers = dns_resolver.resolve(hostname, "TXT", lifetime=8)
        count = 0
        for rdata in answers:
            chunks = []
            for s in rdata.strings:
                chunks.append(s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s))
            text = "".join(chunks)
            count += 1
            result += f"[FOUND] {text}\n"
            if "v=spf1" in text.lower():
                result += "  (SPF record)\n"
            if "v=DMARC1" in text.upper():
                result += "  (DMARC record)\n"
        if count == 0:
            result += "[INFO] No TXT records found\n"
        else:
            result += f"\nTotal TXT records: {count}\n"
    except Exception as exc:
        result += f"[INFO] TXT lookup: {exc}\n"
    return result


def check_dnssec(hostname):
    result = "\n========== DNSSEC =========="
    try:
        import dns.resolver as dns_resolver
        import dns.name as dns_name
        import dns.dnssec as dns_dnssec
    except ImportError:
        result += "\n[ERROR] dnspython not installed. Install with: pip install dnspython\n"
        return result

    try:
        domain = dns_name.from_text(hostname)
        keys = dns_resolver.resolve(domain, "DNSKEY", lifetime=8)
        result += f"\n[FOUND] DNSKEY record count: {len(keys)}\n"
    except Exception as exc:
        result += f"\n[MISSING] DNSKEY lookup failed or no DNSSEC enabled: {exc}\n"
        return result

    try:
        child = dns_resolver.resolve(domain, "DS", lifetime=8)
        result += f"[FOUND] DS records present: {len(child)}\n"
    except Exception as exc:
        result += f"[WARNING] DS records not found or unreachable: {exc}\n"

    return result


def check_tls_connection(url):
    import socket
    import ssl as ssl_lib

    result = "\n========== TLS CONNECTION ==========\n"
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme != "https":
        result += "[WARNING] Site not using HTTPS — TLS check skipped\n"
        return result

    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        context = ssl_lib.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                version = ssock.version() or "Unknown"
                cipher = ssock.cipher()
                result += f"[FOUND] TLS version: {version}\n"
                if cipher:
                    result += f"[FOUND] Cipher: {cipher[0]} ({cipher[2]} bits)\n"
                cert = ssock.getpeercert()
                if cert:
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    result += f"[FOUND] Issuer: {issuer.get('organizationName', 'Unknown')}\n"
    except Exception as exc:
        result += f"[ERROR] TLS handshake failed: {exc}\n"
    return result


def discover_assets(html, base_url):
    result = "\n========== ASSETS & TRACKERS =========="
    soup = BeautifulSoup(html, "html.parser")
    assets = {
        "scripts": set(),
        "styles": set(),
        "images": set(),
        "fonts": set(),
        "manifests": set(),
    }
    trackers = set()
    analytics_signals = [
        "google-analytics.com", "gtag.js", "ga.js", "analytics.js",
        "googletagmanager.com", "facebook.net", "facebook.com/tr",
        "adsbygoogle.js", "matomo", "hotjar", "fullstory", "segment.com",
        "optimizely", "mixpanel", "clarity.microsoft.com", "tiktok.com",
        "bing.com", "pinterest.com", "doubleclick.net",
    ]

    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            target = src.strip()
            assets["scripts"].add(target)
            for signal in analytics_signals:
                if signal in target.lower():
                    trackers.add(signal)
        elif script.string:
            text = script.string.lower()
            for signal in analytics_signals:
                if signal in text:
                    trackers.add(signal)

    for link in soup.find_all("link", rel=True, href=True):
        rel = " ".join(link.get("rel", [])).lower()
        href = link["href"].strip()
        if "stylesheet" in rel:
            assets["styles"].add(href)
        if "manifest" in rel:
            assets["manifests"].add(href)

    for img in soup.find_all(["img", "source", "picture"]):
        src = img.get("src") or img.get("data-src") or img.get("srcset")
        if src:
            assets["images"].add(src.strip())

    for tag in soup.find_all(True):
        src = tag.get("src")
        if src and src.strip().lower().endswith((".woff", ".woff2", ".ttf", ".otf", ".eot")):
            assets["fonts"].add(src.strip())

    for asset_type, items in assets.items():
        result += f"\n{asset_type.title()} found: {len(items)}\n"
        for item in sorted(list(items)[:20]):
            result += f" - {urljoin(base_url, item)}\n"

    if trackers:
        result += "\nTrackers / analytics detected:\n"
        for tracker in sorted(trackers):
            result += f" - {tracker}\n"
    else:
        result += "\nNo common trackers or analytics signatures detected in page assets.\n"

    return result


def check_mail_config(hostname, base_domain):
    """Basic mail security from DNS (SPF/DMARC/MX) — no external API."""
    result = "\n========== MAIL CONFIG ==========\n"
    try:
        import dns.resolver as dns_resolver
    except ImportError:
        result += "[ERROR] dnspython not installed\n"
        return result

    domain = base_domain or hostname
    has_mx = False
    try:
        mx = dns_resolver.resolve(domain, "MX", lifetime=8)
        has_mx = True
        for r in mx:
            result += f"[FOUND] MX: {r.exchange} (priority {r.preference})\n"
    except Exception:
        result += "[WARNING] No MX records found\n"

    spf = dmarc = False
    try:
        for rdata in dns_resolver.resolve(domain, "TXT", lifetime=8):
            text = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if "v=spf1" in text.lower():
                spf = True
                result += f"[FOUND] SPF: {text[:120]}\n"
            if "v=dkim1" in text.lower():
                dkim = True
                result += f"[FOUND] DKIM record found in TXT: {text[:120]}\n"
    except Exception:
        pass

    try:
        for rdata in dns_resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=8):
            text = b"".join(rdata.strings).decode("utf-8", errors="replace")
            dmarc = True
            result += f"[FOUND] DMARC: {text[:120]}\n"
    except Exception:
        result += f"[MISSING] DMARC record (_dmarc.{domain})\n"

    try:
        selector_name = f"default._domainkey.{domain}"
        for rdata in dns_resolver.resolve(selector_name, "TXT", lifetime=8):
            text = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if "v=dkim1" in text.lower():
                dkim = True
                result += f"[FOUND] DKIM selector found: {selector_name}\n"
    except Exception:
        pass

    if not spf:
        result += "[MISSING] SPF TXT record (Severity: MEDIUM)\n"
    if not dmarc:
        result += "[MISSING] DMARC record (Severity: MEDIUM)\n"
    if not dkim:
        result += "[MISSING] DKIM record (Severity: MEDIUM)\n"
    if has_mx and spf:
        result += "[FOUND] Basic mail configuration looks present\n"
    return result


# =========================
# CONTENT LEAKAGE SCANNER
# =========================

def extract_emails(html, url):
    """Extract and classify email addresses from HTML"""
    result = "\n========== EMAIL EXTRACTION ==========\n"
    # Enhanced email pattern
    email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    emails_found = set()
    
    for match in re.finditer(email_pattern, html):
        email = match.group(0).lower()
        emails_found.add(email)
    
    if emails_found:
        result += f"[FOUND] {len(emails_found)} email address(es)\n"
        for email in sorted(emails_found):
            email_type = "admin" if any(t in email for t in ["admin", "root", "system"]) else \
                        "support" if any(t in email for t in ["support", "help", "ticket"]) else \
                        "info" if any(t in email for t in ["info", "contact", "hello"]) else "other"
            result += f" - {email} ({email_type})\n"
        result += "[SEVERITY] INFO - Email addresses may be used for targeted attacks\n"
    else:
        result += "[NO EMAILS FOUND]\n"
    
    return result


def extract_phone_numbers(html):
    """Extract phone numbers with type detection"""
    result = "\n========== PHONE EXTRACTION ==========\n"
    # Patterns: +1-XXX-XXX-XXXX, (XXX) XXX-XXXX, XXX.XXX.XXXX
    phone_patterns = [
        r'\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}',
        r'\(\d{3}\)\s?\d{3}[-.\s]?\d{4}',
        r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',
        r'tel:\+?[\d\s\-\(\)\.]{10,}',
    ]
    
    phones_found = set()
    for pattern in phone_patterns:
        for match in re.finditer(pattern, html, re.IGNORECASE):
            phone = match.group(0).strip()
            phones_found.add(phone)
    
    if phones_found:
        result += f"[FOUND] {len(phones_found)} phone number(s)\n"
        for phone in sorted(phones_found):
            result += f" - {phone}\n"
        result += "[SEVERITY] MEDIUM - Phone numbers can be used for social engineering\n"
    else:
        result += "[NO PHONE NUMBERS FOUND]\n"
    
    return result


def detect_api_keys(html):
    """Detect common API key patterns"""
    result = "\n========== API KEY DETECTION ==========\n"
    
    api_key_patterns = {
        "aws": r"(AKIA[0-9A-Z]{16})",
        "stripe": r"(sk_live_[A-Za-z0-9]{20}|pk_live_[A-Za-z0-9]{20})",
        "api_key": r"(api[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?)",
        "jwt": r"(eyJ[A-Za-z0-9_\-\.]+\.eyJ[A-Za-z0-9_\-\.]+\.[A-Za-z0-9_\-\.]+)",
        "bearer": r"(Bearer\s+[A-Za-z0-9._\-]+)",
        "oauth": r"(oauth[_-]?(token|secret|key)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{15,}['\"]?)",
    }
    
    keys_found = {}
    for key_type, pattern in api_key_patterns.items():
        matches = set()
        for match in re.finditer(pattern, html, re.IGNORECASE):
            matched_text = match.group(1) if match.lastindex else match.group(0)
            # Avoid duplicates and redact sensitive parts
            if len(matched_text) > 8:
                redacted = matched_text[:8] + "..." + matched_text[-4:] if len(matched_text) > 12 else matched_text
                matches.add(redacted)
        if matches:
            keys_found[key_type] = matches
    
    if keys_found:
        result += "[FOUND] Potential API keys detected\n"
        for key_type, keys in keys_found.items():
            result += f"\n{key_type.upper()} ({len(keys)} found):\n"
            for key in sorted(keys)[:5]:  # Show first 5
                result += f" - {key}\n"
        result += "\n[SEVERITY] CRITICAL - Exposed API keys can compromise services\n"
    else:
        result += "[NO API KEYS FOUND]\n"
    
    return result


def detect_secrets(html):
    """Detect common secrets patterns"""
    result = "\n========== SECRETS DETECTION ==========\n"
    
    secret_patterns = {
        "password": r"(password\s*[=:]\s*['\"]([^'\"]{4,})['\"])",
        "private_key": r"(-----BEGIN\s+(PRIVATE|RSA)\s+KEY-----)",
        "secret": r"(secret\s*[=:]\s*['\"]([^'\"]{6,})['\"])",
        "token": r"(token\s*[=:]\s*['\"]([A-Za-z0-9_\-\.]{15,})['\"])",
        "database_url": r"(database[_-]?url\s*[=:]\s*['\"]([^'\"]{10,})['\"])",
        "encryption_key": r"(encryption[_-]?key\s*[=:]\s*['\"]([^'\"]{15,})['\"])",
    }
    
    secrets_found = {}
    for secret_type, pattern in secret_patterns.items():
        matches = set()
        for match in re.finditer(pattern, html, re.IGNORECASE):
            matched_text = match.group(1) if match.lastindex else match.group(0)
            matches.add(matched_text[:30] + "..." if len(matched_text) > 30 else matched_text)
        if matches:
            secrets_found[secret_type] = matches
    
    if secrets_found:
        result += "[FOUND] Potential secrets detected\n"
        for secret_type, secrets in secrets_found.items():
            result += f"\n{secret_type.upper()} ({len(secrets)} found):\n"
            for secret in sorted(secrets)[:3]:  # Show first 3
                result += f" - {secret}\n"
        result += "\n[SEVERITY] CRITICAL - Exposed secrets can compromise the entire application\n"
    else:
        result += "[NO SECRETS FOUND]\n"
    
    return result


def analyze_comments(html):
    """Extract and analyze HTML and JavaScript comments"""
    result = "\n========== COMMENT ANALYSIS ==========\n"
    
    # HTML comments
    html_comments = re.findall(r'<!--\s*(.*?)\s*-->', html, re.DOTALL)
    
    # JavaScript comments (single and multi-line)
    js_comments = re.findall(r'//\s*(.+?)(?=\n|$)|\s*/\*\s*(.*?)\s*\*/', html, re.DOTALL)
    
    interesting_keywords = [
        'todo', 'fixme', 'hack', 'bug', 'xxx', 'password', 'secret', 'key',
        'api', 'debug', 'admin', 'test', 'remove', 'deprecated', 'vulnerable'
    ]
    
    suspicious_comments = []
    
    for comment in html_comments:
        comment_lower = comment.lower()
        if any(keyword in comment_lower for keyword in interesting_keywords):
            suspicious_comments.append(('HTML', comment[:100]))
    
    for comment_pair in js_comments:
        comment = comment_pair[0] or comment_pair[1]
        if comment:
            comment_lower = comment.lower()
            if any(keyword in comment_lower for keyword in interesting_keywords):
                suspicious_comments.append(('JavaScript', comment[:100]))
    
    if suspicious_comments:
        result += f"[FOUND] {len(suspicious_comments)} suspicious comment(s)\n"
        for comm_type, comment in suspicious_comments[:5]:
            result += f"\n[{comm_type}]\n{comment}\n"
        result += "\n[SEVERITY] MEDIUM - Comments may reveal sensitive information\n"
    else:
        result += f"[FOUND] {len(html_comments) + len(js_comments)} comment(s), none appear suspicious\n"
    
    return result


def extract_js_secrets(js_content):
    """Analyze JavaScript for exposed secrets and sensitive data"""
    result = "\n========== JAVASCRIPT SECRETS ==========\n"
    
    js_patterns = {
        "api_endpoint": r"(https?://[a-zA-Z0-9\.\-_:/?=&]+/api/[a-zA-Z0-9\/_-]+)",
        "hardcoded_token": r"(token\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{20,}['\"]?)",
        "env_variable": r"(process\.env\.[A-Z_]+)",
        "window_secrets": r"(window\.[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*['\"]?[A-Za-z0-9_\-\.]{10,}['\"]?)",
    }
    
    secrets_found = {}
    for secret_type, pattern in js_patterns.items():
        matches = set()
        for match in re.finditer(pattern, js_content, re.IGNORECASE):
            matched_text = match.group(1) if match.lastindex else match.group(0)
            matches.add(matched_text[:50] if len(matched_text) > 50 else matched_text)
        if matches:
            secrets_found[secret_type] = matches
    
    if secrets_found:
        result += "[FOUND] Potential secrets in JavaScript\n"
        for secret_type, secrets in secrets_found.items():
            result += f"\n{secret_type.upper()} ({len(secrets)} found):\n"
            for secret in sorted(secrets)[:5]:
                result += f" - {secret}\n"
        result += "\n[SEVERITY] HIGH - JavaScript secrets are accessible to browser developers\n"
    else:
        result += "[NO SECRETS FOUND IN JAVASCRIPT]\n"
    
    return result


# =========================
# SEARCH ENGINE RECONNAISSANCE
# =========================

def generate_google_dorks(domain):
    """Generate Google Dork suggestions for reconnaissance"""
    result = "\n========== GOOGLE DORK SUGGESTIONS ==========\n"
    
    dorks = [
        {
            "dork": f'site:{domain} filetype:pdf',
            "purpose": "Find PDF documents hosted on the domain",
            "severity": "MEDIUM"
        },
        {
            "dork": f'site:{domain} filetype:doc OR filetype:docx',
            "purpose": "Find Word documents that may contain sensitive info",
            "severity": "MEDIUM"
        },
        {
            "dork": f'site:{domain} filetype:xls OR filetype:xlsx',
            "purpose": "Find Excel spreadsheets with potential data",
            "severity": "MEDIUM"
        },
        {
            "dork": f'site:{domain} admin',
            "purpose": "Find admin pages and login portals",
            "severity": "HIGH"
        },
        {
            "dork": f'site:{domain} backup OR backup.zip OR backup.tar',
            "purpose": "Find backup files",
            "severity": "CRITICAL"
        },
        {
            "dork": f'site:{domain} ".git" OR ".svn"',
            "purpose": "Find exposed version control repositories",
            "severity": "CRITICAL"
        },
        {
            "dork": f'site:{domain} config OR configuration',
            "purpose": "Find configuration files",
            "severity": "CRITICAL"
        },
        {
            "dork": f'site:{domain} test OR staging OR dev',
            "purpose": "Find development and staging environments",
            "severity": "HIGH"
        },
    ]
    
    result += f"[FOUND] {len(dorks)} Google Dork suggestions\n\n"
    for i, dork_item in enumerate(dorks, 1):
        result += f"{i}. [{dork_item['severity']}] {dork_item['purpose']}\n"
        result += f"   Dork: {dork_item['dork']}\n\n"
    
    result += "[INFO] Use these dorks to search for exposed information on Google\n"
    result += "[SEVERITY] INFO - These searches may reveal sensitive exposed data\n"
    
    return result


def analyze_search_engine_exposure(domain):
    """Check indexing status and exposure estimation"""
    result = "\n========== SEARCH ENGINE EXPOSURE ==========\n"
    
    result += f"Domain: {domain}\n\n"
    result += "[INFO] To check actual indexing, use:\n"
    result += f" - Google Search Console: https://search.google.com/search-console\n"
    result += f" - Google Cache: https://webcache.googleusercontent.com/cache:{domain}\n"
    result += f" - Bing Webmaster: https://www.bing.com/webmaster\n\n"
    
    result += "[RECOMMENDATIONS]\n"
    result += "1. Check Google Search Console for indexed pages count\n"
    result += "2. Review Search Analytics to see indexed pages\n"
    result += "3. Check if robots.txt is blocking sensitive areas\n"
    result += "4. Use 'Exclude from index' for sensitive pages\n"
    result += "5. Set up proper noindex meta tags\n"
    result += "6. Monitor for unexpected indexed pages\n\n"
    
    result += "[SEVERITY] MEDIUM - Unintended indexing can expose sensitive information\n"
    
    return result


def find_cached_pages(domain):
    """Identify cached versions of pages"""
    result = "\n========== CACHED PAGES ==========\n"
    
    result += f"[INFO] Search Engine Cache Information for {domain}\n\n"
    
    result += "[GOOGLE CACHE]\n"
    result += f" - URL: https://webcache.googleusercontent.com/cache:{domain}\n"
    result += f" - Also try: https://webcache.googleusercontent.com/cache:www.{domain}\n\n"
    
    result += "[BING CACHE]\n"
    result += f" - URL: https://cc.bingj.com/cache.aspx?q=site:{domain}\n\n"
    
    result += "[WAYBACK MACHINE]\n"
    result += f" - URL: https://web.archive.org/web/*/{ domain}/*\n"
    result += " - Shows historical snapshots of the website\n\n"
    
    result += "[RECOMMENDATIONS]\n"
    result += "1. Request cache removal from Google if sensitive info is cached\n"
    result += "2. Use robots.txt to prevent re-caching\n"
    result += "3. Monitor Wayback Machine for historical data\n"
    result += "4. Add noarchive meta tag to prevent archival\n\n"
    
    result += "[SEVERITY] MEDIUM - Cached pages may contain outdated sensitive information\n"
    
    return result


def discover_exposed_documents(domain):
    """Find exposed documents via search patterns"""
    result = "\n========== DOCUMENT DISCOVERY ==========\n"
    
    file_types = {
        "pdf": "PDF documents",
        "doc": "Word documents (.doc)",
        "docx": "Word documents (.docx)",
        "xls": "Excel spreadsheets (.xls)",
        "xlsx": "Excel spreadsheets (.xlsx)",
        "ppt": "PowerPoint presentations",
        "pptx": "PowerPoint presentations",
        "txt": "Text files",
        "zip": "Archive files",
        "tar": "Tar archives",
    }
    
    result += "[FOUND] Suggested searches to find exposed documents\n\n"
    
    for ext, desc in file_types.items():
        dork = f'site:{domain} filetype:{ext}'
        result += f"[{ext.upper()}] {desc}\n"
        result += f" - Search: {dork}\n\n"
    
    result += "[RECOMMENDATIONS]\n"
    result += "1. Audit all indexed documents\n"
    result += "2. Remove sensitive documents from search results\n"
    result += "3. Use robots.txt to block document directories\n"
    result += "4. Add password protection to sensitive documents\n"
    result += "5. Use noindex for document directories\n\n"
    
    result += "[SEVERITY] INFO - Exposed documents often contain sensitive data\n"
    
    return result


def find_public_repositories(domain):
    """Find GitHub/GitLab repositories related to the domain"""
    result = "\n========== PUBLIC REPOSITORIES ==========\n"
    
    result += "[INFO] Search for repositories related to domain\n\n"
    
    repositories = [
        {
            "platform": "GitHub",
            "search": f"https://github.com/search?q={domain}",
            "info": "Search GitHub for public repositories"
        },
        {
            "platform": "GitLab",
            "search": f"https://gitlab.com/search?search={domain}",
            "info": "Search GitLab for public projects"
        },
        {
            "platform": "Bitbucket",
            "search": f"https://bitbucket.org/search?search_text={domain}",
            "info": "Search Bitbucket repositories"
        },
        {
            "platform": "SourceForge",
            "search": f"https://sourceforge.net/directory/?q={domain}",
            "info": "Search SourceForge projects"
        },
    ]
    
    for repo in repositories:
        result += f"[{repo['platform']}]\n"
        result += f" - {repo['info']}\n"
        result += f" - Search: {repo['search']}\n\n"
    
    result += "[RECOMMENDATIONS]\n"
    result += "1. Search for repositories with your domain name\n"
    result += "2. Check for credentials in repository history\n"
    result += "3. Review commit history for sensitive information\n"
    result += "4. Look for forks that may contain sensitive data\n"
    result += "5. Monitor for new repositories\n\n"
    
    result += "[SEVERITY] INFO - Source code repositories often contain secrets\n"
    
    return result


def find_paste_references(domain):
    """Find references in pastebin, gist, and similar services"""
    result = "\n========== PASTE REFERENCES ==========\n"
    
    result += "[INFO] Search paste and code sharing sites\n\n"
    
    paste_sites = [
        {
            "site": "Pastebin",
            "search": f"https://pastebin.com/search?q={domain}",
            "info": "Popular paste sharing service"
        },
        {
            "site": "GitHub Gist",
            "search": f"https://gist.github.com/search?q={domain}",
            "info": "GitHub's code snippet sharing"
        },
        {
            "site": "PasteBin.com Alternative",
            "search": f"https://www.codepad.co/search?q={domain}",
            "info": "Code sharing platform"
        },
        {
            "site": "HasteBin",
            "search": f"https://hasteb.in/search?q={domain}",
            "info": "Temporary code sharing"
        },
    ]
    
    for paste in paste_sites:
        result += f"[{paste['site']}]\n"
        result += f" - {paste['info']}\n"
        result += f" - Search: {paste['search']}\n\n"
    
    result += "[RECOMMENDATIONS]\n"
    result += "1. Monitor paste sites for your domain/company name\n"
    result += "2. Report leaked credentials immediately\n"
    result += "3. Set up alerts for domain mentions\n"
    result += "4. Review and remove old pastes\n"
    result += "5. Use services like Google Alerts or Have I Been Pwned\n\n"
    
    result += "[SEVERITY] INFO - Pastes often contain exposed credentials\n"
    
    return result


# ===== PHASE 2: ENHANCED ENUMERATION & ENTRY POINT MAPPER =====

def discover_virtual_hosts(domain):
    """Discover virtual hosts with concurrent DNS + HTTP requests"""
    start_time = time.time()
    result = "\n========== VIRTUAL HOSTS ENUMERATION (OPTIMIZED) ==========\n"
    result += "[INFO] Identifying virtual hosts and subdomains (concurrent scanning)\n\n"

    metrics = ScanMetrics()

    common_subdomains = [
        "www", "mail", "ftp", "webmail", "smtp", "pop", "ns", "cpanel",
        "whm", "autodiscover", "autoconfig", "m", "blog", "shop",
        "admin", "api", "cdn", "dev", "staging", "test", "prod",
        "backup", "old", "new", "git", "svn", "vpn", "portal",
    ]

    discovered = []
    timeout_streak = 0
    total_subdomains = len(common_subdomains)
    checked_count = 0

    result += f"[PROGRESS] Starting scan of {total_subdomains} subdomains...\n"

    # Concurrent DNS + HTTP checks
    with ThreadPoolExecutor(max_workers=_MAX_CONCURRENT) as executor:
        futures = {}

        for subdomain in common_subdomains:
            # Check if we should continue (limit reached)
            if not metrics.should_continue():
                result += f"[INFO] Discovery limit ({_MAX_DISCOVERIES}) reached, stopping early\n"
                break

            host = f"{subdomain}.{domain}"

            def check_host(h):
                """Check if host is reachable"""
                try:
                    ip = socket.gethostbyname(h)
                except Exception:
                    return {"host": h, "ip": None, "status": None}

                # Try HTTPS first, then HTTP
                for proto in ["https", "http"]:
                    target_url = f"{proto}://{h}"
                    response = _fetch(target_url, metrics=metrics)
                    if response:
                        return {"host": h, "ip": ip, "status": response.status_code, "url": target_url}

                return {"host": h, "ip": ip, "status": None}

            futures[executor.submit(check_host, host)] = host

        for future in as_completed(futures):
            try:
                result_item = future.result()
                checked_count += 1

                # Update progress in result periodically (every 10%)
                if checked_count % max(1, total_subdomains // 10) == 0:
                    elapsed = metrics.get_elapsed()
                    result += f"[PROGRESS] Checked {checked_count}/{total_subdomains} subdomains... (elapsed: {elapsed:.1f}s)\n"

                if result_item["status"]:
                    discovered.append(result_item)
                    metrics.record_discovery()
                    timeout_streak = 0
                else:
                    timeout_streak += 1

                # Early exit if too many consecutive failures
                if timeout_streak >= _EARLY_EXIT_THRESHOLD:
                    break

            except Exception:
                timeout_streak += 1
                if timeout_streak >= _EARLY_EXIT_THRESHOLD:
                    break

    elapsed = metrics.get_elapsed()

    if discovered:
        result += f"\n[FOUND] {len(discovered)} responsive virtual host(s)\n"
        for item in sorted(discovered, key=lambda x: x["host"]):
            result += f" - {item['host']} ({item['ip']})"
            if item['status']:
                result += f" status={item['status']}"
            result += "\n"
    else:
        result += "\n[INFO] No common virtual hosts resolved\n"

    # Summary with metrics
    summary = metrics.get_summary()
    result += f"\n[METRICS]\n"
    result += f"  - Elapsed time: {elapsed:.2f}s\n"
    result += f"  - Subdomains checked: {checked_count}/{total_subdomains}\n"
    result += f"  - Requests made: {summary['requests_made']}\n"
    result += f"  - Requests skipped (cache/duplicate): {summary['requests_skipped']}\n"
    if summary['skipped_breakdown']:
        result += f"  - Skip reasons: {', '.join([f'{k}({v})' for k,v in summary['skipped_breakdown'].items()])}\n"
    result += f"  - Discoveries: {summary['discoveries']}\n"

    result += "\n[RECOMMENDATION]\n"
    result += f" 1. Use dnsrecon/amass for deeper virtual host enumeration on {domain}\n"
    result += f" 2. Check DNS records and subdomain brute force results\n"
    result += f" 3. Review CDN/WAF hostnames for aliasing and alternate domains\n\n"
    result += "[SEVERITY] INFO - Virtual hosts may expose additional attack surfaces\n"
    return result


def scan_common_admin_paths(url):
    """Scan for admin paths with concurrent requests, filtering, and early exit"""
    start_time = time.time()
    result = "\n========== ADMIN PATHS DISCOVERY (OPTIMIZED) ==========\n"
    result += "[INFO] Identifying common administrative endpoints (concurrent scanning)\n\n"

    metrics = ScanMetrics()

    admin_paths = {
        "Admin Panels": [
            "/admin", "/administrator", "/admin-panel", "/admin/login",
            "/dashboard", "/control", "/backend", "/manager"
        ],
        "CMS Paths": [
            "/wp-admin", "/wp-login.php", "/joomla", "/drupal",
            "/sites/default/files", "/node", "/blog"
        ],
        "Development": [
            "/.git", "/.svn", "/.hg", "/.env", "/.env.local",
            "/config", "/config.php", "/settings.php", "/secrets"
        ],
        "API Endpoints": [
            "/api", "/api/v1", "/api/v2", "/api/admin",
            "/rest", "/graphql", "/swagger", "/swagger-ui"
        ],
        "Backup & Logs": [
            "/backup", "/backups", "/.backup", "/old",
            "/log", "/logs", "/error.log", "/.htaccess"
        ]
    }

    # Flatten and sample paths if needed
    all_paths = []
    for paths in admin_paths.values():
        all_paths.extend(paths)

    max_samples = 15  # Smart sampling to avoid brute-forcing
    if len(all_paths) > max_samples:
        important = [p for p in all_paths if any(x in p for x in ["admin", "api", "git", "env", "swagger"])]
        sampled = [p for p in all_paths if p not in important]
        all_paths = important + sampled[:max_samples - len(important)]

    total_paths = len(all_paths)
    found = []
    timeout_streak = 0
    skipped_static = 0
    skipped_third_party = 0

    result += f"[PROGRESS] Starting scan of {total_paths} admin/sensitive paths...\n"

    # Concurrent path checks
    with ThreadPoolExecutor(max_workers=_MAX_CONCURRENT) as executor:
        futures = {}

        for path in all_paths:
            # Check if we should continue (limit reached)
            if not metrics.should_continue():
                result += f"[INFO] Discovery limit ({_MAX_DISCOVERIES}) reached, stopping early\n"
                break

            target_url = url.rstrip("/") + path

            # Skip if it's a static asset
            if _is_static_asset(target_url):
                metrics.record_skipped(target_url, reason="static_asset")
                skipped_static += 1
                continue

            # Skip if it would redirect to a third-party domain (optimization)
            # We can't know until we fetch, but we can check common patterns
            # For now, we'll let it fetch but filter results later

            futures[executor.submit(_fetch, target_url, metrics=metrics)] = path

        checked_count = 0
        for future in as_completed(futures):
            path = futures[future]
            try:
                response = future.result()
                checked_count += 1

                # Update progress periodically
                if checked_count % 5 == 0:
                    elapsed = metrics.get_elapsed()
                    result += f"[PROGRESS] Checked {checked_count}/{len(futures)} paths... (elapsed: {elapsed:.1f}s, found: {len(found)})\n"

                status = response.status_code if response else None

                if response and status not in (404, 502, 503, 504):
                    # Check if response redirected to third-party domain
                    if response.history:
                        final_url = response.url
                        base_domain = urlparse(url).netloc
                        if _is_third_party_domain(final_url, base_domain):
                            metrics.record_skipped(final_url, reason="third_party")
                            skipped_third_party += 1
                            continue

                    result += f" - {path} [accessible status={status}]\n"
                    found.append({"path": path, "status": status})
                    metrics.record_discovery()
                    timeout_streak = 0
                elif response is None:
                    timeout_streak += 1
                    # Early exit on WAF/rate-limiting (consecutive timeouts)
                    if timeout_streak >= _EARLY_EXIT_THRESHOLD:
                        result += f"\n[WARNING] Possible WAF/rate-limiting detected, stopping further checks\n"
                        break

            except Exception:
                pass

    elapsed = metrics.get_elapsed()
    summary = metrics.get_summary()

    result += f"\n[SUMMARY] {len(found)} accessible admin/sensitive path(s) identified\n"
    result += f"[METRICS]\n"
    result += f"  - Elapsed time: {elapsed:.2f}s\n"
    result += f"  - Paths checked: {checked_count}/{total_paths}\n"
    result += f"  - Requests made: {summary['requests_made']}\n"
    result += f"  - Requests skipped: {summary['requests_skipped']}\n"
    if skipped_static > 0:
        result += f"  - Skipped (static assets): {skipped_static}\n"
    if skipped_third_party > 0:
        result += f"  - Skipped (third-party): {skipped_third_party}\n"
    if summary['skipped_breakdown']:
        result += f"  - Skip reasons: {', '.join([f'{k}({v})' for k,v in summary['skipped_breakdown'].items()])}\n"
    result += f"  - Discoveries: {summary['discoveries']}\n"

    if found:
        result += "[SEVERITY] INFO - Accessible admin paths discovered\n"
    else:
        result += "[INFO] No accessible admin paths discovered from common list\n"

    return result


def discover_alternate_ports(domain):
    """Discover ports with concurrent scanning, filtering, and early exit"""
    start_time = time.time()
    result = "\n========== ALTERNATE PORTS DISCOVERY (OPTIMIZED) ==========\n"
    result += "[INFO] Scanning common alternate ports for reachable services (concurrent scanning)\n\n"

    metrics = ScanMetrics()

    port_categories = {
        "HTTP/HTTPS": [80, 443, 8080, 8443, 8888, 9000, 9001],
        "Developer Services": [3000, 5000, 8000, 8001],
        "Admin/Management": [8008, 8009, 8010, 9200, 9300],
        "Datastores": [3306, 5432, 6379, 27017]
    }

    discovered = []
    timeout_streak = 0
    total_ports = sum(len(ports) for ports in port_categories.values())
    checked_count = 0

    result += f"[PROGRESS] Starting scan of {total_ports} ports...\n"

    # Concurrent port scanning
    with ThreadPoolExecutor(max_workers=_MAX_CONCURRENT) as executor:
        futures = {}

        for category, ports in port_categories.items():
            for port in ports:
                # Check if we should continue (limit reached)
                if not metrics.should_continue():
                    result += f"[INFO] Discovery limit ({_MAX_DISCOVERIES}) reached, stopping early\n"
                    break

                def scan_port(p, cat):
                    """Scan a single port"""
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)  # Port timeout
                    try:
                        if sock.connect_ex((domain, p)) == 0:
                            response = None
                            if p in (80, 8080, 8888, 3000, 5000, 8000, 8001, 9000, 9001):
                                target_url = f"http://{domain}:{p}"
                                response = _fetch(target_url, metrics=metrics)
                            elif p in (443, 8443):
                                target_url = f"https://{domain}:{p}"
                                response = _fetch(target_url, metrics=metrics)

                            status = response.status_code if response else "open"
                            return {"port": p, "category": cat, "status": status}
                    except socket.timeout:
                        return None
                    except Exception:
                        return None
                    finally:
                        sock.close()

                    return None

                futures[executor.submit(scan_port, port, category)] = port

        for future in as_completed(futures):
            try:
                result_item = future.result()
                checked_count += 1

                # Update progress periodically
                if checked_count % max(1, total_ports // 5) == 0:
                    elapsed = metrics.get_elapsed()
                    result += f"[PROGRESS] Checked {checked_count}/{total_ports} ports... (elapsed: {elapsed:.1f}s, found: {len(discovered)})\n"

                if result_item:
                    discovered.append(result_item)
                    metrics.record_discovery()
                    timeout_streak = 0
                else:
                    timeout_streak += 1
                    # Early exit if target unreachable
                    if timeout_streak >= _EARLY_EXIT_THRESHOLD:
                        break

            except Exception:
                timeout_streak += 1
                if timeout_streak >= _EARLY_EXIT_THRESHOLD:
                    break

    elapsed = metrics.get_elapsed()
    summary = metrics.get_summary()

    if discovered:
        result += f"\n[FOUND] {len(discovered)} open port(s) on {domain}\n"
        for item in sorted(discovered, key=lambda x: x["port"]):
            result += f" - {item['port']}/tcp ({item['category']}) status={item['status']}\n"
        result += "\n[SEVERITY] INFO - Open alternate ports may expose additional services\n"
    else:
        result += "\n[INFO] No common alternate ports appear reachable\n"
        result += "[RECOMMENDATION]\n"
        result += f" 1. Use nmap -p- {domain} for full port enumeration\n"
        result += f" 2. Use masscan -p1-65535 {domain} for fast coverage\n"

    result += f"\n[METRICS]\n"
    result += f"  - Elapsed time: {elapsed:.2f}s\n"
    result += f"  - Ports scanned: {checked_count}/{total_ports}\n"
    result += f"  - Requests made: {summary['requests_made']}\n"
    result += f"  - Requests skipped: {summary['requests_skipped']}\n"
    if summary['skipped_breakdown']:
        result += f"  - Skip reasons: {', '.join([f'{k}({v})' for k,v in summary['skipped_breakdown'].items()])}\n"
    result += f"  - Discoveries: {summary['discoveries']}\n"

    return result


def find_common_paths(domain):
    """Find common paths with concurrent requests, filtering, and smart sampling"""
    start_time = time.time()
    result = "\n========== COMMON PATHS DISCOVERY (OPTIMIZED) ==========\n"
    result += "[INFO] Probing common directory and file paths (concurrent scanning)\n\n"

    metrics = ScanMetrics()

    path_categories = {
        "Standard Paths": [
            "/", "/index.html", "/index.php", "/index.asp",
            "/home", "/homepage", "/main", "/start"
        ],
        "Static Files": [
            "/assets", "/static", "/public", "/css", "/js",
            "/images", "/img", "/media", "/files", "/uploads"
        ],
        "Directories": [
            "/vendor", "/lib", "/libs", "/plugins", "/modules",
            "/extensions", "/themes", "/templates", "/components"
        ],
        "Documentation": [
            "/docs", "/documentation", "/readme", "/changelog",
            "/api/docs", "/swagger", "/openapi", "/postman"
        ],
        "Version Control": [
            "/.git/config", "/.gitignore", "/.git/HEAD",
            "/.svn/entries", "/.hg/store"
        ]
    }

    # Flatten paths and apply smart sampling
    all_paths = []
    for paths in path_categories.values():
        all_paths.extend(paths)

    max_samples = 15  # Smart sampling
    if len(all_paths) > max_samples:
        important = [p for p in all_paths if any(x in p for x in ["api", "docs", "git", "admin", "config"])]
        sampled = [p for p in all_paths if p not in important]
        all_paths = important + sampled[:max_samples - len(important)]

    total_paths = len(all_paths)
    found = []
    timeout_streak = 0
    skipped_static = 0
    skipped_third_party = 0
    base_domain = domain

    result += f"[PROGRESS] Starting scan of {total_paths} common paths...\n"

    # Try HTTPS first, then HTTP (single check per path, not double)
    base_urls = [f"https://{domain}", f"http://{domain}"]

    # Concurrent path requests
    with ThreadPoolExecutor(max_workers=_MAX_CONCURRENT) as executor:
        futures = {}

        for path in all_paths:
            # Check if we should continue (limit reached)
            if not metrics.should_continue():
                result += f"[INFO] Discovery limit ({_MAX_DISCOVERIES}) reached, stopping early\n"
                break

            def check_path(p):
                """Check a path (try HTTPS first, then HTTP)"""
                for base in base_urls:
                    target = base.rstrip("/") + p

                    # Skip static assets
                    if _is_static_asset(target):
                        metrics.record_skipped(target, reason="static_asset")
                        continue

                    response = _fetch(target, metrics=metrics)
                    if response and response.status_code not in (404, 502, 503, 504):
                        return {"path": p, "url": target, "status": response.status_code}
                return None

            futures[executor.submit(check_path, path)] = path

        checked_count = 0
        for future in as_completed(futures):
            path = futures[future]
            try:
                result_item = future.result()
                checked_count += 1

                # Update progress periodically
                if checked_count % 5 == 0:
                    elapsed = metrics.get_elapsed()
                    result += f"[PROGRESS] Checked {checked_count}/{len(futures)} paths... (elapsed: {elapsed:.1f}s, found: {len(found)})\n"

                if result_item:
                    # Check if redirected to third-party domain
                    response = _CACHE.get((result_item['url'], "GET", True))
                    if response and response.history:
                        final_url = response.url
                        if _is_third_party_domain(final_url, base_domain):
                            metrics.record_skipped(final_url, reason="third_party")
                            skipped_third_party += 1
                            continue

                    found.append(result_item)
                    metrics.record_discovery()
                    timeout_streak = 0
                else:
                    timeout_streak += 1
                    # Early exit on repeated timeouts
                    if timeout_streak >= _EARLY_EXIT_THRESHOLD:
                        result += f"\n[WARNING] Repeated timeouts detected, stopping further checks\n"
                        break

            except Exception:
                timeout_streak += 1
                if timeout_streak >= _EARLY_EXIT_THRESHOLD:
                    break

    elapsed = metrics.get_elapsed()
    summary = metrics.get_summary()

    result += f"\n[SUMMARY] {len(found)} accessible common path(s) identified\n"
    result += f"[METRICS]\n"
    result += f"  - Elapsed time: {elapsed:.2f}s\n"
    result += f"  - Paths checked: {checked_count}/{total_paths}\n"
    result += f"  - Requests made: {summary['requests_made']}\n"
    result += f"  - Requests skipped: {summary['requests_skipped']}\n"
    if skipped_static > 0:
        result += f"  - Skipped (static assets): {skipped_static}\n"
    if skipped_third_party > 0:
        result += f"  - Skipped (third-party): {skipped_third_party}\n"
    if summary['skipped_breakdown']:
        result += f"  - Skip reasons: {', '.join([f'{k}({v})' for k,v in summary['skipped_breakdown'].items()])}\n"
    result += f"  - Discoveries: {summary['discoveries']}\n"

    if found:
        result += "[SEVERITY] INFO - Accessible paths reveal application surface and information disclosure risk\n"
    else:
        result += "[INFO] No accessible common paths discovered from the candidate list\n"

    return result


def enumerate_forms(html, url):
    """Enumerate and analyze forms in the page"""
    result = "\n========== FORM ENUMERATION ==========\n"
    
    if not html:
        result += "[ERROR] No HTML content provided\n"
        return result
    
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    
    result += f"[INFO] Found {len(forms)} form(s)\n\n"
    
    if not forms:
        result += "[NO FORMS] No forms detected on this page\n"
        return result
    
    for idx, form in enumerate(forms, 1):
        result += f"[FORM {idx}]\n"
        
        action = form.get('action', 'Not specified')
        if action and not action.startswith('http'):
            action = urljoin(url, action)
        result += f" - Action: {action}\n"
        
        method = form.get('method', 'GET').upper()
        result += f" - Method: {method}\n"
        
        enctype = form.get('enctype', 'application/x-www-form-urlencoded')
        result += f" - Encoding: {enctype}\n"
        
        inputs = form.find_all('input')
        result += f" - Inputs: {len(inputs)}\n"
        
        for inp in inputs:
            inp_type = inp.get('type', 'text')
            inp_name = inp.get('name', 'unnamed')
            inp_value = inp.get('value', '')
            result += f"    * {inp_name} ({inp_type}) = {inp_value[:30]}\n"
        
        selects = form.find_all('select')
        if selects:
            result += f" - Dropdowns: {len(selects)}\n"
            for select in selects:
                select_name = select.get('name', 'unnamed')
                options = select.find_all('option')
                result += f"    * {select_name}: {len(options)} options\n"
        
        textareas = form.find_all('textarea')
        if textareas:
            result += f" - Text Areas: {len(textareas)}\n"
        
        result += "\n"
    
    result += "[SEVERITY] INFO - Forms are primary entry points for injection attacks\n"
    
    return result


def extract_parameters(html, url):
    """Extract URL parameters and form parameters"""
    result = "\n========== PARAMETER EXTRACTION ==========\n"
    
    result += "[INFO] Analyzing parameters in URLs and forms\n\n"
    
    # Extract from URL
    parsed = urlparse(url)
    result += f"[URL PARAMETERS]\n"
    if parsed.query:
        params = parsed.query.split('&')
        for param in params:
            result += f" - {param}\n"
    else:
        result += " - No query parameters in URL\n"
    
    result += "\n"
    
    # Extract from HTML
    if not html:
        result += "[FORM PARAMETERS] No HTML content\n"
        return result
    
    soup = BeautifulSoup(html, 'html.parser')
    
    # Find all input fields
    inputs = soup.find_all('input')
    result += f"[FORM INPUTS] Found {len(inputs)} input field(s)\n"
    
    param_types = {}
    for inp in inputs:
        param_name = inp.get('name')
        param_type = inp.get('type', 'text')
        if param_name:
            if param_type not in param_types:
                param_types[param_type] = []
            param_types[param_type].append(param_name)
    
    for p_type, names in param_types.items():
        result += f"\n [{p_type}]\n"
        for name in names:
            result += f"  - {name}\n"
    
    result += "\n[SEVERITY] INFO - Parameters are attack surface for injection/XSS\n"
    
    return result


def analyze_http_headers(headers):
    """Analyze HTTP response headers for security and tech info"""
    result = "\n========== HTTP HEADERS ANALYSIS ==========\n"
    
    if not headers:
        result += "[ERROR] No headers provided\n"
        return result
    
    result += f"[INFO] Analyzed {len(headers)} header(s)\n\n"
    
    # Security headers
    result += "[SECURITY HEADERS]\n"
    security_header_names = [
        'content-security-policy',
        'strict-transport-security',
        'x-content-type-options',
        'x-frame-options',
        'x-xss-protection',
        'referrer-policy',
        'permissions-policy'
    ]
    
    missing_security = []
    for header_name in security_header_names:
        if header_name in headers:
            value = headers[header_name]
            result += f" ✓ {header_name}: {value[:60]}\n"
        else:
            missing_security.append(header_name)
    
    if missing_security:
        result += f"\n[MISSING SECURITY HEADERS]\n"
        for header in missing_security:
            result += f" ✗ {header}\n"
    
    # Technology fingerprinting
    result += f"\n[TECHNOLOGY FINGERPRINTING]\n"
    tech_headers = {
        'server': 'Web Server',
        'x-powered-by': 'Framework',
        'x-aspnet-version': 'ASP.NET Version',
        'x-runtime-version': 'Runtime',
        'content-type': 'Content Type'
    }
    
    for header_key, description in tech_headers.items():
        if header_key in headers:
            result += f" - {description}: {headers[header_key]}\n"
    
    # Technology fingerprinting is informational in most cases
    result += "\n[SEVERITY] INFO - Headers reveal technology stack\n"
    
    return result


def identify_technologies(html, headers):
    """Identify technologies used by the application"""
    result = "\n========== TECHNOLOGY IDENTIFICATION ==========\n"
    
    technologies = {
        'Frontend': {},
        'Backend': {},
        'Infrastructure': {}
    }
    
    # From headers
    if headers:
        if 'server' in headers:
            server = headers['server']
            technologies['Infrastructure']['Web Server'] = server
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by']
            technologies['Backend']['Framework'] = powered_by
    
    # From HTML
    if html:
        soup = BeautifulSoup(html, 'html.parser')
        
        # Check for framework patterns
        tech_patterns = {
            'React': [r'react', r'__REACT_', r'_react'],
            'Vue': [r'vue', r'__vue__', r'v-app'],
            'Angular': [r'angular', r'ng-app', r'ng-controller'],
            'jQuery': [r'jquery', r'\$\.ajax', r'jQuery'],
            'Bootstrap': [r'bootstrap', r'col-md-', r'container-fluid'],
            'Tailwind': [r'tailwind', r'tw-', r'@apply'],
            'PHP': [r'\.php', r'php\?', r'laravel', r'wordpress'],
            'Python': [r'django', r'flask', r'fastapi', r'aiohttp'],
            'Node.js': [r'express', r'next\.js', r'nuxt'],
            'Java': [r'spring', r'tomcat', r'\.jsp'],
            '.NET': [r'aspx', r'asp\.net', r'mvc'],
        }
        
        html_lower = html.lower()
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_lower):
                    category = 'Frontend' if tech in ['React', 'Vue', 'Angular', 'jQuery', 'Bootstrap', 'Tailwind'] else 'Backend'
                    technologies[category][tech] = 'Detected'
                    break
    
    # Display results
    for category, techs in technologies.items():
        if techs:
            result += f"\n[{category.upper()}]\n"
            for tech, info in techs.items():
                result += f" - {tech}: {info}\n"
    
    if not any(technologies.values()):
        result += "[No specific technologies identified]\n"
    
    # Identifying technologies is primarily informational; downgrade
    # to MEDIUM/INFO so it doesn't drive critical security score.
    result += "\n[SEVERITY] INFO - Technology stack detected\n"
    
    return result


# ===== PHASE 3: EXECUTION PATHS, ARCHITECTURE MAPPER, FRAMEWORK ENHANCEMENT =====

def trace_execution_paths(html, url):
    """Trace application execution paths and data flow"""
    result = "\n========== EXECUTION PATHS ANALYSIS ==========\n"
    
    if not html:
        result += "[ERROR] No HTML content to analyze\n"
        return result
    
    soup = BeautifulSoup(html, 'html.parser')
    
    # Find entry points
    result += "[ENTRY POINTS]\n"
    
    # Forms as entry points
    forms = soup.find_all('form')
    if forms:
        result += f" - {len(forms)} form(s) detected\n"
        for idx, form in enumerate(forms, 1):
            action = form.get('action', 'Not specified')
            method = form.get('method', 'GET').upper()
            result += f"   * Form {idx}: {method} → {action}\n"
    
    # Links as entry points
    links = soup.find_all('a', href=True)
    internal_links = [link['href'] for link in links if not link['href'].startswith('http') and link['href'].startswith('/')]
    if internal_links:
        result += f" - {len(internal_links)} internal links\n"
        for link in internal_links[:5]:
            result += f"   * {link}\n"
        if len(internal_links) > 5:
            result += f"   ... and {len(internal_links) - 5} more\n"
    
    # API endpoints
    result += "\n[API ENDPOINTS]\n"
    api_patterns = {
        'REST': [r'/api/', r'/api/v[0-9]/', r'/rest/'],
        'GraphQL': [r'/graphql', r'/gql'],
        'RPC': [r'/rpc', r'/xmlrpc']
    }
    
    found_apis = False
    for api_type, patterns in api_patterns.items():
        for pattern in patterns:
            if re.search(pattern, html):
                result += f" - {api_type} API detected in page\n"
                found_apis = True
                break
    
    if not found_apis:
        result += " - No API endpoints detected\n"
    
    # JavaScript event handlers (potential flow triggers)
    result += "\n[FLOW TRIGGERS]\n"
    scripts = soup.find_all('script')
    if scripts:
        result += f" - {len(scripts)} script(s) found\n"
        result += " - Possible flow triggers: onclick, onload, onchange, onsubmit\n"
    
    result += "\n[SEVERITY] INFO - Understanding execution paths prevents workflow bypasses\n"
    
    return result


def map_application_architecture(html, headers, url):
    """Map application architecture, microservices, and dependencies"""
    result = "\n========== ARCHITECTURE MAPPING ==========\n"
    
    result += "[INFRASTRUCTURE COMPONENTS]\n"
    
    # Web server detection from headers
    web_server = headers.get('server', 'Unknown') if headers else 'Unknown'
    result += f" - Web Server: {web_server}\n"
    
    # Detect proxy/CDN
    if headers:
        if 'x-forwarded-for' in headers or 'cf-ray' in headers:
            result += " - Load Balancer/Proxy: Detected\n"
        if 'cf-ray' in headers:
            result += " - CDN: Cloudflare\n"
        elif 'x-amzn-requestid' in headers:
            result += " - CDN/Infrastructure: AWS\n"
    
    # Database detection from error messages or HTML
    databases = {
        'MySQL': [r'mysql', r'mysqli'],
        'PostgreSQL': [r'postgresql', r'postgres'],
        'MongoDB': [r'mongodb', r'mongo'],
        'Oracle': [r'oracle database'],
        'SQL Server': [r'mssql', r'sql server'],
        'Redis': [r'redis'],
        'Elasticsearch': [r'elasticsearch']
    }
    
    result += "\n[POSSIBLE DATABASES]\n"
    found_db = False
    if html:
        html_lower = html.lower()
        for db_name, patterns in databases.items():
            for pattern in patterns:
                if re.search(pattern, html_lower):
                    result += f" - {db_name}\n"
                    found_db = True
                    break
    
    if not found_db:
        result += " - Database type not identifiable from page content\n"
    
    # Microservices detection
    result += "\n[MICROSERVICES INDICATORS]\n"
    microservice_indicators = {
        'API Gateway': [r'/api/gateway', r'/api/v[0-9]'],
        'Service Registry': [r'consul', r'eureka', r'zookeeper'],
        'Message Queue': [r'kafka', r'rabbitmq', r'amqp'],
        'Containerization': [r'docker', r'kubernetes', r'container']
    }
    
    found_ms = False
    if html:
        html_lower = html.lower()
        for service, patterns in microservice_indicators.items():
            for pattern in patterns:
                if re.search(pattern, html_lower):
                    result += f" - {service}: Detected\n"
                    found_ms = True
                    break
    
    if not found_ms:
        result += " - No microservices patterns detected\n"
    
    # External dependencies
    result += "\n[EXTERNAL DEPENDENCIES]\n"
    result += " - Check for: CDNs, APIs, third-party services\n"
    result += " - Monitor for: Dependency vulnerabilities, version mismatches\n"
    
    result += "\n[SEVERITY] INFO - Architecture flaws can enable privilege escalation\n"
    
    return result


def analyze_framework_vulnerabilities(html, headers, url):
    """Analyze framework-specific vulnerabilities and version mismatches"""
    result = "\n========== FRAMEWORK ENHANCEMENT & VULNERABILITIES ==========\n"
    
    # Framework detection with known vulnerability patterns
    frameworks = {
        'Django': {
            'patterns': [r'django', r'/admin/', r'csrf_token'],
            'vulns': ['SQL Injection', 'CSRF', 'XXE', 'Template Injection'],
            'headers': ['X-Django-Version']
        },
        'Flask': {
            'patterns': [r'flask', r'werkzeug', r'jinja2'],
            'vulns': ['Debug Mode Enabled', 'Pickle Deserialization', 'JINJA2 SSTI'],
            'headers': ['Server']
        },
        'Spring Boot': {
            'patterns': [r'spring', r'/actuator', r'spring-boot'],
            'vulns': ['Actuator Exposure', 'Deserialization', 'RCE'],
            'headers': ['X-Application-Context']
        },
        'Laravel': {
            'patterns': [r'laravel', r'/app/', r'LARAVEL_'],
            'vulns': ['Mass Assignment', 'Route Parameter Injection', 'File Inclusion'],
            'headers': ['X-Laravel-Version']
        },
        'ASP.NET': {
            'patterns': [r'asp\.net', r'aspx', r'web\.config'],
            'vulns': ['XML External Entity', 'Deserialization', 'Path Traversal'],
            'headers': ['Server', 'X-AspNet-Version']
        },
        'Express.js': {
            'patterns': [r'express', r'node\.js', r'npm'],
            'vulns': ['NoSQL Injection', 'Prototype Pollution', 'SSRF'],
            'headers': ['X-Powered-By']
        },
        'Ruby on Rails': {
            'patterns': [r'rails', r'ruby', r'rack'],
            'vulns': ['YAML Deserialization', 'SQLi', 'Mass Assignment'],
            'headers': ['X-Runtime']
        }
    }
    
    html_lower = html.lower() if html else ""
    headers_str = str(headers).lower() if headers else ""
    
    detected_frameworks = []
    result += "[DETECTED FRAMEWORKS]\n"
    
    for framework, info in frameworks.items():
        for pattern in info['patterns']:
            if re.search(pattern, html_lower) or re.search(pattern, headers_str):
                detected_frameworks.append(framework)
                result += f" - {framework}\n"
                break
    
    if not detected_frameworks:
        result += " - Framework not identifiable\n"
    
    # Version detection
    result += "\n[VERSION DETECTION]\n"
    version_headers = {
        'Server': 'Web Server',
        'X-Powered-By': 'Framework/Runtime',
        'X-AspNet-Version': 'ASP.NET Version',
        'X-Runtime': 'Runtime Version',
    }
    
    if headers:
        for header_key, description in version_headers.items():
            if header_key in headers:
                result += f" - {description}: {headers[header_key]}\n"
    
    result += " - Note: Use Wappalyzer for more detailed version detection\n"
    
    # Framework-specific vulnerabilities
    result += "\n[FRAMEWORK-SPECIFIC VULNERABILITIES]\n"
    
    for framework in detected_frameworks:
        if framework in frameworks:
            result += f"\n {framework} - Known Issues:\n"
            for vuln in frameworks[framework]['vulns']:
                result += f"  * {vuln}\n"
    
    if not detected_frameworks:
        result += " Generic framework vulnerabilities:\n"
        result += "  * Injection attacks (SQL, NoSQL, LDAP)\n"
        result += "  * Deserialization flaws\n"
        result += "  * Weak authentication/authorization\n"
        result += "  * Security misconfiguration\n"
        result += "  * Sensitive data exposure\n"
    
    # Mitigation recommendations
    result += "\n[REMEDIATION]\n"
    result += " 1. Keep framework and dependencies updated\n"
    result += " 2. Review framework security best practices\n"
    result += " 3. Disable debug/verbose error messages in production\n"
    result += " 4. Use Web Application Firewall (WAF) for framework-specific rules\n"
    result += " 5. Regular security audits and penetration testing\n"
    result += " 6. Implement framework-level security controls\n"
    
    result += "\n[SEVERITY] INFO - Framework vulnerabilities are frequently exploited\n"
    
    return result


def detect_api_contracts(html, url):
    """Detect and analyze API contracts and data models"""
    result = "\n========== API CONTRACT ANALYSIS ==========\n"
    
    if not html:
        result += "[ERROR] No HTML content\n"
        return result
    
    result += "[API DOCUMENTATION]\n"
    
    # Swagger/OpenAPI detection
    api_docs = {
        'Swagger/OpenAPI': [r'swagger', r'openapi', r'/swagger', r'/api-docs'],
        'RAML': [r'raml', r'/schemas', r'raml\.json'],
        'Blueprint': [r'blueprint', r'apib'],
        'Postman': [r'postman', r'/postman']
    }
    
    found_docs = False
    for doc_type, patterns in api_docs.items():
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                result += f" - {doc_type}: Found\n"
                result += f"   Check: /{doc_type.lower()}/index.html, /docs, /api-docs\n"
                found_docs = True
    
    if not found_docs:
        result += " - No API documentation detected\n"
    
    # Data model detection
    result += "\n[DATA MODELS]\n"
    result += " - Common endpoints for data discovery:\n"
    result += "   * /api/schema - Schema definition\n"
    result += "   * /api/models - Data models\n"
    result += "   * /graphql - GraphQL endpoint\n"
    result += "   * /.well-known/openapi.json\n"
    
    # Check for JSON-LD or other structured data
    if 'json-ld' in html.lower() or 'schema.org' in html.lower():
        result += "\n [STRUCTURED DATA]\n"
        result += " - JSON-LD or schema.org markup detected\n"
        result += " - May reveal data models and relationships\n"
    
    result += "\n[SEVERITY] INFO - API contracts reveal expected data flow\n"
    
    return result


def map_data_flows(html, url):
    """Map data flow and potential injection points"""
    result = "\n========== DATA FLOW ANALYSIS ==========\n"
    
    if not html:
        result += "[ERROR] No HTML content\n"
        return result
    
    soup = BeautifulSoup(html, 'html.parser')
    
    # Identify data sources
    result += "[DATA SOURCES]\n"
    
    # Input fields
    inputs = soup.find_all('input')
    if inputs:
        result += f" - {len(inputs)} input field(s) from HTML forms\n"
        input_types = {}
        for inp in inputs:
            inp_type = inp.get('type', 'text')
            input_types[inp_type] = input_types.get(inp_type, 0) + 1
        for itype, count in input_types.items():
            result += f"   * {itype}: {count}\n"
    
    # Script data attributes
    result += f" - Check data-* attributes for client-side data\n"
    
    # Query parameters
    parsed = urlparse(url)
    if parsed.query:
        result += f" - URL query parameters detected\n"
        params = parsed.query.split('&')
        result += f"   Parameters: {len(params)}\n"
    
    # Data destinations
    result += "\n[DATA DESTINATIONS]\n"
    
    # APIs
    if re.search(r'fetch\(|ajax\(|XMLHttpRequest', html):
        result += " - AJAX/Fetch requests to backends\n"
        result += "   Likely destinations: /api/*, /services/*, endpoints from network tab\n"
    
    # Cookies and storage
    result += " - Browser storage: localStorage, sessionStorage, IndexedDB\n"
    result += " - Cookies: Session, preferences, tracking\n"
    
    # Data transformation
    result += "\n[TRANSFORMATION POINTS]\n"
    result += " - Client-side: JavaScript, template engines\n"
    result += " - Server-side: Controllers, middlewares, ORM\n"
    result += " - Database: Stored procedures, triggers\n"
    
    # Injection vulnerability points
    result += "\n[INJECTION VULNERABILITY POINTS]\n"
    result += " 1. Input validation bypass (length, type, format)\n"
    result += " 2. Server-side template injection (SSTI)\n"
    result += " 3. SQL injection (parameterized queries bypass)\n"
    result += " 4. NoSQL injection (query operator injection)\n"
    result += " 5. Command injection (shell commands)\n"
    result += " 6. XML injection (XXE, XPath injection)\n"
    
    result += "\n[SEVERITY] INFO - Data flow analysis reveals injection attacks vectors\n"
    
    return result
