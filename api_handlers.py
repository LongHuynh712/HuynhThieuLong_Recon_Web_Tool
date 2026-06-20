"""JSON API handlers — Web Check compatible endpoints."""

from __future__ import annotations

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from scanner import (
    safe_request,
    get_whois_info,
    get_dns_records,
    get_registered_domain,
    check_robots,
    crawl_links,
    fingerprint_target,
    check_network_info,
)
from webcheck_checks import (
    trace_redirects,
    check_social_tags,
    check_security_txt,
    detect_firewall,
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
from browser_service import browser_screenshot, browser_cookies, browser_scan

API_TIMEOUT = 40


def normalize_url(url):
    if not url or not str(url).strip():
        raise ValueError("Query parameter `url` is required")
    raw = str(url).strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def _fetch(url):
    response = safe_request(url)
    if not response:
        raise ConnectionError(f"Cannot connect to {url}")
    return response


def _parse_http_security(response):
    headers = {k.lower(): v for k, v in response.headers.items()}
    mapping = {
        "content-security-policy": "contentSecurityPolicy",
        "strict-transport-security": "strictTransportPolicy",
        "x-content-type-options": "xContentTypeOptions",
        "x-frame-options": "xFrameOptions",
        "x-xss-protection": "xXSSProtection",
        "referrer-policy": "referrerPolicy",
        "permissions-policy": "permissionsPolicy",
        "cross-origin-opener-policy": "crossOriginOpenerPolicy",
        "cross-origin-resource-policy": "crossOriginResourcePolicy",
        "cross-origin-embedder-policy": "crossOriginEmbedderPolicy",
    }
    return {key: h in headers for h, key in mapping.items()}


def api_get_ip(url):
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid hostname")
    try:
        ip = socket.gethostbyname(hostname)
        return {"ip": ip, "hostname": hostname}
    except Exception as exc:
        return {"error": str(exc)}


def api_headers(url):
    response = _fetch(url)
    return dict(response.headers)


def api_http_security(url):
    response = _fetch(url)
    return _parse_http_security(response)


def api_hsts(url):
    response = _fetch(url)
    hsts = response.headers.get("Strict-Transport-Security")
    if not hsts:
        return {"present": False, "value": None}
    result = {"present": True, "value": hsts}
    lower = hsts.lower()
    result["includeSubDomains"] = "includesubdomains" in lower
    result["preload"] = "preload" in lower
    max_age = re.search(r"max-age=(\d+)", hsts, re.I)
    if max_age:
        result["maxAge"] = int(max_age.group(1))
    return result


def api_ssl(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {"skipped": "Site is not HTTPS"}
    hostname = parsed.hostname
    port = parsed.port or 443
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            return {
                "valid": True,
                "tlsVersion": ssock.version(),
                "cipher": ssock.cipher(),
                "subject": dict(x[0] for x in cert.get("subject", ())),
                "issuer": dict(x[0] for x in cert.get("issuer", ())),
                "notAfter": cert.get("notAfter"),
                "notBefore": cert.get("notBefore"),
                "subjectAltName": cert.get("subjectAltName"),
            }


def api_network(url):
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid hostname")
    try:
        ip = socket.gethostbyname(hostname)
        report = check_network_info(ip)
        return {"hostname": hostname, "ip": ip, "report": report.strip()}
    except Exception as exc:
        return {"error": str(exc)}


def api_csp(url):
    response = _fetch(url)
    return {"report": check_csp_policy(response).strip()}


def api_assets(url):
    response = _fetch(url)
    return {"report": discover_assets(response.text, url)}


def api_tls_connection(url):
    text = check_tls_connection(url)
    return {"report": text.strip(), "parsed": _lines_to_dict(text)}


def api_dns(url):
    parsed = urlparse(url)
    domain = parsed.hostname
    base = get_registered_domain(domain)
    combined = get_dns_records(domain, ["A", "AAAA"])
    if base and base != domain:
        combined += get_dns_records(base, ["MX", "NS", "TXT", "CNAME"])
    return {"hostname": domain, "records": combined}


def api_whois(url):
    parsed = urlparse(url)
    domain = get_registered_domain(parsed.hostname)
    text = get_whois_info(domain)
    return {"domain": domain, "whois": text}


def api_txt_records(url):
    parsed = urlparse(url)
    domain = get_registered_domain(parsed.hostname)
    text = check_txt_records(domain)
    return {"domain": domain, "records": text}


def api_mail_config(url):
    parsed = urlparse(url)
    domain = parsed.hostname
    base = get_registered_domain(domain)
    text = check_mail_config(domain, base)
    return {"report": text.strip()}


def api_redirects(url):
    text = trace_redirects(url)
    hops = re.findall(r"^\s*\d+\.\s*(.+)$", text, re.M)
    return {"redirects": hops}


def api_social_tags(url):
    response = _fetch(url)
    text = check_social_tags(response.text)
    return {"tags": _lines_to_dict(text), "report": text.strip()}


def api_security_txt(url):
    text = check_security_txt(url)
    present = "[FOUND] security.txt" in text
    return {"isPresent": present, "report": text.strip()}


def api_firewall(url):
    response = _fetch(url)
    text = detect_firewall(response)
    waf_match = re.search(r"WAF/CDN detected:\s*(.+)", text)
    return {"hasWaf": bool(waf_match), "waf": waf_match.group(1).strip() if waf_match else None}


def api_status(url):
    response = _fetch(url)
    return {
        "isUp": 200 <= response.status_code < 400,
        "responseCode": response.status_code,
        "responseTime": response.elapsed.total_seconds() * 1000 if response.elapsed else None,
    }


def api_robots_txt(url):
    result = check_robots(url)
    if isinstance(result, tuple):
        text, sitemaps = result
    else:
        text, sitemaps = result, []
    return {"robots": text.strip(), "sitemaps": sitemaps or []}


def api_linked_pages(url):
    response = _fetch(url)
    links_result, _, links = crawl_links(url, response.text)
    base_host = urlparse(url).netloc.lower()
    internal_count = sum(1 for link in links if base_host in urlparse(link).netloc.lower())
    external_count = max(0, len(links) - internal_count)
    return {
        "internal": internal_count,
        "external": external_count,
        "total": len(links),
        "report": links_result.strip(),
    }


def api_cookies(url):
    response = _fetch(url)
    header_cookies = response.headers.get("Set-Cookie")
    header_list = []
    if header_cookies:
        header_list = re.split(r", (?=[A-Za-z_][A-Za-z0-9_-]*=)", header_cookies)

    browser_data = browser_cookies(url)
    if browser_data.get("error"):
        browser_data = browser_scan(url)

    return {
        "headerCookies": header_list,
        "clientCookies": browser_data.get("clientCookies") or browser_data.get("cookies") or [],
        "skipped": browser_data.get("skipped"),
        "hint": browser_data.get("hint"),
    }


def api_screenshot(url):
    data = browser_screenshot(url)
    if data.get("skipped"):
        return {"skipped": data["skipped"], "hint": data.get("hint")}
    if data.get("error"):
        return {"error": data["error"]}
    image = data.get("image") or data.get("screenshot")
    return {"image": image, "width": data.get("width"), "height": data.get("height")}


def api_tech_stack(url):
    response = _fetch(url)
    fp_text = fingerprint_target(response)
    browser_data = browser_scan(url)
    return {
        "fingerprint": fp_text.strip(),
        "generators": browser_data.get("generators") or [],
        "scriptSources": browser_data.get("scriptSources") or [],
        "browserTitle": browser_data.get("title"),
    }


def api_fingerprint(url):
    response = _fetch(url)
    return {"report": fingerprint_target(response).strip()}


def _lines_to_dict(text):
    out = {}
    for line in text.splitlines():
        m = re.match(r"\[FOUND\]\s*([^:]+):\s*(.+)", line)
        if m:
            out[m.group(1).strip()] = m.group(2).strip()
    return out


# Registry — endpoint name → handler (matches web-check /api/<name>)
def api_fingerprint(url):
    response = _fetch(url)
    result = fingerprint_target(response)
    return {"fingerprint": result.strip()}


def api_content_leakage(url):
    response = _fetch(url)
    html = response.text
    emails = extract_emails(html, url)
    phones = extract_phone_numbers(html)
    api_keys = detect_api_keys(html)
    secrets = detect_secrets(html)
    comments = analyze_comments(html)
    
    return {
        "emails": emails.strip(),
        "phones": phones.strip(),
        "api_keys": api_keys.strip(),
        "secrets": secrets.strip(),
        "comments": comments.strip(),
        "report": f"{emails}\n{phones}\n{api_keys}\n{secrets}\n{comments}".strip()
    }


def api_search_engine_recon(url):
    parsed = urlparse(url)
    domain = parsed.hostname or parsed.netloc
    
    if not domain:
        raise ValueError("Invalid domain")
    
    dorks = generate_google_dorks(domain)
    exposure = analyze_search_engine_exposure(domain)
    cached = find_cached_pages(domain)
    documents = discover_exposed_documents(domain)
    repos = find_public_repositories(domain)
    pastes = find_paste_references(domain)
    
    return {
        "domain": domain,
        "dorks": dorks.strip(),
        "exposure": exposure.strip(),
        "cached_pages": cached.strip(),
        "documents": documents.strip(),
        "repositories": repos.strip(),
        "pastes": pastes.strip(),
        "report": f"{dorks}\n{exposure}\n{cached}\n{documents}\n{repos}\n{pastes}".strip()
    }


def api_enhanced_enumeration(url):
    """Enumerate virtual hosts, admin paths, ports, and common paths"""
    parsed = urlparse(url)
    domain = parsed.hostname or parsed.netloc
    
    if not domain:
        raise ValueError("Invalid domain")
    
    vhosts = discover_virtual_hosts(domain)
    admin_paths = scan_common_admin_paths(url)
    ports = discover_alternate_ports(domain)
    paths = find_common_paths(domain)
    
    return {
        "domain": domain,
        "virtual_hosts": vhosts.strip(),
        "admin_paths": admin_paths.strip(),
        "alternate_ports": ports.strip(),
        "common_paths": paths.strip(),
        "report": f"{vhosts}\n{admin_paths}\n{ports}\n{paths}".strip()
    }


def api_entry_point_mapper(url):
    """Map forms, parameters, headers, and technology stack"""
    try:
        response = safe_request(url)
        if not response:
            raise ConnectionError("Failed to fetch URL")
        
        forms = enumerate_forms(response.text, url)
        params = extract_parameters(response.text, url)
        headers = analyze_http_headers(response.headers)
        tech = identify_technologies(response.text, response.headers)
        
        return {
            "url": url,
            "forms": forms.strip(),
            "parameters": params.strip(),
            "http_headers": headers.strip(),
            "technologies": tech.strip(),
            "report": f"{forms}\n{params}\n{headers}\n{tech}".strip()
        }
    except Exception as e:
        raise ValueError(f"Entry point mapping failed: {str(e)}")


def api_execution_paths(url):
    """Trace execution paths and data flow"""
    try:
        response = safe_request(url)
        if not response:
            raise ConnectionError("Failed to fetch URL")
        
        paths = trace_execution_paths(response.text, url)
        flows = map_data_flows(response.text, url)
        
        return {
            "url": url,
            "execution_paths": paths.strip(),
            "data_flows": flows.strip(),
            "report": f"{paths}\n{flows}".strip()
        }
    except Exception as e:
        raise ValueError(f"Execution paths analysis failed: {str(e)}")


def api_architecture_mapper(url):
    """Map application architecture and infrastructure"""
    try:
        response = safe_request(url)
        if not response:
            raise ConnectionError("Failed to fetch URL")
        
        architecture = map_application_architecture(response.text, response.headers, url)
        api_contracts = detect_api_contracts(response.text, url)
        
        return {
            "url": url,
            "architecture": architecture.strip(),
            "api_contracts": api_contracts.strip(),
            "report": f"{architecture}\n{api_contracts}".strip()
        }
    except Exception as e:
        raise ValueError(f"Architecture mapping failed: {str(e)}")


def api_framework_enhancement(url):
    """Analyze framework-specific vulnerabilities and versions"""
    try:
        response = safe_request(url)
        if not response:
            raise ConnectionError("Failed to fetch URL")
        
        framework_analysis = analyze_framework_vulnerabilities(response.text, response.headers, url)
        
        return {
            "url": url,
            "framework_analysis": framework_analysis.strip(),
            "report": framework_analysis.strip()
        }
    except Exception as e:
        raise ValueError(f"Framework analysis failed: {str(e)}")


API_REGISTRY = {
    "get-ip": api_get_ip,
    "headers": api_headers,
    "http-security": api_http_security,
    "hsts": api_hsts,
    "ssl": api_ssl,
    "tls-connection": api_tls_connection,
    "dns": api_dns,
    "whois": api_whois,
    "txt-records": api_txt_records,
    "mail-config": api_mail_config,
    "redirects": api_redirects,
    "social-tags": api_social_tags,
    "security-txt": api_security_txt,
    "firewall": api_firewall,
    "status": api_status,
    "robots-txt": api_robots_txt,
    "linked-pages": api_linked_pages,
    "network": api_network,
    "csp": api_csp,
    "assets": api_assets,
    "cookies": api_cookies,
    "screenshot": api_screenshot,
    "tech-stack": api_tech_stack,
    "fingerprint": api_fingerprint,
    "content-leakage": api_content_leakage,
    "search-engine-recon": api_search_engine_recon,
    "enhanced-enumeration": api_enhanced_enumeration,
    "entry-point-mapper": api_entry_point_mapper,
    "execution-paths": api_execution_paths,
    "architecture-mapper": api_architecture_mapper,
    "framework-enhancement": api_framework_enhancement,
}


def run_check(name, url):
    handler = API_REGISTRY.get(name)
    if not handler:
        return {"error": f"Unknown check: {name}"}
    try:
        return handler(url)
    except Exception as exc:
        return {"error": str(exc)}


def run_all_checks(url, max_workers=8):
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(run_check, name, url): name for name in API_REGISTRY}
        for future in as_completed(futures, timeout=API_TIMEOUT + 5):
            name = futures[future]
            try:
                results[name] = future.result(timeout=API_TIMEOUT)
            except Exception as exc:
                results[name] = {"error": str(exc)}
    return results


def api_documentation():
    return {
        "name": "Web Recon API",
        "version": "1.0",
        "description": "Web Check–compatible OSINT API (Flask + Puppeteer)",
        "usage": "GET /api/<check>?url=example.com",
        "bulk": "GET /api?url=example.com",
        "checks": sorted(API_REGISTRY.keys()),
        "puppeteer_checks": ["cookies", "screenshot", "tech-stack"],
        "example": "/api/screenshot?url=https://example.com",
    }
