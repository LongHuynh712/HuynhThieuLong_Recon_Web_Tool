# Enhanced Enumeration Performance Optimization Module
# Provides concurrent, timeout-protected, early-exit scanning with metrics

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from urllib.parse import urlparse

import cloudscraper


# Performance Configuration
PERFORMANCE_CONFIG = {
    "request_timeout": 4.0,  # Reduced from 20-30s to 4s
    "max_concurrent_threads": 8,  # Parallel execution
    "max_path_samples": 15,  # Smart sampling for large targets
    "early_exit_threshold": 3,  # Exit after 3 consecutive timeouts
    "port_timeout": 2.0,  # Port scan timeout
}


class PerformanceMetrics:
    """Track performance metrics during enumeration"""
    
    def __init__(self):
        self.start_time = time.time()
        self.requests_performed = 0
        self.requests_skipped = 0
        self.request_cache = {}  # URL -> response cache
        self.timeout_count = 0
        self.early_exits = 0
        self.concurrent_requests = 0
        self.max_concurrent = 0
        
    def record_request(self, url, response, from_cache=False):
        """Record a request attempt"""
        if from_cache:
            self.requests_skipped += 1
        else:
            self.requests_performed += 1
            self.request_cache[url] = response
            
    def record_timeout(self):
        """Record a timeout"""
        self.timeout_count += 1
        
    def record_early_exit(self, reason):
        """Record an early exit"""
        self.early_exits += 1
        
    def start_concurrent(self):
        """Mark start of concurrent operation"""
        self.concurrent_requests += 1
        if self.concurrent_requests > self.max_concurrent:
            self.max_concurrent = self.concurrent_requests
            
    def end_concurrent(self):
        """Mark end of concurrent operation"""
        self.concurrent_requests -= 1
        
    def get_summary(self):
        """Get performance summary"""
        elapsed = time.time() - self.start_time
        return {
            "execution_time_seconds": round(elapsed, 2),
            "requests_performed": self.requests_performed,
            "requests_skipped": self.requests_skipped,
            "total_requests": self.requests_performed + self.requests_skipped,
            "timeout_count": self.timeout_count,
            "early_exits": self.early_exits,
            "max_concurrent_threads": self.max_concurrent,
            "efficiency": round((self.requests_skipped / max(1, self.requests_performed + self.requests_skipped)) * 100, 1),
        }


def _fetch_optimized(url, timeout=None, metrics=None):
    """
    Optimized fetch with:
    - Configurable timeout (default 4s)
    - Cache support
    - Early return on cache hit
    """
    timeout = timeout or PERFORMANCE_CONFIG["request_timeout"]
    
    # Check cache first
    if metrics and url in metrics.request_cache:
        metrics.record_request(url, metrics.request_cache[url], from_cache=True)
        return metrics.request_cache[url]
    
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
            method="GET",
            url=url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        
        if metrics:
            metrics.record_request(url, response)
        return response
        
    except socket.timeout:
        if metrics:
            metrics.record_timeout()
        return None
    except Exception:
        return None


def discover_virtual_hosts_optimized(domain, metrics=None):
    """
    Optimized virtual host discovery with:
    - Concurrent DNS lookups
    - Concurrent HTTP requests
    - Early exit on unreachable target
    - Timeout protection
    """
    if not metrics:
        metrics = PerformanceMetrics()
        
    result = "\n========== VIRTUAL HOSTS ENUMERATION (OPTIMIZED) ==========\n"
    result += "[INFO] Identifying virtual hosts and subdomains (concurrent scanning)\n\n"
    
    common_subdomains = [
        "www", "mail", "ftp", "webmail", "smtp", "pop", "ns", "cpanel",
        "whm", "autodiscover", "autoconfig", "m", "blog", "shop",
        "admin", "api", "cdn", "dev", "staging", "test", "prod",
        "backup", "old", "new", "git", "svn", "vpn", "portal",
    ]
    
    discovered = []
    timeout_streak = 0
    
    # Concurrent DNS + HTTP requests
    with ThreadPoolExecutor(max_workers=PERFORMANCE_CONFIG["max_concurrent_threads"]) as executor:
        futures = {}
        
        for subdomain in common_subdomains:
            host = f"{subdomain}.{domain}"
            
            def check_host(h):
                """Check if host is reachable"""
                try:
                    ip = socket.gethostbyname(h)
                except Exception:
                    return {"host": h, "ip": None, "status": None}
                
                # Try HTTPS first, then HTTP
                for proto in ["https", "http"]:
                    response = _fetch_optimized(f"{proto}://{h}", metrics=metrics)
                    if response:
                        return {"host": h, "ip": ip, "status": response.status_code}
                
                return {"host": h, "ip": ip, "status": None}
            
            futures[executor.submit(check_host, host)] = host
        
        for future in as_completed(futures):
            try:
                result_item = future.result()
                if result_item["status"]:
                    discovered.append(result_item)
                    timeout_streak = 0
                else:
                    timeout_streak += 1
                    
                # Early exit if too many timeouts
                if timeout_streak >= PERFORMANCE_CONFIG["early_exit_threshold"]:
                    metrics.record_early_exit("Too many consecutive timeouts on virtual host checks")
                    break
                    
            except Exception:
                timeout_streak += 1
                if timeout_streak >= PERFORMANCE_CONFIG["early_exit_threshold"]:
                    metrics.record_early_exit("Too many consecutive errors on virtual host checks")
                    break
    
    if discovered:
        result += f"[FOUND] {len(discovered)} responsive virtual host(s)\n"
        for item in sorted(discovered, key=lambda x: x["host"]):
            result += f" - {item['host']} ({item['ip']})"
            if item['status']:
                result += f" status={item['status']}"
            result += "\n"
    else:
        result += "[INFO] No common virtual hosts resolved\n"
    
    result += f"\n[METRICS] Performed {metrics.requests_performed} requests, skipped {metrics.requests_skipped} (cache hits)\n"
    result += "[RECOMMENDATION]\n"
    result += f" 1. Use dnsrecon/amass for deeper virtual host enumeration on {domain}\n"
    result += f" 2. Check DNS records and subdomain brute force results\n"
    result += f" 3. Review CDN/WAF hostnames for aliasing and alternate domains\n\n"
    result += "[SEVERITY] MEDIUM - Virtual hosts may expose additional attack surfaces\n"
    
    return result, metrics


def scan_common_admin_paths_optimized(url, metrics=None):
    """
    Optimized admin paths scanning with:
    - Concurrent requests
    - Early exit on WAF detection
    - Smart path sampling
    - Timeout protection
    """
    if not metrics:
        metrics = PerformanceMetrics()
        
    result = "\n========== ADMIN PATHS DISCOVERY (OPTIMIZED) ==========\n"
    result += "[INFO] Identifying common administrative endpoints (concurrent scanning)\n\n"
    
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
    
    # Flatten paths and apply smart sampling if needed
    all_paths = []
    for paths in admin_paths.values():
        all_paths.extend(paths)
    
    # Use sampling for large targets to avoid brute-forcing
    if len(all_paths) > PERFORMANCE_CONFIG["max_path_samples"]:
        # Keep important paths, sample others
        important = [p for p in all_paths if any(x in p for x in ["admin", "api", "git", "env", "swagger"])]
        sampled = [p for p in all_paths if p not in important]
        all_paths = important + sampled[:PERFORMANCE_CONFIG["max_path_samples"] - len(important)]
    
    found = []
    timeout_streak = 0
    
    # Concurrent path requests
    with ThreadPoolExecutor(max_workers=PERFORMANCE_CONFIG["max_concurrent_threads"]) as executor:
        futures = {}
        
        for path in all_paths:
            target_url = url.rstrip("/") + path
            futures[executor.submit(_fetch_optimized, target_url, metrics=metrics)] = path
        
        for future in as_completed(futures):
            path = futures[future]
            try:
                response = future.result()
                status = response.status_code if response else None
                
                if response and status not in (404, 502, 503, 504):
                    result += f" - {path} [accessible status={status}]\n"
                    found.append({"path": path, "status": status})
                    timeout_streak = 0
                elif response is None:
                    timeout_streak += 1
                    # Early exit on WAF blocking (too many timeouts)
                    if timeout_streak >= PERFORMANCE_CONFIG["early_exit_threshold"]:
                        metrics.record_early_exit("Possible WAF blocking detected on admin paths")
                        result += f"\n[WARNING] Possible WAF/rate-limiting detected, stopping further admin path checks\n"
                        break
                        
            except Exception:
                pass
    
    result += f"\n[SUMMARY] {len(found)} accessible admin/sensitive path(s) identified\n"
    result += f"[METRICS] Performed {metrics.requests_performed} requests, skipped {metrics.requests_skipped} (cache hits)\n\n"
    
    if found:
        result += "[SEVERITY] MEDIUM - Accessible admin paths discovered\n"
    else:
        result += "[INFO] No accessible admin paths discovered from common list\n"
    
    return result, metrics


def discover_alternate_ports_optimized(domain, metrics=None):
    """
    Optimized port discovery with:
    - Concurrent port scanning
    - Timeout protection (2s per scan)
    - Early exit on unreachable target
    - Smart port selection
    """
    if not metrics:
        metrics = PerformanceMetrics()
        
    result = "\n========== ALTERNATE PORTS DISCOVERY (OPTIMIZED) ==========\n"
    result += "[INFO] Scanning common alternate ports for reachable services (concurrent scanning)\n\n"
    
    port_categories = {
        "HTTP/HTTPS": [80, 443, 8080, 8443, 8888, 9000, 9001],
        "Developer Services": [3000, 5000, 8000, 8001],
        "Admin/Management": [8008, 8009, 8010, 9200, 9300],
        "Datastores": [3306, 5432, 6379, 27017]
    }
    
    discovered = []
    timeout_streak = 0
    
    # Concurrent port scanning
    with ThreadPoolExecutor(max_workers=PERFORMANCE_CONFIG["max_concurrent_threads"]) as executor:
        futures = {}
        
        for category, ports in port_categories.items():
            for port in ports:
                def scan_port(p, cat):
                    """Scan a single port"""
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(PERFORMANCE_CONFIG["port_timeout"])
                    try:
                        if sock.connect_ex((domain, p)) == 0:
                            response = None
                            if p in (80, 8080, 8888, 3000, 5000, 8000, 8001, 9000, 9001):
                                response = _fetch_optimized(f"http://{domain}:{p}", metrics=metrics)
                            elif p in (443, 8443):
                                response = _fetch_optimized(f"https://{domain}:{p}", metrics=metrics)
                            
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
                if result_item:
                    discovered.append(result_item)
                    timeout_streak = 0
                else:
                    timeout_streak += 1
                    
                # Early exit if target appears unreachable
                if timeout_streak >= PERFORMANCE_CONFIG["early_exit_threshold"]:
                    metrics.record_early_exit("Target appears unreachable (too many port scan timeouts)")
                    break
                    
            except Exception:
                timeout_streak += 1
                if timeout_streak >= PERFORMANCE_CONFIG["early_exit_threshold"]:
                    metrics.record_early_exit("Too many port scan errors")
                    break
    
    if discovered:
        result += f"[FOUND] {len(discovered)} open port(s) on {domain}\n"
        for item in sorted(discovered, key=lambda x: x["port"]):
            result += f" - {item['port']}/tcp ({item['category']}) status={item['status']}\n"
        result += "\n[SEVERITY] MEDIUM - Open alternate ports may expose additional services\n"
    else:
        result += "[INFO] No common alternate ports appear reachable\n"
        result += "[RECOMMENDATION]\n"
        result += f" 1. Use nmap -p- {domain} for full port enumeration\n"
        result += f" 2. Use masscan -p1-65535 {domain} for fast coverage\n"
    
    result += f"\n[METRICS] Scanned {metrics.requests_performed} ports, skipped {metrics.requests_skipped} (cache hits)\n"
    
    return result, metrics


def find_common_paths_optimized(domain, metrics=None):
    """
    Optimized common paths discovery with:
    - Concurrent requests
    - Request deduplication (single check for http/https)
    - Smart path sampling
    - Early exit on unreachable target
    """
    if not metrics:
        metrics = PerformanceMetrics()
        
    result = "\n========== COMMON PATHS DISCOVERY (OPTIMIZED) ==========\n"
    result += "[INFO] Probing common directory and file paths (concurrent scanning)\n\n"
    
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
    
    # Use sampling for large targets
    if len(all_paths) > PERFORMANCE_CONFIG["max_path_samples"]:
        important = [p for p in all_paths if any(x in p for x in ["api", "docs", "git", "admin", "config"])]
        sampled = [p for p in all_paths if p not in important]
        all_paths = important + sampled[:PERFORMANCE_CONFIG["max_path_samples"] - len(important)]
    
    found = []
    timeout_streak = 0
    
    # Try HTTPS first, then HTTP (single check per path, not double)
    base_urls = [f"https://{domain}", f"http://{domain}"]
    
    # Concurrent path requests
    with ThreadPoolExecutor(max_workers=PERFORMANCE_CONFIG["max_concurrent_threads"]) as executor:
        futures = {}
        
        for path in all_paths:
            def check_path(p):
                """Check a path (try HTTPS first, then HTTP)"""
                for base in base_urls:
                    target = base.rstrip("/") + p
                    response = _fetch_optimized(target, metrics=metrics)
                    if response and response.status_code not in (404, 502, 503, 504):
                        return {"path": p, "url": target, "status": response.status_code}
                return None
            
            futures[executor.submit(check_path, path)] = path
        
        for future in as_completed(futures):
            path = futures[future]
            try:
                result_item = future.result()
                if result_item:
                    result += f" - {result_item['path']} [status={result_item['status']}]\n"
                    found.append(result_item)
                    timeout_streak = 0
                else:
                    timeout_streak += 1
                    
                # Early exit on repeated timeouts
                if timeout_streak >= PERFORMANCE_CONFIG["early_exit_threshold"]:
                    metrics.record_early_exit("Repeated timeouts on path checks")
                    result += f"\n[WARNING] Repeated timeouts detected, stopping further path checks\n"
                    break
                    
            except Exception:
                timeout_streak += 1
                if timeout_streak >= PERFORMANCE_CONFIG["early_exit_threshold"]:
                    metrics.record_early_exit("Too many path check errors")
                    break
    
    result += f"\n[SUMMARY] {len(found)} accessible common path(s) identified\n"
    result += f"[METRICS] Performed {metrics.requests_performed} requests, skipped {metrics.requests_skipped} (cache hits)\n\n"
    
    if found:
        result += "[SEVERITY] MEDIUM - Accessible paths reveal application surface and information disclosure risk\n"
    else:
        result += "[INFO] No accessible common paths discovered from the candidate list\n"
    
    return result, metrics
