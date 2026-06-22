# [WSTG-INFO-04] Bổ sung theo OWASP WSTG 4.1
"""Enumerate applications — DNS subdomain probe + TCP port scan."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from wstg_info._helpers import fetch_page, hostname_from_url, registered_domain_from_url

COMMON_SUBDOMAINS = (
    "www", "api", "dev", "staging", "stage", "test", "admin", "mail", "smtp",
    "portal", "cdn", "static", "app", "beta", "demo", "internal", "vpn",
)

COMMON_PORTS = (21, 22, 25, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017)


def _resolve_subdomain(fqdn: str) -> str | None:
    try:
        return socket.gethostbyname(fqdn)
    except OSError:
        return None


def _probe_subdomain(domain: str, prefix: str) -> dict | None:
    host = f"{prefix}.{domain}"
    ip = _resolve_subdomain(host)
    if not ip:
        return None
    https = fetch_page(f"https://{host}")
    http = fetch_page(f"http://{host}") if not https else None
    resp = https or http
    return {
        "host": host,
        "ip": ip,
        "scheme": "https" if https else ("http" if http else None),
        "status": resp.status_code if resp else None,
    }


def _scan_port(ip: str, port: int, timeout: float = 1.5) -> dict | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((ip, port)) == 0:
            return {"port": port, "state": "open"}
    except OSError:
        return None
    finally:
        sock.close()
    return None


def enumerate_applications(url: str) -> dict:
    domain = registered_domain_from_url(url)
    host = hostname_from_url(url)

    subdomains = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_probe_subdomain, domain, prefix) for prefix in COMMON_SUBDOMAINS]
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                subdomains.append(result)

    target_ip = _resolve_subdomain(host) or _resolve_subdomain(domain)
    open_ports = []
    if target_ip:
        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = [pool.submit(_scan_port, target_ip, port) for port in COMMON_PORTS]
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    open_ports.append(result)
    open_ports.sort(key=lambda x: x["port"])

    report = "\n========== WSTG-INFO-04 APPLICATION ENUMERATION (SUPPLEMENT) ==========\n"
    report += f"Domain: {domain}\nTarget IP: {target_ip or 'Unknown'}\n\n"
    report += f"[FOUND] {len(subdomains)} responsive subdomain(s)\n"
    for sub in sorted(subdomains, key=lambda x: x["host"]):
        report += f" - {sub['host']} ({sub['ip']})"
        if sub.get("status"):
            report += f" HTTP {sub['status']}"
        report += "\n"
    report += f"\n[FOUND] {len(open_ports)} open TCP port(s) on {target_ip or 'target'}\n"
    for p in open_ports:
        report += f" - {p['port']}/tcp open\n"

    return {
        "wstg_id": "WSTG-INFO-04",
        "domain": domain,
        "target_ip": target_ip,
        "subdomains": subdomains,
        "open_ports": open_ports,
        "report": report.strip(),
    }
