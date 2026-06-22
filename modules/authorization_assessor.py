"""
OWASP WSTG 4.5 - Authorization Assessment (Passive)
Detects IDOR patterns, privilege escalation indicators, forced browsing, missing access control.
"""

from __future__ import annotations

import re
from typing import Any
import requests
from urllib.parse import urlparse, parse_qs

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class AuthorizationAssessor:
    """Passive authorization security assessment."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.findings: list[dict] = []
        self.recommendations: list[str] = []
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "ReconSight/1.0 (PassiveScanner)",
        })
        self._session.verify = False
        self._session.timeout = 10
        self.visited_urls = set()

    def run_all_tests(self) -> dict[str, Any]:
        """Run all authorization assessment checks."""
        try:
            resp = self._session.get(self.base_url, timeout=10)
            html = resp.text or ""
            self.visited_urls.add(self.base_url)
        except Exception:
            html = ""

        self._check_idor_indicators(html)
        self._check_admin_paths(html)
        self._check_jwt_tokens(html, resp)
        self._check_url_parameter_patterns(html)
        self._check_missing_access_control(html)

        severity = self._determine_severity()

        return {
            "test_name": "Authorization Assessment (Passive)",
            "wstg_reference": ["WSTG-4.5"],
            "severity": severity,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": {
                "total_findings": len(self.findings),
                "idor_suspected": any("idor" in f.get("title", "").lower() for f in self.findings),
                "admin_paths_found": any("admin" in f.get("title", "").lower() for f in self.findings),
            }
        }

    def _check_idor_indicators(self, html: str):
        """Detect potential IDOR patterns in URLs and forms."""
        # Look for numeric IDs in URLs
        id_patterns = [
            r'/(?:user|account|profile|order|invoice|document|file)/?(\d+)',
            r'[?&]id=\d+',
            r'[?&]uid=\d+',
            r'[?&]oid=\d+',
            r'[?&]pid=\d+'
        ]
        lower_html = html.lower()
        matches = []
        for pattern in id_patterns:
            if re.search(pattern, lower_html):
                matches.append(pattern)

        if matches:
            self._add_finding(
                title="Potential IDOR Indicators Detected",
                severity="MEDIUM",
                evidence=f"Found numeric ID patterns: {len(matches)} occurrences. Patterns: {', '.join(matches[:3])}",
                recommendation="Review endpoints that use sequential numeric identifiers. Implement proper access control checks (authorization) to ensure users can only access their own resources."
            )
        else:
            self._add_finding(
                title="No IDOR Indicators Detected",
                severity="INFO",
                evidence="No obvious numeric ID patterns found in HTML.",
                recommendation="Continue monitoring for IDOR vulnerabilities, especially if using predictable identifiers."
            )

    def _check_admin_paths(self, html: str):
        """Detect presence of admin/management paths."""
        admin_keywords = [
            r'/admin',
            r'/administrator',
            r'/dashboard',
            r'/cpanel',
            r'/manage',
            r'/manager',
            r'/wp-admin',
            r'/admin/login',
            r'/adminpanel'
        ]
        lower_html = html.lower()
        found = []
        for kw in admin_keywords:
            if re.search(kw, lower_html):
                found.append(kw.strip('/'))
        if found:
            self._add_finding(
                title="Admin/Management Paths Discovered",
                severity="INFO",
                evidence=f"Found {len(found)} admin-related paths: {', '.join(found[:5])}",
                recommendation="Ensure admin interfaces are protected with strong authentication, authorization, IP restrictions, and are not directly accessible to unauthenticated users."
            )
        else:
            self._add_finding(
                title="No Admin Paths Detected",
                severity="INFO",
                evidence="No common admin/management paths found on homepage.",
                recommendation="If admin interfaces exist, ensure they are not easily guessable (security through obscurity is not sufficient)."
            )

    def _check_jwt_tokens(self, html: str, resp):
        """Detect JWT tokens in URLs, cookies, or page source."""
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        # Check HTML
        html_matches = re.findall(jwt_pattern, html)
        # Check cookies
        cookie_matches = []
        if resp:
            for cookie in resp.cookies:
                val = cookie.value
                if re.fullmatch(jwt_pattern, val):
                    cookie_matches.append(cookie.name)
        # Check URL (self.base_url)
        url_matches = re.findall(jwt_pattern, self.base_url)

        all_matches = html_matches + cookie_matches + url_matches
        if all_matches:
            self._add_finding(
                title="JWT Tokens Detected",
                severity="MEDIUM",
                evidence=f"Found {len(all_matches)} JWT-like token(s) in HTML/cookies/URL. Tokens may be exposed to client-side scripts or logs.",
                recommendation="Ensure JWT tokens are stored securely (HttpOnly cookies preferred over localStorage), have appropriate expiration, and are validated server-side. Do not expose sensitive data in JWT payload."
            )

    def _check_url_parameter_patterns(self, html: str):
        """Analyze URL parameters for potential security weaknesses."""
        # Extract links from HTML (simple)
        links = re.findall(r'href=["\']([^"\']+)["\']', html, re.I)
        suspicious_params = ['user', 'uid', 'email', 'role', 'admin', 'debug', 'test', 'id', 'key', 'token']
        param_freq = {}
        for link in links:
            if '?' in link:
                qs = urlparse(link).query
                params = parse_qs(qs)
                for p in params:
                    if p.lower() in suspicious_params:
                        param_freq[p] = param_freq.get(p, 0) + 1
        if param_freq:
            top = sorted(param_freq.items(), key=lambda x: -x[1])[:5]
            self._add_finding(
                title="Suspicious URL Parameters Detected",
                severity="LOW",
                evidence=f"Found sensitive parameters in URLs: {', '.join(f'{k}({v})' for k,v in top)}",
                recommendation="Avoid passing sensitive data or identifiers in URL query strings, as they may be logged, cached, or leaked via Referer headers. Use POST or secure session tokens instead."
            )

    def _check_missing_access_control(self, html: str):
        """Passive check for missing access control indicators (e.g., exposed APIs)."""
        # Look for API endpoints in JavaScript code
        api_patterns = [
            r'/api/[\w/]+',
            r'\.(get|post|put|delete)\(["\']/api/',
            r'fetch\(["\']/api/',
            r'axios\.(get|post)\(["\']/api/'
        ]
        lower_html = html.lower()
        api_endpoints = set()
        for pattern in api_patterns:
            for match in re.findall(pattern, lower_html):
                api_endpoints.add(match)
        if api_endpoints:
            self._add_finding(
                title="API Endpoints Exposed in Client-Side Code",
                severity="INFO",
                evidence=f"Found {len(api_endpoints)} API endpoint references in JavaScript/HTML.",
                recommendation="Ensure API endpoints enforce proper authentication and authorization on the server side. Client-side exposure is not a vulnerability but indicates need for server-side access control."
            )

    def _add_finding(self, title: str, severity: str, evidence: str, recommendation: str | None = None):
        finding = {
            "title": title,
            "severity": severity,
            "evidence": evidence,
            "cwe_ids": self._map_to_cwe(title, severity)
        }
        self.findings.append(finding)
        if recommendation:
            self.recommendations.append(recommendation)

    def _determine_severity(self) -> str:
        if any(f["severity"] == "CRITICAL" for f in self.findings):
            return "CRITICAL"
        if any(f["severity"] == "HIGH" for f in self.findings):
            return "HIGH"
        if any(f["severity"] == "MEDIUM" for f in self.findings):
            return "MEDIUM"
        return "INFO"

    def _map_to_cwe(self, title: str, severity: str) -> list[str]:
        title_l = title.lower()
        mapping = {
            "idor": ["CWE-639", "CWE-862"],
            "admin": ["CWE-284"],
            "jwt": ["CWE-113"],
            "url parameter": ["CWE-598"],
            "access control": ["CWE-284", "CWE-285"],
        }
        for key, cwes in mapping.items():
            if key in title_l:
                return cwes
        return []
