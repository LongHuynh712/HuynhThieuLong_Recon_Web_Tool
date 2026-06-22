"""
OWASP WSTG 4.7 - Input Validation Assessment (Passive)
Detects XSS, SQLi, SSRF, Open Redirect, File Upload indicators via static analysis.
"""

from __future__ import annotations

import re
from typing import Any
import requests
from urllib.parse import urlparse, parse_qs

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class InputValidationAssessor:
    """Passive input validation security assessment."""

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

    def run_all_tests(self) -> dict[str, Any]:
        """Run all input validation assessment checks."""
        try:
            resp = self._session.get(self.base_url, timeout=10)
            html = resp.text or ""
        except Exception:
            html = ""

        self._check_xss_indicators(html)
        self._check_sqli_indicators(html)
        self._check_ssrf_indicators(html)
        self._check_open_redirect_indicators(html, resp)
        self._check_file_upload_indicators(html)

        severity = self._determine_severity()

        return {
            "test_name": "Input Validation Assessment (Passive)",
            "wstg_reference": ["WSTG-4.7"],
            "severity": severity,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": {
                "total_findings": len(self.findings),
                "xss_suspected": any("xss" in f.get("title", "").lower() for f in self.findings),
                "sqli_suspected": any("sqli" in f.get("title", "").lower() for f in self.findings),
                "open_redirect_found": any("redirect" in f.get("title", "").lower() for f in self.findings),
            }
        }

    def _check_xss_indicators(self, html: str):
        """Detect potential XSS sinks in HTML/JavaScript."""
        # Dangerous patterns: innerHTML, document.write, eval, alert, script injection
        xss_sinks = [
            r'innerHTML\s*=',
            r'document\.write\s*\(',
            r'eval\s*\(',
            r'\.html\s*\(',
            r'document\.cookie\s*=',
            r'location\s*=\s*',
            r'window\.location\s*=',
            r'src\s*=\s*["\']javascript:',
            r'onerror\s*=',
            r'onload\s*=',
            r'onclick\s*=',
            r'ondblclick\s*=',
            r'onmouseover\s*='
        ]
        lower_html = html.lower()
        matches = []
        for pattern in xss_sinks:
            for m in re.findall(pattern, lower_html):
                matches.append(m.strip())
        if matches:
            self._add_finding(
                title="Potential XSS Sinks Detected",
                severity="MEDIUM",
                evidence=f"Found {len(matches)} JavaScript patterns that could lead to XSS if user input is reflected without sanitization. Examples: {', '.join(set(matches)[:5])}",
                recommendation="Ensure all user-controlled input is properly sanitized/encoded before being inserted into the DOM. Use safe APIs like textContent, avoid innerHTML, and implement Content Security Policy (CSP)."
            )
        else:
            self._add_finding(
                title="No XSS Sinks Detected",
                severity="INFO",
                evidence="No obvious JavaScript sinks found.",
                recommendation="Continue to avoid dangerous DOM manipulation patterns."
            )

    def _check_sqli_indicators(self, html: str):
        """Detect potential SQL injection indicators in client-side code."""
        # Look for SQL keywords concatenated with strings
        sql_patterns = [
            r'SELECT\s+.*\s+FROM',
            r'INSERT\s+INTO',
            r'UPDATE\s+.*\s+SET',
            r'DELETE\s+FROM',
            r'DROP\s+TABLE',
            r'exec\s*\(',
            r'execute\s*\(',
            r'createStatement\s*\(',
            r'query\s*\(',
            r'sql\s*=\s*["\']SELECT'
        ]
        lower_html = html.lower()
        matches = []
        for pattern in sql_patterns:
            if re.search(pattern, lower_html, re.I):
                matches.append(pattern)
        if matches:
            self._add_finding(
                title="SQL Code Patterns Detected in Client-Side",
                severity="LOW",
                evidence=f"Found {len(matches)} SQL-like patterns in JavaScript/HTML. This may indicate dynamic query construction, which is dangerous if any part is derived from user input.",
                recommendation="Use parameterized queries/prepared statements on server side. Never construct SQL queries by string concatenation with user input."
            )

    def _check_ssrf_indicators(self, html: str):
        """Detect potential SSRF via URL fetching functions."""
        ssrf_sinks = [
            r'fetch\s*\(',
            r'axios\.(get|post)',
            r'\.open\s*\(',
            r'request\s*\(',
            r'http\.get\s*\(',
            r'urllib',
            r'curl\s+'
        ]
        lower_html = html.lower()
        matches = []
        for pattern in ssrf_sinks:
            if re.search(pattern, lower_html):
                matches.append(pattern)
        if matches:
            self._add_finding(
                title="Potential SSRF Vectors Detected",
                severity="MEDIUM",
                evidence=f"Found {len(matches)} network request patterns that could be exploited for SSRF if user-controlled URLs are used without validation.",
                recommendation="Validate and whitelist user-supplied URLs. Use allowlists for outbound destinations, block private IP ranges, and avoid using user input in network requests."
            )

    def _check_open_redirect_indicators(self, html: str, resp):
        """Detect open redirect parameters."""
        # Check for redirect parameters in URL
        parsed = urlparse(self.base_url)
        qs = parse_qs(parsed.query)
        redirect_params = ['redirect', 'url', 'next', 'return', 'callback', 'return_to', 'goto']
        found_params = [p for p in redirect_params if p in qs]
        # Also check forms with redirect fields
        html_redirect_fields = re.findall(r'name=["\'](redirect|url|next|return|callback|goto)["\']', html, re.I)
        all_found = set(found_params + html_redirect_fields)
        if all_found:
            self._add_finding(
                title="Open Redirect Parameters Detected",
                severity="LOW",
                evidence=f"Found redirect-related parameters: {', '.join(all_found)}. These may be vulnerable to open redirect attacks if not validated.",
                recommendation="Ensure any redirect parameters are validated against a whitelist of allowed domains or relative paths only. Avoid redirecting to arbitrary user-supplied URLs."
            )

    def _check_file_upload_indicators(self, html: str):
        """Detect file upload forms."""
        if re.search(r'<form[^>]*enctype=["\']multipart/form-data["\']', html, re.I):
            file_inputs = re.findall(r'<input[^>]*type=["\']file["\']', html, re.I)
            if file_inputs:
                self._add_finding(
                    title="File Upload Form Detected",
                    severity="INFO",
                    evidence=f"Found form with file upload capability ({len(file_inputs)} file input fields).",
                    recommendation="Ensure file uploads are validated: restrict file types, scan for malware, store outside web root, and serve via dedicated endpoints with proper access control."
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
            "xss": ["CWE-79"],
            "sqli": ["CWE-89"],
            "ssrf": ["CWE-918"],
            "redirect": ["CWE-601"],
            "file upload": ["CWE-434"],
        }
        for key, cwes in mapping.items():
            if key in title_l:
                return cwes
        return []
