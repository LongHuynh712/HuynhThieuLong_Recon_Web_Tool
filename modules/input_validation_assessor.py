"""
OWASP WSTG 4.7 - Input Validation Assessment (Passive) - ENHANCED
Detects XSS, SQLi, SSRF, Open Redirect, Path Traversal, File Upload indicators via static analysis.
Coverage: ~60% of WSTG-4.7 test cases
"""

from __future__ import annotations

import re
from typing import Any
import requests
from urllib.parse import urlparse, parse_qs, urljoin

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class InputValidationAssessor:
    """Passive input validation security assessment - Enhanced version."""

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
            resp = None

        # Core checks
        self._check_xss_indicators(html)
        self._check_reflected_xss(html)
        self._check_context_aware_reflection(html)
        self._check_dom_xss_sinks(html)

        # SQL Injection detection - Enhanced
        self._check_sqli_indicators(html)
        self._check_sql_error_correlation(html)
        self._check_sql_parameter_patterns(html)

        # SSRF Detection - Enhanced
        self._check_ssrf_indicators(html)
        self._check_ssrf_parameter_patterns(html)

        # Open Redirect - Enhanced
        self._check_open_redirect_indicators(html, resp)

        # Path Traversal - NEW
        self._check_path_traversal_indicators(html)

        # File Upload - NEW
        self._check_file_upload_security(html)

        # Parameter pollution - NEW
        self._check_parameter_pollution(html)

        severity = self._determine_severity()

        return {
            "test_name": "Input Validation Assessment (Passive - Enhanced)",
            "wstg_reference": ["WSTG-4.7", "WSTG-4.7.1", "WSTG-4.7.2", "WSTG-4.7.3", "WSTG-4.7.6"],
            "severity": severity,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": {
                "total_findings": len(self.findings),
                "xss_suspected": any("xss" in f.get("title", "").lower() for f in self.findings),
                "sqli_suspected": any("sqli" in f.get("title", "").lower() for f in self.findings),
                "open_redirect_found": any("redirect" in f.get("title", "").lower() for f in self.findings),
                "path_traversal_found": any("path traversal" in f.get("title", "").lower() for f in self.findings),
                "ssrf_suspected": any("ssrf" in f.get("title", "").lower() for f in self.findings),
            }
        }

    # ==================== XSS DETECTION ====================

    def _check_xss_indicators(self, html: str):
        """Detect potential XSS sinks in HTML/JavaScript."""
        xss_sinks = [
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'insertAdjacentHTML\s*\(',
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
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
            r'onmouseover\s*=',
            r'onmouseout\s*=',
            r'onmousedown\s*=',
            r'onmouseup\s*=',
            r'onkeypress\s*=',
            r'onkeydown\s*=',
            r'onkeyup\s*=',
            r'onsubmit\s*=',
            r'onfocus\s*=',
            r'onblur\s*='
        ]
        lower_html = html.lower()
        matches = []
        for pattern in xss_sinks:
            found = re.findall(pattern, lower_html)
            matches.extend([m.strip() for m in found])
        if matches:
            unique_matches = list(set(matches))[:10]
            self._add_finding(
                title="Potential XSS Sinks Detected",
                severity="MEDIUM",
                evidence=f"Found {len(matches)} JavaScript patterns that could lead to XSS if user input is reflected without sanitization. Examples: {', '.join(unique_matches)}",
                recommendation="Ensure all user-controlled input is properly sanitized/encoded before being inserted into the DOM. Use safe APIs like textContent, avoid innerHTML, and implement Content Security Policy (CSP).",
                wstg_ids=["WSTG-4.7.2"]
            )

    def _check_reflected_xss(self, html: str):
        """Detect reflected XSS by checking if URL query parameters appear verbatim in the response body."""
        parsed = urlparse(self.base_url)
        qs = parse_qs(parsed.query)
        reflected = []
        lower_html = html.lower()
        for param, values in qs.items():
            for val in values:
                if val and val.lower() in lower_html:
                    reflected.append((param, val))
        if reflected:
            samples = [f"{p}={v[:30]}" for p, v in reflected[:3]]
            self._add_finding(
                title="Reflected XSS Detected",
                severity="MEDIUM",
                evidence=f"Found {len(reflected)} query parameters echoed back in the page (possible XSS). Samples: {', '.join(samples)}",
                recommendation="Validate and encode all reflected input. Use context-appropriate encoding and a CSP.",
                wstg_ids=["WSTG-4.7.2"]
            )

    def _check_context_aware_reflection(self, html: str):
        """Check whether reflected parameters appear inside <script> blocks – higher XSS risk."""
        parsed = urlparse(self.base_url)
        qs = parse_qs(parsed.query)
        script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
        risky = []
        for block in script_blocks:
            lower_block = block.lower()
            for param, values in qs.items():
                for val in values:
                    if val and val.lower() in lower_block:
                        risky.append((param, val))
        if risky:
            samples = [f"{p}={v[:20]}" for p, v in risky[:3]]
            self._add_finding(
                title="Context-Aware Reflected XSS Detected",
                severity="HIGH",
                evidence=f"Found {len(risky)} parameters reflected inside <script> tags – potential XSS. Samples: {', '.join(samples)}",
                recommendation="Escape/encode values before injecting into JavaScript. Use JSON.stringify() for data, or safe templating.",
                wstg_ids=["WSTG-4.7.2"]
            )

    def _check_dom_xss_sinks(self, html: str):
        """Detect DOM-based XSS patterns including eval, document.write, and location assignment."""
        dom_patterns = [
            (r'document\.write\s*\(', 'document.write'),
            (r'document\.writeln\s*\(', 'document.writeln'),
            (r'innerHTML\s*=', 'innerHTML assignment'),
            (r'outerHTML\s*=', 'outerHTML assignment'),
            (r'insertAdjacentHTML\s*\(', 'insertAdjacentHTML'),
            (r'eval\s*\(', 'eval()'),
            (r'new\s+Function\s*\(', 'new Function()'),
            (r'setTimeout\s*\(\s*["\']', 'setTimeout with string'),
            (r'setInterval\s*\(\s*["\']', 'setInterval with string'),
            (r'location\s*=\s*', 'location assignment'),
            (r'window\.location\s*=\s*', 'window.location assignment'),
            (r'location\.href\s*=\s*', 'location.href assignment'),
            (r'location\.replace\s*\(', 'location.replace()'),
        ]
        matches = []
        for pattern, name in dom_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                matches.append(name)
        if matches:
            unique_matches = list(set(matches))
            self._add_finding(
                title="DOM-based XSS Sinks Detected",
                severity="HIGH",
                evidence=f"Found dangerous DOM manipulation patterns: {', '.join(unique_matches[:8])}",
                recommendation="Replace innerHTML with textContent, avoid eval(), use safe navigation methods. Implement CSP and input sanitization.",
                wstg_ids=["WSTG-4.7.1", "WSTG-4.7.2"]
            )

    # ==================== SQL INJECTION DETECTION ====================

    def _check_sqli_indicators(self, html: str):
        """Detect potential SQL injection indicators in client-side code."""
        sql_patterns = [
            r'SELECT\s+.*\s+FROM',
            r'INSERT\s+INTO',
            r'UPDATE\s+.*\s+SET',
            r'DELETE\s+FROM',
            r'DROP\s+TABLE',
            r'CREATE\s+TABLE',
            r'ALTER\s+TABLE',
            r'exec\s*\(',
            r'execute\s*\(',
            r'createStatement\s*\(',
            r'prepareStatement\s*\(',
            r'query\s*\(',
            r'sql\s*=\s*["\']SELECT',
            r'WHERE\s+\w+\s*=',
            r'UNION\s+SELECT',
            r'--\s*$',  # SQL comment
            r'/\*.*?\*/',  # SQL block comment
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
                evidence=f"Found {len(matches)} SQL-like patterns in JavaScript/HTML. This may indicate dynamic query construction.",
                recommendation="Use parameterized queries/prepared statements on server side. Never construct SQL queries by string concatenation with user input.",
                wstg_ids=["WSTG-4.7.5"]
            )

    def _check_sql_error_correlation(self, html: str):
        """Look for typical SQL error messages that may leak via the response body."""
        sql_errors = {
            'MySQL': [
                r'mysql_fetch_\w+\(\): supplied argument is not a valid MySQL result resource',
                r'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version',
                r'Warning: mysql_\w+\(\):',
                r'MySQL server has gone away',
                r'Unknown column \'[^\']+\' in \'field list\'',
            ],
            'PostgreSQL': [
                r'PostgreSQL.*error',
                r'ERROR:\s* syntax error at or near',
                r'ERROR:\s* invalid input syntax for',
                r'psql',
                r'pg_\w+\(\): query failed',
            ],
            'MSSQL': [
                r'Microsoft SQL Native Client error',
                r'SQLServerException',
                r'Incorrect syntax near',
                r'Unclosed quotation mark after the character string',
                r'Conversion failed when converting',
            ],
            'Oracle': [
                r'ORA-\d{5}',
                r'Oracle error',
                r'ORA-00942: table or view does not exist',
                r'ORA-06512: at line',
                r'SQL command not properly ended',
            ],
            'SQLite': [
                r'sqlite3\.OperationalError',
                r'SQLite error',
                r'no such table:',
                r'unknown database',
            ],
            'Generic': [
                r'sql syntax error',
                r'unclosed quotation mark',
                r'invalid column name',
                r'incorrect syntax near',
                r'unexpected end of command',
            ]
        }
        lower_html = html.lower()
        findings_by_db = {}
        for db_type, patterns in sql_errors.items():
            matches = []
            for pattern in patterns:
                if re.search(pattern, lower_html, re.I):
                    matches.append(pattern)
            if matches:
                findings_by_db[db_type] = len(matches)

        if findings_by_db:
            details = ', '.join([f"{db}({count})" for db, count in findings_by_db.items()])
            severity = "HIGH" if len(findings_by_db) >= 2 else "MEDIUM"
            self._add_finding(
                title="Database Error Message Leakage Detected",
                severity=severity,
                evidence=f"Found SQL error signatures in the page: {details}",
                recommendation="Hide detailed database errors from users; present generic error messages and log details server-side. Configure proper error handling.",
                wstg_ids=["WSTG-4.7.5"]
            )

    def _check_sql_parameter_patterns(self, html: str):
        """Detect suspicious SQL parameter patterns in URLs and forms."""
        # Check for typical SQL injection test patterns
        sqli_test_patterns = [
            r'[\'"]\s*OR\s+[\'"]?\s*\w+[\'"]?\s*=\s*[\'"]?\w+[\'"]',
            r'[\'"]\s*UNION\s+SELECT\s+',
            r'[\'"]\s*--\s*$',
            r'[\'"]\s*#\s*$',
            r'[\'"]\s*[\r\n]',
            r'1\s*=\s*1\s*--',
            r'1\s*=\s*1\s*#',
            r'OR\s+1\s*=\s*1',
            r'AND\s+1\s*=\s*1',
        ]
        matches = 0
        for pattern in sqli_test_patterns:
            if re.search(pattern, html, re.I):
                matches += 1
        if matches >= 2:
            self._add_finding(
                title="SQL Injection Test Patterns Detected",
                severity="MEDIUM",
                evidence=f"Found {matches} SQL injection test patterns (OR 1=1, UNION SELECT, comments) in page source.",
                recommendation="Ensure input validation and parameterized queries. Review if these are legitimate or test artifacts.",
                wstg_ids=["WSTG-4.7.5"]
            )

    # ==================== SSRF DETECTION ====================

    def _check_ssrf_indicators(self, html: str):
        """Detect potential SSRF via URL fetching functions."""
        ssrf_sinks = [
            r'fetch\s*\(',
            r'axios\.(get|post|put|delete|patch)',
            r'\.open\s*\(',
            r'request\s*\(',
            r'http\.get\s*\(',
            r'http\.post\s*\(',
            r'urllib\.request\.urlopen',
            r'curl\s+',
            r'session\.get\s*\(',
            r'session\.post\s*\(',
            r'requests\.(get|post)',
            r'\.ajax\s*\(',
            r'\$\.(get|post|ajax)',
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
                recommendation="Validate and whitelist user-supplied URLs. Use allowlists for outbound destinations, block private IP ranges (127.0.0.1, 10.0.0.0/8, 192.168.0.0/16, ::1), and avoid using user input in network requests.",
                wstg_ids=["WSTG-4.7.3"]
            )

    def _check_ssrf_parameter_patterns(self, html: str):
        """Detect SSRF-prone parameters in forms and URLs."""
        ssrf_params = [
            'url', 'callback', 'webhook', 'api_url', 'feed_url', 'fetch_url',
            'download', 'file', 'path', 'redirect', 'next', 'site', 'domain',
            'host', 'ip', 'address', 'endpoint', 'resource', 'src'
        ]
        # Check query parameters
        parsed = urlparse(self.base_url)
        qs = parse_qs(parsed.query)
        found_in_url = [p for p in ssrf_params if p in qs]
        # Check form fields
        html_params = re.findall(r'name=["\']([^"\']+)["\']', html, re.I)
        found_in_html = [p for p in ssrf_params if p.lower() in [hp.lower() for hp in html_params]]
        all_found = list(set(found_in_url + found_in_html))
        if all_found:
            self._add_finding(
                title="SSRF-prone Parameters Detected",
                severity="LOW",
                evidence=f"Found {len(all_found)} parameters that may be used for SSRF: {', '.join(all_found[:8])}",
                recommendation="Ensure these parameters are validated against a whitelist of allowed domains/IPs. Block internal IP ranges and use allowlists for external destinations.",
                wstg_ids=["WSTG-4.7.3"]
            )

    # ==================== OPEN REDIRECT DETECTION ====================

    def _check_open_redirect_indicators(self, html: str, resp):
        """Detect open redirect parameters."""
        # Check for redirect parameters in URL
        parsed = urlparse(self.base_url)
        qs = parse_qs(parsed.query)
        redirect_params = ['redirect', 'url', 'next', 'return', 'callback', 'return_to', 'goto', 'target', 'destination', 'path']
        found_params = [p for p in redirect_params if p in qs]
        # Also check forms with redirect fields
        html_redirect_fields = re.findall(r'name=["\'](redirect|url|next|return|callback|goto|target|destination|path)["\']', html, re.I)
        all_found = set(found_params + html_redirect_fields)
        if all_found:
            self._add_finding(
                title="Open Redirect Parameters Detected",
                severity="LOW",
                evidence=f"Found redirect-related parameters: {', '.join(all_found)}. These may be vulnerable to open redirect attacks if not validated.",
                recommendation="Ensure any redirect parameters are validated against a whitelist of allowed domains or relative paths only. Avoid redirecting to arbitrary user-supplied URLs. Use a mapping of short identifiers to known URLs instead of passing full URLs.",
                wstg_ids=["WSTG-4.7.4"]
            )

    # ==================== PATH TRAVERSAL DETECTION ====================

    def _check_path_traversal_indicators(self, html: str):
        """Detect path traversal vulnerable parameters and file access patterns."""
        # Common path traversal parameters
        path_params = ['file', 'path', 'document', 'download', 'load', 'read', 'include',
                       'template', 'page', 'show', 'view', 'content', 'filename',
                       'dir', 'folder', 'root', 'home', 'filepath']
        # Check URL parameters
        parsed = urlparse(self.base_url)
        qs = parse_qs(parsed.query)
        found_params = [p for p in path_params if p in qs]
        # Check form fields
        html_fields = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', html, re.I)
        found_fields = [f for f in html_fields if f.lower() in path_params]
        all_found = list(set(found_params + found_fields))

        # Check for traversal sequences in the URL itself
        traversal_in_url = False
        if '..' in self.base_url or '%2e%2e' in self.base_url.lower() or '...' in self.base_url:
            traversal_in_url = True

        if all_found or traversal_in_url:
            evidence_parts = []
            if all_found:
                evidence_parts.append(f"parameters: {', '.join(all_found[:8])}")
            if traversal_in_url:
                evidence_parts.append("traversal sequences detected in URL")
            self._add_finding(
                title="Path Traversal Indicators Detected",
                severity="MEDIUM",
                evidence=f"Found path traversal risk: {'; '.join(evidence_parts)}",
                recommendation="Validate and sanitize file/path parameters. Use allowlists of allowed filenames/paths. Resolve paths to a known safe directory and reject attempts to traverse outside. Never use user input directly in file system operations.",
                wstg_ids=["WSTG-4.7.5"]
            )

    # ==================== FILE UPLOAD SECURITY ====================

    def _check_file_upload_security(self, html: str):
        """Detect file upload forms and assess security."""
        if re.search(r'<form[^>]*enctype=["\']multipart/form-data["\']', html, re.I):
            file_inputs = re.findall(r'<input[^>]*type=["\']file["\'][^>]*>', html, re.I)
            if file_inputs:
                # Check for accept attribute (client-side restriction)
                accept_attrs = re.findall(r'accept=["\']([^"\']+)["\']', html, re.I)
                has_accept = len(accept_attrs) > 0

                # Check for multiple file upload
                multiple_attrs = re.findall(r'multiple\s*["\']?', html, re.I)
                allows_multiple = len(multiple_attrs) > 0

                evidence = f"Found {len(file_inputs)} file upload field(s)."
                if has_accept:
                    evidence += " Client-side file type restrictions present."
                if allows_multiple:
                    evidence += " Multiple file upload allowed."

                severity = "MEDIUM"  # File uploads always warrant scrutiny
                if not has_accept:
                    evidence += " No file type restrictions detected."
                    severity = "HIGH"

                self._add_finding(
                    title="File Upload Form Detected",
                    severity=severity,
                    evidence=evidence,
                    recommendation="Ensure file uploads are validated: 1) Server-side file type validation (MIME type + extension), 2) File size limits, 3) Scan for malware, 4) Store outside web root, 5) Use random filenames, 6) Serve via dedicated endpoints, 7) Never trust client-side restrictions.",
                    wstg_ids=["WSTG-4.7.7"]
                )

    # ==================== PARAMETER POLLUTION ====================

    def _check_parameter_pollution(self, html: str):
        """Detect potential HTTP parameter pollution vulnerabilities."""
        # Check for multiple same-named parameters in URL
        parsed = urlparse(self.base_url)
        qs = parse_qs(parsed.query)
        duplicate_params = [k for k, v in qs.items() if len(v) > 1]

        if duplicate_params:
            self._add_finding(
                title="HTTP Parameter Pollution Risk",
                severity="LOW",
                evidence=f"Found parameters with multiple values: {', '.join(duplicate_params[:5])}",
                recommendation="Ensure server-side handling of duplicate parameters is consistent. Validate and use only the first or last value as appropriate. Implement allowlists for expected parameters.",
                wstg_ids=["WSTG-4.7.13"]
            )

    # ==================== LEGACY CHECKS (preserved for compatibility) ====================

    def _check_parameter_fuzzing_indicators(self, html: str):
        """Detect parameters containing special characters that are reflected back."""
        parsed = urlparse(self.base_url)
        qs = parse_qs(parsed.query)
        suspicious = []
        lower_html = html.lower()
        for param, values in qs.items():
            for val in values:
                if any(ch in val for ch in ['<', '>', '"', "'", ';', '|', '&']):
                    if val.lower() in lower_html:
                        suspicious.append((param, val))
        if suspicious:
            samples = [f"{p}={v[:20]}" for p, v in suspicious[:3]]
            self._add_finding(
                title="Parameter Fuzzing Indicator Detected",
                severity="LOW",
                evidence=f"Found {len(suspicious)} query parameters with special characters reflected in response. Samples: {', '.join(samples)}",
                recommendation="Validate and sanitize all parameters. Reject or encode special characters before processing.",
                wstg_ids=["WSTG-4.7.2"]
            )

    def _add_finding(self, title: str, severity: str, evidence: str, recommendation: str | None = None, wstg_ids: list[str] = None):
        finding = {
            "title": title,
            "severity": severity,
            "evidence": evidence,
            "cwe_ids": self._map_to_cwe(title, severity)
        }
        if wstg_ids:
            finding["wstg_ids"] = wstg_ids
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
            "sql injection": ["CWE-89"],
            "ssrf": ["CWE-918"],
            "redirect": ["CWE-601"],
            "open redirect": ["CWE-601"],
            "path traversal": ["CWE-22"],
            "file upload": ["CWE-434"],
            "parameter pollution": ["CWE-235"],
        }
        for key, cwes in mapping.items():
            if key in title_l:
                return cwes
        return []
