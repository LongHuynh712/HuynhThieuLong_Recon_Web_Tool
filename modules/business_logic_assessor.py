"""
OWASP WSTG 4.10 - Business Logic Assessment (Passive)
Detects workflow bypass indicators, predictable identifiers, business process weaknesses.
"""

from __future__ import annotations

import re
from typing import Any
import requests
from urllib.parse import urlparse, parse_qs
from datetime import datetime

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class BusinessLogicAssessor:
    """Passive business logic security assessment."""

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
        """Run all business logic assessment checks."""
        try:
            resp = self._session.get(self.base_url, timeout=10)
            html = resp.text or ""
        except Exception:
            html = ""

        self._check_predictable_identifiers(html)
        self._check_workflow_parameters(html)
        self._check_price_manipulation(html)
        self._check_sequential_patterns(html)
        self._check_sensitive_operations_exposure(html)
        self._check_robots_sitemap()

        severity = self._determine_severity()

        return {
            "test_name": "Business Logic Assessment (Passive)",
            "wstg_reference": ["WSTG-4.10"],
            "severity": severity,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": {
                "total_findings": len(self.findings),
                "predictable_ids_found": any("predictable" in f.get("title", "").lower() for f in self.findings),
                "workflow_issues_found": any("workflow" in f.get("title", "").lower() for f in self.findings),
            }
        }

    def _check_predictable_identifiers(self, html: str):
        """Detect predictable resource identifiers (e.g., order numbers, invoice IDs)."""
        patterns = [
            r'/(order|invoice|bill|shipment|package|ticket|case)/?(\d{4,})',  # /order/12345
            r'/(order|invoice)[A-Z0-9]{6,}',  # alphanumeric codes
            r'[?&](order|invoice|tracking|shipment)id=(\d+)',
            r'/[a-z]{2,}-\d{4,}',  # prefix with numbers
        ]
        lower_html = html.lower()
        matches = []
        for pattern in patterns:
            if re.search(pattern, lower_html):
                matches.append(pattern)
        if matches:
            self._add_finding(
                title="Predictable Resource Identifiers Detected",
                severity="MEDIUM",
                evidence=f"Found {len(matches)} patterns suggesting predictable identifiers (order numbers, invoice IDs). Examples: {', '.join(matches[:3])}",
                recommendation="Review if these identifiers can be guessed. If they expose sensitive data, use random UUIDs or non-sequential identifiers. Ensure authorization checks are performed before disclosing resource details."
            )

    def _check_workflow_parameters(self, html: str):
        """Detect workflow steps exposed via parameters."""
        # Look for step, stage, phase parameters
        workflow_params = ['step', 'stage', 'phase', 'page', 'next', 'prev', 'flow']
        links = re.findall(r'href=["\']([^"\']+)["\']', html, re.I)
        param_usage = {}
        for link in links:
            if '?' in link:
                qs = parse_qs(urlparse(link).query)
                for p in qs:
                    if p.lower() in workflow_params:
                        param_usage[p] = param_usage.get(p, 0) + 1
        if param_usage:
            self._add_finding(
                title="Workflow Parameters Detected",
                severity="LOW",
                evidence=f"Found workflow-related parameters in URLs: {', '.join(f'{k}({v})' for k,v in param_usage.items())}",
                recommendation="Ensure workflow progression is enforced server-side and cannot be bypassed by skipping steps or modifying parameters."
            )

    def _check_price_manipulation(self, html: str):
        """Detect price or cost parameters in HTML/JS."""
        price_keywords = ['price', 'cost', 'amount', 'total', 'discount', 'fee', 'rate']
        forms = re.findall(r'<form[^>]*>', html, re.I)
        price_in_forms = False
        for form in forms:
            if any(kw in form.lower() for kw in price_keywords):
                price_in_forms = True
                break
        if price_in_forms:
            self._add_finding(
                title="Price Parameters in Forms Detected",
                severity="MEDIUM",
                evidence="HTML forms contain fields that may relate to price, cost, or discount values.",
                recommendation="Never trust client-side price parameters. Always recalculate prices server-side based on product catalog and user eligibility."
            )

    def _check_sequential_patterns(self, html: str):
        """Check for sequential numbers in visible text (could be IDs)."""
        # Look for numbers that appear frequently (4+ digits)
        numbers = re.findall(r'\b(\d{4,})\b', html)
        if len(numbers) > 10:
            # Check if they are sequential-ish: compute differences
            try:
                nums = [int(n) for n in numbers[:20]]
                diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
                avg_diff = sum(diffs) / len(diffs) if diffs else 0
                if 1 <= avg_diff <= 100:
                    self._add_finding(
                        title="Sequential Number Pattern Detected",
                        severity="LOW",
                        evidence=f"Found {len(numbers)} numbers with average step {avg_diff:.1f}, suggesting sequential identifiers.",
                        recommendation="Consider using non-predictable identifiers to prevent enumeration attacks."
                    )
            except:
                pass

    def _check_sensitive_operations_exposure(self, html: str):
        """Detect sensitive operations that might lack authorization."""
        sensitive_ops = [
            r'/admin/',
            r'/settings',
            r'/billing',
            r'/payment',
            r'/upload',
            r'/delete',
            r'/export',
            r'/config',
            r'/reset',
            r'/disable',
            r'/enable'
        ]
        lower_html = html.lower()
        found_ops = []
        for op in sensitive_ops:
            if op.strip('/') in lower_html:
                found_ops.append(op.strip('/'))
        if found_ops:
            self._add_finding(
                title="Sensitive Operations Endpoints Discovered",
                severity="INFO",
                evidence=f"Found references to sensitive operations: {', '.join(set(found_ops))}",
                recommendation="Ensure all sensitive operations require proper authentication and authorization. Implement role-based access control (RBAC)."
            )

    def _check_robots_sitemap(self):
        """Check robots.txt and sitemap.xml for sensitive paths."""
        from urllib.parse import urljoin
        try:
            robots_url = urljoin(self.base_url, '/robots.txt')
            resp = self._session.get(robots_url, timeout=5)
            if resp.status_code == 200 and resp.text:
                disallowed = re.findall(r'Disallow:\s*/(\S+)', resp.text)
                sensitive = [d for d in disallowed if any(kw in d.lower() for kw in ['admin', 'private', 'internal', 'test', 'dev', 'api', 'backup'])]
                if sensitive:
                    self._add_finding(
                        title="Sensitive Paths in robots.txt",
                        severity="LOW",
                        evidence=f"robots.txt disallows sensitive-looking paths: {', '.join(sensitive[:5])}",
                        recommendation="While robots.txt is public, avoid listing truly sensitive paths. Use proper access controls instead of obscurity."
                    )
        except:
            pass
        try:
            sitemap_url = urljoin(self.base_url, '/sitemap.xml')
            resp = self._session.get(sitemap_url, timeout=5)
            if resp.status_code == 200 and resp.text:
                # Look for admin or private URLs in sitemap
                admin_urls = re.findall(r'<loc>[^<]*/(admin|internal|private|dashboard)[^<]*</loc>', resp.text, re.I)
                if admin_urls:
                    self._add_finding(
                        title="Admin URLs in Sitemap",
                        severity="LOW",
                        evidence=f"Sitemap.xml contains {len(admin_urls)} admin/management URLs.",
                        recommendation="Avoid listing administrative interfaces in sitemap.xml, as it may attract attackers."
                    )
        except:
            pass

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
            "predictable": ["CWE-330"],
            "workflow": ["CWE-636"],
            "price": ["CWE-602"],
            "sequential": ["CWE-330"],
            "sensitive operations": ["CWE-284"],
        }
        for key, cwes in mapping.items():
            if key in title_l:
                return cwes
        return []
