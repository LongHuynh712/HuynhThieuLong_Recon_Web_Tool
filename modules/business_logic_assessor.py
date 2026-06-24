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
        self._check_state_transition_validation(html)
        self._check_workflow_consistency(html)
        self._check_transaction_sequence(html)
        self._check_predictable_workflow_detection(html)

        severity = self._determine_severity()

        return {
            "test_name": "Business Logic Assessment (Passive)",
            "wstg_reference": [
                "WSTG-4.10",
                "WSTG-4.10.1 (Business Logic Data Validation)",
                "WSTG-4.10.2 (Ability to Forge Requests)",
                "WSTG-4.10.3 (Integrity Checks)",
                "WSTG-4.10.4 (Process Timing)",
                "WSTG-4.10.5 (Number of Times a Function Can Be Used)",
                "WSTG-4.10.6 (Circumvention of Workflows)",
                "WSTG-4.10.7 (Defenses Against Application Misuse)",
                "WSTG-4.10.8 (Upload of Unexpected File Types)",
            ],
            "severity": severity,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": {
                "total_findings": len(self.findings),
                "predictable_ids_found": any("predictable" in f.get("title", "").lower() for f in self.findings),
                "workflow_issues_found": any("workflow" in f.get("title", "").lower() for f in self.findings),
                "state_transition_issues": any("state transition" in f.get("title", "").lower() for f in self.findings),
                "consistency_issues": any("consistency" in f.get("title", "").lower() for f in self.findings),
                "transaction_sequence_issues": any("transaction" in f.get("title", "").lower() for f in self.findings),
                "predictable_workflow_issues": any("predictable workflow" in f.get("title", "").lower() for f in self.findings),
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

    def _check_state_transition_validation(self, html: str):
        """
        WSTG 4.10.1 / 4.10.2: State Transition Validation
        Detects state parameters, status fields, and transitions that may be
        manipulated client-side to bypass server-side state enforcement.
        """
        state_params = [
            'status', 'state', 'current_state', 'order_status', 'account_status',
            'approval_status', 'verified', 'approved', 'confirmed', 'completed',
            'active', 'inactive', 'pending', 'cancelled', 'rejected'
        ]

        # Check hidden inputs carrying state values
        hidden_inputs = re.findall(
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']*)["\'][^>]*value=["\']([^"\']*)["\'][^>]*/?>',
            html, re.IGNORECASE
        )
        # Fallback: also match name before type
        hidden_inputs += re.findall(
            r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']*)["\'][^>]*/?>',
            html, re.IGNORECASE
        )

        state_hidden_fields = []
        for name, value in hidden_inputs:
            if any(sp in name.lower() for sp in state_params):
                state_hidden_fields.append({'name': name, 'value': value})

        if state_hidden_fields:
            field_strs = [f"{fld['name']}={fld['value']}" for fld in state_hidden_fields[:5]]
            self._add_finding(
                title="State Transition Values in Hidden Fields",
                severity="HIGH",
                evidence=f"Found {len(state_hidden_fields)} hidden form fields carrying state values: "
                         f"{', '.join(field_strs)}",
                recommendation="Never rely on client-side hidden fields for state management. "
                               "Enforce all state transitions server-side with proper validation. "
                               "Use server-side session or database state tracking."
            )

        # Check URL parameters that control state
        links = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        state_url_params = []
        for link in links:
            if '?' in link:
                qs = parse_qs(urlparse(link).query)
                for param_name, param_values in qs.items():
                    if any(sp in param_name.lower() for sp in state_params):
                        state_url_params.append({
                            'param': param_name,
                            'values': param_values,
                            'url': link[:80]
                        })

        if state_url_params:
            self._add_finding(
                title="State Transition Parameters in URLs",
                severity="MEDIUM",
                evidence=f"Found {len(state_url_params)} URL parameters controlling state/status: "
                         f"{', '.join(p['param'] for p in state_url_params[:5])}",
                recommendation="URL parameters should not control critical state transitions. "
                               "Implement server-side state machines with proper validation."
            )

        # Check JavaScript state manipulation
        js_state_patterns = [
            r'\bstatus\s*=\s*["\']\w+["\'\s;]',
            r'\bstate\s*=\s*["\']\w+["\'\s;]',
            r'setState\s*\(',
            r'updateStatus\s*\(',
            r'changeState\s*\(',
        ]
        js_state_matches = []
        for pattern in js_state_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            js_state_matches.extend(matches)

        if js_state_matches:
            self._add_finding(
                title="Client-Side State Transition Manipulation",
                severity="MEDIUM",
                evidence=f"Found {len(js_state_matches)} JavaScript state manipulation patterns: "
                         f"{', '.join(m.strip()[:40] for m in js_state_matches[:5])}",
                recommendation="State transitions managed in client-side JavaScript can be tampered with. "
                               "Validate all state changes on the server and use signed tokens for state integrity."
            )

    def _check_workflow_consistency(self, html: str):
        """
        WSTG 4.10.3 / 4.10.4: Workflow Consistency Checks
        Detects integrity weaknesses in multi-step workflows: missing CSRF tokens,
        unprotected step progression, timing indicators, and consistency gaps.
        """
        # Check multi-step forms without CSRF protection
        forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
        unprotected_forms = []
        csrf_token_patterns = [
            r'csrf', r'_token', r'authenticity_token', r'__RequestVerificationToken',
            r'antiforgery', r'xsrf'
        ]

        for i, form_content in enumerate(forms):
            has_csrf = any(
                re.search(pattern, form_content, re.IGNORECASE)
                for pattern in csrf_token_patterns
            )
            has_action = bool(re.search(r'action=["\']', form_content, re.IGNORECASE))
            has_method_post = bool(re.search(r'method=["\']post["\'\s]', html, re.IGNORECASE))

            if not has_csrf and (has_action or has_method_post):
                unprotected_forms.append(i + 1)

        if unprotected_forms:
            self._add_finding(
                title="Workflow Forms Without Integrity Tokens",
                severity="HIGH",
                evidence=f"{len(unprotected_forms)} form(s) lack CSRF/integrity tokens "
                         f"(form positions: {', '.join(str(f) for f in unprotected_forms[:5])})",
                recommendation="Add CSRF tokens to all state-changing forms. Implement integrity checks "
                               "(HMAC signatures) on workflow data to prevent tampering."
            )

        # Check for step-skip indicators: links that jump between non-adjacent steps
        step_links = re.findall(
            r'href=["\'][^"\']*[?&](?:step|stage|phase)=(\d+)[^"\']*["\']',
            html, re.IGNORECASE
        )
        if len(step_links) >= 2:
            steps = sorted(set(int(s) for s in step_links))
            gaps = [steps[i+1] - steps[i] for i in range(len(steps)-1)]
            if any(g > 1 for g in gaps):
                self._add_finding(
                    title="Workflow Step Consistency Gap",
                    severity="MEDIUM",
                    evidence=f"Detected workflow steps with non-sequential progression: "
                             f"steps {steps}. Gaps suggest steps may be skippable.",
                    recommendation="Enforce sequential workflow progression server-side. "
                                   "Validate that all prerequisite steps are completed before allowing advancement."
                )

        # Detect timing-related parameters
        timing_params = ['timeout', 'timer', 'ttl', 'expires', 'deadline', 'countdown',
                         'delay', 'wait', 'duration', 'retry_after']
        timing_found = []
        for link in re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            if '?' in link:
                qs = parse_qs(urlparse(link).query)
                for param in qs:
                    if any(tp in param.lower() for tp in timing_params):
                        timing_found.append(param)
        # Also check hidden inputs for timing
        for match in re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', html, re.IGNORECASE):
            if any(tp in match.lower() for tp in timing_params):
                timing_found.append(match)

        if timing_found:
            self._add_finding(
                title="Process Timing Parameters Exposed",
                severity="LOW",
                evidence=f"Found timing-related parameters that may be manipulable: "
                         f"{', '.join(set(timing_found)[:5])}",
                recommendation="Do not expose timing controls client-side. Enforce timeouts "
                               "and deadlines server-side to prevent race condition exploitation."
            )

    def _check_transaction_sequence(self, html: str):
        """
        WSTG 4.10.5 / 4.10.6: Transaction Sequence Analysis
        Detects replay vulnerabilities, missing idempotency controls,
        re-submittable forms, and workflow circumvention indicators.
        """
        # Check for forms without idempotency keys
        forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
        idempotency_patterns = [
            r'idempotency', r'idempotent', r'request_id', r'transaction_id',
            r'nonce', r'unique_token', r'submission_id'
        ]

        forms_without_idempotency = 0
        action_forms = 0
        for form_content in forms:
            # Only check forms that perform actions (POST forms)
            form_tag = re.search(r'<form[^>]*>', form_content, re.IGNORECASE)
            is_post = bool(re.search(r'method=["\']post["\'\s]', form_content, re.IGNORECASE))
            if not is_post:
                continue
            action_forms += 1
            has_idempotency = any(
                re.search(p, form_content, re.IGNORECASE)
                for p in idempotency_patterns
            )
            if not has_idempotency:
                forms_without_idempotency += 1

        if forms_without_idempotency > 0:
            self._add_finding(
                title="Transaction Replay Risk — Missing Idempotency Controls",
                severity="MEDIUM",
                evidence=f"{forms_without_idempotency} of {action_forms} POST form(s) lack idempotency keys "
                         f"(nonce, transaction_id, etc.), allowing potential duplicate submissions.",
                recommendation="Add unique idempotency tokens to all transactional forms. "
                               "Implement server-side duplicate detection using transaction IDs."
            )

        # Detect quantity/count fields that might allow unlimited operations
        quantity_fields = re.findall(
            r'<input[^>]*name=["\']([^"\']*(?:qty|quantity|count|amount|num|repeat)[^"\']*)["\']',
            html, re.IGNORECASE
        )
        if quantity_fields:
            self._add_finding(
                title="Transaction Quantity Fields Without Apparent Limits",
                severity="MEDIUM",
                evidence=f"Found {len(quantity_fields)} quantity/count input fields: "
                         f"{', '.join(quantity_fields[:5])}",
                recommendation="Enforce server-side min/max limits on all quantity and count fields. "
                               "Implement rate limiting for transactional operations. "
                               "Validate that quantities are within acceptable business ranges."
            )

        # Detect direct action links (GET-based state changes)
        dangerous_action_links = re.findall(
            r'href=["\']([^"\']*(?:delete|remove|cancel|approve|confirm|execute|transfer|debit|credit)[^"\']*)["\']',
            html, re.IGNORECASE
        )
        if dangerous_action_links:
            self._add_finding(
                title="State-Changing Operations via GET Requests",
                severity="HIGH",
                evidence=f"Found {len(dangerous_action_links)} links that trigger state-changing actions via GET: "
                         f"{', '.join(l[:60] for l in dangerous_action_links[:3])}",
                recommendation="Never use GET requests for state-changing operations. "
                               "Use POST/PUT/DELETE with CSRF protection. "
                               "Implement confirmation steps for destructive actions."
            )

        # Detect re-submit indicators
        resubmit_patterns = [
            r'post-redirect-get',
            r'PRG',
            r'prevent.*resubmit',
            r'already.*submitted',
            r'duplicate.*submission',
        ]
        for pattern in resubmit_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                self._add_finding(
                    title="Transaction Resubmission Controls Detected",
                    severity="INFO",
                    evidence=f"Page contains references to submission control patterns (e.g., PRG pattern).",
                    recommendation="Verify that resubmission prevention is enforced server-side, "
                                   "not just via client-side checks."
                )
                break

    def _check_predictable_workflow_detection(self, html: str):
        """
        WSTG 4.10.7 / 4.10.8: Predictable Workflow Detection
        Identifies predictable workflow paths, exposed upload mechanisms,
        insufficient input type restrictions, and enumerable process endpoints.
        """
        # Check for predictable multi-step URL patterns
        step_urls = re.findall(
            r'href=["\']([^"\']*(?:step|stage|phase|wizard|checkout)[/-]?(\d+)[^"\']*)["\']',
            html, re.IGNORECASE
        )
        if step_urls:
            step_numbers = [int(s[1]) for s in step_urls if s[1].isdigit()]
            unique_steps = sorted(set(step_numbers))
            self._add_finding(
                title="Predictable Workflow Step URLs",
                severity="MEDIUM",
                evidence=f"Found {len(step_urls)} predictable workflow URLs with steps: {unique_steps}. "
                         f"Examples: {', '.join(s[0][:60] for s in step_urls[:3])}",
                recommendation="Use opaque workflow tokens instead of sequential step numbers. "
                               "Implement server-side workflow state validation that cannot be predicted or enumerated."
            )

        # Check file upload fields with insufficient type restrictions
        upload_fields = re.findall(
            r'<input[^>]*type=["\']file["\'][^>]*/?>',
            html, re.IGNORECASE
        )
        unrestricted_uploads = []
        for field in upload_fields:
            has_accept = bool(re.search(r'accept=["\']', field, re.IGNORECASE))
            if not has_accept:
                unrestricted_uploads.append(field[:80])

        if unrestricted_uploads:
            self._add_finding(
                title="Unrestricted File Upload Fields",
                severity="HIGH",
                evidence=f"Found {len(unrestricted_uploads)} file upload field(s) without "
                         f"client-side type restrictions (accept attribute missing).",
                recommendation="Add accept attributes to file inputs for client-side filtering. "
                               "ALWAYS validate file types, sizes, and content server-side. "
                               "Use allowlists for permitted MIME types and extensions."
            )

        # Detect exposed API endpoint patterns suggesting enumerable workflows
        api_patterns = re.findall(
            r'["\'](/api/v\d+/[a-z_]+/\d+(?:/[a-z_]+)?)["\']',
            html, re.IGNORECASE
        )
        if api_patterns:
            self._add_finding(
                title="Enumerable API Workflow Endpoints",
                severity="MEDIUM",
                evidence=f"Found {len(api_patterns)} API endpoints with numeric IDs suggesting enumerable workflows: "
                         f"{', '.join(api_patterns[:5])}",
                recommendation="Use UUIDs or opaque tokens instead of sequential IDs in API endpoints. "
                               "Implement proper authorization checks for each API resource."
            )

        # Detect client-side workflow navigation controls
        nav_controls = re.findall(
            r'(?:onclick|ng-click|v-on:click|@click)=["\'][^"\']*(?:next|previous|back|forward|skip|goto)[^"\']*["\']',
            html, re.IGNORECASE
        )
        if nav_controls:
            self._add_finding(
                title="Client-Side Workflow Navigation Controls",
                severity="LOW",
                evidence=f"Found {len(nav_controls)} client-side workflow navigation handlers "
                         f"(next/previous/skip buttons controlled via JavaScript).",
                recommendation="Client-side navigation should only drive UI. "
                               "All step transitions must be validated and authorized server-side. "
                               "Ensure users cannot skip required steps by manipulating JavaScript."
            )

        # Detect hardcoded workflow paths or process maps
        workflow_maps = re.findall(
            r'(?:var|let|const)\s+\w*(?:steps|workflow|process|pipeline|stages)\w*\s*=\s*\[',
            html, re.IGNORECASE
        )
        if workflow_maps:
            self._add_finding(
                title="Predictable Workflow Map Exposed in JavaScript",
                severity="MEDIUM",
                evidence=f"Found {len(workflow_maps)} JavaScript arrays defining workflow steps/stages. "
                         f"Workflow structure is visible to attackers.",
                recommendation="Do not expose complete workflow structure in client-side code. "
                               "Load only the current step information and validate progression server-side."
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
            "predictable": ["CWE-330"],
            "workflow": ["CWE-636"],
            "price": ["CWE-602"],
            "sequential": ["CWE-330"],
            "sensitive operations": ["CWE-284"],
            "state transition": ["CWE-372", "CWE-841"],
            "integrity": ["CWE-354"],
            "consistency": ["CWE-799"],
            "timing": ["CWE-367"],
            "transaction": ["CWE-799", "CWE-837"],
            "replay": ["CWE-294"],
            "idempotency": ["CWE-837"],
            "quantity": ["CWE-770"],
            "file upload": ["CWE-434"],
            "unrestricted": ["CWE-434"],
            "enumerable": ["CWE-200"],
            "navigation": ["CWE-636"],
        }
        for key, cwes in mapping.items():
            if key in title_l:
                return cwes
        return []
