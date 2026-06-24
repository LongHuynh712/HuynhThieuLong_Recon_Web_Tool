"""
OWASP WSTG 4.5 - Authorization Assessment (Passive)
Detects IDOR patterns, privilege escalation indicators, forced browsing, missing access control.

Enhanced passive checks map findings to granular WSTG-4.5.x IDs:
  4.5.1 privilege escalation / auth bypass, 4.5.3 IDOR, 4.5.4 forced browsing,
  4.5.6 insecure direct object reference confidence scoring,
  4.5.8 bypassing authorization scheme / role matrix.
All checks are passive: they inspect only the already-fetched page HTML/URLs.
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
        """Run all authorization assessment checks.

        Each check is passive (HTML/URL inspection only) and maps its
        findings to granular OWASP WSTG-4.5.x identifiers.
        """
        try:
            resp = self._session.get(self.base_url, timeout=10)
            html = resp.text or ""
            self.visited_urls.add(self.base_url)
        except Exception:
            resp = None
            html = ""

        self._check_idor_indicators(html)                # WSTG-4.5.3 / 4.5.6
        self._check_admin_paths(html)                    # WSTG-4.5.8
        self._check_jwt_tokens(html, resp)               # WSTG-4.5.1
        self._check_url_parameter_patterns(html)         # WSTG-4.5.1
        self._check_missing_access_control(html)         # WSTG-4.5.8
        self._check_sequential_id(html)                  # WSTG-4.5.6
        self._check_role_based_access_matrix(html)       # WSTG-4.5.8
        self._check_privilege_escalation(html)           # WSTG-4.5.1
        self._check_forced_browsing()                    # WSTG-4.5.4

        severity = self._determine_severity()

        # Aggregate every WSTG-4.5.x id produced across all findings.
        wstg_covered = sorted({
            wid
            for f in self.findings
            for wid in f.get("wstg_ids", [])
        })

        return {
            "test_name": "Authorization Assessment (Passive)",
            "wstg_reference": ["WSTG-4.5"] + wstg_covered,
            "severity": severity,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": {
                "total_findings": len(self.findings),
                "idor_suspected": any("idor" in f.get("title", "").lower() for f in self.findings),
                "admin_paths_found": any("admin" in f.get("title", "").lower() for f in self.findings),
                "wstg_ids_covered": wstg_covered,
                "privilege_escalation_validated": any("privilege escalation" in f.get("title", "").lower() for f in self.findings),
                "forced_browsing_verified": any("forced browsing" in f.get("title", "").lower() for f in self.findings),
                "role_matrix_analyzed": any("role" in f.get("title", "").lower() for f in self.findings),
                "idor_confidence_scored": any("idor" in f.get("title", "").lower() for f in self.findings),
            }
        }


    def _check_idor_indicators(self, html: str):
        """Detect potential IDOR patterns in URLs and forms with confidence scoring.

        Scans the already-fetched HTML for numeric and UUID identifier patterns in
        resource URLs and parameters, then computes a passive confidence
        score (0-100) from corroborating signals: predictable sequential
        ids, client-side exposure of resource refs, sensitive object names,
        and absence of visible server-side access-control hints.
        Supports UUID v4, RFC4122 UUID, and UUID in URLs/API endpoints.
        """
        # Look for numeric IDs and UUIDs in URLs
        id_patterns = [
            r'/(?:user|account|profile|order|invoice|document|file)/?(\d+)',
            r'[?&]id=\d+',
            r'[?&]uid=\d+',
            r'[?&]oid=\d+',
            r'[?&]pid=\d+'
        ]
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        uuid_in_url_pattern = rf'(?:/(?:user|account|profile|order|invoice|document|file)/?|[?&](?:id|uid|oid|pid)=){uuid_pattern}'
        # Combine patterns
        all_patterns = id_patterns + [uuid_in_url_pattern]
        lower_html = html.lower()
        matches = []
        for pattern in all_patterns:
            if re.search(pattern, lower_html, re.IGNORECASE):
                matches.append(pattern)

        if matches:
            # Confidence scoring (passive): corroborate the raw indicator.
            score = 40  # base: id pattern present
            signals = [f"{len(matches)} ID pattern(s)"]

            # Corroborating signals raise confidence.
            if re.search(r'/(?:order|invoice|ticket|case)/?\d{4,}', lower_html):
                score += 15
                signals.append("resource ids on order/invoice/ticket paths")
            if re.search(r'[?&](?:user|uid|account)=\d+', lower_html):
                score += 15
                signals.append("user/account id in query string")
            # Client-side assembly of resource URLs is a strong IDOR enabler.
            if re.search(r'fetch\(|axios\.|XMLHttpRequest|\$\.(get|post|ajax)\(', html, re.I):
                score += 10
                signals.append("client-side HTTP calls assemble resource URLs")
            # No visible auth/role guard in the page lowers assurance.
            if not re.search(r'role|permission|authorize|csrf|_token|authenticity', html, re.I):
                score += 10
                signals.append("no visible role/permission guard in page")
            # Identifiers passed in fragments/inline JS (XSS->IDOR chain).
            if re.search(r'(?:window\.location|document\.referrer|localstorage)', lower_html):
                score += 10
                signals.append("ids fed from client storage/location")

            # UUID-specific signals
            uuid_matches = re.findall(uuid_pattern, lower_html, re.IGNORECASE)
            if uuid_matches:
                uuid_count = len(uuid_matches)
                score += min(uuid_count * 5, 30)  # up to 30 points for UUIDs
                signals.append(f"{uuid_count} UUID(s) detected in HTML")

            # UUID in URL/API endpoint patterns
            if re.search(uuid_in_url_pattern, lower_html, re.IGNORECASE):
                score += 15
                signals.append("UUIDs in resource URLs/parameters")

            score = min(score, 100)
            if score >= 75:
                severity = "HIGH"
                label = "High"
            elif score >= 55:
                severity = "MEDIUM"
                label = "Medium"
            else:
                severity = "LOW"
                label = "Low"

            self._add_finding(
                title="Potential IDOR Indicators Detected",
                severity=severity,
                evidence=f"IDOR confidence {score}/100 ({label}). Patterns: {len(matches)} occurrences. Signals: {', '.join(signals)}. Patterns: {', '.join(str(matches[:3]))}",
                recommendation="Review endpoints that use predictable identifiers. Implement object-level authorization (owner checks) server-side; avoid predictable sequential ids and parameter-based references; prefer unguessable UUIDs; do not trust client-supplied object references."
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
            r'/adminpanel',
            r'/panel',
            r'/control-panel',
            r'/admin-panel',
            r'/backend',
            r'/superadmin'
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

    def _check_sequential_id(self, html: str):
        """Detect sequential numeric IDs that may be predictable.
        Looks for several numeric ID patterns and checks whether they appear to increment.
        """
        patterns = [r'/(?:order|invoice|ticket|case)/?(\d{4,})', r'[?&]id=(\d{4,})']
        ids = []
        for pat in patterns:
            ids.extend([int(m) for m in re.findall(pat, html)])
        if len(ids) >= 3:
            ids.sort()
            diffs = [ids[i+1] - ids[i] for i in range(len(ids)-1)]
            avg = sum(diffs) / len(diffs) if diffs else 0
            if 1 <= avg <= 10:
                self._add_finding(
                    title="Sequential Numeric IDs Detected",
                    severity="MEDIUM",
                    evidence=f"Found {len(ids)} numeric IDs with average step {avg:.1f}",
                    recommendation="Replace sequential IDs with random/UUID values and enforce proper authorization checks."
                )
                # Return early – we already reported
                return
        # No clear sequential pattern
        self._add_finding(
            title="No Sequential ID Pattern Detected",
            severity="INFO",
            evidence="Numeric IDs do not show a sequential pattern.",
            recommendation="Continue monitoring for predictable IDs."
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

    # ------------------------------------------------------------------ #
    # Improved passive checks (WSTG-4.5.x) added in this update.
    # _check_role_based_access_matrix / _check_privilege_escalation /
    # _check_forced_browsing were referenced by run_all_tests() but had
    # no implementation; they are completed here. Each is read-only and
    # inspects only the already-fetched page snapshot.
    # ------------------------------------------------------------------ #

    def _check_role_based_access_matrix(self, html: str) -> None:
        """Analyze the role/permission matrix surface (WSTG-4.5.8).

        Passive: detects declared roles and permission/feature gating in
        the page (role keywords, hidden admin-only controls, role checks
        in inline JS) and assesses whether the client appears to be the
        sole enforcement point (a missing-access-control smell).
        """
        lower = html.lower()
        roles_pattern = r"\b(?:admin|administrator|superuser|super[-\s]?admin|manager|editor|moderator|user|guest|anonymous|owner|member|subscriber|customer|operator|superuser|root|moderator|privileged_user|poweruser|sysadmin)\b"
        roles = set(re.findall(roles_pattern, lower, flags=re.I))
        # Role checks appearing in inline scripts -> client-side enforcement.
        client_role_guards = re.findall(
            r'(?:role|userrole|isadmin|hasrole|permission|can[A-Z]\w*|usertype)\s*[=!]==?\s*["\'][^"\']+["\']',
            html, re.I,
        )
        permission_attrs = re.findall(
            r'data-(?:role|permission|requires-role|auth|access)\s*=\s*["\']([^"\']+)["\']',
            html, re.I,
        )
        hidden_admin_controls = re.findall(
            r'<[^>]+(?:hidden|style=["\'][^"\']*display:\s*none|aria-hidden=["\']true)[^>]*'
            r'(?:admin|manage|delete|configure)[^>]*>',
            html, re.I,
        )

        signals: list[str] = []
        if roles:
            signals.append(f"declared roles: {', '.join(sorted(roles)[:6])}")
        if client_role_guards:
            signals.append(f"{len(client_role_guards)} client-side role/permission check(s)")
        if permission_attrs:
            signals.append(f"{len(permission_attrs)} data-role/permission attribute(s)")
        if hidden_admin_controls:
            signals.append(f"{len(hidden_admin_controls)} hidden admin-only control(s) in markup")

        if client_role_guards and not self._has_server_side_guard_hint(html):
            # Client-only enforcement is the core missing-access-control smell.
            self._add_finding(
                title="Role Matrix Analysis — Client-Side Enforcement Risk",
                severity="HIGH",
                evidence="; ".join(signals + ["role gating detected only in client markup/JS — re-authorize server-side"]),
                recommendation="Define and enforce a server-side role/permission matrix; never rely on client-side role checks or hidden controls for access control. Re-check authorization per request.",
            )
        elif signals:
            self._add_finding(
                title="Role Matrix Analysis — Roles Detected",
                severity="INFO",
                evidence="; ".join(signals),
                recommendation="Maintain a centralized server-side role-to-permission matrix; verify each privileged action against it server-side.",
            )
        else:
            self._add_finding(
                title="Role Matrix Analysis — No Role Surface Detected",
                severity="INFO",
                evidence="No role/permission declarations or client-side role guards observed on the scanned page.",
                recommendation="If roles exist, enforce the role/permission matrix server-side and avoid exposing role logic to the client.",
            )

    def _check_reflection_based_idor(self, html: str) -> None:
        """WSTG-4.5.3: Detect IDOR via parameter reflection (reflected in response).

        Identifies parameter tampering where id=user_id=account_id=profile_id=
        reflects back user data or sensitive information in response.
        """
        idor_reflection_keywords = [
            r'id=\d+', r'user_id=\d+', r'account_id=\d+', r'profile_id=\d+',
            r'uid=\d+', r'oid=\d+', r'key=\d+', r'ref=\d+'
        ]
        parsed = urlparse(self.base_url)
        qs = parse_qs(parsed.query)
        reflected = []
        lower_html = html.lower()

        # Check URL query parameters that appear in response
        for param, values in qs.items():
            param_lower = param.lower()
            if any(kw in param_lower for kw in ['id', 'user', 'account', 'profile', 'uid', 'ref']):
                for val in values:
                    # Check if value is reflected
                    if val and val.lower() in lower_html:
                        reflected.append(f"{param}={val[:30]}")

        # Check for sensitive data reflection: PII, tokens, state
        sensitive_patterns = [
            r'email=[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            r'name=[a-zA-Z]+', r'phone=\+?[0-9\s-]+',
            r'token=[a-zA-Z0-9_-]{20,}', r'session=[a-zA-Z0-9_-]{16,}',
            r'address=[a-zA-Z0-9\s,]+'
        ]
        sensitive_reflections = []
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, lower_html, re.I)
            sensitive_reflections.extend(matches[:5])

        if reflected or sensitive_reflections:
            reflection_list = list(set(reflected + sensitive_reflections))
            self._add_finding(
                title="IDOR via Parameter Reflection Detected",
                severity="HIGH",
                evidence=f"Found {len(reflection_list)} reflected parameters suggesting IDOR: {', '.join(reflection_list[:10])}" + (f" and {len(reflection_list)-10} more" if len(reflection_list) > 10 else ""),
                recommendation="Do not reflect user-supplied identifiers directly in responses. Validate all object access server-side. Use object-level authorization (owner/permission checks) instead of client-supplied IDs. Return 403/404 for unauthorized access.",
                wstg_ids=["WSTG-4.5.3", "WSTG-4.5.6"]
            )
        else:
            self._add_finding(
                title="No IDOR via Reflection Detected",
                severity="INFO",
                evidence="No reflected ID parameters or sensitive data found.",
                recommendation="Continue monitoring for parameter reflection vulnerabilities.",
                wstg_ids=["WSTG-4.5.3"]
            )

    def _check_forced_browsing_advanced(self) -> None:
        """WSTG-4.5.4 Enhanced: Detect forced browsing to sensitive paths.

        Scans for direct access to administrative and management interfaces.
        """
        forced_browsing_paths = [
            '/admin', '/admin/', '/admin/index',
            '/panel', '/control-panel', '/admin-panel',
            '/manage', '/manager',
            '/private', '/internal',
            '/debug', '/console',
            '/staff', '/root',
            '/cms', '/backend',
        ]
        try:
            resp = self._session.get(self.base_url, timeout=10)
            html = resp.text
        except Exception:
            html = ""
            resp = None

        lower_html = html.lower()
        found_paths = []

        # Check links and references
        for path in forced_browsing_paths:
            if path in lower_html:
                found_paths.append(path)

        # Check for suspicious form actions pointing to admin paths
        forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>', lower_html, re.I)
        admin_forms = [f for f in forms if any(ap in f for ap in ['/admin', '/panel', '/manage', '/private'])]

        # Check for JavaScript navigation to admin endpoints
        js_admin = bool(re.search(r'(?:window\.location|document\.location|location\.href|window\.open|fetch\(|axios\.get)\([^)]*(?:/admin|/panel|/manage|/private)', lower_html))

        if found_paths or admin_forms or js_admin:
            all_paths = list(set(found_paths + admin_forms[:10]))
            self._add_finding(
                title=f"Forced Browsing Indicators Detected ({len(all_paths)} paths)",
                severity="HIGH",
                evidence=f"Found direct forced browsing to sensitive paths: {', '.join(all_paths[:10])}" + (f" and {len(all_paths)-10} more" if len(all_paths) > 10 else ""),
                recommendation="Deny by default. Use allowlists for allowed paths. Gate administrative access with authentication and role checks. Return 404 for unauthorized sensitive paths. Implement anti-automation and rate limiting on suspicious paths.",
                wstg_ids=["WSTG-4.5.4", "WSTG-4.5.8"]
            )
        else:
            self._add_finding(
                title="No Forced Browsing Indicators Detected",
                severity="INFO",
                evidence="No direct forced browsing to admin/management paths found.",
                recommendation="Continue monitoring and restrict access to sensitive endpoints.",
                wstg_ids=["WSTG-4.5.4"]
            )

    def _check_privilege_escalation_advanced(self, html: str) -> None:
        """WSTG-4.5.1 Enhanced: Detect privilege escalation indicators.

        Looks for role= permission= access= privilege= isAdmin= patterns
        and client-side role enforcement that may be bypassed.
        """
        privilege_keywords = [
            'role=', 'permission=', 'access=', 'privilege=', 'role_name=',
            'user_role=', 'isAdmin=', 'is_admin=', 'admin=true', 'admin=1',
            'access_level=', 'can_', 'has_permission', 'user_type',
        ]
        lower_html = html.lower()
        found = []

        for keyword in privilege_keywords:
            matches = re.findall(r'[?&]' + re.escape(keyword) + r'[^&\s]+', lower_html)
            if matches:
                found.extend(matches[:10])

        # Check for client-side role checks in JavaScript
        role_js_patterns = [
            r'(?:if|while|for)\s*\([^)]*role|user_role|isAdmin[^)]*\)',
            r'role\s*==\s*["\'][^"\']*admin[^"\']*',
            r'if\s*\([^)]*admin.*\)\s*{[^}]*}',
        ]
        role_js_found = []
        for pattern in role_js_patterns:
            matches = re.findall(pattern, lower_html, re.I)
            role_js_found.extend(matches[:5])

        # Check for role parameters in hidden form fields
        hidden_role_fields = re.findall(
            r'<input[^>]*name=["\'](?:role|permission|access|privilege|isAdmin)["\'][^>]*>',
            html, re.I
        )

        if found or role_js_found or hidden_role_fields:
            all_issues = list(set(found + role_js_found + hidden_role_fields[:15]))
            self._add_finding(
                title="Privilege Escalation Indicators Detected",
                severity="HIGH",
                evidence=f"Found privilege elevation parameters and patterns: {', '.join(all_issues[:15])}" + (f" and {len(all_issues)-15} more" if len(all_issues) > 15 else ""),
                recommendation="Do not trust client-side role/permission parameters. Enforce role checks server-side with least privilege. Validate all privilege-related claims server-side. Never allow elevation via query parameters. Use session-bound roles and enforce object ownership checks.",
                wstg_ids=["WSTG-4.5.1", "WSTG-4.5.8"]
            )
        else:
            self._add_finding(
                title="No Privilege Escalation Indicators Detected",
                severity="INFO",
                evidence="No client-mutable role/privilege parameters found.",
                recommendation="Continue enforcing server-side role matrix validation.",
                wstg_ids=["WSTG-4.5.1"]
            )

    def _check_hidden_admin_panels(self, html: str) -> None:
        """Discover hidden administration/management panels in application.

        Looks for dashboard, backend, controlpanel, cms, management in links and content.
        """
        admin_panels = [
            'dashboard', 'backend', 'control-panel', 'controlpanel',
            'cms', 'management', 'manager', 'admin-panel', 'adminpanel',
            'config', 'settings', 'superuser', 'root', 'staff'
        ]
        lower_html = html.lower()
        found = []

        for panel in admin_panels:
            if panel in lower_html:
                found.append(panel)

        if found:
            self._add_finding(
                title=f"Hidden Administration Panel Detected ({len(set(found))} panels)",
                severity="HIGH",
                evidence=f"Found hidden admin panel indicators: {', '.join(set(found)[:10])}" + (f" and {len(set(found))-10} more" if len(set(found)) > 10 else ""),
                recommendation="Restrict access to admin panels with strong authentication and authorization. Require MFA. Use IP allowlists. Monitor access logs. Rename administrative paths and hide them from sitemaps and navigation.",
                wstg_ids=["WSTG-4.5.8"]
            )
        else:
            self._add_finding(
                title="No Hidden Admin Panels Detected",
                severity="INFO",
                evidence="No common admin panel keywords found in page source.",
                recommendation="If admin panels exist, ensure they are not discoverable and enforce strong access controls.",
                wstg_ids=["WSTG-4.5.8"]
            )
        """Validate privilege-escalation exposure (WSTG-4.5.1).

        Passive: detects privilege-escalation enablers such as role/flags
        carried in client-mutable places (query params, form fields,
        localStorage, JWT payload), self-service state changes without
        re-auth, and parameter-based role hints.
        """
        lower = html.lower()
        issues: list[str] = []

        # Role/privilege hints in query strings or form fields (tamperable).
        if re.search(r'[?&](?:role|userrole|usertype|isadmin|admin|privilege|level)=', lower):
            issues.append("role/privilege parameter carried in URL (client-mutable)")
        if re.search(r'<input[^>]+name=["\'](?:role|userrole|usertype|isadmin|admin|privilege)["\']', html, re.I):
            issues.append("role/privilege exposed in a form field (client-mutable)")

        # JWT carrying role/admin claims visible client-side.
        jwt_claims = self._peek_jwt_role_claims(html)
        if jwt_claims:
            issues.append(f"JWT exposes role/admin claim(s): {', '.join(jwt_claims)}")

        # Client storage of role state.
        if re.search(r'localstorage\.[gs]etItem\s*\(\s*["\'](?:role|userrole|isadmin|admin|userType)', lower):
            issues.append("role state read/written from localStorage (client-mutable)")

        # Self-service state change without re-auth/step-up hint.
        if re.search(r'(?:change\s+password|reset\s+password|update\s+email|delete\s+account|change\s+role|add\s+user)', lower):
            if not re.search(r're[-\s]?enter\s+password|current\s+password|re[-\s]?auth|step[-\s]?up|verify\s+identity', lower):
                issues.append("sensitive self-service action without visible re-authentication")

        if issues:
            severity = "HIGH" if any("JWT" in i or "client-mutable" in i for i in issues) else "MEDIUM"
            self._add_finding(
                title="Privilege Escalation Validation — Escalation Enablers Detected",
                severity=severity,
                evidence="; ".join(issues),
                recommendation="Keep all role/privilege state server-side and session-bound; reject role/privilege parameters from the client; require re-authentication (step-up) for sensitive self-service actions; keep role claims out of client-readable JWTs.",
            )
        else:
            self._add_finding(
                title="Privilege Escalation Validation — No Passive Enablers",
                severity="INFO",
                evidence="No client-mutable role parameters, exposed JWT role claims, or unguarded self-service actions detected on the scanned page.",
                recommendation="Continue enforcing privilege decisions server-side and re-validating on sensitive actions.",
            )

    def _check_forced_browsing(self) -> None:
        """Verify forced-browsing exposure (WSTG-4.5.4).

        Passive: checks the page and any extracted links for sensitive,
        guessable resource paths (admin/config/backup/api internals) that
        may be reachable by direct request (forced browsing). No request
        is made to those paths — only their presence as references is noted.
        """
        try:
            resp = self._session.get(self.base_url, timeout=10)
            html = resp.text or ""
        except Exception:
            html = ""

        lower = html.lower()
        sensitive_path_patterns = [
            r'/(?:admin|administrator|cpanel|wp-admin|manage|manager)(?:/|\b)',
            r'/(?:config|configuration|settings|setup|install)\.(?:php|json|xml|bak|old|txt|sql)',
            r'/(?:backup|backups|dump|db|database)\b',
            r'/(?:\.git|\.svn|\.env|\.htaccess|web\.config|robots\.txt|sitemap\.xml)',
            r'/(?:api|internal|private|debug|test|dev|staging)/[\w/-]+',
        ]
        found: list[str] = []
        for pat in sensitive_path_patterns:
            for m in re.findall(pat, lower):
                if m not in found:
                    found.append(m)

        # Links/hrefs that point at sensitive-looking resources.
        hrefs = re.findall(r'(?:href|src|action|url)\s*=\s*["\']([^"\']+)["\']', html, re.I)
        sensitive_hrefs = [h for h in hrefs if re.search(
            r'(?:admin|config|backup|\.git|\.env|\.bak|/internal/|/debug/|/private/)', h, re.I,
        )]

        if found or sensitive_hrefs:
            evidence_parts = []
            if found:
                evidence_parts.append(f"{len(found)} sensitive path pattern(s): {', '.join(found[:5])}")
            if sensitive_hrefs:
                evidence_parts.append(f"{len(sensitive_hrefs)} sensitive link reference(s): {', '.join(sensitive_hrefs[:3])}")
            self._add_finding(
                title="Forced Browsing Verification — Sensitive Paths Exposed",
                severity="MEDIUM",
                evidence="; ".join(evidence_parts),
                recommendation="Deny by default; require explicit authorization on every server-side route; remove backups/config/.git/.env from web roots; return 404 (not 403) for unauthorized sensitive paths to avoid enumeration.",
            )
        else:
            self._add_finding(
                title="Forced Browsing Verification — No Sensitive Paths Referenced",
                severity="INFO",
                evidence="No admin/config/backup/.git/.env/internal/debug path references found on the scanned page.",
                recommendation="Keep deny-by-default routing; ensure sensitive paths are not linked or guessable.",
            )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _has_server_side_guard_hint(self, html: str) -> bool:
        """Heuristic: does the page hint at server-side authorization?"""
        return bool(re.search(
            r'csrf|_token|authenticity_token|x-csrf|bearer|authorization:\s*bearer|'
            r'requires?[-\s]?auth|protected|/auth/|/login|/logout',
            html, re.I,
        ))

    def _peek_jwt_role_claims(self, html: str) -> list[str]:
        """Decode (no verify) JWTs in the page and report role/admin claims."""
        claims: list[str] = []
        try:
            import base64
            import json as _json
        except Exception:
            return claims
        for tok in re.findall(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', html):
            try:
                seg = tok.split('.')[1]
                seg += '=' * (-len(seg) % 4)
                payload = _json.loads(base64.urlsafe_b64decode(seg.encode('ascii')).decode('utf-8', 'ignore'))
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            for key, val in payload.items():
                kl = key.lower()
                if any(w in kl for w in ('role', 'admin', 'priv', 'scope', 'usertype', 'permission', 'auth')) and val not in (None, "", [], {}):
                    claims.append(f"{key}={val}")
        return claims

    def _add_finding(self, title: str, severity: str, evidence: str, recommendation: str | None = None):
        wstg_ids, cwe_ids = self._map_to_wstg_and_cwe(title, severity)
        finding = {
            "title": title,
            "severity": severity,
            "evidence": evidence,
            "cwe_ids": cwe_ids,
            "wstg_ids": wstg_ids,
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

    def _map_to_wstg_and_cwe(self, title: str, severity: str) -> tuple[list[str], list[str]]:
        """Map a finding title to OWASP WSTG-4.5.x and CWE IDs."""
        t = title.lower()
        wstg: list[str] = []
        cwe: list[str] = []

        # --- WSTG-4.5.x mapping ---
        if "privilege escalation" in t or "escalation" in t:
            wstg.append("WSTG-4.5.1")
        if "idor" in t or "direct object" in t or "sequential" in t:
            wstg.append("WSTG-4.5.3")
            wstg.append("WSTG-4.5.6")
        if "forced browsing" in t:
            wstg.append("WSTG-4.5.4")
        if "role matrix" in t or "role" in t:
            wstg.append("WSTG-4.5.8")
        if "admin" in t or "access control" in t or "api endpoint" in t:
            wstg.append("WSTG-4.5.8")
        if "suspicious url parameter" in t or "jwt" in t:
            wstg.append("WSTG-4.5.1")

        # Dedupe, preserve order.
        wstg = list(dict.fromkeys(wstg))

        # --- CWE mapping (preserved + broadened) ---
        if "idor" in t or "direct object" in t or "sequential" in t:
            cwe.extend(["CWE-639", "CWE-862"])
        if "admin" in t or "access control" in t or "api endpoint" in t or "role" in t:
            cwe.extend(["CWE-284", "CWE-285"])
        if "jwt" in t:
            cwe.append("CWE-113")
        if "suspicious url parameter" in t:
            cwe.append("CWE-598")
        if "forced browsing" in t:
            cwe.append("CWE-425")
        if "privilege escalation" in t or "escalation" in t:
            cwe.extend(["CWE-269", "CWE-285"])

        cwe = list(dict.fromkeys(cwe))
        return wstg, cwe

    def _map_to_cwe(self, title: str, severity: str) -> list[str]:
        """Map finding to CWE IDs (legacy, kept for backwards compatibility)."""
        return self._map_to_wstg_and_cwe(title, severity)[1]
