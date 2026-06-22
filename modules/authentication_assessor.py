"""
OWASP WSTG 4.3 & 4.4 - Authentication Assessment (Passive)
Detects MFA, login forms, password reset, account lockout indicators, weak auth.
"""

from __future__ import annotations

import re
from typing import Any
import requests
from urllib.parse import urljoin, urlparse

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class AuthenticationAssessor:
    """Passive authentication security assessment."""

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
        """Run all authentication assessment checks."""
        # Check homepage for login/reset/MFA indicators
        try:
            resp = self._session.get(self.base_url, timeout=10)
            html = resp.text or ""
        except Exception:
            resp = None
            html = ""

        self._check_mfa(html)
        self._check_login_form(html)
        self._check_password_reset(html)
        self._check_account_lockout(html)
        self._check_weak_auth(html, resp)
        self._check_credential_transport()
        self._check_browser_cache(html, resp)
        self._check_remember_me(html)

        severity = self._determine_severity()

        return {
            "test_name": "Authentication Assessment (Passive)",
            "wstg_reference": ["WSTG-4.3", "WSTG-4.4"],
            "severity": severity,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": {
                "total_findings": len(self.findings),
                "mfa_detected": any("mfa" in f.get("title", "").lower() for f in self.findings),
                "login_form_found": any("login form" in f.get("title", "").lower() for f in self.findings),
                "password_reset_found": any("password reset" in f.get("title", "").lower() for f in self.findings),
            }
        }

    def _check_mfa(self, html: str):
        """Detect Multi-Factor Authentication indicators."""
        indicators = [
            r"two[-\s]?factor",
            r"2fa",
            r"totp",
            r"one[-\s]?time\s+password",
            r"multi[-\s]?factor",
            r"authenticator\s+app",
            r"verify\s+code",
            r"security\s+code",
            r"mfa\s+setup",
            r"enable\s+2fa"
        ]
        lower_html = html.lower()
        matches = []
        for pattern in indicators:
            if re.search(pattern, lower_html):
                matches.append(pattern)
        if matches:
            self._add_finding(
                title="Multi-Factor Authentication (MFA) Detected",
                severity="INFO",
                evidence=f"Found MFA indicators: {', '.join(matches)}",
                recommendation="Keep MFA enabled for all user accounts."
            )
        else:
            self._add_finding(
                title="No MFA Indicators Found",
                severity="MEDIUM",
                evidence="No two-factor authentication prompts or setup detected on login/account pages.",
                recommendation="Implement Multi-Factor Authentication (MFA) for all user accounts, especially privileged access."
            )

    def _check_login_form(self, html: str):
        """Detect login form presence and security attributes."""
        # Simple detection of <form> with password input
        has_password_input = bool(re.search(r'<input[^>]*type=["\']password["\']', html, re.I))
        has_login_form = bool(re.search(r'<form[^>]*(?:login|signin|authenticate)', html, re.I)) or has_password_input

        if has_login_form:
            # Check autocomplete
            autocomplete_off = bool(re.search(r'autocomplete=["\']off["\']', html, re.I))
            # Check for action attribute (should be POST)
            method_post = bool(re.search(r'<form[^>]*method=["\']post["\']', html, re.I))

            evidence = []
            if not autocomplete_off:
                evidence.append("autocomplete not explicitly off")
            if not method_post:
                evidence.append("form method not POST")
            evidence_str = "; ".join(e for e in evidence) if evidence else "Form appears properly configured"

            severity = "LOW" if evidence else "INFO"
            self._add_finding(
                title="Login Form Detected",
                severity=severity,
                evidence=f"Login form found. Details: {evidence_str}",
                recommendation="Ensure login forms use POST, autocomplete=off, and are served over HTTPS."
            )
        else:
            self._add_finding(
                title="No Login Form Detected",
                severity="INFO",
                evidence="No obvious login form found on homepage.",
                recommendation="If authentication is required, ensure login pages are discoverable and properly secured."
            )

    def _check_password_reset(self, html: str):
        """Detect password reset functionality."""
        reset_indicators = [
            r"forgot\s+password",
            r"reset\s+password",
            r"recover\s+account",
            r"password\s+recovery",
            r"reset\s+link",
            r" forgot\s+your\s+password"
        ]
        lower_html = html.lower()
        found = any(re.search(pat, lower_html) for pat in reset_indicators)
        if found:
            self._add_finding(
                title="Password Reset Functionality Detected",
                severity="INFO",
                evidence="Password reset link/button found.",
                recommendation="Ensure reset tokens are single-use, time-limited, and do not reveal user existence."
            )
        else:
            self._add_finding(
                title="No Password Reset Detected",
                severity="LOW",
                evidence="No password reset mechanism found on homepage.",
                recommendation="Provide a secure password reset flow for users."
            )

    def _check_account_lockout(self, html: str):
        """Detect account lockout indicators."""
        lockout_phrases = [
            r"account\s+locked",
            r"too\s+many\s+attempts",
            r"account\s+temporarily\s+locked",
            r"exceeded\s+login\s+attempts",
            r"account\s+disabled",
            r"please\s+try\s+again\s+later"
        ]
        lower_html = html.lower()
        found = any(re.search(pat, lower_html) for pat in lockout_phrases)
        if found:
            self._add_finding(
                title="Account Lockout Mechanism Detected",
                severity="INFO",
                evidence="Account lockout or rate limiting messages found.",
                recommendation="Account lockout is a good defense against brute force; ensure it is configured correctly (temporary, not permanent)."
            )
        else:
            self._add_finding(
                title="No Account Lockout Indicators",
                severity="MEDIUM",
                evidence="No explicit account lockout or rate limiting indicators on login page.",
                recommendation="Implement account lockout or progressive delays after multiple failed login attempts."
            )

    def _check_weak_auth(self, html: str, resp):
        """Detect weak authentication mechanisms."""
        issues = []

        # Check for HTTP Basic Auth (WWW-Authenticate header)
        if resp and "www-authenticate" in resp.headers:
            www_auth = resp.headers["www-authenticate"]
            if "basic" in www_auth.lower():
                issues.append("HTTP Basic Authentication detected (credentials base64-encoded, not secure without TLS)")
                self.recommendations.append("Replace Basic Auth with a secure form-based authentication over HTTPS.")

        # Check for autocomplete on password fields (HTML attribute)
        if re.search(r'<input[^>]*type=["\']password["\'][^>]*autocomplete=["\']on["\']', html, re.I):
            issues.append("Password field with autocomplete enabled")
            self.recommendations.append("Disable autocomplete on sensitive password fields: autocomplete='off'.")

        # Check for lack of CSRF token (if form exists)
        if re.search(r'<form', html, re.I):
            has_csrf = bool(re.search(r'csrf|_token|authenticity_token', html, re.I))
            if not has_csrf:
                issues.append("No CSRF token detected in form")
                self.recommendations.append("Implement CSRF tokens on all state-changing forms.")

        severity = "HIGH" if len(issues) >= 2 else "MEDIUM" if issues else "INFO"
        self._add_finding(
            title="Weak Authentication Indicators" if issues else "No Weak Authentication Indicators",
            severity=severity,
            evidence="; ".join(issues) if issues else "No obvious weak auth patterns detected.",
            recommendation="Use strong authentication mechanisms, avoid Basic Auth, and ensure CSRF protection."
        )

    def _check_credential_transport(self):
        """Check if credentials are transmitted securely (HTTPS)."""
        if self.base_url.startswith("https://"):
            self._add_finding(
                title="Credentials Transported Over HTTPS",
                severity="INFO",
                evidence="Site uses HTTPS, protecting credentials in transit.",
                recommendation="Ensure all pages, especially login and password reset, enforce HTTPS."
            )
        else:
            self._add_finding(
                title="Credentials Transported Over HTTP",
                severity="CRITICAL",
                evidence="Site does not use HTTPS, exposing credentials to interception.",
                recommendation="Enable HTTPS everywhere with HSTS."
            )

    def _check_browser_cache(self, html: str, resp):
        """Check for browser cache vulnerabilities."""
        cache_headers = {}
        if resp:
            for hdr in ["Cache-Control", "Pragma", "Expires"]:
                if hdr in resp.headers:
                    cache_headers[hdr] = resp.headers[hdr]

        # Check for sensitive inputs that might be cached
        has_password_field = bool(re.search(r'type=["\']password["\']', html, re.I))
        issues = []
        if has_password_field:
            # Check for cache control headers that prevent caching
            cc = cache_headers.get("Cache-Control", "").lower()
            if "private" not in cc and "no-store" not in cc and "max-age=0" not in cc:
                issues.append("Password page may be cached by browsers")
                self.recommendations.append("Add Cache-Control: no-store, no-cache, must-revalidate to pages with password fields.")

        severity = "MEDIUM" if issues else "INFO"
        self._add_finding(
            title="Browser Cache Analysis" if not issues else "Potential Cache Vulnerability",
            severity=severity,
            evidence="Cache headers present: " + str(cache_headers) if cache_headers else "No cache headers detected",
            recommendation="Ensure sensitive pages are not cached by browsers."
        )

    def _check_remember_me(self, html: str):
        """Detect 'Remember Me' functionality."""
        if re.search(r'remember\s+me|keep\s+me\s+logged\s+in', html, re.I):
            self._add_finding(
                title="Remember Me Functionality Detected",
                severity="INFO",
                evidence="'Remember me' option found on login form.",
                recommendation="Ensure remember-me tokens are secure, long-lived, and stored as persistent cookies with proper flags."
            )

    def _add_finding(self, title: str, severity: str, evidence: str, recommendation: str | None = None):
        """Add a finding with consistent structure."""
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
        """Determine overall module severity."""
        if any(f["severity"] == "CRITICAL" for f in self.findings):
            return "CRITICAL"
        if any(f["severity"] == "HIGH" for f in self.findings):
            return "HIGH"
        if any(f["severity"] == "MEDIUM" for f in self.findings):
            return "MEDIUM"
        return "INFO"

    def _map_to_cwe(self, title: str, severity: str) -> list[str]:
        """Map finding to CWE IDs (simplified)."""
        title_l = title.lower()
        mapping = {
            "mfa": ["CWE-306", "CWE-623"],
            "login": ["CWE-521"],
            "password reset": ["CWE-640"],
            "lockout": ["CWE-307"],
            "weak auth": ["CWE-287"],
            "credential": ["CWE-319"],
            "cache": ["CWE-524"],
            "remember": ["CWE-565"]
        }
        for key, cwes in mapping.items():
            if key in title_l:
                return cwes
        return []
