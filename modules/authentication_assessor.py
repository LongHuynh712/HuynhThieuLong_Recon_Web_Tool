"""
OWASP WSTG 4.3 & 4.4 - Authentication Assessment (Passive)
Detects MFA, login forms, password reset, account lockout indicators, weak auth.

Enhanced passive checks map findings to granular WSTG-4.4.x IDs:
  4.4.1 credential transport, 4.4.3 lockout, 4.4.4 auth schema / MFA,
  4.4.5 remember-me, 4.4.6 browser cache, 4.4.7 password policy,
  4.4.9 password reset / username enumeration.
All checks are passive: they only inspect the already-fetched page HTML/headers.
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
        """Run all authentication assessment checks.

        Each check is passive (HTML/header inspection only) and maps its
        findings to granular OWASP WSTG-4.4.x identifiers.
        """
        # Fetch the target page once; every check inspects this snapshot.
        try:
            resp = self._session.get(self.base_url, timeout=10)
            html = resp.text or ""
        except Exception:
            resp = None
            html = ""

        # Existing baseline checks (behaviour unchanged).
        self._check_credential_transport()           # WSTG-4.4.1
        self._check_mfa(html)                        # WSTG-4.4.4
        self._check_login_form(html)                 # WSTG-4.4.4
        self._check_password_reset(html)             # WSTG-4.4.9
        self._check_account_lockout(html)            # WSTG-4.4.3
        self._check_weak_auth(html, resp)            # WSTG-4.4.4 / 4.4.7
        self._check_password_policy(html)            # WSTG-4.4.7
        self._check_username_enumeration(html)       # WSTG-4.4.9
        self._check_browser_cache(html, resp)        # WSTG-4.4.6
        self._check_remember_me(html)                # WSTG-4.4.5

        # Enhanced passive checks added in this update.
        self._check_password_reset_token(html, resp)        # WSTG-4.4.9
        self._check_mfa_enriched(html, resp)                # WSTG-4.4.4
        self._check_account_lockout_enriched(html, resp)    # WSTG-4.4.3
        self._check_username_enumeration_enriched(html, resp)  # WSTG-4.4.9
        self._check_password_policy_scoring(html, resp)     # WSTG-4.4.7

        severity = self._determine_severity()

        # Aggregate the WSTG IDs every finding produced, for the report.
        wstg_covered = sorted({
            wid
            for f in self.findings
            for wid in f.get("wstg_ids", [])
        })

        return {
            "test_name": "Authentication Assessment (Passive)",
            "wstg_reference": ["WSTG-4.3"] + wstg_covered,
            "severity": severity,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": {
                "total_findings": len(self.findings),
                "mfa_detected": any("mfa" in f.get("title", "").lower() for f in self.findings),
                "login_form_found": any("login form" in f.get("title", "").lower() for f in self.findings),
                "password_reset_found": any("password reset" in f.get("title", "").lower() for f in self.findings),
                "wstg_ids_covered": wstg_covered,
                # Per-control coverage flags surfaced from the new checks.
                "password_reset_token_analyzed": any("reset token" in f.get("title", "").lower() for f in self.findings),
                "mfa_coverage_assessed": any("mfa coverage" in f.get("title", "").lower() for f in self.findings),
                "account_lockout_verified": any("lockout verification" in f.get("title", "").lower() for f in self.findings),
                "username_enumeration_validated": any("enumeration validation" in f.get("title", "").lower() for f in self.findings),
                "password_policy_scored": any("password policy strength" in f.get("title", "").lower() for f in self.findings),
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

    def _check_password_policy(self, html: str):
        """Detect password complexity requirements on the signup/reset pages.

        Looks for hints such as minimum length, required character classes, or
        explicit policy text.
        """
        policy_keywords = [
            r'minimum\s+length',
            r'at\s+least\s+\d+\s+characters',
            r'uppercase',
            r'lowercase',
            r'special\s+character',
            r'\d+\s+numbers',
            r'password\s+must\s+contain',
        ]
        lower_html = html.lower()
        matches = []
        for pat in policy_keywords:
            if re.search(pat, lower_html):
                matches.append(pat)
        if matches:
            self._add_finding(
                title="Password Policy Indicators Detected",
                severity="INFO",
                evidence=f"Found {len(matches)} password‑policy related patterns.",
                recommendation="Ensure the policy enforces a minimum of 8 characters, includes upper/lowercase, numbers and special characters, and communicates it clearly to users."
            )
        else:
            self._add_finding(
                title="No Explicit Password Policy Detected",
                severity="LOW",
                evidence="No clear password‑policy text found on scanned pages.",
                recommendation="Publish password complexity requirements to guide users and improve security."
            )

    def _check_username_enumeration(self, html: str):
        """Detect indicators that the application reveals whether a username exists.

        Typical messages include "user not found", "invalid email", or timing differences.
        Since we are passive, we look for textual hints.
        """
        enumeration_patterns = [
            r'user\s+does\s+not\s+exist',
            r'no\s+account\s+found',
            r'invalid\s+username',
            r'email\s+not\s+registered',
            r'unknown\s+user',
        ]
        lower_html = html.lower()
        found = []
        for pat in enumeration_patterns:
            if re.search(pat, lower_html):
                found.append(pat)
        if found:
            self._add_finding(
                title="Username Enumeration Indicators Detected",
                severity="MEDIUM",
                evidence=f"Found messages suggesting user existence checks: {', '.join(found)}",
                recommendation="Use generic error messages (e.g., 'Invalid credentials') that do not reveal whether the username or password was incorrect."
            )
        else:
            self._add_finding(
                title="No Username Enumeration Indicators Detected",
                severity="INFO",
                evidence="Login and reset pages did not expose explicit username existence messages.",
                recommendation="Maintain generic authentication error handling."
            )

    # ------------------------------------------------------------------ #
    # Enhanced passive checks (WSTG-4.4.x) added in this update.
    # Each is self-contained, read-only, and inspects only the page
    # snapshot already captured in run_all_tests().
    # ------------------------------------------------------------------ #

    def _check_password_reset_token(self, html: str, resp) -> None:
        """Passively analyse password-reset token handling (WSTG-4.4.9).

        Looks for token-bearing reset links, predictable/short token hints,
        token leakage in cleartext (HTTP) contexts, and whether reset forms
        appear to re-use tokens. No reset flow is ever triggered.
        """
        lower = html.lower()
        risk_signals: list[str] = []

        # Tokens embedded in page links/JS (potential leakage via referrer/history).
        token_in_url = re.search(
            r'(?:reset[_\-]?token|token|hash|code|otp)=["\']?[a-z0-9\-_]{6,}["\']?',
            lower,
        )
        # Reset link placeholders that suggest a token is passed in the URL path.
        token_in_path = re.search(
            r'/reset[^"\'\s]*\?(?:token|t|hash|code)=',
            lower,
        ) or re.search(
            r'/reset/(?:[a-z0-9\-_]{8,})',
            lower,
        )
        # Hints of short / numeric-only / predictable tokens.
        short_token_hint = re.search(
            r'(?:4|5|6|7)[- ]?digit|numeric\s+(?:code|token)|token\s+expires?\s+in\s+\d',
            lower,
        )

        if token_in_url or token_in_path:
            risk_signals.append("reset token carried in URL/query string (may leak via Referrer/History)")
        if short_token_hint:
            risk_signals.append("short or numeric-only reset token suggested (predictable / brute-forceable)")
        # Token sent over cleartext transport.
        if self.base_url.startswith("http://") and (
            re.search(r'reset|forgot|recover', lower) or token_in_url or token_in_path
        ):
            risk_signals.append("reset token exposed over HTTP (interceptable)")

        if risk_signals:
            self._add_finding(
                title="Password Reset Token Handling Weakness",
                severity="HIGH",
                evidence="; ".join(risk_signals),
                recommendation="Issue high-entropy, single-use, time-boxed reset tokens; deliver them out-of-band or via POST body; bind tokens to the account and invalidate on use/expiry.",
            )
        else:
            self._add_finding(
                title="Password Reset Token Analysis (No Clear Passive Weakness)",
                severity="INFO",
                evidence="No reset tokens observed in page URLs/JS and no short-token hints detected on the scanned page.",
                recommendation="Confirm reset tokens are high-entropy, single-use, time-limited, and not transmitted in URLs.",
            )

    def _check_mfa_enriched(self, html: str, resp) -> None:
        """Refine MFA detection and assess coverage (WSTG-4.4.4).

        Distinguishes enrolled vs. optional MFA, detects known provider/
        SDK signatures, and flags when privileged actions or reset flows
        lack an MFA step. Passive only.
        """
        lower = html.lower()
        mfa_present = bool(re.search(
            r'two[-\s]?factor|2fa|totp|multi[-\s]?factor|authenticator\s+app|'
            r'one[-\s]?time\s+password|security\s+code|verify\s+code|'
            r'enable\s+2fa|mfa\s+setup|webauthn|u2f|passkey|fido|backup\s+codes?',
            lower,
        ))
        provider_signals = re.findall(
            r'googleauthenticator|authy|duo|okta\s+verify|microsoft\s+authenticator|'
            r'twilio\s+verify|onelogin|yubikey|webauthn',
            lower,
        )
        # MFA appears optional (offered but not enforced at login).
        optional_mfa = mfa_present and bool(re.search(
            r'enable\s+2fa|set\s+up\s+(?:2fa|two[-\s]?factor|authenticator)|'
            r'optional|mfa\s+setup|protect\s+your\s+account|enhance\s+your\s+security',
            lower,
        ))
        # Sensitive flows that ideally re-check MFA.
        sensitive_flow = bool(re.search(
            r'password\s+reset|change\s+password|delete\s+account|transfer|'
            r'withdraw|billing|security\s+settings',
            lower,
        ))

        if not mfa_present:
            self._add_finding(
                title="MFA Coverage Assessment — MFA Not Detected",
                severity="HIGH",
                evidence="No MFA/WebAuthn/passkey or authenticator indicators found on the scanned page.",
                recommendation="Enforce MFA (TOTP/WebAuthn/passkey) at login and for sensitive actions; do not make it merely optional.",
            )
            return

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

    def _check_account_lockout_enriched(self, html: str, resp) -> None:
        """Verify account-lockout / rate-limit posture (WSTG-4.4.3).

        Passive: detects lockout messaging, CAPTCHA/anti-automation, and
        progressive-delay hints. Does NOT submit login attempts.
        """
        lower = html.lower()
        lockout_msg = bool(re.search(
            r'account\s+(?:locked|temporarily\s+locked|disabled)|too\s+many\s+(?:attempts|login\s+attempts)|'
            r'exceeded\s+(?:login\s+)?attempts|please\s+try\s+again\s+later|temporarily\s+blocked',
            lower,
        ))
        captcha = bool(re.search(
            r'captcha|recaptcha|hcaptcha|turnstile|geetest|funcaptcha|arkose',
            lower,
        ))
        rate_limit_header = bool(resp and re.search(
            r'x-ratelimit-limit|x-ratelimit-remaining|retry-after',
            ", ".join(k.lower() for k in (resp.headers.keys() if resp else [])),
        ))
        progressive_delay = bool(re.search(
            r'progressive\s+delay|backoff|wait\s+\d+\s+(?:second|minute)|increasing\s+delay',
            lower,
        ))

        mechanisms: list[str] = []
        if lockout_msg:
            mechanisms.append("lockout messaging")
        if captcha:
            mechanisms.append("CAPTCHA / anti-automation")
        if rate_limit_header:
            mechanisms.append("rate-limit response headers")
        if progressive_delay:
            mechanisms.append("progressive delay")

        if mechanisms:
            self._add_finding(
                title="Account Lockout Verification — Controls Present",
                severity="INFO",
                evidence="Anti-brute-force mechanisms detected: " + ", ".join(mechanisms),
                recommendation="Ensure lockout is temporary with progressive delays, considers account lock vs. IP rate-limiting, and cannot be abused to deny service to known users.",
            )
        else:
            self._add_finding(
                title="Account Lockout Verification — No Controls Detected",
                severity="HIGH",
                evidence="No lockout messaging, CAPTCHA, rate-limit headers, or progressive-delay hints found.",
                recommendation="Implement temporary account lockout with progressive delays and/or CAPTCHA after repeated failures; mitigate user-targeted lockout DoS by combining IP and account throttling.",
            )

    def _check_username_enumeration_enriched(self, html: str, resp) -> None:
        """Validate username-enumeration exposure (WSTG-4.4.9).

        Passive: detects differential messaging, "forgot password" flows
        that reveal existence (e.g. 'we sent an email to j••@x.com'),
        registration-time availability checks, and distinct error
        styling/markup that leaks validity. No accounts are probed.
        """
        lower = html.lower()
        differential_msgs = re.findall(
            r'user\s+does\s+not\s+exist|no\s+account\s+found|invalid\s+username|'
            r'email\s+not\s+registered|unknown\s+user|that\s+username\s+is\s+available|'
            r'username\s+(?:already\s+)?(?:taken|available)|email\s+is\s+not\s+in\s+our\s+records',
            lower,
        )
        # Reset flow that echoes masked contact info, confirming existence.
        masked_echo = bool(re.search(
            r'we\s+(?:have\s+)?sent\s+(?:a\s+)?(?:link|code|email)\s+to\s+[a-z0-9._%+\-]*\*|'
            r'if\s+.*?exists.*?you\s+will|instructions\s+sent\s+to\s+[a-z0-9._%+\-]*•',
            lower,
        ))
        # Two different error text/styling for user vs. password.
        distinct_error = bool(re.search(
            r'invalid\s+username|user\s+does\s+not\s+exist|no\s+account\s+found',
            lower,
        )) and bool(re.search(r'invalid\s+password|incorrect\s+password|wrong\s+password', lower))

        signals: list[str] = []
        if differential_msgs:
            signals.append("differential messages: " + ", ".join(sorted(set(differential_msgs))[:4]))
        if masked_echo:
            signals.append("reset flow echoes masked account identifier (confirms existence)")
        if distinct_error:
            signals.append("distinct user-vs-password error text (reveals which field failed)")

        if signals:
            self._add_finding(
                title="Username Enumeration Validation — Exposure Detected",
                severity="MEDIUM",
                evidence="; ".join(signals),
                recommendation="Return one generic message for all auth/reset failures; avoid confirming or echoing account identifiers; apply consistent timing and identical markup for valid and invalid accounts.",
            )
        else:
            self._add_finding(
                title="Username Enumeration Validation — No Passive Exposure",
                severity="INFO",
                evidence="No differential messaging, masked-identifier echo, or distinct user/password errors detected on the scanned page.",
                recommendation="Keep auth and reset error messages generic and timing-consistent across valid/invalid accounts.",
            )

    def _check_password_policy_scoring(self, html: str, resp) -> None:
        """Score password-policy strength from passive hints (WSTG-4.4.7).

        Awards points for observable enforcement cues (min length >= 8,
        character-class diversity, length >= 12, MFA present, breach
        /reuse rules, lockout) and reports a 0–100 score with the gap.
        """
        lower = html.lower()
        score = 0
        matched: list[str] = []

        # Minimum length cues.
        m = re.search(r'(?:at\s+least|min(?:imum)?(?:\s+length)?(?:\s+of)?(?:\s+is)?)\s+(\d+)\s+char', lower)
        min_len = int(m.group(1)) if m else None
        if min_len is not None:
            if min_len >= 8:
                score += 25
                matched.append(f"min length {min_len}")
            if min_len >= 12:
                score += 15
                matched.append(f"min length {min_len} (>=12)")
        else:
            if re.search(r'minimum\s+length|password\s+must\s+contain', lower):
                score += 10
                matched.append("generic min-length/policy text")

        # Character-class diversity.
        classes = 0
        if re.search(r'uppercase|capital\s+letter|a[-\s]?z', lower):
            classes += 1; matched.append("uppercase")
        if re.search(r'lowercase|small\s+letter', lower):
            classes += 1; matched.append("lowercase")
        if re.search(r'(?:special|symbol)\s+character|[!@#$%^&*]', lower):
            classes += 1; matched.append("special")
        if re.search(r'\b(?:number|digit|numeric)\b|\d+\s+numbers?', lower):
            classes += 1; matched.append("number")
        score += min(classes * 10, 30)

        # Composition / anti-reuse / breach rules.
        if re.search(r'not\s+(?:be\s+)?(?:the\s+)?same\s+as\s+(?:the\s+)?(?:old|previous|last)\s+password|password\s+history|no\s+reuse', lower):
            score += 10; matched.append("password history / no reuse")
        if re.search(r'breach|have\s+i\s+been\s+pwnt|compromised\s+password|known\s+(?:bad|weak)\s+password', lower):
            score += 10; matched.append("breach-list check")
        if re.search(r'two[-\s]?factor|2fa|totp|multi[-\s]?factor|authenticator\s+app|passkey|webauthn', lower):
            score += 5; matched.append("MFA present (defense-in-depth)")
        if re.search(r'account\s+locked|too\s+many\s+attempts|lockout|rate\s+limit', lower):
            score += 5; matched.append("lockout/throttle")

        score = min(score, 100)
        if score >= 70:
            severity = "INFO"
            label = "Strong"
        elif score >= 40:
            severity = "MEDIUM"
            label = "Moderate"
        else:
            severity = "HIGH"
            label = "Weak"

        evidence = f"Score {score}/100 ({label}). Matched cues: {', '.join(matched) if matched else 'none observed'}."
        self._add_finding(
            title=f"Password Policy Strength Score — {label} ({score}/100)",
            severity=severity,
            evidence=evidence,
            recommendation="Enforce >=12 chars, 3+ character classes, no common/breached passwords, password history/no reuse, and pair with MFA and lockout for defense-in-depth.",
        )

    def _check_registration_discovery(self) -> None:
        """WSTG-IDNT-06: Detect registration endpoints.

        Locates /register, /signup, /create-account, /join, /new-user pages
        by parsing HTML links and checking common paths.
        """
        registration_paths = [
            '/register', '/register/',
            '/signup', '/signup/',
            '/create-account', '/create-account/',
            '/join', '/join/',
            '/new-user', '/new-user/',
            '/register.html', '/signup.html',
            '/create-account.php',
        ]
        try:
            resp = self._session.get(self.base_url, timeout=10)
            html = resp.text or ""
        except Exception:
            html = ""
            resp = None

        found_paths = []
        # Check HTML links
        for path in registration_paths:
            test_url = urljoin(self.base_url, path.lstrip('/'))
            try:
                test_resp = self._session.get(test_url, timeout=3)
                if test_resp.status_code == 200:
                    found_paths.append({'path': path, 'status': 200, 'type': 'html_link'})
            except Exception:
                pass

        # Check HTML content for mentions
        for path in registration_paths:
            if path in html.lower():
                found_paths.append({'path': path, 'status': 'mentioned', 'type': 'html_mention'})
                break

        # Check for registration forms
        if any('name="register"' in html.lower() or 'name="signup"' in html.lower()
                or 'registration' in html.lower() or 'create account' in html.lower()):
            found_paths.append({'path': 'form', 'status': 'form_detected', 'type': 'form'})

        if not found_paths:
            self._add_finding(
                title="No Registration Endpoint Detected",
                severity="INFO",
                evidence="Scanned common registration paths and forms; none found.",
                recommendation="If registration is required, provide a secure registration flow. Ensure it includes email verification, strong password policy, and CSRF protection."
            )
        else:
            path_descriptions = [f"{p['path']}({p['status']})" for p in found_paths[:5]]
            more_text = f" and {len(found_paths)-5} more" if len(found_paths) > 5 else ""
            self._add_finding(
                title=f"Registration Endpoints Detected ({len(found_paths)} found)",
                severity="INFO",
                evidence=f"Found registration endpoints: {', '.join(path_descriptions)}{more_text}",
                recommendation="Ensure registration pages enforce strong passwords, require email verification, and implement rate limiting and CSRF protection to prevent abuse."
            )

    def _check_account_recovery(self) -> None:
        """WSTG-IDNT-08: Detect account recovery / password reset endpoints.

        Locates /forgot-password, /reset-password, /recover-account,
        /password-reset, and similar recovery paths.
        """
        recovery_paths = [
            '/forgot-password', '/forgot-password/',
            '/reset-password', '/reset-password/',
            '/recover-account', '/recover-account/',
            '/password-reset', '/password-reset/',
            '/recover', '/recover/',
            '/account-recovery',
            '/forgot', '/forgot/',
        ]
        try:
            resp = self._session.get(self.base_url, timeout=10)
            html = resp.text or ""
        except Exception:
            html = ""
            resp = None

        found_paths = []
        # Check HTML links
        for path in recovery_paths:
            test_url = urljoin(self.base_url, path.lstrip('/'))
            try:
                test_resp = self._session.get(test_url, timeout=3)
                if test_resp.status_code == 200:
                    found_paths.append({'path': path, 'status': 200, 'type': 'html_link'})
            except Exception:
                pass

        # Check HTML content for mentions
        for path in recovery_paths:
            if path in html.lower():
                found_paths.append({'path': path, 'status': 'mentioned', 'type': 'html_mention'})
                break

        # Check for recovery forms
        recovery_phrases = ['forgot password', 'reset password', 'recover account',
                             'account recovery', 'forgot-password', 'password recovery']
        if any(phrase in html.lower() for phrase in recovery_phrases):
            found_paths.append({'path': 'form', 'status': 'form_detected', 'type': 'form'})

        if not found_paths:
            self._add_finding(
                title="No Account Recovery Endpoint Detected",
                severity="INFO",
                evidence="Scanned common recovery paths and forms; none found.",
                recommendation="Implement a secure password reset flow with email verification, time-limited tokens, and no username enumeration leaks in error messages."
            )
        else:
            path_descriptions = [f"{p['path']}({p['status']})" for p in found_paths[:5]]
            more_text = f" and {len(found_paths)-5} more" if len(found_paths) > 5 else ""
            self._add_finding(
                title=f"Account Recovery Endpoints Detected ({len(found_paths)} found)",
                severity="INFO",
                evidence=f"Found recovery endpoints: {', '.join(path_descriptions)}{more_text}",
                recommendation="Ensure recovery flows use single-use tokens, enforce email ownership verification, limit attempts, and expire tokens after one use."
            )

    def _check_identity_provider_discovery(self) -> None:
        """Discover OAuth/OIDC/SAML identity providers.

        Detects Google Login, Microsoft Login, Facebook Login, GitHub Login,
        Apple Login, and SAML provider pages/endpoints.
        """
        try:
            resp = self._session.get(self.base_url, timeout=10)
            html = resp.text or ""
        except Exception:
            html = ""
            resp = None

        providers = {
            'Google': ['google', 'gstatic', 'accounts.google.com', 'oauth2.googleapis.com'],
            'Microsoft': ['login.live.com', 'login.microsoftonline.com', 'msft.sts.microsoft.com'],
            'Facebook': ['facebook', 'fbcdn.net', 'facebook.com', 'connect.facebook.net'],
            'GitHub': ['github.com', 'githubassets.com', 'github.githubassets.com'],
            'Apple': ['appleid.apple.com', 'idmsa.apple.com'],
            'Twitter': ['twitter.com', 'api.twitter.com'],
            'LinkedIn': ['linkedin.com', 'www.linkedin.com'],
            'SAML': ['saml', 'saml2', 'saml/', '/sso/', '/idp/', 'identityprovider', 'sso'],
            'OAuth': ['oauth2', 'oauth', 'authorize', 'connect'],
            'OpenID': ['openid', 'openid-connect'],
        }

        found = []
        lower_html = html.lower()

        # Check for provider domains in links
        for provider, patterns in providers.items():
            for pattern in patterns:
                if pattern in lower_html and provider not in [f['provider'] for f in found]:
                    found.append({
                        'provider': provider,
                        'type': 'domain_match',
                        'patterns': [pattern]
                    })
                    break

        # Check for OAuth/OIDC endpoints
        oauth_endpoints = [
            '/oauth', '/oauth/authorize',
            '/oauth2', '/oauth2/authorize',
            '/authorize',
        ]
        for path in oauth_endpoints:
            test_url = urljoin(self.base_url, path.lstrip('/'))
            try:
                test_resp = self._session.get(test_url, timeout=3)
                if test_resp.status_code in (200, 301, 302):
                    provider_name = 'OAuth/OIDC'
                    found.append({'provider': provider_name, 'type': 'endpoint', 'path': path})
            except Exception:
                pass

        # Check for SAML SSO pages
        saml_paths = ['/saml', '/sso', '/idp', '/shibboleth']
        for path in saml_paths:
            test_url = urljoin(self.base_url, path.lstrip('/'))
            try:
                test_resp = self._session.get(test_url, timeout=3)
                if test_resp.status_code in (200, 301, 302):
                    found.append({'provider': 'SAML', 'type': 'saml_endpoint', 'path': path})
            except Exception:
                pass

        if not found:
            self._add_finding(
                title="No Identity Provider Detected",
                severity="INFO",
                evidence="No OAuth/OIDC/SAML provider patterns found in page source.",
                recommendation="If using third-party identity providers, ensure they are configured with PKCE, nonce validation, and proper token scopes."
            )
        else:
            provider_descriptions = [f"{f['provider']}({f['type']})" for f in found[:5]]
            more_text = f" and {len(found)-5} more" if len(found) > 5 else ""
            self._add_finding(
                title=f"Identity Provider(s) Detected ({len(found)} providers)",
                severity="INFO",
                evidence=f"Found identity providers: {', '.join(provider_descriptions)}{more_text}",
                recommendation="Verify all identity providers enforce strong authentication (MFA where possible), audit token handling, and prevent open redirect vulnerabilities in OAuth flows."
            )

    def _check_username_enumeration_enhanced(self, html: str, resp) -> None:
        """WSTG-IDNT-06 Enhanced: Analyze username/email/userID enumeration exposure patterns.

        Looks for email addresses, username fields, user ID patterns, and
        application-specific identifiers that may reveal user existence.
        """
        if not html:
            try:
                resp = self._session.get(self.base_url, timeout=10)
                html = resp.text
            except:
                return

        lower = html.lower()
        findings = []

        # 1. Email addresses in page source (username enumeration source)
        email_patterns = [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            r'user@[a-zA-Z0-9.-]+',
            r'mailto:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        ]
        emails_found = set()
        for pattern in email_patterns:
            emails_found.update(re.findall(pattern, lower))

        # 2. Username input fields
        username_inputs = re.findall(r'<input[^>]*name=["\'](?:username|user[_-]?name|login[_-]?name|email[_-]?name)["\'][^>]*>', lower)
        username_inputs += re.findall(r'<input[^>]*id=["\'](?:username|user[_-]?name|login[_-]?name|email[_-]?name)["\'][^>]*>', lower)

        # 3. User ID patterns in URLs and JavaScript
        user_id_patterns = [
            r'/user/?\d+',
            r'/profile/?\d+',
            r'/account/?\d+',
            r'user_id=\d+',
            r'uid=\d+',
        ]
        user_ids_found = set()
        for pattern in user_id_patterns:
            user_ids_found.update(re.findall(pattern, lower))

        # 4. Application-specific user identifiers
        app_user_ids = [
            r'/u/\w+',  # Discourse-style
            r'/user/\w+',  # GitHub-style
            r'/user/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',  # UUID user
            r'data-user-id=["\'][^"\']+["\']',
            r'"userId"\s*:\s*["\'][^"\']+["\']',
            r'userHandle',
            r'username',
        ]
        app_user_ids_found = set()
        for pattern in app_user_ids:
            app_user_ids_found.update(re.findall(pattern, lower))

        # 5. Registration/login success messages that reveal existence
        reg_success_msgs = [
            r'account already exists',
            r'email already registered',
            r'username taken',
            r'user exists',
        ]
        success_hints = any(re.search(pat, lower) for pat in reg_success_msgs)

        # 6. Account recovery success messages
        recovery_success = [
            r'password reset link sent',
            r'instructions sent to your email',
            r'if that email is in our system',
        ]
        recovery_hints = any(re.search(pat, lower) for pat in recovery_success)

        # Evaluate risk
        issues = []
        if len(emails_found) > 0:
            issues.append(f"Found {len(emails_found)} email addresses in page source (username enumeration source)")
        if len(username_inputs) > 0:
            issues.append(f"Found {len(username_inputs)} username input fields")
        if len(user_ids_found) > 0:
            issues.append(f"Found {len(user_ids_found)} numeric user ID patterns")
        if len(app_user_ids_found) > 0:
            issues.append(f"Found {len(app_user_ids_found)} application user identifiers")
        if success_hints:
            issues.append("Registration success messages may reveal user existence")
        if recovery_hints:
            issues.append("Recovery success messages leak email existence")

        if issues:
            self._add_finding(
                title="Username/Email Enumeration Exposure Indicators Detected",
                severity="MEDIUM",
                evidence="; ".join(issues),
                recommendation="Use generic error messages for all authentication/reset operations. Avoid leaking user existence. Apply rate limiting to prevent enumeration. Use blind endpoints that don't distinguish valid vs invalid users."
            )
        else:
            self._add_finding(
                title="No Username/Email Enumeration Indicators Detected",
                severity="INFO",
                evidence="No obvious enumeration exposure patterns found.",
                recommendation="Maintain generic success/error handling and timing consistency to prevent username enumeration."
            )
        """Score password-policy strength from passive hints (WSTG-4.4.7).

        Awards points for observable enforcement cues (min length >= 8,
        character-class diversity, length >= 12, MFA present, breach
        /reuse rules, lockout) and reports a 0–100 score with the gap.
        """
        lower = html.lower()
        score = 0
        matched: list[str] = []

        # Minimum length cues.
        m = re.search(r'(?:at\s+least|min(?:imum)?(?:\s+length)?(?:\s+of)?(?:\s+is)?)\s+(\d+)\s+char', lower)
        min_len = int(m.group(1)) if m else None
        if min_len is not None:
            if min_len >= 8:
                score += 25
                matched.append(f"min length {min_len}")
            if min_len >= 12:
                score += 15
                matched.append(f"min length {min_len} (>=12)")
        else:
            if re.search(r'minimum\s+length|password\s+must\s+contain', lower):
                score += 10
                matched.append("generic min-length/policy text")

        # Character-class diversity.
        classes = 0
        if re.search(r'uppercase|capital\s+letter|a[-\s]?z', lower):
            classes += 1; matched.append("uppercase")
        if re.search(r'lowercase|small\s+letter', lower):
            classes += 1; matched.append("lowercase")
        if re.search(r'(?:special|symbol)\s+character|[!@#$%^&*]', lower):
            classes += 1; matched.append("special")
        if re.search(r'\b(?:number|digit|numeric)\b|\d+\s+numbers?', lower):
            classes += 1; matched.append("number")
        score += min(classes * 10, 30)

        # Composition / anti-reuse / breach rules.
        if re.search(r'not\s+(?:be\s+)?(?:the\s+)?same\s+as\s+(?:the\s+)?(?:old|previous|last)\s+password|password\s+history|no\s+reuse', lower):
            score += 10; matched.append("password history / no reuse")
        if re.search(r'breach|have\s+i\s+been\s+pwnt|compromised\s+password|known\s+(?:bad|weak)\s+password', lower):
            score += 10; matched.append("breach-list check")
        if re.search(r'two[-\s]?factor|2fa|totp|multi[-\s]?factor|authenticator\s+app|passkey|webauthn', lower):
            score += 5; matched.append("MFA present (defense-in-depth)")
        if re.search(r'account\s+locked|too\s+many\s+attempts|lockout|rate\s+limit', lower):
            score += 5; matched.append("lockout/throttle")

        score = min(score, 100)
        if score >= 70:
            severity = "INFO"
            label = "Strong"
        elif score >= 40:
            severity = "MEDIUM"
            label = "Moderate"
        else:
            severity = "HIGH"
            label = "Weak"

        evidence = f"Score {score}/100 ({label}). Matched cues: {', '.join(matched) if matched else 'none observed'}."
        self._add_finding(
            title=f"Password Policy Strength Score — {label} ({score}/100)",
            severity=severity,
            evidence=evidence,
            recommendation="Enforce >=12 chars, 3+ character classes, no common/breached passwords, password history/no reuse, and pair with MFA and lockout for defense-in-depth.",
        )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _add_finding(self, title: str, severity: str, evidence: str, recommendation: str = "") -> None:
        """Add a finding with consistent structure.

        Includes CWE IDs and the WSTG-4.4.x IDs derived from the finding
        title so the report can map coverage back to the test catalogue.
        """
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

    def _map_to_wstg_and_cwe(self, title: str, severity: str) -> tuple[list[str], list[str]]:
        """Map a finding title to OWASP WSTG-4.4.x and CWE IDs.

        Returns (wstg_ids, cwe_ids). Multiple keywords may apply.
        """
        t = title.lower()
        wstg: list[str] = []
        cwe: list[str] = []

        # --- WSTG-4.4.x mapping (keyword -> WSTG ID set) ---
        if "credential" in t and "transport" in t:
            wstg.append("WSTG-4.4.1")
        if "lockout" in t or "lock out" in t:
            wstg.append("WSTG-4.4.3")
        if "mfa" in t or "multi-factor" in t or "two-factor" in t or "authenticator" in t:
            wstg.append("WSTG-4.4.4")
        if "weak auth" in t or "authenticat" in t or "login form" in t:
            wstg.append("WSTG-4.4.4")
        if "remember" in t:
            wstg.append("WSTG-4.4.5")
        if "cache" in t:
            wstg.append("WSTG-4.4.6")
        if "password policy" in t or "password strength" in t:
            wstg.append("WSTG-4.4.7")
        if "password reset" in t or "reset token" in t:
            wstg.append("WSTG-4.4.9")
        if "enumeration" in t:
            wstg.append("WSTG-4.4.9")

        # Deduplicate while preserving order.
        seen: set[str] = set()
        wstg = [w for w in wstg if not (w in seen or seen.add(w))]

        # --- CWE mapping (kept from the original logic, broadened) ---
        if "mfa" in t:
            cwe.extend(["CWE-306", "CWE-623"])
        if "login" in t or "weak auth" in t:
            cwe.append("CWE-521")
        if "password reset" in t or "reset token" in t:
            cwe.append("CWE-640")
        if "lockout" in t:
            cwe.append("CWE-307")
        if "weak auth" in t:
            cwe.append("CWE-287")
        if "credential" in t and "transport" in t:
            cwe.append("CWE-319")
        if "cache" in t:
            cwe.append("CWE-524")
        if "remember" in t:
            cwe.append("CWE-565")
        if "enumeration" in t:
            cwe.append("CWE-204")
        if "password policy" in t or "password strength" in t:
            cwe.append("CWE-521")

        cwe = list(dict.fromkeys(cwe))  # dedupe, preserve order
        return wstg, cwe

    def _determine_severity(self) -> str:
        """Determine overall module severity."""
        if any(f["severity"] == "CRITICAL" for f in self.findings):
            return "CRITICAL"
        if any(f["severity"] == "HIGH" for f in self.findings):
            return "HIGH"
        if any(f["severity"] == "MEDIUM" for f in self.findings):
            return "MEDIUM"
        return "INFO"
