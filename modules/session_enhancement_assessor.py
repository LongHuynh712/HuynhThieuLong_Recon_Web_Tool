"""
OWASP WSTG 4.6 - Session Management Enhancement (Passive)
Detects session fixation indicators, session entropy issues, logout presence, JWT analysis.
"""

from __future__ import annotations

import re
import base64
import json
import math
from typing import Any
import requests
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class SessionEnhancementAssessor:
    """Passive session management security assessment."""

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
        """Run all session enhancement assessment checks."""
        try:
            resp = self._session.get(self.base_url, timeout=10)
        except Exception:
            resp = None

        self._check_session_cookies(resp)
        self._check_jwt_tokens(resp)
        self._check_logout_presence(resp)
        self._check_session_token_entropy(resp)
        self._check_session_fixation_indicators(resp)

        severity = self._determine_severity()

        return {
            "test_name": "Session Management Enhancement (Passive)",
            "wstg_reference": ["WSTG-4.6"],
            "severity": severity,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": {
                "total_findings": len(self.findings),
                "jwt_detected": any("jwt" in f.get("title", "").lower() for f in self.findings),
                "logout_present": any("logout" in f.get("title", "").lower() for f in self.findings),
            }
        }

    def _check_session_cookies(self, resp):
        """Check cookie attributes for session security."""
        if not resp:
            return
        cookies = resp.cookies
        session_cookies = [c for c in cookies if any(kw in c.name.lower() for kw in ['sess', 'session', 'sid', 'auth', 'token', 'id'])]
        issues = []
        for c in session_cookies:
            flags = []
            if not c.secure:
                flags.append("Secure flag missing")
            # HttpOnly check: requests doesn't expose HttpOnly directly; infer from Set-Cookie header
            if 'httponly' not in (resp.headers.get('Set-Cookie', '')).lower():
                flags.append("HttpOnly flag may be missing")
            # SameSite
            samesite_match = re.search(r'SameSite=([^;]+)', resp.headers.get('Set-Cookie', ''), re.I)
            if not samesite_match or samesite_match.group(1).lower() == 'none':
                flags.append("SameSite not set or None")
            if flags:
                issues.append(f"{c.name}: {', '.join(flags)}")
                self.recommendations.append(f"Set Secure, HttpOnly, and SameSite=Strict/Lax on session cookie '{c.name}'.")
        if issues:
            self._add_finding(
                title="Session Cookie Security Issues",
                severity="HIGH" if len(issues) >= 2 else "MEDIUM",
                evidence=f"Found {len(issues)} session cookies with missing security flags: " + "; ".join(issues[:3]),
                recommendation="Always set Secure, HttpOnly, and SameSite attributes on session cookies to protect against theft and CSRF."
            )
        else:
            self._add_finding(
                title="Session Cookies Properly Configured",
                severity="INFO",
                evidence="Session cookies (if any) appear to have security flags set.",
                recommendation="Continue to enforce Secure, HttpOnly, and SameSite on all session-related cookies."
            )

    def _check_jwt_tokens(self, resp):
        """Analyze JWT tokens in cookies or HTML."""
        if not resp:
            return
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        # Check cookies
        jwt_cookies = []
        for cookie in resp.cookies:
            if re.fullmatch(jwt_pattern, cookie.value):
                jwt_cookies.append(cookie.name)
        # Check HTML
        html = resp.text or ""
        jwt_html = re.findall(jwt_pattern, html)
        if jwt_cookies or jwt_html:
            # Decode first JWT to check algorithm
            token = jwt_cookies[0] if jwt_cookies else jwt_html[0]
            try:
                parts = token.split('.')
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
                alg = header.get('alg', 'none')
                exp = payload.get('exp')
                issues = []
                if alg == 'none':
                    issues.append("JWT uses 'none' algorithm (unsigned)")
                if alg.startswith('HS') and 'secret' in str(payload).lower():
                    issues.append("JWT payload may contain secrets")
                if not exp:
                    issues.append("JWT has no expiration")
                severity = "MEDIUM" if issues else "INFO"
                self._add_finding(
                    title="JWT Tokens Detected and Analyzed",
                    severity=severity,
                    evidence=f"Found JWT(s): {len(jwt_cookies)} in cookies, {len(jwt_html)} in HTML. Algorithm: {alg}, Exp: {exp or 'none'}",
                    recommendation="Ensure JWT tokens are signed with strong algorithms (RS256/ES256), have reasonable expiration, and do not contain sensitive data. Store in HttpOnly cookies, not localStorage."
                )
                if issues:
                    for issue in issues:
                        self.recommendations.append(f"JWT issue: {issue}")
            except Exception as e:
                self._add_finding(
                    title="JWT Tokens Detected",
                    severity="LOW",
                    evidence=f"Found JWT-like tokens but could not decode: {e}",
                    recommendation="Review JWT implementation for proper signature verification and expiration."
                )

    def _check_logout_presence(self, resp):
        """Check for logout functionality."""
        if not resp:
            return
        html = resp.text or ""
        logout_indicators = [
            r'logout',
            r'sign\s?out',
            r'log\s?out',
            r'disconnect',
            r'auth.*logout'
        ]
        lower_html = html.lower()
        found = any(re.search(pat, lower_html) for pat in logout_indicators)
        if found:
            self._add_finding(
                title="Logout Mechanism Detected",
                severity="INFO",
                evidence="Found logout link/button on page.",
                recommendation="Ensure logout invalidates server-side session and clears cookies."
            )
        else:
            self._add_finding(
                title="No Logout Mechanism Detected",
                severity="LOW",
                evidence="Could not find logout functionality.",
                recommendation="Provide a clear logout mechanism that fully terminates the session."
            )

    def _check_session_token_entropy(self, resp):
        """Assess session token entropy (if tokens are visible)."""
        if not resp:
            return
        # Look for tokens in cookies or hidden inputs
        tokens = []
        for cookie in resp.cookies:
            val = cookie.value
            if len(val) >= 16 and re.match(r'^[a-zA-Z0-9_-]+$', val):
                tokens.append(val)
        html = resp.text or ""
        hidden_inputs = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\']', html, re.I)
        tokens.extend([v for v in hidden_inputs if len(v) >= 16])
        if tokens:
            # Simple entropy estimation: character set diversity
            sample = tokens[0]
            unique_chars = len(set(sample))
            length = len(sample)
            # Rough estimate: if length >= 32 and unique chars > 10, likely okay
            if length < 32 or unique_chars < 10:
                self._add_finding(
                    title="Session Token Entropy May Be Low",
                    severity="MEDIUM",
                    evidence=f"Session token example: {sample[:16]}... (length={length}, unique_chars={unique_chars})",
                    recommendation="Ensure session tokens have sufficient length (>=128 bits) and are generated using cryptographically secure random number generator."
                )

    def _check_session_fixation_indicators(self, resp):
        """Check for session fixation weaknesses (passive)."""
        if not resp:
            return
        # Look for session ID in URL (SID in query)
        if '?' in self.base_url:
            if re.search(r'(sess|session|sid|jsessionid)=', self.base_url, re.I):
                self._add_finding(
                    title="Session ID in URL Detected",
                    severity="HIGH",
                    evidence="Session identifier found in URL query parameters.",
                    recommendation="Never transmit session IDs in URLs (cookies or POST body only) to prevent leakage via Referer headers, logs, and bookmarks."
                )
        # Check for Set-Cookie without Secure on HTTPS
        if self.base_url.startswith('https://'):
            set_cookie = resp.headers.get('Set-Cookie', '')
            if 'secure' not in set_cookie.lower():
                self._add_finding(
                    title="Session Cookie Missing Secure Flag on HTTPS",
                    severity="HIGH",
                    evidence="Session cookie does not have Secure flag, exposing it to network theft if HTTPS is not enforced or mixed content occurs.",
                    recommendation="Always set Secure flag on cookies when using HTTPS."
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
            "cookie": ["CWE-614"],
            "jwt": ["CWE-113"],
            "logout": ["CWE-613"],
            "session fixation": ["CWE-384"],
            "entropy": ["CWE-330"],
            "session id in url": ["CWE-598"],
        }
        for key, cwes in mapping.items():
            if key in title_l:
                return cwes
        return []
