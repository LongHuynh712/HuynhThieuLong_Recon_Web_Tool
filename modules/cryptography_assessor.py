'''
OWASP WSTG 4.8 - Cryptography Assessment (Passive)
Detects TLS version, cipher strength, certificate validation, weak crypto usage, JWT algorithm review.
'''

from __future__ import annotations

import ssl
import socket
import re
import base64
import json
from datetime import datetime
from typing import Any
import requests
from urllib.parse import urlparse

# Suppress insecure warnings – we may connect without verification for passive checks
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


class CryptographyAssessor:
    """Passive cryptography security assessment.

    The assessor performs network‑level TLS checks, analyses certificates, scans
    HTML/JS for usage of weak cryptographic primitives and reviews any JWTs
    found in cookies or page content.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.findings: list[dict] = []
        self.recommendations: list[str] = []
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "ReconSight/1.0 (PassiveScanner)"})
        self._session.verify = False
        self._session.timeout = 10

    def run_all_tests(self) -> dict[str, Any]:
        """Execute all cryptography checks and return a structured result."""
        # Basic HTTPS GET for cookie/JWT checks – we ignore content later
        try:
            resp = self._session.get(self.base_url, timeout=10)
        except Exception:
            resp = None

        self._check_tls_details()
        self._check_certificate_validity()
        self._check_weak_crypto_in_page()
        self._check_jwt_algorithms(resp)
        # New checks
        self._check_hsts()
        self._check_secure_cookie_crypto()

        severity = self._determine_severity()
        return {
            "test_name": "Cryptography Assessment (Passive)",
            "wstg_reference": ["WSTG-4.8"],
            "severity": severity,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": {
                "total_findings": len(self.findings),
                "tls_issues": any("tls" in f.get("title", "").lower() for f in self.findings),
                "weak_crypto": any("weak" in f.get("title", "").lower() for f in self.findings),
            },
        }

    # ---------------------------------------------------------------------
    # TLS version / cipher checks
    # ---------------------------------------------------------------------
    def _check_tls_details(self) -> None:
        """Retrieve TLS version and cipher suite information.

        Uses the standard library ``ssl`` to open a TCP connection and inspect
        the negotiated parameters. Low‑strength protocols (SSLv2/3, TLS<1.2) or
        ciphers with <128‑bit encryption are reported.
        """
        parsed = urlparse(self.base_url)
        hostname = parsed.hostname or self.base_url.replace('https://', '').split('/')[0]
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        context = ssl.create_default_context()
        # Force a broad set of protocols to let the server negotiate its best
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_version = ssock.version()
                    cipher_name, tls_proto, cipher_bits = ssock.cipher()
        except Exception as e:
            self._add_finding(
                title="TLS Information Retrieval Failed",
                severity="MEDIUM",
                evidence=str(e),
                recommendation="Ensure the service is reachable over TLS and that the scanning host can perform a TLS handshake."
            )
            return

        # Evaluate protocol version
        if tls_version is None or tls_version.startswith("SSL") or tls_version < "TLSv1.2":
            self._add_finding(
                title="Outdated TLS/SSL Protocol Detected",
                severity="HIGH",
                evidence=f"Negotiated protocol: {tls_version}",
                recommendation="Disable SSLv2/3 and TLS < 1.2. Enforce TLS 1.2 or higher."
            )
        else:
            self._add_finding(
                title="TLS Protocol Acceptable",
                severity="INFO",
                evidence=f"Negotiated protocol: {tls_version}",
                recommendation="Continue to monitor for deprecation of older versions."
            )

        # Evaluate cipher strength
        if cipher_bits is None or cipher_bits < 128:
            self._add_finding(
                title="Weak Cipher Suite Detected",
                severity="HIGH",
                evidence=f"Cipher: {cipher_name} ({cipher_bits} bits)",
                recommendation="Prefer cipher suites with >=128‑bit security (e.g., AES‑GCM). Disable export‑grade ciphers."
            )
        else:
            self._add_finding(
                title="Cipher Suite Strength Adequate",
                severity="INFO",
                evidence=f"Cipher: {cipher_name} ({cipher_bits} bits)",
                recommendation="No immediate action required."
            )

    # ---------------------------------------------------------------------
    # Certificate checks
    # ---------------------------------------------------------------------
    def _check_certificate_validity(self) -> None:
        """Fetch the leaf certificate and verify expiration / hostname match.

        ``ssl.get_server_certificate`` returns PEM; we parse dates with ``ssl``.
        """
        parsed = urlparse(self.base_url)
        hostname = parsed.hostname or self.base_url.replace('https://', '').split('/')[0]
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            pem = ssl.get_server_certificate((hostname, port), timeout=5)
            cert = ssl.PEM_cert_to_DER_cert(pem)
            x509 = ssl._ssl._test_decode_cert(pem)  # internal helper returns dict
        except Exception as e:
            self._add_finding(
                title="Certificate Retrieval Failed",
                severity="MEDIUM",
                evidence=str(e),
                recommendation="Verify the server presents a valid X.509 certificate over HTTPS."
            )
            return

        # Expiration check
        not_before = x509.get("notBefore")
        not_after = x509.get("notAfter")
        fmt = "%b %d %H:%M:%S %Y %Z"
        try:
            exp_date = datetime.strptime(not_after, fmt)
            now = datetime.utcnow()
            days_left = (exp_date - now).days
        except Exception:
            days_left = None

        if days_left is not None and days_left < 30:
            self._add_finding(
                title="Certificate Near Expiration",
                severity="MEDIUM",
                evidence=f"Expires in {days_left} days on {exp_date.isoformat()}",
                recommendation="Renew the TLS certificate before it expires to avoid service disruption."
            )
        else:
            self._add_finding(
                title="Certificate Validity Period Acceptable",
                severity="INFO",
                evidence=f"Expires on {exp_date.isoformat() if days_left is not None else 'unknown'}",
                recommendation="Monitor certificate expiration regularly."
            )

    # ---------------------------------------------------------------------
    # Weak crypto usage in page source
    # ---------------------------------------------------------------------
    def _check_hsts(self) -> None:
        """Validate the Strict‑Transport‑Security (HSTS) header.
        Ensures the header exists and includes a `max‑age` of at least one year (31536000 seconds).
        """
        try:
            resp = self._session.get(self.base_url, timeout=5)
            hsts = resp.headers.get('Strict-Transport-Security')
        except Exception as e:
            self._add_finding(
                title="HSTS Retrieval Failed",
                severity="MEDIUM",
                evidence=str(e),
                recommendation="Ensure the server returns a Strict‑Transport‑Security header over HTTPS."
            )
            return

        if not hsts:
            self._add_finding(
                title="Missing HSTS Header",
                severity="HIGH",
                evidence="No Strict-Transport-Security header present.",
                recommendation="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to enforce HTTPS."
            )
            return

        max_age_match = re.search(r'max-age\s*=\s*(\d+)', hsts, re.I)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:
                self._add_finding(
                    title="Weak HSTS Max‑Age",
                    severity="MEDIUM",
                    evidence=f"max‑age={max_age} seconds (< 1 year)",
                    recommendation="Set `max-age` to at least 31536000 (1 year) and consider `includeSubDomains`."
                )
            else:
                self._add_finding(
                    title="HSTS Header Properly Configured",
                    severity="INFO",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    recommendation="Keep HSTS enabled and monitor its configuration."
                )
        else:
            self._add_finding(
                title="Malformed HSTS Header",
                severity="MEDIUM",
                evidence=f"Header value: {hsts}",
                recommendation="Ensure the header follows the spec and includes `max-age`."
            )

    def _check_secure_cookie_crypto(self) -> None:
        """Review Set‑Cookie headers for secure attributes and weak token storage.
        Flags missing Secure, HttpOnly, SameSite attributes and detects Base64‑like values.
        """
        try:
            resp = self._session.get(self.base_url, timeout=5)
            set_cookie = resp.headers.get('Set-Cookie')
        except Exception as e:
            self._add_finding(
                title="Cookie Retrieval Failed",
                severity="MEDIUM",
                evidence=str(e),
                recommendation="Ensure the application sets cookies with proper security flags."
            )
            return

        if not set_cookie:
            self._add_finding(
                title="No Set‑Cookie Header Detected",
                severity="INFO",
                evidence="Response does not contain a Set‑Cookie header.",
                recommendation="If cookies are used, add Secure, HttpOnly, and SameSite attributes."
            )
            return

        # Split possible multiple cookies (simple split on commas – may not be perfect but works for most cases)
        cookies = [c.strip() for c in set_cookie.split(',')]
        for ck in cookies:
            ck_lower = ck.lower()
            name = ck.split('=')[0].strip()
            missing = []
            if 'secure' not in ck_lower:
                missing.append('Secure')
            if 'httponly' not in ck_lower:
                missing.append('HttpOnly')
            if not re.search(r'samesite\s*=\s*(strict|lax)', ck_lower):
                missing.append('SameSite')
            if missing:
                self._add_finding(
                    title=f"Cookie `{name}` Missing Security Flags",
                    severity="MEDIUM",
                    evidence=f"Missing: {', '.join(missing)}",
                    recommendation="Add the missing flags to the Set‑Cookie header."
                )
            # Detect Base64‑like token values (>=20 chars, typical of JWTs or random tokens)
            val_match = re.search(r'=(\S+)', ck)
            if val_match:
                val = val_match.group(1)
                if len(val) >= 20 and re.fullmatch(r'[A-Za-z0-9+/=]+', val):
                    try:
                        base64.b64decode(val, validate=True)
                        self._add_finding(
                            title=f"Cookie `{name}` Contains Base64 Token",
                            severity="LOW",
                            evidence="Potentially weak token storage; consider using opaque random tokens or signed JWTs.",
                            recommendation="Replace with securely generated tokens and store them HttpOnly."
                        )
                    except Exception:
                        pass

    def _check_weak_crypto_in_page(self) -> None:
        """Search HTML/JS for references to weak algorithms (MD5, SHA‑1, etc.)."""
        try:
            resp = self._session.get(self.base_url, timeout=10)
            html = resp.text or ""
        except Exception:
            html = ""

        weak_patterns = {
            "MD5": r"\bmd5\b",
            "SHA1": r"\bsha1\b",
            "DES": r"\bdes\b",
            "RC4": r"\brc4\b",
            "Base64": r"\bbase64\b",
        }
        found = []
        for name, pat in weak_patterns.items():
            if re.search(pat, html, re.I):
                found.append(name)
        if found:
            self._add_finding(
                title="Weak Cryptographic Primitives Detected",
                severity="MEDIUM",
                evidence=f"Found usage of: {', '.join(found)}",
                recommendation="Replace weak algorithms with modern equivalents (e.g., SHA‑256, AES‑GCM). Avoid storing passwords with MD5/SHA‑1."
            )
        else:
            self._add_finding(
                title="No Weak Cryptographic Primitives Detected",
                severity="INFO",
                evidence="Search did not reveal MD5, SHA‑1, DES, RC4 or raw Base64 usage.",
                recommendation="Continue using strong primitives."
            )

    # ---------------------------------------------------------------------
    # JWT algorithm analysis (reuse logic from SessionEnhancementAssessor)
    # ---------------------------------------------------------------------
    def _check_jwt_algorithms(self, resp) -> None:
        """Inspect any JWTs for insecure algorithms or missing expiration.

        Looks at cookies and page source for JWT‑like strings, decodes the
        header/payload and checks ``alg`` and ``exp`` fields.
        """
        if not resp:
            return
        jwt_pat = r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
        # Cookies
        jwt_cookies = []
        for cookie in resp.cookies:
            if re.fullmatch(jwt_pat, cookie.value):
                jwt_cookies.append((cookie.name, cookie.value))
        # HTML source
        jwt_html = re.findall(jwt_pat, resp.text or "")

        all_jwts = [("cookie", name, val) for name, val in jwt_cookies] + [("html", None, t) for t in jwt_html]
        if not all_jwts:
            self._add_finding(
                title="No JWT Tokens Detected",
                severity="INFO",
                evidence="No JWT‑like strings found in cookies or page source.",
                recommendation="If JWTs are used, ensure they follow best‑practice settings."
            )
            return

        issues = []
        for src, name, token in all_jwts:
            try:
                header_b64, payload_b64, _ = token.split('.')
                header_json = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))
                payload_json = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
                alg = header_json.get('alg', '').upper()
                exp = payload_json.get('exp')
                if alg == 'NONE':
                    issues.append(f"{src} JWT uses 'none' algorithm (unsigned)")
                if alg.startswith('HS') and any('secret' in str(v).lower() for v in payload_json.values()):
                    issues.append(f"{src} JWT payload appears to contain secrets")
                if not exp:
                    issues.append(f"{src} JWT missing expiration claim")
            except Exception as e:
                issues.append(f"{src} JWT could not be parsed: {e}")

        if issues:
            self._add_finding(
                title="Insecure JWT Configuration Detected",
                severity="HIGH" if any('none' in i.lower() or 'missing expiration' in i.lower() for i in issues) else "MEDIUM",
                evidence="; ".join(issues),
                recommendation="Use strong signing algorithms (RS256/ES256), include a reasonable expiration, and keep secrets out of the payload. Store JWTs in HttpOnly cookies."
            )
        else:
            self._add_finding(
                title="JWT Tokens Appear Secure",
                severity="INFO",
                evidence="All discovered JWTs use strong algorithms and contain expiration.",
                recommendation="Maintain current JWT handling practices."
            )

    # ---------------------------------------------------------------------
    # Helper utilities
    # ---------------------------------------------------------------------
    def _add_finding(self, title: str, severity: str, evidence: str, recommendation: str | None = None) -> None:
        finding = {
            "title": title,
            "severity": severity,
            "evidence": evidence,
            "cwe_ids": self._map_to_cwe(title, severity),
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
        tl = title.lower()
        mapping = {
            "tls": ["CWE-326"],
            "cipher": ["CWE-326"],
            "certificate": ["CWE-295"],
            "weak cryptographic": ["CWE-327"],
            "jwt": ["CWE-113"],
        }
        for key, cwes in mapping.items():
            if key in tl:
                return cwes
        return []
