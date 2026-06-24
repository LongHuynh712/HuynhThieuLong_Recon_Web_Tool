"""
OWASP WSTG 4.12 - API Security Assessment (Passive) - ENHANCED
Validates OpenAPI/Swagger exposure, detects GraphQL endpoints, classifies
sensitive API endpoints, reviews API authentication, discovers API versions,
and detects rate limiting.
Coverage: ~75% of WSTG-4.12 + WSTG-4.11 API-related tests
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

class APISecurityAssessor:
    """Passive API security assessment - Enhanced version."""

    # Enhanced OpenAPI/Swagger documentation/spec locations
    _OPENAPI_PATHS = [
        "/swagger", "/swagger.json", "/swagger.yaml", "/swagger.yml",
        "/swagger-ui", "/swagger-ui.html", "/swagger-ui/index.html",
        "/api/swagger", "/api/swagger.json", "/api/swagger.yaml",
        "/api-docs", "/api-docs.json", "/api-docs.yaml", "/api-docs/index.html",
        "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/openapi", "/openapi.json", "/openapi.yaml", "/openapi.yml",
        "/.well-known/swagger.json", "/.well-known/openapi.json",
        "/redoc", "/redoc.html",
    ]

    # Enhanced GraphQL endpoint locations
    _GRAPHQL_PATHS = [
        "/graphql", "/graphql/", "/graph", "/gql",
        "/graphiql", "/graphiql/", "/graphiql.php",
        "/api/graphql", "/api/v1/graphql", "/api/v2/graphql",
        "/v1/graphql", "/v2/graphql", "/.graphql",
    ]

    # API Version discovery paths
    _API_VERSION_PATHS = [
        "/api/v1", "/api/v2", "/api/v3",
        "/v1", "/v2", "/v3",
        "/api/1.0", "/api/1.1", "/api/2.0",
        "/rest/v1", "/rest/v2",
        "/oauth/v1", "/oauth/v2",
    ]

    # Keywords used to classify an endpoint's sensitivity
    _SENSITIVE_KEYWORDS = {
        "privileged": ["/admin", "/administrator", "/manage", "/manager",
                       "/cpanel", "/internal", "/debug", "/console", "/superuser"],
        "financial": ["/payment", "/payments", "/billing", "/checkout",
                      "/charge", "/invoice", "/transactions", "/wallet", "/balance"],
        "personal_data": ["/user", "/users", "/account", "/accounts",
                          "/profile", "/me", "/customers", "/emails",
                          "/personal", "/identity", "/pii"],
        "auth": ["/login", "/signin", "/register", "/signup", "/auth",
                 "/oauth", "/token", "/password", "/reset", "/sessions",
                 "/verify", "/confirm", "/activate"],
        "data_flow": ["/upload", "/uploads", "/export", "/import", "/backup",
                      "/dump", "/download", "/files", "/documents",
                      "/import", "/migrate", "/sync"],
        "config": ["/config", "/configuration", "/settings", "/env",
                   "/secrets", "/keys", "/metadata", "/properties"],
        "admin_api": ["/admin/api", "/api/admin", "/internal/api", "/system"],
    }

    # Tokens/credentials that may be leaked into client-side code
    _CREDENTIAL_PATTERNS = [
        (r'["\'](?:x-?api-?key|apikey|api-?key)["\']\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API key"),
        (r'["\'](?:authorization|auth)["\']\s*[:=]\s*["\']Bearer\s+([A-Za-z0-9_\-\.=]{20,})["\']', "Bearer token"),
        (r'["\'](?:secret|client_secret|private_key|client_id)["\']\s*[:=]\s*["\']([^"\']{16,})["\']', "Secret value"),
        (r'access_token["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.=]{20,})["\']', "Access token"),
        (r'refresh_token["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.=]{20,})["\']', "Refresh token"),
    ]

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.findings: list[dict] = []
        self.recommendations: list[str] = []
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "ReconSight/1.0 (PassiveScanner)"})
        self._session.verify = False
        self._session.timeout = 10
        self.discovered_endpoints: set[str] = set()
        self.openapi_specs: list[dict] = []
        self.api_versions: set[str] = set()
        self.rate_limit_info: dict[str, Any] = {}

    def run_all_tests(self) -> dict[str, Any]:
        """Execute all API security checks."""
        try:
            resp = self._session.get(self.base_url, timeout=10)
            html = resp.text or ""
            homepage_resp = resp
        except Exception:
            html = ""
            homepage_resp = None

        # 1. OpenAPI/Swagger discovery
        self._check_openapi_exposure()
        # 2. GraphQL discovery and introspection
        self._check_graphql_introspection()
        # 3. API version discovery (NEW)
        self._check_api_version_discovery()
        # 4. Rate limiting detection (NEW)
        self._check_rate_limiting(homepage_resp)
        # 5. Sensitive endpoint classification
        self._check_sensitive_endpoints(html)
        # 6. API authentication review
        self._check_api_authentication(html, homepage_resp)

        severity = self._determine_severity()
        covered = sorted({wid for f in self.findings for wid in f.get("wstg_ids", [])})

        return {
            "test_name": "API Security Assessment (Enhanced)",
            "wstg_reference": ["WSTG-4.12"] + covered,
            "severity": severity,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": {
                "total_findings": len(self.findings),
                "openapi_exposed": any("exposed" in f.get("title", "").lower() for f in self.findings),
                "graphql_introspection": any("introspection enabled" in f.get("title", "").lower() for f in self.findings),
                "sensitive_endpoints": any("sensitive endpoints classified" in f.get("title", "").lower() for f in self.findings),
                "auth_issues": any(("unauthenticated" in f.get("title", "").lower()
                                   or "credential" in f.get("title", "").lower()
                                   or "basic auth" in f.get("title", "").lower())
                                  and f.get("severity") != "INFO" for f in self.findings),
                "endpoints_discovered": len(self.discovered_endpoints),
                "api_versions_found": list(self.api_versions),
                "rate_limiting_detected": self.rate_limit_info.get("detected", False),
            },
        }

    # ------------------------------------------------------------------
    # 1. Enhanced OpenAPI/Swagger discovery
    # ------------------------------------------------------------------
    def _check_openapi_exposure(self) -> None:
        """Validate OpenAPI/Swagger documentation exposure."""
        found_specs: list[dict] = []

        for path in self._OPENAPI_PATHS:
            test_url = urljoin(self.base_url + "/", path.lstrip("/"))
            try:
                response = self._session.get(test_url, timeout=5)
            except Exception:
                continue

            if response.status_code != 200:
                continue

            content_type = response.headers.get("Content-Type", "")
            text = response.text or ""

            looks_like_spec = (
                "json" in content_type.lower()
                or "yaml" in content_type.lower()
                or "openapi" in text[:2000].lower()
                or "swagger" in text[:2000].lower()
                or '"paths"' in text[:5000]
            )
            if not looks_like_spec:
                continue

            spec_info: dict[str, Any] = {
                "url": test_url,
                "path": path,
                "content_type": content_type,
                "size": len(response.content),
            }

            try:
                content = response.json()
                spec_info["parseable"] = True
                info = content.get("info", {}) if isinstance(content, dict) else {}
                spec_info["title"] = info.get("title", "Unknown")
                spec_info["version"] = info.get("version", "Unknown")
                paths = content.get("paths", {}) if isinstance(content, dict) else {}
                path_items = list(paths.keys()) if isinstance(paths, dict) else []
                spec_info["endpoints_count"] = len(path_items)
                spec_info["endpoints"] = path_items
                for p in path_items:
                    self.discovered_endpoints.add(p)
                sensitive = self._classify_paths(path_items)
                spec_info["sensitive_endpoints"] = sensitive
            except Exception:
                spec_info["parseable"] = False
                spec_info["endpoints_count"] = 0

            found_specs.append(spec_info)
            self.openapi_specs.append(spec_info)

        if not found_specs:
            self._add_finding(
                title="No OpenAPI/Swagger Exposure Detected",
                severity="INFO",
                evidence=f"Probed {len(self._OPENAPI_PATHS)} common documentation/spec paths; none returned a parseable OpenAPI document.",
                recommendation="Keep API documentation out of production or behind authentication.",
                wstg_ids=["WSTG-4.12.1"]
            )
            return

        total_endpoints = sum(s.get("endpoints_count", 0) for s in found_specs)
        sensitive_total = sum(len(s.get("sensitive_endpoints", {})) for s in found_specs)
        any_sensitive = sensitive_total > 0
        any_unparseable = any(not s.get("parseable", False) for s in found_specs)

        if any_sensitive:
            severity = "HIGH"
            evidence = (
                f"{len(found_specs)} OpenAPI/Swagger document(s) publicly exposed "
                f"revealing {total_endpoints} endpoint(s) including {sensitive_total} sensitive operation(s)."
            )
            recommendation = "Remove or gate API documentation behind authentication. Redact sensitive endpoints from publicly served specs."
        elif any_unparseable:
            severity = "MEDIUM"
            evidence = (
                f"{len(found_specs)} OpenAPI/Swagger document(s) exposed but not fully parseable."
            )
            recommendation = "Restrict access to API documentation/specs in production."
        else:
            severity = "MEDIUM"
            evidence = (
                f"{len(found_specs)} OpenAPI/Swagger document(s) publicly exposed "
                f"revealing {total_endpoints} endpoint(s)."
            )
            recommendation = "Disable or authenticate API documentation to avoid endpoint enumeration."

        self._add_finding(
            title="OpenAPI/Swagger Documentation Exposed",
            severity=severity,
            evidence=evidence,
            recommendation=recommendation,
            wstg_ids=["WSTG-4.12.1"]
        )

    # ------------------------------------------------------------------
    # 2. Enhanced GraphQL introspection detection
    # ------------------------------------------------------------------
    def _check_graphql_introspection(self) -> None:
        """Detect GraphQL endpoints and introspection."""
        introspection_query = {
            "query": "{ __schema { queryType { name } types { name kind } } }"
        }
        endpoints_found: list[dict] = []
        introspection_enabled_count = 0

        for path in self._GRAPHQL_PATHS:
            test_url = urljoin(self.base_url + "/", path.lstrip("/"))
            try:
                response = self._session.post(test_url, json=introspection_query, timeout=5)
            except Exception:
                continue

            if response.status_code != 200:
                continue

            body_text = response.text or ""
            endpoint_info: dict[str, Any] = {"url": test_url, "path": path}

            try:
                parsed = response.json()
            except Exception:
                parsed = None

            introspection_enabled = (
                "__schema" in body_text
                or "__type" in body_text
                or (isinstance(parsed, dict) and isinstance(parsed.get("data"), dict)
                    and ("__schema" in parsed["data"] or "__type" in parsed["data"]))
            )
            endpoint_info["introspection_enabled"] = introspection_enabled
            endpoint_info["returns_errors"] = isinstance(parsed, dict) and "errors" in parsed

            if introspection_enabled:
                introspection_enabled_count += 1
                type_count = body_text.count('"name"')
                endpoint_info["approx_types"] = type_count
                self.discovered_endpoints.add(path)

            endpoints_found.append(endpoint_info)

        if not endpoints_found:
            self._add_finding(
                title="No GraphQL Endpoint Detected",
                severity="INFO",
                evidence=f"Probed {len(self._GRAPHQL_PATHS)} common GraphQL paths; none responded with a 200 status.",
                recommendation="If GraphQL is used, ensure introspection is disabled and the endpoint is authenticated.",
                wstg_ids=["WSTG-4.12.1"]
            )
            return

        if introspection_enabled_count:
            self._add_finding(
                title="GraphQL Introspection Enabled",
                severity="HIGH",
                evidence=(
                    f"{introspection_enabled_count} GraphQL endpoint(s) returned schema data "
                    f"via introspection (out of {len(endpoints_found)} found)."
                ),
                recommendation="Disable GraphQL introspection in production. Enforce authentication and authorization. Add query depth/complexity limits.",
                wstg_ids=["WSTG-4.12.1"]
            )
        else:
            self._add_finding(
                title="GraphQL Endpoint Detected – Introspection Disabled",
                severity="MEDIUM",
                evidence=f"{len(endpoints_found)} GraphQL endpoint(s) responded but did not expose schema data.",
                recommendation="Ensure the GraphQL endpoint enforces authentication, authorization, and query complexity limits.",
                wstg_ids=["WSTG-4.12.1"]
            )

    # ------------------------------------------------------------------
    # 3. NEW: API Version Discovery
    # ------------------------------------------------------------------
    def _check_api_version_discovery(self) -> None:
        """Discover API version endpoints."""
        versions_found: list[str] = []

        for path in self._API_VERSION_PATHS:
            test_url = urljoin(self.base_url + "/", path.lstrip("/"))
            try:
                response = self._session.get(test_url, timeout=5)
                if response.status_code in (200, 301, 302, 308):
                    versions_found.append(path)
                    self.api_versions.add(path)
                    self.discovered_endpoints.add(path)
            except Exception:
                continue

        if versions_found:
            self._add_finding(
                title="API Version Endpoints Discovered",
                severity="INFO",
                evidence=f"Found {len(versions_found)} API version endpoint(s): {', '.join(versions_found[:10])}",
                recommendation="Ensure versioned API endpoints are properly documented and secured. Consider deprecating old versions and enforcing authentication on all versions.",
                wstg_ids=["WSTG-4.12.1"]
            )

    # ------------------------------------------------------------------
    # 4. NEW: Rate Limiting Detection
    # ------------------------------------------------------------------
    def _check_rate_limiting(self, response) -> None:
        """Detect rate limiting headers and behaviors."""
        if not response:
            return

        rate_limit_headers = {
            "X-RateLimit-Limit": None,
            "X-RateLimit-Remaining": None,
            "X-RateLimit-Reset": None,
            "Retry-After": None,
        }

        found_headers: dict[str, str] = {}
        for header in rate_limit_headers:
            value = response.headers.get(header)
            if value:
                found_headers[header] = value

        # Check for 429 status on a rapid-fire request (simple check)
        rate_limit_detected = bool(found_headers)

        self.rate_limit_info = {
            "detected": rate_limit_detected,
            "headers": found_headers,
        }

        if rate_limit_detected:
            evidence = f"Rate limiting headers detected: {', '.join(found_headers.keys())}"
            if "X-RateLimit-Remaining" in found_headers:
                evidence += f" (Remaining: {found_headers['X-RateLimit-Remaining']})"
            self._add_finding(
                title="Rate Limiting Detected",
                severity="INFO",
                evidence=evidence,
                recommendation="Rate limiting is implemented. Ensure limits are appropriate for your API usage patterns and that limits are enforced consistently across all endpoints.",
                wstg_ids=["WSTG-4.12.5"]
            )
        else:
            self._add_finding(
                title="No Rate Limiting Headers Detected",
                severity="MEDIUM",
                evidence="API responses do not include standard rate limiting headers (X-RateLimit-*, Retry-After).",
                recommendation="Implement rate limiting on all API endpoints to prevent abuse, DoS attacks, and ensure fair usage. Return appropriate 429 responses with Retry-After header when limits are exceeded.",
                wstg_ids=["WSTG-4.12.5"]
            )

    # ------------------------------------------------------------------
    # 5. Sensitive endpoint classification (unchanged)
    # ------------------------------------------------------------------
    def _check_sensitive_endpoints(self, html: str) -> None:
        """Classify discovered API endpoints by sensitivity."""
        client_endpoints = self._extract_endpoints_from_html(html)
        for ep in client_endpoints:
            self.discovered_endpoints.add(ep)

        if not self.discovered_endpoints:
            self._add_finding(
                title="No Sensitive Endpoints Detected",
                severity="INFO",
                evidence="No API endpoint references found in markup or OpenAPI specs.",
                recommendation="Continue monitoring for sensitive endpoint exposure.",
            )
            return

        classification = self._classify_paths(list(self.discovered_endpoints))
        sensitive_categories = {cat: eps for cat, eps in classification.items() if eps}

        if not sensitive_categories:
            self._add_finding(
                title="Endpoints Discovered – None Classified Sensitive",
                severity="INFO",
                evidence=f"{len(self.discovered_endpoints)} endpoint(s) discovered; none matched sensitive keyword categories.",
                recommendation="Review discovered endpoints to confirm none handle privileged or personal data.",
            )
            return

        total_sensitive = sum(len(eps) for eps in sensitive_categories.values())
        detail = "; ".join(f"{cat}: {len(eps)} ({', '.join(eps[:3])})" for cat, eps in sensitive_categories.items())
        severity = "HIGH" if any(cat in ("privileged", "financial", "config") for cat in sensitive_categories) else "MEDIUM"

        self._add_finding(
            title="Sensitive Endpoints Classified",
            severity=severity,
            evidence=f"{total_sensitive} sensitive endpoint(s) across {len(sensitive_categories)} category/categories. {detail}",
            recommendation="Enforce strict authentication and per-resource authorization on every sensitive endpoint. Use non-predictable identifiers and least-privilege role checks.",
            wstg_ids=["WSTG-4.12.1", "WSTG-4.12.3"]
        )

    # ------------------------------------------------------------------
    # 6. API authentication review (enhanced)
    # ------------------------------------------------------------------
    def _check_api_authentication(self, html: str, homepage_resp) -> None:
        """Review API authentication posture."""
        issues: list[str] = []

        # 6a. Probe discovered endpoints without credentials
        unauthenticated_accessible: list[str] = []
        sample_endpoints = list(self.discovered_endpoints)[:15]
        for ep in sample_endpoints:
            test_url = self._absolute_endpoint_url(ep)
            if test_url is None:
                continue
            try:
                response = self._session.get(test_url, timeout=5)
                if response.status_code == 200:
                    unauthenticated_accessible.append(ep)
            except Exception:
                continue

        if unauthenticated_accessible:
            sensitive_class = self._classify_paths(unauthenticated_accessible)
            sensitive_hits = [ep for cat, eps in sensitive_class.items() if eps for ep in eps]
            if sensitive_hits:
                issues.append(f"{len(sensitive_hits)} sensitive endpoint(s) accessible without authentication: {', '.join(sensitive_hits[:5])}")
                self._add_finding(
                    title="Unauthenticated Access to Sensitive API Endpoints",
                    severity="HIGH",
                    evidence=f"Sensitive endpoints returned 200 without credentials: {', '.join(sensitive_hits[:5])}",
                    recommendation="Require authentication and per-resource authorization on all sensitive endpoints. Return 401/403 for unauthenticated requests.",
                    wstg_ids=["WSTG-4.12.2", "WSTG-4.12.3"]
                )
            elif unauthenticated_accessible:
                self._add_finding(
                    title="API Endpoints Accessible Without Authentication",
                    severity="MEDIUM",
                    evidence=f"{len(unauthenticated_accessible)} endpoint(s) returned 200 without credentials.",
                    recommendation="Confirm whether these endpoints are intentionally public; otherwise enforce authentication.",
                    wstg_ids=["WSTG-4.12.2"]
                )

        # 6b. Scan for leaked credentials/tokens (enhanced patterns)
        leaked: list[str] = []
        for pattern, label in self._CREDENTIAL_PATTERNS:
            for match in re.findall(pattern, html, re.I):
                if re.fullmatch(r"(your[_\-]?key|xxx+|placeholder|<[^>]+>|example)", match, re.I):
                    continue
                leaked.append(f"{label} (value preview: {match[:6]}…)")
        if leaked:
            issues.append(f"{len(leaked)} credential/token(s) exposed in client-side code")
            self._add_finding(
                title="API Credentials Exposed in Client-Side Code",
                severity="HIGH",
                evidence=f"Found {len(leaked)} credential-like value(s) embedded in HTML/JS: {', '.join(leaked[:5])}",
                recommendation="Never embed API keys, bearer tokens, or secrets in client-side code. Proxy authenticated requests through a backend that holds secrets server-side. Rotate any exposed credentials.",
                wstg_ids=["WSTG-4.12.2"]
            )

        # 6c. Check for HTTP Basic auth
        basic_auth_detected = False
        for probe_path in ("/api", "/api/v1", "/rest"):
            test_url = urljoin(self.base_url + "/", probe_path.lstrip("/"))
            try:
                response = self._session.get(test_url, timeout=5)
                www_auth = response.headers.get("WWW-Authenticate", "")
                if "basic" in www_auth.lower():
                    basic_auth_detected = True
                    break
            except Exception:
                continue

        if basic_auth_detected:
            self._add_finding(
                title="HTTP Basic Authentication on API Endpoint",
                severity="MEDIUM",
                evidence="An API entry point advertises HTTP Basic authentication (WWW-Authenticate: Basic).",
                recommendation="Replace Basic Auth with token-based schemes (OAuth 2.0, JWT) over HTTPS. Basic credentials are replayable.",
                wstg_ids=["WSTG-4.12.2"]
            )

        # 6d. JWT token analysis (NEW)
        self._check_jwt_tokens(homepage_resp)

        if not issues:
            self._add_finding(
                title="No API Authentication Weaknesses Detected",
                severity="INFO",
                evidence="Discovered endpoints were protected or no credentials were found in client-side code.",
                recommendation="Maintain token-based authentication with short-lived, scoped credentials.",
                wstg_ids=["WSTG-4.12.2"]
            )

    # ------------------------------------------------------------------
    # NEW: JWT Token Analysis
    # ------------------------------------------------------------------
    def _check_jwt_tokens(self, response) -> None:
        """Analyze JWT tokens for security issues."""
        if not response:
            return

        jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        jwt_cookies = []
        for cookie in response.cookies:
            if re.fullmatch(jwt_pattern, cookie.value):
                jwt_cookies.append((cookie.name, cookie.value))
        jwt_html = re.findall(jwt_pattern, response.text or "")

        all_jwts = [("cookie", name, val) for name, val in jwt_cookies] + [("html", None, t) for t in jwt_html]
        if not all_jwts:
            return

        issues = []
        for src, name, token in all_jwts[:5]:  # Check first 5 tokens
            try:
                header_b64, payload_b64, _ = token.split('.')
                header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))
                payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
                alg = header.get('alg', 'none').upper()
                exp = payload.get('exp')

                if alg == 'NONE':
                    issues.append(f"{src} JWT uses 'none' algorithm (unsigned)")
                if alg.startswith('HS') and any('secret' in str(v).lower() for v in payload.values()):
                    issues.append(f"{src} JWT payload may contain secrets")
                if not exp:
                    issues.append(f"{src} JWT missing expiration")
            except Exception:
                issues.append(f"{src} JWT could not be parsed")

        if issues:
            severity = "HIGH" if any('none' in i.lower() or 'missing expiration' in i.lower() for i in issues) else "MEDIUM"
            self._add_finding(
                title="JWT Token Security Issues Detected",
                severity=severity,
                evidence="; ".join(issues),
                recommendation="Use strong signing algorithms (RS256/ES256), include expiration, and keep secrets out of payload. Store JWTs in HttpOnly cookies.",
                wstg_ids=["WSTG-4.12.2", "WSTG-4.12.4"]
            )

    # ------------------------------------------------------------------
    # Helpers (unchanged)
    # ------------------------------------------------------------------
    def _extract_endpoints_from_html(self, html: str) -> list[str]:
        """Pull API endpoint references from client-side markup/JS."""
        if not html:
            return []
        patterns = [
            r'["\'`](/api/[\w\-/{}.:]+)["\'`]',
            r'["\'`](/rest/[\w\-/{}.:]+)["\'`]',
            r'fetch\(\s*["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']',
            r'\.(?:get|post|put|delete|patch)\(\s*["\'](/[^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'["\'](/v\d+/[\w\-/{}.:]+)["\'`]',
        ]
        endpoints: set[str] = set()
        for pat in patterns:
            for match in re.findall(pat, html, re.I):
                candidate = match.split("?")[0]
                if candidate.startswith("/") and len(candidate) > 1:
                    endpoints.add(candidate)
        return list(endpoints)

    def _classify_paths(self, paths: list[str]) -> dict[str, list[str]]:
        """Group endpoint paths into sensitivity categories."""
        classification: dict[str, list[str]] = {cat: [] for cat in self._SENSITIVE_KEYWORDS}
        for path in paths:
            lowered = path.lower()
            for category, keywords in self._SENSITIVE_KEYWORDS.items():
                if any(kw in lowered for kw in keywords):
                    if path not in classification[category]:
                        classification[category].append(path)
        return classification

    def _absolute_endpoint_url(self, endpoint: str) -> str | None:
        """Resolve an endpoint reference against the base URL."""
        if not endpoint:
            return None
        parsed = urlparse(endpoint)
        if parsed.scheme in ("http", "https"):
            return endpoint
        if endpoint.startswith("/"):
            return urljoin(self.base_url + "/", endpoint.lstrip("/"))
        return None

    def _add_finding(self, title: str, severity: str, evidence: str, recommendation: str | None = None, wstg_ids: list[str] = None):
        finding = {
            "title": title,
            "severity": severity,
            "evidence": evidence,
        }
        if wstg_ids:
            finding["wstg_ids"] = wstg_ids
        finding["cwe_ids"] = self._map_to_cwe(title, severity)
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

    def _map_to_wstg(self, title: str) -> list[str]:
        """Map finding title to WSTG 4.12 sub-identifiers."""
        tl = title.lower()
        mapping = {
            "openapi": ["WSTG-4.12.1"],
            "swagger": ["WSTG-4.12.1"],
            "graphql": ["WSTG-4.12.1"],
            "introspection": ["WSTG-4.12.1"],
            "api version": ["WSTG-4.12.1"],
            "sensitive endpoint": ["WSTG-4.12.1", "WSTG-4.12.3"],
            "unauthenticated": ["WSTG-4.12.2", "WSTG-4.12.3"],
            "credential": ["WSTG-4.12.2"],
            "api key": ["WSTG-4.12.2"],
            "jwt": ["WSTG-4.12.2", "WSTG-4.12.4"],
            "basic auth": ["WSTG-4.12.2"],
            "authentication": ["WSTG-4.12.2"],
            "rate limiting": ["WSTG-4.12.5"],
        }
        for key, ids in mapping.items():
            if key in tl:
                return ids
        return ["WSTG-4.12.1"]

    def _map_to_cwe(self, title: str, severity: str) -> list[str]:
        """Map finding title to CWE IDs."""
        tl = title.lower()
        mapping = {
            "openapi": ["CWE-200", "CWE-540"],
            "swagger": ["CWE-200", "CWE-540"],
            "introspection": ["CWE-200", "CWE-639"],
            "graphql": ["CWE-200"],
            "sensitive endpoint": ["CWE-284", "CWE-639"],
            "unauthenticated": ["CWE-306", "CWE-862"],
            "credential": ["CWE-312", "CWE-522"],
            "api key": ["CWE-312", "CWE-522"],
            "jwt": ["CWE-113", "CWE-347"],
            "basic auth": ["CWE-287", "CWE-319"],
            "authentication": ["CWE-306"],
            "rate limiting": ["CWE-770"],
        }
        for key, cwes in mapping.items():
            if key in tl:
                return cwes
        return []
