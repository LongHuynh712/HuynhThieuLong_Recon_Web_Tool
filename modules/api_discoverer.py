"""
API Discoverer Module
OWASP WSTG 4.12 - API Testing
Implements: Swagger/OpenAPI discovery, GraphQL discovery, API documentation
"""

import requests
import json
import re
from typing import List, Dict, Any
from urllib.parse import urljoin

class APIDiscoverer:
    """Discovers and inventories API endpoints"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.apis_discovered = []
        
    def discover_swagger_openapi(self) -> Dict[str, Any]:
        """
        WSTG 4.12: Discover Swagger/OpenAPI documentation
        Locates API documentation and specs
        """
        swagger_paths = [
            '/swagger',
            '/swagger.json',
            '/swagger.yaml',
            '/swagger-ui',
            '/swagger-ui.html',
            '/api/swagger',
            '/api/swagger.json',
            '/api-docs',
            '/api-docs.json',
            '/api-docs.yaml',
            '/v1/api-docs',
            '/v2/api-docs',
            '/v3/api-docs',
            '/openapi',
            '/openapi.json',
            '/openapi.yaml',
            '/.well-known/swagger.json',
            '/.well-known/openapi.json',
        ]
        
        swagger_findings = []
        
        for path in swagger_paths:
            test_url = urljoin(self.base_url, path)
            
            try:
                response = requests.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    swagger_info = {
                        'url': test_url,
                        'path': path,
                        'status': 'FOUND',
                        'type': self._identify_swagger_type(path),
                        'content_type': response.headers.get('Content-Type', ''),
                        'size': len(response.content),
                        'accessible': True,
                        'severity': 'MEDIUM'
                    }
                    
                    # Try to parse content
                    try:
                        content = response.json()
                        swagger_info['parseable'] = True
                        swagger_info['title'] = content.get('info', {}).get('title', 'Unknown')
                        swagger_info['version'] = content.get('info', {}).get('version', 'Unknown')
                        swagger_info['endpoints_count'] = len(content.get('paths', {}))
                    except:
                        swagger_info['parseable'] = False
                    
                    swagger_findings.append(swagger_info)
                    self.apis_discovered.append(swagger_info)
                    
            except:
                pass
        
        return {
            'test_name': 'Swagger/OpenAPI Discovery (WSTG-4.12)',
            'url': self.base_url,
            'swagger_found': len(swagger_findings),
            'swagger_specs': swagger_findings,
            'recommendations': [
                'Disable API documentation in production',
                'Protect API documentation with authentication',
                'Review all documented endpoints',
                'Implement rate limiting for API endpoints',
                'Monitor API documentation access'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.12'
        }
    
    def discover_graphql(self) -> Dict[str, Any]:
        """
        WSTG 4.12: Discover GraphQL endpoints
        Identifies GraphQL APIs and queries introspection
        """
        graphql_paths = [
            '/graphql',
            '/graph',
            '/api/graphql',
            '/graphql/',
            '/api/v1/graphql',
            '/api/v2/graphql',
            '/gql',
            '/.graphql',
        ]
        
        graphql_findings = []
        
        for path in graphql_paths:
            test_url = urljoin(self.base_url, path)
            
            try:
                # Test with introspection query
                payload = {
                    'query': '{ __schema { types { name } } }'
                }
                
                response = requests.post(test_url, json=payload, timeout=5)
                
                if response.status_code == 200:
                    graphql_info = {
                        'url': test_url,
                        'path': path,
                        'status': 'FOUND',
                        'introspection_enabled': '__schema' in response.text,
                        'severity': 'HIGH' if '__schema' in response.text else 'MEDIUM'
                    }
                    
                    try:
                        data = response.json()
                        graphql_info['parseable'] = True
                        graphql_info['has_errors'] = 'errors' in data
                    except:
                        graphql_info['parseable'] = False
                    
                    graphql_findings.append(graphql_info)
                    self.apis_discovered.append(graphql_info)
                    
            except:
                pass
        
        return {
            'test_name': 'GraphQL Discovery (WSTG-4.12)',
            'url': self.base_url,
            'graphql_endpoints': graphql_findings,
            'total_found': len(graphql_findings),
            'introspection_enabled': len([g for g in graphql_findings if g.get('introspection_enabled')]),
            'recommendations': [
                'Disable GraphQL introspection in production',
                'Implement proper authentication and authorization',
                'Add rate limiting to GraphQL queries',
                'Validate and sanitize GraphQL inputs',
                'Monitor GraphQL query patterns',
                'Implement query complexity limits'
            ],
            'severity': 'HIGH',
            'wstg_reference': 'WSTG-4.12'
        }
    
    def discover_rest_api(self) -> Dict[str, Any]:
        """
        WSTG 4.12: Discover REST API endpoints
        Maps REST API infrastructure
        """
        api_paths = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/api/v3',
            '/rest',
            '/rest/api',
            '/v1',
            '/v2',
            '/v3',
        ]
        
        rest_findings = []
        
        for path in api_paths:
            test_url = urljoin(self.base_url, path)
            
            try:
                response = requests.get(test_url, timeout=5)
                
                if response.status_code in [200, 401, 403]:
                    rest_info = {
                        'url': test_url,
                        'path': path,
                        'status': response.status_code,
                        'accessible': response.status_code == 200,
                        'protected': response.status_code in [401, 403],
                        'content_type': response.headers.get('Content-Type', ''),
                    }
                    
                    rest_findings.append(rest_info)
                    self.apis_discovered.append(rest_info)
                    
            except:
                pass
        
        return {
            'test_name': 'REST API Discovery (WSTG-4.12)',
            'url': self.base_url,
            'rest_endpoints': rest_findings,
            'total_found': len(rest_findings),
            'public_endpoints': len([r for r in rest_findings if r['accessible']]),
            'protected_endpoints': len([r for r in rest_findings if r['protected']]),
            'recommendations': [
                'Document all API endpoints',
                'Implement API versioning',
                'Use consistent URL patterns',
                'Implement API authentication',
                'Monitor API usage patterns',
                'Implement API rate limiting'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.12'
        }
    
    def discover_api_documentation(self) -> Dict[str, Any]:
        """
        WSTG 4.12: Discover API documentation
        Finds API documentation pages
        """
        doc_paths = [
            '/docs',
            '/documentation',
            '/api-documentation',
            '/api/docs',
            '/api/documentation',
            '/help',
            '/guide',
            '/guides',
            '/readme',
            '/FAQ',
            '/support',
        ]
        
        doc_findings = []
        
        for path in doc_paths:
            test_url = urljoin(self.base_url, path)
            
            try:
                response = requests.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    doc_info = {
                        'url': test_url,
                        'path': path,
                        'title': self._extract_title(response.text),
                        'accessibility': 'Public' if response.status_code == 200 else 'Protected',
                        'severity': 'MEDIUM'
                    }
                    
                    doc_findings.append(doc_info)
                    
            except:
                pass
        
        return {
            'test_name': 'API Documentation Discovery (WSTG-4.12)',
            'url': self.base_url,
            'documentation_found': doc_findings,
            'total_found': len(doc_findings),
            'recommendations': [
                'Review all documentation for sensitive information',
                'Restrict documentation access in production',
                'Keep documentation in sync with implementation',
                'Remove example credentials from documentation'
            ],
            'severity': 'LOW',
            'wstg_reference': 'WSTG-4.12'
        }
    
    def classify_api_authentication(self) -> Dict[str, Any]:
        """Passive API authentication classification (WSTG-4.12.1).

        Inspects discovered Swagger/OpenAPI specifications for defined
        security schemes (e.g., apiKey, http/bearer, oauth2). The presence
        of any scheme indicates that the API documents authentication
        requirements; lack thereof suggests unauthenticated/public API.
        """
        auth_methods: set[str] = set()
        for entry in self.apis_discovered:
            if entry.get('type') in ('Swagger', 'OpenAPI') and entry.get('parseable'):
                try:
                    resp = requests.get(entry['url'], timeout=5)
                    spec = resp.json()
                    sec_schemes = spec.get('components', {}).get('securitySchemes', {})
                    for name, scheme in sec_schemes.items():
                        auth_methods.add(scheme.get('type', 'unknown'))
                except Exception:
                    continue
        if auth_methods:
            severity = 'MEDIUM'
            finding = f"Authentication schemes documented: {', '.join(sorted(auth_methods))}"
        else:
            severity = 'INFO'
            finding = 'No authentication schemes documented in discovered OpenAPI/Swagger specs.'
        return {
            'test_name': 'API Authentication Classification (Passive) (WSTG-4.12.1)',
            'url': self.base_url,
            'finding': finding,
            'severity': severity,
            'wstg_reference': 'WSTG-4.12.1',
        }

    def detect_api_authorization(self) -> Dict[str, Any]:
        """Passive API authorization indicators (WSTG-4.12.2).

        Looks for role‑based or privilege‑related path fragments (admin,
        manager, role, permission, private) in discovered REST/Swagger
        endpoints and for `security` requirements per operation in OpenAPI
        specs. Presence of such patterns suggests authorization controls
        (or lack thereof) that merit review.
        """
        auth_indicators = []
        # Path‑based heuristics
        sensitive_keywords = ['admin', 'manager', 'role', 'permission', 'private', 'secure', 'auth']
        for entry in self.apis_discovered:
            path = entry.get('path', '')
            if any(kw in path.lower() for kw in sensitive_keywords):
                auth_indicators.append(f"Path contains auth hint: {path}")
        # Swagger per‑operation security checks
        for entry in self.apis_discovered:
            if entry.get('type') in ('Swagger', 'OpenAPI') and entry.get('parseable'):
                try:
                    resp = requests.get(entry['url'], timeout=5)
                    spec = resp.json()
                    # Look for global security or per‑operation security
                    if spec.get('security'):
                        auth_indicators.append('Global security requirements defined in OpenAPI spec')
                    # Scan operations
                    for path_item in spec.get('paths', {}).values():
                        for operation in path_item.values():
                            if isinstance(operation, dict) and operation.get('security'):
                                auth_indicators.append('Operation‑level security defined')
                                break
                except Exception:
                    continue
        if auth_indicators:
            severity = 'MEDIUM'
            finding = f"Authorization indicators detected ({len(auth_indicators)})."
        else:
            severity = 'INFO'
            finding = 'No explicit authorization indicators found.'
        return {
            'test_name': 'API Authorization Indicators (Passive) (WSTG-4.12.2)',
            'url': self.base_url,
            'finding': finding,
            'details': auth_indicators,
            'severity': severity,
            'wstg_reference': 'WSTG-4.12.2',
        }

    def detect_rate_limiting(self) -> Dict[str, Any]:
        """Passive API rate‑limiting detection (WSTG-4.12.3).

        Scans response headers of discovered REST endpoints for common
        rate‑limit headers (`X‑RateLimit-Limit`, `RateLimit`, `Retry-After`,
        `X‑Throttle‑Limit`). The presence of any such header indicates
        that rate limiting may be enforced.
        """
        rate_limit_headers = []
        header_names = ['x-ratelimit-limit', 'ratelimit-limit', 'x-ratelimit-remaining',
                        'retry-after', 'x-throttle-limit', 'x-rate-limit']
        for entry in self.apis_discovered:
            if entry.get('content_type'):
                # entry may have been discovered via GET; we need the response object.
                # Since we only stored metadata, re‑fetch the endpoint to inspect headers.
                try:
                    resp = requests.get(entry['url'], timeout=5)
                    for hdr in header_names:
                        if hdr in resp.headers:
                            rate_limit_headers.append({
                                'url': entry['url'],
                                'header': hdr,
                                'value': resp.headers[hdr]
                            })
                except Exception:
                    continue
        if rate_limit_headers:
            severity = 'MEDIUM'
            finding = f"Rate‑limit headers observed on {len(rate_limit_headers)} endpoint(s)."
        else:
            severity = 'INFO'
            finding = 'No rate‑limit headers detected on discovered endpoints.'
        return {
            'test_name': 'API Rate Limiting Detection (Passive) (WSTG-4.12.3)',
            'url': self.base_url,
            'finding': finding,
            'details': rate_limit_headers,
            'severity': severity,
            'wstg_reference': 'WSTG-4.12.3',
        }

    def score_sensitive_endpoints(self) -> Dict[str, Any]:
        """Passive sensitive endpoint risk scoring (WSTG-4.12.5).

        Assigns a risk score (0‑100) based on the presence of sensitive
        keywords in endpoint paths. Each keyword contributes a weighted
        score; the final score is capped at 100.
        """
        keyword_weights = {
            'admin': 20,
            'config': 15,
            'secret': 20,
            'payment': 15,
            'private': 10,
            'auth': 10,
            'credential': 10,
            'debug': 5,
        }
        total_score = 0
        flagged = []
        for entry in self.apis_discovered:
            path = entry.get('path', '').lower()
            for kw, weight in keyword_weights.items():
                if kw in path:
                    total_score += weight
                    flagged.append({'path': entry['url'], 'keyword': kw, 'weight': weight})
        total_score = min(total_score, 100)
        severity = 'HIGH' if total_score >= 70 else ('MEDIUM' if total_score >= 40 else 'LOW')
        return {
            'test_name': 'Sensitive Endpoint Risk Scoring (Passive) (WSTG-4.12.5)',
            'url': self.base_url,
            'risk_score': total_score,
            'flagged_endpoints': flagged,
            'severity': severity,
            'wstg_reference': 'WSTG-4.12.5',
        }

    def validate_openapi_exposure(self) -> Dict[str, Any]:
        """Passive OpenAPI exposure validation (WSTG-4.12.6).

        Checks whether a publicly reachable OpenAPI/Swagger spec contains
        server URLs that expose internal network addresses or hostnames.
        Presence of such URLs indicates information leakage.
        """
        exposures = []
        for entry in self.apis_discovered:
            if entry.get('type') in ('Swagger', 'OpenAPI') and entry.get('parseable'):
                try:
                    resp = requests.get(entry['url'], timeout=5)
                    spec = resp.json()
                    servers = spec.get('servers', [])
                    for srv in servers:
                        url = srv.get('url', '')
                        # Flag internal IP ranges or localhost
                        if re.search(r'10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|127\.0\.0\.1|localhost', url):
                            exposures.append({'url': entry['url'], 'server_url': url})
                except Exception:
                    continue
        if exposures:
            severity = 'HIGH'
            finding = f"OpenAPI spec exposes internal server URLs on {len(exposures)} endpoint(s)."
        else:
            severity = 'INFO'
            finding = 'No internal server URLs exposed in discovered OpenAPI specs.'
        return {
            'test_name': 'OpenAPI Exposure Validation (Passive) (WSTG-4.12.6)',
            'url': self.base_url,
            'finding': finding,
            'details': exposures,
            'severity': severity,
            'wstg_reference': 'WSTG-4.12.6',
        }

    def run_all_tests(self) -> Dict[str, Any]:
        """Execute all API discovery tests"""
        results = {
            'category': 'API Security Discovery',
            'url': self.base_url,
            'timestamp': self._get_timestamp(),
            'tests': [
                self.discover_swagger_openapi(),
                self.discover_graphql(),
                self.discover_rest_api(),
                self.discover_api_documentation(),
                # New passive analyses added here
                self.classify_api_authentication(),
                self.detect_api_authorization(),
                self.detect_rate_limiting(),
                self.score_sensitive_endpoints(),
                self.validate_openapi_exposure(),
            ],
            'summary': {
                'total_apis': len(self.apis_discovered),
                'swagger_endpoints': len([a for a in self.apis_discovered if 'swagger' in str(a).lower()]),
                'graphql_endpoints': len([a for a in self.apis_discovered if 'graphql' in str(a).lower()]),
                'rest_endpoints': len([a for a in self.apis_discovered if 'rest' in str(a).lower()]),
                # New summary statistics
                'auth_classification': self.classify_api_authentication()['finding'],
                'authorization_indicators': self.detect_api_authorization()['finding'],
                'rate_limiting_detected': self.detect_rate_limiting()['finding'],
                'sensitive_endpoint_risk_score': self.score_sensitive_endpoints()['risk_score'],
                'openapi_exposure_validated': self.validate_openapi_exposure()['finding'],
            },
            'wstg_coverage': 'WSTG-4.12 (API Testing)'
        }
        return results

    
    @staticmethod
    def _identify_swagger_type(path: str) -> str:
        """Identify swagger/openapi type"""
        if 'openapi' in path.lower():
            return 'OpenAPI'
        elif 'swagger' in path.lower():
            return 'Swagger'
        else:
            return 'Unknown'
    
    @staticmethod
    def _extract_title(html: str) -> str:
        """Extract page title from HTML"""
        import re
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return match.group(1) if match else 'Unknown'
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
