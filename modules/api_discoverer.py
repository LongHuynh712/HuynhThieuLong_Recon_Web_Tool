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
                self.discover_api_documentation()
            ],
            'summary': {
                'total_apis': len(self.apis_discovered),
                'swagger_endpoints': len([a for a in self.apis_discovered if 'swagger' in str(a).lower()]),
                'graphql_endpoints': len([a for a in self.apis_discovered if 'graphql' in str(a).lower()]),
                'rest_endpoints': len([a for a in self.apis_discovered if 'rest' in str(a).lower()])
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
