"""
Entry Point Mapper Module
OWASP WSTG 4.7 - Input Validation Testing
Implements: Form discovery, Parameter extraction, API endpoints, Upload forms
"""

import requests
import re
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

class EntryPointMapper:
    """Maps and inventories application entry points"""
    
    def __init__(self, base_url: str, headless_browser=None):
        self.base_url = base_url
        self.browser = headless_browser
        self.session = requests.Session()
        self.forms_inventory = []
        self.parameters_inventory = []
        self.api_endpoints = []
        self.upload_forms = []
        
    def discover_forms(self) -> Dict[str, Any]:
        """
        WSTG 4.7: Discover all forms in the application
        Maps form locations, methods, and input fields
        """
        try:
            response = self.session.get(self.base_url, timeout=10)
            response.raise_for_status()
        except:
            return {'test_name': 'Form Discovery', 'error': 'Failed to fetch page', 'forms': []}
        
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        discovered_forms = []
        
        for idx, form in enumerate(forms):
            form_info = {
                'form_id': idx + 1,
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                'url': urljoin(self.base_url, form.get('action', '')),
                'inputs': [],
                'has_file_upload': False,
                'is_search_form': False,
                'is_login_form': False,
                'is_registration_form': False,
            }
            
            # Analyze form inputs
            for input_field in form.find_all(['input', 'textarea', 'select']):
                input_type = input_field.get('type', 'text').lower()
                input_name = input_field.get('name', '')
                
                if input_name:
                    form_info['inputs'].append({
                        'name': input_name,
                        'type': input_type,
                        'value': input_field.get('value', ''),
                        'required': 'required' in input_field.attrs,
                        'placeholder': input_field.get('placeholder', '')
                    })
                
                if input_type == 'file':
                    form_info['has_file_upload'] = True
                
                # Classify form
                if any(keyword in input_name.lower() for keyword in ['search', 'q', 'query']):
                    form_info['is_search_form'] = True
                if any(keyword in str(form).lower() for keyword in ['login', 'signin', 'username']):
                    form_info['is_login_form'] = True
                if any(keyword in str(form).lower() for keyword in ['register', 'signup', 'registration']):
                    form_info['is_registration_form'] = True
            
            discovered_forms.append(form_info)
            self.forms_inventory.append(form_info)
        
        return {
            'test_name': 'Form Discovery (WSTG-4.7)',
            'url': self.base_url,
            'forms_discovered': len(discovered_forms),
            'forms': discovered_forms,
            'upload_forms': len([f for f in discovered_forms if f['has_file_upload']]),
            'login_forms': len([f for f in discovered_forms if f['is_login_form']]),
            'search_forms': len([f for f in discovered_forms if f['is_search_form']]),
            'recommendations': [
                'Validate all form inputs server-side',
                'Implement CSRF protection tokens',
                'Use proper input encoding',
                'Apply rate limiting to sensitive forms',
                'Log all form submissions'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.7'
        }
    
    def extract_parameters(self) -> Dict[str, Any]:
        """
        WSTG 4.7: Extract GET and POST parameters
        Inventories all parameters found in forms and URLs
        """
        try:
            response = self.session.get(self.base_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
        except:
            return {'test_name': 'Parameter Extraction', 'error': 'Failed to fetch page', 'parameters': []}
        
        parameters = {
            'get_parameters': [],
            'post_parameters': [],
            'hidden_parameters': [],
            'cookie_parameters': []
        }
        
        # Extract from forms
        for form in soup.find_all('form'):
            method = form.get('method', 'GET').upper()
            
            for input_field in form.find_all(['input', 'textarea']):
                param_name = input_field.get('name', '')
                param_type = input_field.get('type', 'text')
                
                if param_name:
                    param_info = {
                        'name': param_name,
                        'type': param_type,
                        'form_action': form.get('action', ''),
                        'evidence': 'Form input'
                    }
                    
                    if param_type == 'hidden':
                        parameters['hidden_parameters'].append(param_info)
                    elif method == 'GET':
                        parameters['get_parameters'].append(param_info)
                    else:
                        parameters['post_parameters'].append(param_info)
                    
                    self.parameters_inventory.append(param_info)
        
        # Extract from URL query strings
        parsed_url = urlparse(self.base_url)
        if parsed_url.query:
            url_params = parse_qs(parsed_url.query)
            for param_name in url_params.keys():
                param_info = {
                    'name': param_name,
                    'type': 'GET',
                    'source': 'URL Query String',
                    'evidence': 'URL parameter'
                }
                parameters['get_parameters'].append(param_info)
                self.parameters_inventory.append(param_info)
        
        # Extract cookies
        if self.session.cookies:
            for cookie_name in self.session.cookies.keys():
                parameters['cookie_parameters'].append({
                    'name': cookie_name,
                    'type': 'Cookie',
                    'evidence': 'HTTP Cookie'
                })
        
        return {
            'test_name': 'Parameter Extraction (WSTG-4.7)',
            'url': self.base_url,
            'total_parameters': sum(len(v) for v in parameters.values()),
            'parameters': parameters,
            'risky_parameter_names': self._identify_risky_parameters(parameters),
            'recommendations': [
                'Whitelist acceptable parameter names',
                'Validate parameter types and values',
                'Implement strict input validation',
                'Use parameterized queries for database access',
                'Sanitize all parameter values'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.7'
        }
    
    def discover_api_endpoints(self) -> Dict[str, Any]:
        """
        WSTG 4.12: Discover API endpoints
        Maps REST API endpoints, GraphQL, WebSockets
        """
        api_patterns = {
            'rest_endpoints': [
                '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/rest/api'
            ],
            'graphql_endpoints': [
                '/graphql', '/graph', '/api/graphql', '/api/graph'
            ],
            'swagger_endpoints': [
                '/swagger', '/swagger.json', '/swagger-ui', '/swagger-ui.html',
                '/api/swagger', '/api-docs', '/api-docs.json'
            ],
            'openapi_endpoints': [
                '/openapi', '/openapi.json', '/openapi.yaml', '/api/openapi'
            ]
        }
        
        discovered_apis = []
        
        for api_type, endpoints in api_patterns.items():
            for endpoint in endpoints:
                test_url = urljoin(self.base_url, endpoint)
                
                try:
                    response = self.session.get(test_url, timeout=5)
                    
                    if response.status_code in [200, 301, 302]:
                        api_info = {
                            'endpoint': endpoint,
                            'url': test_url,
                            'type': api_type,
                            'status_code': response.status_code,
                            'accessible': response.status_code == 200,
                            'content_type': response.headers.get('Content-Type', ''),
                            'severity': 'MEDIUM' if response.status_code == 200 else 'LOW'
                        }
                        
                        # Analyze response
                        if response.status_code == 200:
                            if 'json' in response.text[:500]:
                                api_info['format'] = 'JSON'
                            if 'query' in response.text.lower():
                                api_info['format'] = 'GraphQL'
                            if 'swagger' in response.text.lower():
                                api_info['format'] = 'Swagger/OpenAPI'
                        
                        discovered_apis.append(api_info)
                        self.api_endpoints.append(api_info)
                except:
                    pass
        
        return {
            'test_name': 'API Endpoint Discovery (WSTG-4.12)',
            'base_url': self.base_url,
            'discovered_apis': discovered_apis,
            'total_found': len(discovered_apis),
            'by_type': self._group_apis_by_type(discovered_apis),
            'graphql_enabled': any('graphql' in api['type'] for api in discovered_apis),
            'swagger_exposed': any('swagger' in api['endpoint'] for api in discovered_apis),
            'recommendations': [
                'Secure API endpoints with authentication',
                'Implement API rate limiting',
                'Disable API documentation in production',
                'Use API keys or OAuth for access control',
                'Monitor API endpoint access',
                'Implement CORS policy for APIs'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.12'
        }
    
    def discover_upload_forms(self) -> Dict[str, Any]:
        """
        WSTG 4.10: Discover file upload capabilities
        Identifies upload forms and their characteristics
        """
        try:
            response = self.session.get(self.base_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
        except:
            return {'test_name': 'Upload Form Discovery', 'error': 'Failed to fetch page', 'uploads': []}
        
        upload_forms = []
        
        for form in soup.find_all('form'):
            # Check if form has file input
            file_inputs = form.find_all('input', {'type': 'file'})
            
            if file_inputs:
                upload_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'POST').upper(),
                    'url': urljoin(self.base_url, form.get('action', '')),
                    'enctype': form.get('enctype', ''),
                    'file_inputs': []
                }
                
                for file_input in file_inputs:
                    upload_info['file_inputs'].append({
                        'name': file_input.get('name', ''),
                        'accept': file_input.get('accept', 'any'),
                        'multiple': 'multiple' in file_input.attrs,
                        'required': 'required' in file_input.attrs
                    })
                
                upload_forms.append(upload_info)
                self.upload_forms.append(upload_info)
        
        return {
            'test_name': 'Upload Form Discovery (WSTG-4.10)',
            'url': self.base_url,
            'upload_forms_found': len(upload_forms),
            'upload_forms': upload_forms,
            'recommendations': [
                'Validate file types server-side, not just extension',
                'Store uploads outside web root',
                'Rename uploaded files',
                'Implement file size limits',
                'Scan uploads for malware',
                'Disable script execution in upload directories',
                'Implement rate limiting for uploads'
            ],
            'severity': 'HIGH' if upload_forms else 'LOW',
            'wstg_reference': 'WSTG-4.10'
        }
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Execute all entry point mapping tests"""
        results = {
            'category': 'Entry Point Mapping',
            'base_url': self.base_url,
            'timestamp': self._get_timestamp(),
            'tests': [
                self.discover_forms(),
                self.extract_parameters(),
                self.discover_api_endpoints(),
                self.discover_upload_forms()
            ],
            'summary': {
                'total_forms': len(self.forms_inventory),
                'total_parameters': len(self.parameters_inventory),
                'api_endpoints': len(self.api_endpoints),
                'upload_forms': len(self.upload_forms),
                'total_entry_points': (len(self.forms_inventory) + 
                                      len(self.parameters_inventory) + 
                                      len(self.api_endpoints))
            },
            'wstg_coverage': ['WSTG-4.7 (Input Validation)', 'WSTG-4.12 (API Testing)']
        }
        return results
    
    @staticmethod
    def _identify_risky_parameters(parameters: Dict) -> List[str]:
        """Identify potentially risky parameter names"""
        risky_keywords = ['admin', 'id', 'user', 'pass', 'token', 'key', 
                         'secret', 'debug', 'test', 'eval', 'exec', 'cmd']
        risky_params = []
        
        for param_list in parameters.values():
            for param in param_list:
                param_name = param.get('name', '').lower()
                if any(keyword in param_name for keyword in risky_keywords):
                    risky_params.append(param['name'])
        
        return list(set(risky_params))
    
    @staticmethod
    def _group_apis_by_type(apis: List[Dict]) -> Dict[str, int]:
        """Group APIs by type"""
        grouped = {}
        for api in apis:
            api_type = api['type']
            grouped[api_type] = grouped.get(api_type, 0) + 1
        return grouped
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
