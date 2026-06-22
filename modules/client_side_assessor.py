"""
Client-Side Assessor Module
OWASP WSTG 4.11 - Client-side Testing
Implements: CORS analysis, Clickjacking, Storage analysis, Third-party JS, WebSockets
"""

import requests
import re
from typing import List, Dict, Any
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class ClientSideAssessor:
    """Assesses client-side security issues"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.cors_findings = []
        self.clickjacking_findings = []
        self.storage_findings = []
        
    def analyze_cors(self) -> Dict[str, Any]:
        """
        WSTG 4.11.7: Analyze CORS configuration
        Tests CORS headers and misconfiguration
        """
        cors_findings = []
        
        try:
            # Test basic CORS headers
            headers = {
                'Origin': 'https://attacker.com'
            }
            response = self.session.get(self.base_url, headers=headers, timeout=5)
            
            cors_info = {
                'url': self.base_url,
                'allow_origin': response.headers.get('Access-Control-Allow-Origin', 'Not Set'),
                'allow_credentials': response.headers.get('Access-Control-Allow-Credentials', 'Not Set'),
                'allow_methods': response.headers.get('Access-Control-Allow-Methods', 'Not Set'),
                'allow_headers': response.headers.get('Access-Control-Allow-Headers', 'Not Set'),
                'max_age': response.headers.get('Access-Control-Max-Age', 'Not Set'),
            }
            
            # Assess CORS risk
            allow_origin = cors_info['allow_origin'].lower()
            cors_info['risk'] = 'LOW'
            cors_info['findings'] = []
            
            if allow_origin == '*':
                cors_info['risk'] = 'HIGH'
                cors_info['findings'].append('CORS allows all origins (Access-Control-Allow-Origin: *)')
            elif 'attacker.com' in allow_origin:
                cors_info['risk'] = 'CRITICAL'
                cors_info['findings'].append('CORS reflects origin without validation')
            
            if cors_info['allow_credentials'] == 'true' and cors_info['allow_origin'] == '*':
                cors_info['risk'] = 'CRITICAL'
                cors_info['findings'].append('CORS misconfiguration: Allows credentials with wildcard')
            
            cors_findings.append(cors_info)
            self.cors_findings = cors_findings
            
        except Exception as e:
            cors_findings.append({'error': str(e)})
        
        return {
            'test_name': 'CORS Analysis (WSTG-4.11.7)',
            'url': self.base_url,
            'cors_findings': cors_findings,
            'vulnerabilities_found': len([f for f in cors_findings if f.get('risk') in ['HIGH', 'CRITICAL']]),
            'recommendations': [
                'Implement strict CORS policy',
                'Whitelist specific origins instead of using wildcard',
                'Avoid allowing credentials with unrestricted origins',
                'Regularly audit CORS configuration',
                'Monitor CORS violations'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.11.7'
        }
    
    def detect_clickjacking_protection(self) -> Dict[str, Any]:
        """
        WSTG 4.11.9: Detect clickjacking protection
        Checks for X-Frame-Options and CSP framing protection
        """
        try:
            response = self.session.get(self.base_url, timeout=5)
            headers = response.headers
        except:
            return {'test_name': 'Clickjacking Detection', 'error': 'Failed to fetch page', 'findings': []}
        
        protection_info = {
            'url': self.base_url,
            'x_frame_options': headers.get('X-Frame-Options', 'Not Set'),
            'content_security_policy': headers.get('Content-Security-Policy', 'Not Set'),
            'protected': False,
            'findings': []
        }
        
        # Check X-Frame-Options
        xfo = protection_info['x_frame_options'].upper()
        if xfo in ['DENY', 'SAMEORIGIN']:
            protection_info['protected'] = True
            protection_info['findings'].append(f'X-Frame-Options: {xfo} ✓')
        elif xfo == 'NOT SET':
            protection_info['findings'].append('X-Frame-Options not set (vulnerable to clickjacking)')
        
        # Check CSP framing
        csp = protection_info['content_security_policy']
        if 'frame-ancestors' in csp:
            protection_info['protected'] = True
            protection_info['findings'].append('Content-Security-Policy frame-ancestors set ✓')
        
        return {
            'test_name': 'Clickjacking Protection (WSTG-4.11.9)',
            'url': self.base_url,
            'protection_status': protection_info,
            'vulnerable': not protection_info['protected'],
            'recommendations': [
                'Implement X-Frame-Options: DENY or SAMEORIGIN',
                'Use CSP frame-ancestors directive',
                'Test clickjacking protection',
                'Monitor for UI redressing attacks'
            ],
            'severity': 'MEDIUM' if not protection_info['protected'] else 'LOW',
            'wstg_reference': 'WSTG-4.11.9'
        }
    
    def analyze_storage(self, response_html: str = None) -> Dict[str, Any]:
        """
        WSTG 4.11.12: Analyze browser storage usage
        Identifies localStorage and sessionStorage usage
        """
        if not response_html:
            try:
                response = self.session.get(self.base_url, timeout=10)
                response_html = response.text
            except:
                return {'test_name': 'Storage Analysis', 'error': 'Failed to fetch page', 'storage': []}
        
        storage_patterns = {
            'localStorage': [
                r'localStorage\.setItem',
                r'localStorage\.getItem',
                r'window\.localStorage',
                r'\.localStorage\s*=',
            ],
            'sessionStorage': [
                r'sessionStorage\.setItem',
                r'sessionStorage\.getItem',
                r'window\.sessionStorage',
                r'\.sessionStorage\s*=',
            ],
            'IndexedDB': [
                r'indexedDB',
                r'IDBDatabase',
                r'IDBObjectStore',
            ],
            'WebSQL': [
                r'openDatabase',
                r'db\.transaction',
            ]
        }
        
        storage_findings = []
        sensitive_data_patterns = [
            'token', 'password', 'secret', 'key', 'credential',
            'session', 'auth', 'jwt', 'api_key', 'apikey'
        ]
        
        for storage_type, patterns in storage_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_html, re.IGNORECASE):
                    risk = 'HIGH' if any(
                        sensitive in response_html.lower() 
                        for sensitive in sensitive_data_patterns
                    ) else 'MEDIUM'
                    
                    storage_findings.append({
                        'storage_type': storage_type,
                        'pattern': pattern,
                        'risk': risk,
                        'finding': f'{storage_type} is used in JavaScript'
                    })
                    break
        
        return {
            'test_name': 'Browser Storage Analysis (WSTG-4.11.12)',
            'url': self.base_url,
            'storage_usage': storage_findings,
            'total_storage_types': len(set(f['storage_type'] for f in storage_findings)),
            'recommendations': [
                'Never store sensitive data in localStorage/sessionStorage',
                'Use secure, httpOnly cookies for session tokens',
                'Implement storage encryption if necessary',
                'Clear storage on logout',
                'Validate storage data server-side'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.11.12'
        }
    
    def inventory_third_party_javascript(self, response_html: str = None) -> Dict[str, Any]:
        """
        WSTG 4.11: Inventory third-party JavaScript
        Identifies external JavaScript sources and dependencies
        """
        if not response_html:
            try:
                response = self.session.get(self.base_url, timeout=10)
                response_html = response.text
            except:
                return {'test_name': 'Third-Party JS Inventory', 'error': 'Failed to fetch page', 'scripts': []}
        
        soup = BeautifulSoup(response_html, 'html.parser')
        third_party_scripts = []
        internal_scripts = []
        
        domain_base = self.base_url.split('/')[2]  # Extract domain
        
        for script in soup.find_all('script', {'src': True}):
            src = script.get('src', '')
            
            # Skip relative URLs
            if src.startswith('/') or src.startswith('.'):
                internal_scripts.append(src)
            else:
                # Extract domain from script URL
                script_domain = src.split('/')[2] if '//' in src else domain_base
                
                is_third_party = domain_base not in script_domain
                
                third_party_scripts.append({
                    'src': src,
                    'domain': script_domain,
                    'is_third_party': is_third_party,
                    'type': self._categorize_script(src),
                    'async': 'async' in script.attrs,
                    'defer': 'defer' in script.attrs,
                })
        
        return {
            'test_name': 'Third-Party JavaScript Inventory (WSTG-4.11)',
            'url': self.base_url,
            'third_party_scripts': third_party_scripts,
            'total_third_party': len(third_party_scripts),
            'internal_scripts': len(internal_scripts),
            'script_types': self._count_script_types(third_party_scripts),
            'recommendations': [
                'Audit all third-party scripts',
                'Implement Subresource Integrity (SRI)',
                'Use Content Security Policy (CSP)',
                'Monitor third-party script changes',
                'Minimize third-party dependencies',
                'Regularly scan for malicious scripts'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.11'
        }
    
    def discover_websockets(self, response_html: str = None) -> Dict[str, Any]:
        """
        WSTG 4.11.10: Discover WebSocket usage
        Identifies WebSocket endpoints and communications
        """
        if not response_html:
            try:
                response = self.session.get(self.base_url, timeout=10)
                response_html = response.text
            except:
                return {'test_name': 'WebSocket Discovery', 'error': 'Failed to fetch page', 'websockets': []}
        
        websocket_patterns = [
            r'new\s+WebSocket\s*\(\s*["\']ws:\/\/',
            r'new\s+WebSocket\s*\(\s*["\']wss:\/\/',
            r'\.connect\s*\(\s*["\']ws:',
            r'websocket',
            r'socket\.io',
        ]
        
        websockets_found = []
        
        for pattern in websocket_patterns:
            matches = re.finditer(pattern, response_html, re.IGNORECASE)
            for match in matches:
                websockets_found.append({
                    'pattern': pattern,
                    'match': match.group(),
                    'position': match.start()
                })
        
        return {
            'test_name': 'WebSocket Discovery (WSTG-4.11.10)',
            'url': self.base_url,
            'websockets_found': bool(websockets_found),
            'websocket_details': websockets_found,
            'total_references': len(websockets_found),
            'recommendations': [
                'Implement WebSocket authentication',
                'Validate and sanitize WebSocket messages',
                'Implement rate limiting for WebSocket connections',
                'Use WSS (secure WebSocket) protocol',
                'Monitor WebSocket traffic for anomalies',
                'Test WebSocket security thoroughly'
            ],
            'severity': 'MEDIUM' if websockets_found else 'LOW',
            'wstg_reference': 'WSTG-4.11.10'
        }
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Execute all client-side security tests"""
        html_response = None
        try:
            response = self.session.get(self.base_url, timeout=10)
            html_response = response.text
        except:
            pass
        
        results = {
            'category': 'Client-Side Security Assessment',
            'url': self.base_url,
            'timestamp': self._get_timestamp(),
            'tests': [
                self.analyze_cors(),
                self.detect_clickjacking_protection(),
                self.analyze_storage(html_response),
                self.inventory_third_party_javascript(html_response),
                self.discover_websockets(html_response)
            ],
            'summary': {
                'cors_misconfigured': len(self.cors_findings),
                'clickjacking_protected': True,
                'websockets_detected': False
            },
            'wstg_coverage': 'WSTG-4.11 (Client-side Testing)'
        }
        return results
    
    @staticmethod
    def _categorize_script(src: str) -> str:
        """Categorize script type from URL"""
        src_lower = src.lower()
        
        if 'google-analytics' in src_lower or '_ga' in src_lower:
            return 'Analytics'
        elif 'facebook' in src_lower or 'fbcdn' in src_lower:
            return 'Social Media'
        elif 'adsbygoogle' in src_lower or 'doubleclick' in src_lower:
            return 'Advertising'
        elif 'cdn' in src_lower or 'cloudflare' in src_lower:
            return 'CDN'
        elif 'jquery' in src_lower or 'bootstrap' in src_lower:
            return 'Framework/Library'
        else:
            return 'Other'
    
    @staticmethod
    def _count_script_types(scripts: List[Dict]) -> Dict[str, int]:
        """Count scripts by type"""
        counts = {}
        for script in scripts:
            script_type = script['type']
            counts[script_type] = counts.get(script_type, 0) + 1
        return counts
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
