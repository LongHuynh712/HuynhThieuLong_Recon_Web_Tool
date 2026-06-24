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
        self.postmessage_findings = []
        self.localstorage_findings = []
        self.sessionstorage_findings = []
        self.dangerous_js_findings = []
        
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
    
    def analyze_postmessage_security(self, response_html: str = None) -> Dict[str, Any]:
        """
        WSTG 4.11.11: Analyze postMessage security
        Detects insecure postMessage usage including missing origin validation,
        wildcard targets, and unsafe data handling in message event listeners.
        """
        if not response_html:
            try:
                response = self.session.get(self.base_url, timeout=10)
                response_html = response.text
            except:
                return {'test_name': 'postMessage Security Analysis', 'error': 'Failed to fetch page', 'findings': []}

        findings = []

        # Detect postMessage calls with wildcard target origin
        wildcard_targets = re.findall(
            r'(\.postMessage\s*\([^)]*,[\s]*["\']\*["\']\s*\))',
            response_html, re.IGNORECASE
        )
        for match in wildcard_targets:
            findings.append({
                'type': 'wildcard_target_origin',
                'match': match.strip(),
                'risk': 'HIGH',
                'description': 'postMessage uses wildcard "*" as targetOrigin — any window can receive the message',
                'remediation': 'Specify an explicit target origin instead of "*"'
            })

        # Detect message event listeners
        listeners = re.findall(
            r'(addEventListener\s*\(\s*["\']message["\'][^)]*\))',
            response_html, re.IGNORECASE
        )
        for match in listeners:
            risk = 'MEDIUM'
            description = 'Message event listener detected'
            remediation = 'Validate event.origin before processing message data'

            findings.append({
                'type': 'message_listener',
                'match': match.strip(),
                'risk': risk,
                'description': description,
                'remediation': remediation
            })

        # Detect listeners without origin validation
        # Look for message handlers that don't check event.origin
        handler_blocks = re.findall(
            r'addEventListener\s*\(\s*["\']message["\']\s*,\s*function\s*\([^)]*\)\s*\{([^}]{0,500})',
            response_html, re.IGNORECASE | re.DOTALL
        )
        for block in handler_blocks:
            if 'origin' not in block.lower():
                findings.append({
                    'type': 'missing_origin_check',
                    'match': block[:120].strip(),
                    'risk': 'CRITICAL',
                    'description': 'Message handler does not validate event.origin — vulnerable to cross-origin message injection',
                    'remediation': 'Always check event.origin against a whitelist before processing'
                })

        # Detect innerHTML/eval usage in message handlers
        dangerous_sinks = re.findall(
            r'addEventListener\s*\(\s*["\']message["\'].*?(innerHTML|eval\s*\(|document\.write|outerHTML)',
            response_html, re.IGNORECASE | re.DOTALL
        )
        for sink in dangerous_sinks:
            findings.append({
                'type': 'dangerous_sink_in_handler',
                'match': sink.strip(),
                'risk': 'CRITICAL',
                'description': f'Dangerous sink "{sink}" used inside message event handler — potential DOM-based XSS',
                'remediation': 'Sanitize message data before passing to DOM sinks'
            })

        # Detect general postMessage usage for inventory
        all_postmessage = re.findall(
            r'(\.postMessage\s*\([^)]+\))',
            response_html, re.IGNORECASE
        )
        postmessage_count = len(all_postmessage)

        self.postmessage_findings = findings

        return {
            'test_name': 'postMessage Security Analysis (WSTG-4.11.11)',
            'url': self.base_url,
            'findings': findings,
            'total_postmessage_calls': postmessage_count,
            'total_listeners': len(listeners),
            'vulnerabilities_found': len([f for f in findings if f.get('risk') in ['HIGH', 'CRITICAL']]),
            'recommendations': [
                'Always specify explicit targetOrigin in postMessage() calls',
                'Validate event.origin in all message event listeners',
                'Never use eval() or innerHTML with message data',
                'Implement a whitelist of trusted origins',
                'Sanitize message data before DOM insertion',
                'Log and monitor cross-origin message activity'
            ],
            'severity': 'HIGH' if any(f['risk'] == 'CRITICAL' for f in findings) else 'MEDIUM',
            'wstg_reference': 'WSTG-4.11.11'
        }

    def analyze_localstorage_risks(self, response_html: str = None) -> Dict[str, Any]:
        """
        WSTG 4.11.12: Deep localStorage risk analysis
        Identifies sensitive data stored in localStorage, insecure patterns,
        and missing encryption/expiration controls.
        """
        if not response_html:
            try:
                response = self.session.get(self.base_url, timeout=10)
                response_html = response.text
            except:
                return {'test_name': 'localStorage Risk Analysis', 'error': 'Failed to fetch page', 'findings': []}

        findings = []

        sensitive_keys = [
            'token', 'jwt', 'access_token', 'refresh_token', 'id_token',
            'password', 'passwd', 'secret', 'api_key', 'apikey', 'api-key',
            'session', 'session_id', 'sessionid', 'auth', 'authorization',
            'credential', 'credit_card', 'creditcard', 'ssn', 'social_security',
            'private_key', 'privatekey', 'encryption_key'
        ]

        # Detect localStorage.setItem with sensitive keys
        setitem_calls = re.findall(
            r'localStorage\.setItem\s*\(\s*["\']([^"\']*)["\']\ *,',
            response_html, re.IGNORECASE
        )
        for key in setitem_calls:
            is_sensitive = any(s in key.lower() for s in sensitive_keys)
            findings.append({
                'type': 'localstorage_setitem',
                'key': key,
                'risk': 'CRITICAL' if is_sensitive else 'LOW',
                'sensitive': is_sensitive,
                'description': f'localStorage.setItem stores key "{key}"' + (' — contains sensitive data' if is_sensitive else ''),
                'remediation': 'Use httpOnly secure cookies or encrypt data before storing' if is_sensitive else 'Review stored data for sensitivity'
            })

        # Detect direct assignment patterns: localStorage.key = value
        direct_assigns = re.findall(
            r'localStorage\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*',
            response_html
        )
        for key in direct_assigns:
            if key in ('setItem', 'getItem', 'removeItem', 'clear', 'length'):
                continue
            is_sensitive = any(s in key.lower() for s in sensitive_keys)
            findings.append({
                'type': 'localstorage_direct_assign',
                'key': key,
                'risk': 'HIGH' if is_sensitive else 'LOW',
                'sensitive': is_sensitive,
                'description': f'Direct localStorage property assignment: localStorage.{key}',
                'remediation': 'Avoid direct property assignment; use setItem with proper data handling'
            })

        # Detect localStorage data read back without validation
        getitem_calls = re.findall(
            r'localStorage\.getItem\s*\(\s*["\']([^"\']*)["\']\ *\)',
            response_html, re.IGNORECASE
        )
        for key in getitem_calls:
            findings.append({
                'type': 'localstorage_getitem',
                'key': key,
                'risk': 'MEDIUM',
                'description': f'Data read from localStorage key "{key}" — verify input validation before use',
                'remediation': 'Validate and sanitize data retrieved from localStorage before use'
            })

        # Check for missing clear-on-logout pattern
        has_setitem = bool(setitem_calls or direct_assigns)
        has_clear = bool(re.search(r'localStorage\.clear\s*\(', response_html, re.IGNORECASE))
        has_removeitem = bool(re.search(r'localStorage\.removeItem\s*\(', response_html, re.IGNORECASE))

        if has_setitem and not has_clear and not has_removeitem:
            findings.append({
                'type': 'missing_cleanup',
                'key': 'N/A',
                'risk': 'MEDIUM',
                'sensitive': False,
                'description': 'localStorage is written to but never cleared — potential data persistence after logout',
                'remediation': 'Implement localStorage.clear() or removeItem() on user logout'
            })

        self.localstorage_findings = findings

        return {
            'test_name': 'localStorage Risk Analysis (WSTG-4.11.12)',
            'url': self.base_url,
            'findings': findings,
            'total_keys_stored': len(setitem_calls) + len(direct_assigns),
            'sensitive_keys_found': len([f for f in findings if f.get('sensitive')]),
            'vulnerabilities_found': len([f for f in findings if f.get('risk') in ['HIGH', 'CRITICAL']]),
            'recommendations': [
                'Never store authentication tokens or secrets in localStorage',
                'localStorage data is accessible to any script on the same origin (XSS risk)',
                'Encrypt sensitive data if localStorage usage is unavoidable',
                'Implement data expiration and cleanup mechanisms',
                'Clear localStorage on logout',
                'Validate all data read from localStorage before use'
            ],
            'severity': 'HIGH' if any(f['risk'] == 'CRITICAL' for f in findings) else 'MEDIUM',
            'wstg_reference': 'WSTG-4.11.12'
        }

    def analyze_sessionstorage_risks(self, response_html: str = None) -> Dict[str, Any]:
        """
        WSTG 4.11.12: Deep sessionStorage risk analysis
        Identifies sensitive data in sessionStorage and insecure patterns.
        """
        if not response_html:
            try:
                response = self.session.get(self.base_url, timeout=10)
                response_html = response.text
            except:
                return {'test_name': 'sessionStorage Risk Analysis', 'error': 'Failed to fetch page', 'findings': []}

        findings = []

        sensitive_keys = [
            'token', 'jwt', 'access_token', 'refresh_token', 'id_token',
            'password', 'passwd', 'secret', 'api_key', 'apikey', 'api-key',
            'session', 'session_id', 'sessionid', 'auth', 'authorization',
            'credential', 'credit_card', 'creditcard', 'ssn', 'private_key'
        ]

        # Detect sessionStorage.setItem with sensitive keys
        setitem_calls = re.findall(
            r'sessionStorage\.setItem\s*\(\s*["\']([^"\']*)["\']\ *,',
            response_html, re.IGNORECASE
        )
        for key in setitem_calls:
            is_sensitive = any(s in key.lower() for s in sensitive_keys)
            findings.append({
                'type': 'sessionstorage_setitem',
                'key': key,
                'risk': 'HIGH' if is_sensitive else 'LOW',
                'sensitive': is_sensitive,
                'description': f'sessionStorage.setItem stores key "{key}"' + (' — contains sensitive data' if is_sensitive else ''),
                'remediation': 'Use httpOnly secure cookies for sensitive data' if is_sensitive else 'Review stored data for sensitivity'
            })

        # Detect direct assignment patterns: sessionStorage.key = value
        direct_assigns = re.findall(
            r'sessionStorage\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*',
            response_html
        )
        for key in direct_assigns:
            if key in ('setItem', 'getItem', 'removeItem', 'clear', 'length'):
                continue
            is_sensitive = any(s in key.lower() for s in sensitive_keys)
            findings.append({
                'type': 'sessionstorage_direct_assign',
                'key': key,
                'risk': 'HIGH' if is_sensitive else 'LOW',
                'sensitive': is_sensitive,
                'description': f'Direct sessionStorage property assignment: sessionStorage.{key}',
                'remediation': 'Avoid direct property assignment; use setItem with proper data handling'
            })

        # Detect sessionStorage data read without validation
        getitem_calls = re.findall(
            r'sessionStorage\.getItem\s*\(\s*["\']([^"\']*)["\']\ *\)',
            response_html, re.IGNORECASE
        )
        for key in getitem_calls:
            findings.append({
                'type': 'sessionstorage_getitem',
                'key': key,
                'risk': 'MEDIUM',
                'description': f'Data read from sessionStorage key "{key}" — verify input validation before use',
                'remediation': 'Validate and sanitize data retrieved from sessionStorage before use'
            })

        # Detect sessionStorage used for cross-tab data sharing attempts
        # sessionStorage is per-tab, so cross-tab patterns indicate misunderstanding
        if re.search(r'sessionStorage.*BroadcastChannel|BroadcastChannel.*sessionStorage', response_html, re.IGNORECASE):
            findings.append({
                'type': 'cross_tab_misuse',
                'key': 'N/A',
                'risk': 'MEDIUM',
                'sensitive': False,
                'description': 'sessionStorage used alongside BroadcastChannel — possible cross-tab data leak attempt',
                'remediation': 'sessionStorage is isolated per tab; use localStorage or a backend for cross-tab data'
            })

        self.sessionstorage_findings = findings

        return {
            'test_name': 'sessionStorage Risk Analysis (WSTG-4.11.12)',
            'url': self.base_url,
            'findings': findings,
            'total_keys_stored': len(setitem_calls) + len(direct_assigns),
            'sensitive_keys_found': len([f for f in findings if f.get('sensitive')]),
            'vulnerabilities_found': len([f for f in findings if f.get('risk') in ['HIGH', 'CRITICAL']]),
            'recommendations': [
                'Never store secrets or tokens in sessionStorage',
                'sessionStorage is accessible to XSS attacks on the same origin',
                'Data persists only for the tab lifetime but is still exposed to scripts',
                'Validate all data retrieved from sessionStorage',
                'Use server-side session management for sensitive state',
                'Implement sessionStorage.clear() on logout'
            ],
            'severity': 'HIGH' if any(f['risk'] in ['HIGH', 'CRITICAL'] for f in findings) else 'LOW',
            'wstg_reference': 'WSTG-4.11.12'
        }

    def detect_dangerous_js_patterns(self, response_html: str = None) -> Dict[str, Any]:
        """
        WSTG 4.11.1 / 4.11.2: Detect dangerous JavaScript patterns
        Identifies DOM-based XSS sinks, unsafe eval usage, prototype pollution
        vectors, and other high-risk JavaScript patterns.
        """
        if not response_html:
            try:
                response = self.session.get(self.base_url, timeout=10)
                response_html = response.text
            except:
                return {'test_name': 'Dangerous JS Pattern Detection', 'error': 'Failed to fetch page', 'findings': []}

        findings = []

        # Category 1: DOM-based XSS sinks
        dom_xss_sinks = {
            r'document\.write\s*\(': {'name': 'document.write', 'risk': 'HIGH', 'desc': 'DOM sink — can inject arbitrary HTML'},
            r'document\.writeln\s*\(': {'name': 'document.writeln', 'risk': 'HIGH', 'desc': 'DOM sink — can inject arbitrary HTML'},
            r'\.innerHTML\s*=': {'name': 'innerHTML assignment', 'risk': 'HIGH', 'desc': 'DOM XSS sink — user input can execute scripts'},
            r'\.outerHTML\s*=': {'name': 'outerHTML assignment', 'risk': 'HIGH', 'desc': 'DOM XSS sink — replaces element with arbitrary HTML'},
            r'\.insertAdjacentHTML\s*\(': {'name': 'insertAdjacentHTML', 'risk': 'HIGH', 'desc': 'DOM XSS sink — injects HTML at specified position'},
            r'document\.createElement\s*\(\s*["\']script': {'name': 'dynamic script creation', 'risk': 'MEDIUM', 'desc': 'Dynamically creates script elements'},
        }

        for pattern, info in dom_xss_sinks.items():
            matches = re.findall(pattern, response_html, re.IGNORECASE)
            if matches:
                findings.append({
                    'category': 'dom_xss_sink',
                    'pattern_name': info['name'],
                    'occurrences': len(matches),
                    'risk': info['risk'],
                    'description': info['desc'],
                    'remediation': 'Use textContent/innerText instead, or sanitize with DOMPurify'
                })

        # Category 2: Unsafe code execution patterns
        eval_patterns = {
            r'\beval\s*\(': {'name': 'eval()', 'risk': 'CRITICAL', 'desc': 'Executes arbitrary code — highest risk JavaScript function'},
            r'\bnew\s+Function\s*\(': {'name': 'new Function()', 'risk': 'CRITICAL', 'desc': 'Dynamic code execution via Function constructor'},
            r'setTimeout\s*\(\s*["\']': {'name': 'setTimeout with string', 'risk': 'HIGH', 'desc': 'setTimeout with string argument acts as eval()'},
            r'setInterval\s*\(\s*["\']': {'name': 'setInterval with string', 'risk': 'HIGH', 'desc': 'setInterval with string argument acts as eval()'},
        }

        for pattern, info in eval_patterns.items():
            matches = re.findall(pattern, response_html, re.IGNORECASE)
            if matches:
                findings.append({
                    'category': 'unsafe_execution',
                    'pattern_name': info['name'],
                    'occurrences': len(matches),
                    'risk': info['risk'],
                    'description': info['desc'],
                    'remediation': 'Eliminate eval/Function usage; use safer alternatives like JSON.parse()'
                })

        # Category 3: Prototype pollution vectors
        proto_patterns = {
            r'__proto__': {'name': '__proto__ access', 'risk': 'HIGH', 'desc': 'Prototype pollution vector via __proto__'},
            r'Object\.assign\s*\(\s*\{\}': {'name': 'Object.assign shallow merge', 'risk': 'MEDIUM', 'desc': 'Shallow merge may propagate polluted properties'},
            r'constructor\s*\[\s*["\']prototype': {'name': 'constructor.prototype access', 'risk': 'HIGH', 'desc': 'Direct prototype manipulation via constructor'},
        }

        for pattern, info in proto_patterns.items():
            matches = re.findall(pattern, response_html, re.IGNORECASE)
            if matches:
                findings.append({
                    'category': 'prototype_pollution',
                    'pattern_name': info['name'],
                    'occurrences': len(matches),
                    'risk': info['risk'],
                    'description': info['desc'],
                    'remediation': 'Use Object.create(null) or Map; validate/freeze objects before merging'
                })

        # Category 4: Unsafe URL/navigation patterns
        url_patterns = {
            r'location\s*=\s*': {'name': 'location assignment', 'risk': 'MEDIUM', 'desc': 'Open redirect if user input controls the value'},
            r'location\.href\s*=': {'name': 'location.href assignment', 'risk': 'MEDIUM', 'desc': 'Potential open redirect via location.href'},
            r'window\.open\s*\(': {'name': 'window.open()', 'risk': 'MEDIUM', 'desc': 'May open attacker-controlled URLs'},
            r'javascript\s*:': {'name': 'javascript: URI', 'risk': 'HIGH', 'desc': 'javascript: protocol can execute arbitrary code'},
        }

        for pattern, info in url_patterns.items():
            matches = re.findall(pattern, response_html, re.IGNORECASE)
            if matches:
                findings.append({
                    'category': 'unsafe_navigation',
                    'pattern_name': info['name'],
                    'occurrences': len(matches),
                    'risk': info['risk'],
                    'description': info['desc'],
                    'remediation': 'Validate and sanitize URLs; use allowlists for redirect targets'
                })

        # Category 5: Sensitive data exposure in JS
        data_exposure_patterns = {
            r'["\'](?:password|passwd|secret|api_key|apikey|private_key)["\']\s*:\s*["\']': {
                'name': 'hardcoded secret in JS', 'risk': 'CRITICAL',
                'desc': 'Sensitive data hardcoded in client-side JavaScript'
            },
            r'(?:var|let|const)\s+(?:password|secret|apiKey|api_key|privateKey)\s*=': {
                'name': 'secret in JS variable', 'risk': 'CRITICAL',
                'desc': 'Secret value assigned to JavaScript variable'
            },
        }

        for pattern, info in data_exposure_patterns.items():
            matches = re.findall(pattern, response_html, re.IGNORECASE)
            if matches:
                findings.append({
                    'category': 'data_exposure',
                    'pattern_name': info['name'],
                    'occurrences': len(matches),
                    'risk': info['risk'],
                    'description': info['desc'],
                    'remediation': 'Never expose secrets in client-side code; use environment variables and server-side APIs'
                })

        self.dangerous_js_findings = findings

        # Calculate risk summary
        critical = len([f for f in findings if f.get('risk') == 'CRITICAL'])
        high = len([f for f in findings if f.get('risk') == 'HIGH'])
        medium = len([f for f in findings if f.get('risk') == 'MEDIUM'])

        if critical > 0:
            overall_severity = 'CRITICAL'
        elif high > 0:
            overall_severity = 'HIGH'
        elif medium > 0:
            overall_severity = 'MEDIUM'
        else:
            overall_severity = 'LOW'

        return {
            'test_name': 'Dangerous JavaScript Pattern Detection (WSTG-4.11.1/4.11.2)',
            'url': self.base_url,
            'findings': findings,
            'total_patterns_detected': len(findings),
            'risk_breakdown': {
                'critical': critical,
                'high': high,
                'medium': medium
            },
            'vulnerabilities_found': critical + high,
            'recommendations': [
                'Eliminate eval() and new Function() usage entirely',
                'Replace innerHTML with textContent or DOMPurify-sanitized content',
                'Never hardcode secrets or API keys in client-side JavaScript',
                'Validate all URLs before navigation or redirect',
                'Freeze prototypes and validate merge inputs to prevent prototype pollution',
                'Implement Content Security Policy to restrict inline scripts',
                'Use static analysis tools (ESLint security plugins) in CI/CD pipeline'
            ],
            'severity': overall_severity,
            'wstg_reference': 'WSTG-4.11.1/4.11.2'
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
                self.discover_websockets(html_response),
                self.analyze_postmessage_security(html_response),
                self.analyze_localstorage_risks(html_response),
                self.analyze_sessionstorage_risks(html_response),
                self.detect_dangerous_js_patterns(html_response)
            ],
            'summary': {
                'cors_misconfigured': len(self.cors_findings),
                'clickjacking_protected': True,
                'websockets_detected': False,
                'postmessage_issues': len(self.postmessage_findings),
                'localstorage_risks': len(self.localstorage_findings),
                'sessionstorage_risks': len(self.sessionstorage_findings),
                'dangerous_js_patterns': len(self.dangerous_js_findings)
            },
            'wstg_coverage': [
                'WSTG-4.11 (Client-side Testing)',
                'WSTG-4.11.1 (DOM-based XSS)',
                'WSTG-4.11.2 (JavaScript Execution)',
                'WSTG-4.11.7 (CORS)',
                'WSTG-4.11.9 (Clickjacking)',
                'WSTG-4.11.10 (WebSockets)',
                'WSTG-4.11.11 (Web Messaging)',
                'WSTG-4.11.12 (Browser Storage)'
            ]
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
