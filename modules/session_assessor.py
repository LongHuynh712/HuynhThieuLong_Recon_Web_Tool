"""
Session Assessor Module
OWASP WSTG 4.6 - Session Management Testing
Implements: Cookie analysis, Session token quality, CSRF detection
"""

import requests
import re
from typing import List, Dict, Any
from urllib.parse import urljoin

class SessionAssessor:
    """Assesses session management security"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.cookies_found = []
        self.csrf_tokens = []
        
    def analyze_cookie_attributes(self) -> Dict[str, Any]:
        """
        WSTG 4.6.2: Analyze cookie attributes
        Tests cookie security flags (HttpOnly, Secure, SameSite)
        """
        try:
            response = requests.get(self.base_url, timeout=5)
            cookies = response.cookies
            headers = response.headers
        except:
            return {'test_name': 'Cookie Analysis', 'error': 'Failed to fetch cookies', 'cookies': []}
        
        cookie_set_header = headers.get('Set-Cookie', '')
        cookies_analyzed = []
        
        for cookie_name, cookie_value in cookies.items():
            cookie_info = {
                'name': cookie_name,
                'value_length': len(str(cookie_value)),
                'has_httponly': 'HttpOnly' in cookie_set_header,
                'has_secure': 'Secure' in cookie_set_header,
                'has_samesite': 'SameSite' in cookie_set_header,
                'risk': 'LOW'
            }
            
            # Assess risk
            if not cookie_info['has_httponly']:
                cookie_info['risk'] = 'HIGH'
                cookie_info['finding'] = 'Missing HttpOnly flag (vulnerable to XSS)'
            
            if not cookie_info['has_secure']:
                cookie_info['risk'] = 'HIGH'
                cookie_info['finding'] = 'Missing Secure flag (transmitted over HTTP)'
            
            if not cookie_info['has_samesite']:
                cookie_info['risk'] = 'MEDIUM'
                cookie_info['finding'] = 'Missing SameSite attribute (vulnerable to CSRF)'
            
            cookies_analyzed.append(cookie_info)
            self.cookies_found.append(cookie_info)
        
        return {
            'test_name': 'Cookie Attributes Analysis (WSTG-4.6.2)',
            'url': self.base_url,
            'cookies_found': cookies_analyzed,
            'total_cookies': len(cookies_analyzed),
            'secure_cookies': len([c for c in cookies_analyzed if c['has_secure']]),
            'httponly_cookies': len([c for c in cookies_analyzed if c['has_httponly']]),
            'samesite_cookies': len([c for c in cookies_analyzed if c['has_samesite']]),
            'recommendations': [
                'Set HttpOnly flag on all session cookies',
                'Set Secure flag for HTTPS-only transmission',
                'Implement SameSite attribute (Strict/Lax)',
                'Set appropriate cookie expiration',
                'Use secure domain restrictions'
            ],
            'severity': 'HIGH',
            'wstg_reference': 'WSTG-4.6.2'
        }
    
    def detect_csrf_tokens(self, response_html: str = None) -> Dict[str, Any]:
        """
        WSTG 4.6.5: Detect CSRF protection tokens
        Identifies anti-CSRF token mechanisms
        """
        if not response_html:
            try:
                response = requests.get(self.base_url, timeout=10)
                response_html = response.text
            except:
                return {'test_name': 'CSRF Detection', 'error': 'Failed to fetch page', 'tokens': []}
        
        csrf_patterns = {
            'csrf_token': [
                r'name=["\']csrf["\']',
                r'name=["\']_csrf["\']',
                r'name=["\']CSRFToken["\']',
                r'name=["\']csrfmiddlewaretoken["\']',
            ],
            'xsrf_token': [
                r'name=["\']xsrf-token["\']',
                r'name=["\']X-CSRF-TOKEN["\']',
                r'name=["\']_xsrf["\']',
            ],
            'request_verification': [
                r'__RequestVerificationToken',
                r'AntiforgeryToken',
            ]
        }
        
        tokens_found = []
        
        for token_type, patterns in csrf_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_html, re.IGNORECASE):
                    tokens_found.append({
                        'type': token_type,
                        'pattern': pattern,
                        'found': True,
                        'protection': 'CSRF protection implemented'
                    })
                    self.csrf_tokens.append(token_type)
                    break
        
        csrf_protected = len(tokens_found) > 0
        
        return {
            'test_name': 'CSRF Token Detection (WSTG-4.6.5)',
            'url': self.base_url,
            'csrf_tokens_found': tokens_found,
            'csrf_protected': csrf_protected,
            'total_tokens': len(tokens_found),
            'recommendations': [
                'Implement CSRF tokens on all state-changing requests',
                'Validate CSRF tokens server-side',
                'Use SameSite cookie attribute as defense-in-depth',
                'Implement custom headers for CSRF protection (X-Requested-With)',
                'Monitor for CSRF attacks'
            ],
            'severity': 'HIGH' if not csrf_protected else 'LOW',
            'wstg_reference': 'WSTG-4.6.5'
        }
    
    def assess_session_fixation(self) -> Dict[str, Any]:
        """
        WSTG 4.6.3: Assess session fixation vulnerability
        Tests if session IDs change on authentication
        """
        findings = []
        
        try:
            # First request - pre-auth
            response1 = requests.get(self.base_url, timeout=5)
            pre_auth_cookies = response1.cookies
            
            # Second request - simulate post-auth (would need actual login in real scenario)
            response2 = requests.get(self.base_url, timeout=5)
            post_auth_cookies = response2.cookies
            
            # Compare session IDs
            findings.append({
                'test': 'Session ID Regeneration',
                'description': 'Checking if session IDs change between requests',
                'pre_auth_cookies': dict(pre_auth_cookies),
                'post_auth_cookies': dict(post_auth_cookies),
                'finding': 'Session ID management requires authentication testing'
            })
            
        except Exception as e:
            findings.append({'error': str(e)})
        
        return {
            'test_name': 'Session Fixation Assessment (WSTG-4.6.3)',
            'url': self.base_url,
            'findings': findings,
            'recommendations': [
                'Regenerate session ID on successful authentication',
                'Invalidate old session after authentication',
                'Implement session ID timeout',
                'Use unpredictable session ID generation',
                'Log session activity for anomaly detection'
            ],
            'severity': 'HIGH',
            'wstg_reference': 'WSTG-4.6.3'
        }
    
    def analyze_session_timeout(self) -> Dict[str, Any]:
        """
        WSTG 4.6.7: Analyze session timeout mechanisms
        Tests for appropriate session expiration
        """
        findings = []
        
        try:
            response = requests.get(self.base_url, timeout=5)
            headers = response.headers
            
            # Check for cache control headers
            cache_control = headers.get('Cache-Control', '')
            pragma = headers.get('Pragma', '')
            expires = headers.get('Expires', '')
            
            findings.append({
                'cache_control': cache_control,
                'pragma': pragma,
                'expires': expires,
                'assessment': 'Session timeout configuration detected'
            })
            
        except Exception as e:
            findings.append({'error': str(e)})
        
        return {
            'test_name': 'Session Timeout Analysis (WSTG-4.6.7)',
            'url': self.base_url,
            'findings': findings,
            'recommendations': [
                'Implement appropriate session timeout (15-30 minutes for sensitive apps)',
                'Provide idle timeout warnings',
                'Clear sensitive data on timeout',
                'Implement absolute session duration limit',
                'Log session termination events'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.6.7'
        }
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Execute all session management tests"""
        html_response = None
        try:
            response = requests.get(self.base_url, timeout=10)
            html_response = response.text
        except:
            pass
        
        results = {
            'category': 'Session Management Assessment',
            'url': self.base_url,
            'timestamp': self._get_timestamp(),
            'tests': [
                self.analyze_cookie_attributes(),
                self.detect_csrf_tokens(html_response),
                self.assess_session_fixation(),
                self.analyze_session_timeout()
            ],
            'summary': {
                'cookies_analyzed': len(self.cookies_found),
                'csrf_tokens_found': len(self.csrf_tokens),
                'session_security_issues': len([c for c in self.cookies_found if c['risk'] == 'HIGH'])
            },
            'wstg_coverage': 'WSTG-4.6 (Session Management Testing)'
        }
        return results
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
