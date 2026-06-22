"""
Error Handler Assessor Module
OWASP WSTG 4.8 - Error Handling and Logging Testing
Implements: Debug page detection, Stack trace exposure, Error message analysis
"""

import requests
import re
from typing import List, Dict, Any
from urllib.parse import urljoin

class ErrorHandlerAssessor:
    """Assesses error handling and information disclosure"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.error_pages = []
        self.stack_traces = []
        
    def detect_debug_pages(self) -> Dict[str, Any]:
        """
        WSTG 4.8: Detect debug pages and information exposure
        Tests for common debug endpoints
        """
        debug_paths = [
            '/debug',
            '/debug.php',
            '/admin',
            '/admin.php',
            '/admin/debug',
            '/__debug__',
            '/debug/',
            '/dev',
            '/development',
            '/testing',
            '/test',
            '/console',
            '/api/debug',
            '/api/status',
            '/health',
            '/health-check',
            '/status',
            '/metrics',
            '/actuator',
            '/actuator/env',
            '/actuator/health',
            '/.well-known/debug',
        ]
        
        debug_findings = []
        
        for path in debug_paths:
            test_url = urljoin(self.base_url, path)
            
            try:
                response = requests.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    debug_info = {
                        'url': test_url,
                        'path': path,
                        'status': response.status_code,
                        'exposed': True,
                        'severity': 'CRITICAL',
                        'content_preview': response.text[:200]
                    }
                    
                    # Check for debug indicators
                    if 'debug' in response.text.lower():
                        debug_info['finding'] = 'Debug interface exposed'
                    elif 'env' in response.text.lower() and response.status_code == 200:
                        debug_info['finding'] = 'Environment variables potentially exposed'
                    else:
                        debug_info['finding'] = 'Sensitive information endpoint accessible'
                    
                    debug_findings.append(debug_info)
                    self.error_pages.append(debug_info)
                    
            except:
                pass
        
        return {
            'test_name': 'Debug Page Detection (WSTG-4.8)',
            'url': self.base_url,
            'debug_pages': debug_findings,
            'total_found': len(debug_findings),
            'exposed': len(debug_findings) > 0,
            'recommendations': [
                'Disable debug mode in production',
                'Restrict access to debug endpoints with authentication',
                'Remove all debug code from production',
                'Implement access controls on sensitive endpoints',
                'Monitor for unauthorized debug access attempts'
            ],
            'severity': 'CRITICAL' if debug_findings else 'LOW',
            'wstg_reference': 'WSTG-4.8'
        }
    
    def detect_stack_traces(self, response_html: str = None) -> Dict[str, Any]:
        """
        WSTG 4.8.2: Detect stack trace exposure
        Tests for visible error stack traces with sensitive information
        """
        if not response_html:
            # Try to trigger errors
            try:
                response = requests.get(self.base_url + '/?error=test', timeout=5)
                response_html = response.text
            except:
                response_html = ''
        
        stack_trace_patterns = {
            'Python': [
                r'Traceback \(most recent call last\)',
                r'File ".*?", line \d+',
                r'(ValueError|TypeError|RuntimeError|NameError|AttributeError)',
            ],
            'PHP': [
                r'Fatal error:',
                r'Warning:',
                r'Parse error:',
                r'on line \d+',
            ],
            'Java': [
                r'java\.lang\.',
                r'Exception in thread',
                r'at java\.',
                r'\.java:\d+',
            ],
            'ASP.NET': [
                r'System\..*Exception',
                r'Server Error in',
                r'Description: An unhandled exception',
            ],
            'Node.js': [
                r'Error: ',
                r'at new ',
                r'at .*\.js:\d+:\d+',
            ]
        }
        
        traces_found = []
        
        for lang, patterns in stack_trace_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, response_html, re.MULTILINE)
                if matches:
                    traces_found.append({
                        'language': lang,
                        'pattern': pattern,
                        'matches': len(matches),
                        'severity': 'HIGH',
                        'finding': f'{lang} stack trace detected in response'
                    })
                    self.stack_traces.append(lang)
                    break
        
        return {
            'test_name': 'Stack Trace Detection (WSTG-4.8.2)',
            'url': self.base_url,
            'stack_traces': traces_found,
            'total_found': len(traces_found),
            'exposed': len(traces_found) > 0,
            'recommendations': [
                'Implement custom error pages',
                'Log errors server-side without exposing details',
                'Return generic error messages to users',
                'Implement error handling middleware',
                'Monitor error logs for patterns',
                'Test error scenarios regularly'
            ],
            'severity': 'HIGH' if traces_found else 'LOW',
            'wstg_reference': 'WSTG-4.8.2'
        }
    
    def analyze_error_messages(self) -> Dict[str, Any]:
        """
        WSTG 4.8.1: Analyze error message information disclosure
        Tests common error pages for sensitive information
        """
        error_paths = [
            '/?error=1',
            '/?id=999999',
            '/invalid-page',
            '/404',
            '/500',
            '/error',
            '/error.php',
            '/notfound',
        ]
        
        error_findings = []
        
        for path in error_paths:
            test_url = urljoin(self.base_url, path)
            
            try:
                response = requests.get(test_url, timeout=5)
                
                if response.status_code >= 400:
                    # Check error page content for information disclosure
                    content_lower = response.text.lower()
                    
                    sensitive_indicators = [
                        ('SQL error', r'sql|mysql|postgresql|database'),
                        ('File path disclosure', r'[c-z]:\\|/home/|/var/www'),
                        ('Technology fingerprint', r'php|apache|nginx|tomcat|iis'),
                        ('Application path', r'/app/|/src/|/lib/'),
                    ]
                    
                    for indicator_name, pattern in sensitive_indicators:
                        if re.search(pattern, content_lower):
                            error_findings.append({
                                'url': test_url,
                                'status': response.status_code,
                                'disclosure_type': indicator_name,
                                'severity': 'MEDIUM',
                                'finding': f'{indicator_name} detected in error response'
                            })
                            break
                            
            except:
                pass
        
        return {
            'test_name': 'Error Message Analysis (WSTG-4.8.1)',
            'url': self.base_url,
            'error_messages': error_findings,
            'total_found': len(error_findings),
            'sensitive_info_disclosed': len(error_findings) > 0,
            'recommendations': [
                'Implement generic error messages',
                'Avoid revealing application structure',
                'Don\'t display file paths or line numbers',
                'Don\'t reveal technology stack',
                'Implement error logging without user exposure',
                'Test all error scenarios'
            ],
            'severity': 'MEDIUM' if error_findings else 'LOW',
            'wstg_reference': 'WSTG-4.8.1'
        }
    
    def test_verbose_error_modes(self) -> Dict[str, Any]:
        """
        WSTG 4.8: Test for verbose error handling modes
        Checks for debug modes that expose information
        """
        findings = []
        
        test_parameters = [
            ('debug=true', 'Debug parameter'),
            ('debug=1', 'Debug flag'),
            ('verbose=true', 'Verbose logging'),
            ('mode=dev', 'Development mode'),
            ('environment=development', 'Development environment'),
        ]
        
        for param, description in test_parameters:
            test_url = self.base_url + '?' + param
            
            try:
                response = requests.get(test_url, timeout=5)
                
                if 'debug' in response.text.lower() or 'verbose' in response.text.lower():
                    findings.append({
                        'parameter': param,
                        'description': description,
                        'activated': True,
                        'severity': 'HIGH'
                    })
                    
            except:
                pass
        
        return {
            'test_name': 'Verbose Error Mode Testing (WSTG-4.8)',
            'url': self.base_url,
            'verbose_modes': findings,
            'total_found': len(findings),
            'recommendations': [
                'Disable verbose modes in production',
                'Remove debug parameters from final code',
                'Implement environment-specific configurations',
                'Use configuration management for error levels',
                'Monitor for debug mode enablement'
            ],
            'severity': 'HIGH' if findings else 'LOW',
            'wstg_reference': 'WSTG-4.8'
        }
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Execute all error handling tests"""
        html_response = None
        try:
            response = requests.get(self.base_url, timeout=10)
            html_response = response.text
        except:
            pass
        
        results = {
            'category': 'Error Handling Assessment',
            'url': self.base_url,
            'timestamp': self._get_timestamp(),
            'tests': [
                self.detect_debug_pages(),
                self.detect_stack_traces(html_response),
                self.analyze_error_messages(),
                self.test_verbose_error_modes()
            ],
            'summary': {
                'error_pages_found': len(self.error_pages),
                'stack_traces_exposed': len(self.stack_traces),
                'information_disclosure_risks': len([e for e in self.error_pages if e.get('severity') == 'CRITICAL'])
            },
            'wstg_coverage': 'WSTG-4.8 (Error Handling Testing)'
        }
        return results
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
