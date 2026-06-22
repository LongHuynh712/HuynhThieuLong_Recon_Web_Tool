"""
Technology Intelligence Module
OWASP WSTG 4.1 - Information Gathering
Implements: Framework detection, CMS detection, Library detection, Confidence scoring
"""

import requests
import re
from typing import List, Dict, Any, Tuple
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class TechnologyIntelligence:
    """Detects technologies and frameworks used by application"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.technologies = []
        self.confidence_scores = {}
        
    def detect_frameworks(self, response_html: str = None) -> Dict[str, Any]:
        """
        WSTG 4.1: Detect web frameworks
        Identifies framework signatures and evidence
        """
        if not response_html:
            try:
                response = requests.get(self.base_url, timeout=10)
                response_html = response.text
                headers = response.headers
            except:
                return {'test_name': 'Framework Detection', 'error': 'Failed to fetch page', 'frameworks': []}
        else:
            headers = {}
        
        frameworks = {
            'PHP': {
                'indicators': [
                    (r'X-Powered-By: PHP', 'header', 100),
                    (r'phpinfo', 'content', 95),
                    (r'\.php', 'url', 60),
                    (r'php_uname', 'content', 100),
                    (r'PHPSESSID', 'content', 90),
                ],
                'confidence': 0
            },
            'Django': {
                'indicators': [
                    (r'Django', 'header', 100),
                    (r'csrfmiddlewaretoken', 'content', 95),
                    (r'/admin/$', 'url', 80),
                    (r'django_version', 'content', 100),
                ],
                'confidence': 0
            },
            'Flask': {
                'indicators': [
                    (r'Werkzeug', 'header', 100),
                    (r'Flask', 'content', 100),
                    (r'flask.pocoo.com', 'content', 95),
                    (r'_ga', 'cookie', 50),
                ],
                'confidence': 0
            },
            'Laravel': {
                'indicators': [
                    (r'laravel_session', 'cookie', 90),
                    (r'XSRF-TOKEN', 'cookie', 85),
                    (r'Laravel', 'header', 100),
                    (r'/artisan', 'file', 100),
                ],
                'confidence': 0
            },
            'ASP.NET': {
                'indicators': [
                    (r'ASP.NET', 'header', 100),
                    (r'__VIEWSTATE', 'content', 95),
                    (r'__EVENTVALIDATION', 'content', 95),
                    (r'\.aspx', 'url', 85),
                    (r'web.config', 'file', 100),
                ],
                'confidence': 0
            },
            'Node.js/Express': {
                'indicators': [
                    (r'Express', 'header', 100),
                    (r'Node.js', 'header', 100),
                    (r'connect.sid', 'cookie', 90),
                    (r'npm', 'content', 60),
                ],
                'confidence': 0
            },
            'Ruby on Rails': {
                'indicators': [
                    (r'_rails_session', 'cookie', 95),
                    (r'Rails', 'header', 100),
                    (r'Rails', 'content', 80),
                    (r'Gemfile', 'file', 95),
                ],
                'confidence': 0
            }
        }
        
        # Check headers
        for header_name, header_value in headers.items():
            for framework_name, framework_info in frameworks.items():
                for pattern, indicator_type, weight in framework_info['indicators']:
                    if indicator_type == 'header' and re.search(pattern, str(header_value), re.IGNORECASE):
                        frameworks[framework_name]['confidence'] = min(100, 
                            frameworks[framework_name]['confidence'] + weight)
        
        # Check HTML content
        if response_html:
            for framework_name, framework_info in frameworks.items():
                for pattern, indicator_type, weight in framework_info['indicators']:
                    if indicator_type == 'content' and re.search(pattern, response_html, re.IGNORECASE):
                        frameworks[framework_name]['confidence'] = min(100, 
                            frameworks[framework_name]['confidence'] + weight)
        
        detected_frameworks = [
            {
                'name': name,
                'confidence': info['confidence'],
                'confidence_level': self._confidence_to_level(info['confidence'])
            }
            for name, info in frameworks.items()
            if info['confidence'] > 0
        ]
        
        return {
            'test_name': 'Framework Detection (WSTG-4.1)',
            'url': self.base_url,
            'frameworks': detected_frameworks,
            'primary_framework': detected_frameworks[0]['name'] if detected_frameworks else None,
            'recommendations': [
                'Hide framework version information',
                'Customize error pages to hide framework',
                'Remove default files and directories',
                'Apply framework-specific security patches',
                'Configure security headers'
            ],
            'severity': 'LOW',
            'wstg_reference': 'WSTG-4.1'
        }
    
    def detect_cms(self, response_html: str = None) -> Dict[str, Any]:
        """
        WSTG 4.1: Detect CMS platforms
        Identifies WordPress, Drupal, Joomla, etc.
        """
        if not response_html:
            try:
                response = requests.get(self.base_url, timeout=10)
                response_html = response.text
            except:
                return {'test_name': 'CMS Detection', 'error': 'Failed to fetch page', 'cms': []}
        
        cms_signatures = {
            'WordPress': [
                r'wp-content',
                r'wp-includes',
                r'wordpress_version',
                r'wp-json',
                r'wp-admin',
                r'/wp-',
            ],
            'Drupal': [
                r'drupal',
                r'/sites/default/',
                r'Drupal.settings',
                r'drupal_version',
            ],
            'Joomla': [
                r'com_content',
                r'/components/',
                r'Joomla',
                r'joomla',
            ],
            'Magento': [
                r'Magento',
                r'mage_errors',
                r'magento',
                r'/skin/',
            ],
            'Shopify': [
                r'shopify',
                r'Shopify.shop',
                r'/cdn/shop/',
            ]
        }
        
        detected_cms = []
        
        for cms_name, signatures in cms_signatures.items():
            confidence = 0
            for signature in signatures:
                if re.search(signature, response_html, re.IGNORECASE):
                    confidence += 20
            
            if confidence > 0:
                detected_cms.append({
                    'name': cms_name,
                    'confidence': min(100, confidence),
                    'confidence_level': self._confidence_to_level(min(100, confidence))
                })
        
        return {
            'test_name': 'CMS Detection (WSTG-4.1)',
            'url': self.base_url,
            'cms_detected': detected_cms,
            'primary_cms': detected_cms[0]['name'] if detected_cms else None,
            'recommendations': [
                'Keep CMS updated',
                'Audit plugins and extensions',
                'Implement WAF rules for CMS',
                'Harden CMS configuration',
                'Monitor for malicious plugins'
            ],
            'severity': 'LOW',
            'wstg_reference': 'WSTG-4.1'
        }
    
    def detect_libraries(self, response_html: str = None) -> Dict[str, Any]:
        """
        WSTG 4.1: Detect libraries and dependencies
        Identifies JavaScript, CSS, and server-side libraries
        """
        if not response_html:
            try:
                response = requests.get(self.base_url, timeout=10)
                response_html = response.text
            except:
                return {'test_name': 'Library Detection', 'error': 'Failed to fetch page', 'libraries': []}
        
        soup = BeautifulSoup(response_html, 'html.parser')
        libraries = {
            'JavaScript': [],
            'CSS': [],
            'Server': []
        }
        
        # JavaScript libraries
        js_signatures = {
            'jQuery': [r'jquery', r'/jquery', r'jQuery'],
            'React': [r'react', r'_react'],
            'Angular': [r'angular', r'ng-'],
            'Vue': [r'vue', r'__VUE__'],
            'Bootstrap': [r'bootstrap', r'bs-'],
            'AJAX': [r'XMLHttpRequest'],
        }
        
        # CSS frameworks
        css_signatures = {
            'Bootstrap': [r'bootstrap', r'bs-'],
            'Tailwind': [r'tailwind'],
            'Bulma': [r'bulma'],
            'Foundation': [r'foundation'],
        }
        
        # Check scripts
        for script in soup.find_all('script'):
            src = script.get('src', '')
            content = script.string or ''
            
            for lib_name, patterns in js_signatures.items():
                for pattern in patterns:
                    if re.search(pattern, src + content, re.IGNORECASE):
                        libraries['JavaScript'].append(lib_name)
                        break
        
        # Check stylesheets
        for link in soup.find_all('link', {'rel': 'stylesheet'}):
            href = link.get('href', '')
            
            for lib_name, patterns in css_signatures.items():
                for pattern in patterns:
                    if re.search(pattern, href, re.IGNORECASE):
                        libraries['CSS'].append(lib_name)
                        break
        
        return {
            'test_name': 'Library Detection (WSTG-4.1)',
            'url': self.base_url,
            'libraries': libraries,
            'total_libraries': sum(len(v) for v in libraries.values()),
            'unique_libraries': list(set(sum(libraries.values(), []))),
            'recommendations': [
                'Keep all libraries updated',
                'Monitor for known vulnerabilities',
                'Minimize use of third-party libraries',
                'Audit library dependencies',
                'Use dependency scanning tools'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.1'
        }
    
    def generate_technology_report(self) -> Dict[str, Any]:
        """
        WSTG 4.1: Generate comprehensive technology report
        Combines all technology detection results
        """
        html_response = None
        try:
            response = requests.get(self.base_url, timeout=10)
            html_response = response.text
        except:
            pass
        
        return {
            'test_name': 'Technology Intelligence Report (WSTG-4.1)',
            'url': self.base_url,
            'timestamp': self._get_timestamp(),
            'technologies': {
                'frameworks': self.detect_frameworks(html_response),
                'cms': self.detect_cms(html_response),
                'libraries': self.detect_libraries(html_response)
            },
            'recommendations': [
                'Document all technology stack components',
                'Implement version pinning for dependencies',
                'Monitor for security updates',
                'Perform regular security audits',
                'Maintain software bill of materials (SBOM)'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.1'
        }
    
    @staticmethod
    def _confidence_to_level(confidence: int) -> str:
        """Convert confidence score to level"""
        if confidence >= 80:
            return 'HIGH'
        elif confidence >= 50:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
