"""
Search Engine Reconnaissance Module
OWASP WSTG 4.1 - Information Gathering
Implements: Google Dorks, Public documents, Indexed pages, Public repos
"""

import re
from urllib.parse import urlparse, urljoin
import requests
from typing import List, Dict, Any, Set
import json

class SearchEngineRecon:
    """Search engine-based reconnaissance"""
    
    def __init__(self, target_domain: str, headless_browser=None):
        self.target_domain = target_domain
        self.base_domain = self._extract_base_domain(target_domain)
        self.browser = headless_browser
        self.findings = []
        self.dorks_inventory = []
        self.indexed_pages = []
        self.public_docs = []
        self.public_repos = []
        
    def _extract_base_domain(self, domain: str) -> str:
        """Extract base domain from URL or domain string"""
        if domain.startswith('http'):
            domain = urlparse(domain).netloc
        return domain.split('www.')[-1] if domain.startswith('www.') else domain
    
    def generate_google_dorks(self) -> Dict[str, Any]:
        """
        WSTG 4.1.1: Generate Google Dork recommendations
        Returns structured dork inventory for the target domain
        """
        dorks = {
            'documents': [
                f'site:{self.base_domain} filetype:pdf',
                f'site:{self.base_domain} filetype:docx',
                f'site:{self.base_domain} filetype:xlsx',
                f'site:{self.base_domain} filetype:pptx',
                f'site:{self.base_domain} filetype:txt',
            ],
            'administrative': [
                f'site:{self.base_domain} "admin" OR "administrator"',
                f'site:{self.base_domain} "login" OR "signin"',
                f'site:{self.base_domain} "dashboard"',
                f'site:{self.base_domain} "management console"',
            ],
            'sensitive_data': [
                f'site:{self.base_domain} "password" OR "pwd"',
                f'site:{self.base_domain} "api_key" OR "apikey" OR "api key"',
                f'site:{self.base_domain} "token" OR "secret"',
                f'site:{self.base_domain} "credential"',
                f'site:{self.base_domain} "config" OR "configuration"',
            ],
            'backup_and_old': [
                f'site:{self.base_domain} inurl:backup OR inurl:old OR inurl:archive',
                f'site:{self.base_domain} filetype:bak OR filetype:old OR filetype:backup',
                f'site:{self.base_domain} "~" OR ".bak" OR ".old" OR ".orig"',
            ],
            'version_control': [
                f'site:{self.base_domain} ".git" OR ".github" OR ".gitlab"',
                f'site:{self.base_domain} ".svn" OR ".hg" OR ".bzr"',
                f'site:{self.base_domain} inurl:".git/config"',
            ],
            'source_disclosure': [
                f'site:{self.base_domain} inurl:".asp" OR inurl:".php" OR inurl:".jsp"',
                f'site:{self.base_domain} "begin rsa private key" OR "begin openssh"',
            ],
            'misconfiguration': [
                f'site:{self.base_domain} "robots.txt"',
                f'site:{self.base_domain} "sitemap.xml"',
                f'site:{self.base_domain} ".env" OR ".env.local"',
                f'site:{self.base_domain} "web.config" OR "web.xml"',
            ],
            'development': [
                f'site:{self.base_domain} "localhost" OR "127.0.0.1" OR "192.168"',
                f'site:{self.base_domain} "debug" OR "test" OR "dev"',
                f'site:{self.base_domain} "TODO" OR "FIXME" OR "XXX"',
            ],
        }
        
        self.dorks_inventory = dorks
        return {
            'test_name': 'Google Dork Inventory (WSTG-4.1.1)',
            'domain': self.base_domain,
            'dorks_by_category': dorks,
            'total_dorks': sum(len(v) for v in dorks.values()),
            'instructions': 'Use these dorks with Google Search to identify exposed information',
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.1.1'
        }
    
    def discover_public_documents(self, scan_depth: int = 1) -> Dict[str, Any]:
        """
        WSTG 4.1.1: Discover publicly indexed documents
        Uses search engine queries to find exposed documents
        """
        document_types = ['pdf', 'docx', 'xlsx', 'pptx', 'txt', 'zip', 'doc', 'xls']
        findings = []
        
        for doc_type in document_types:
            query = f'site:{self.base_domain} filetype:{doc_type}'
            finding = {
                'document_type': doc_type,
                'search_query': query,
                'discovery_method': 'Search Engine Index Query',
                'severity': 'MEDIUM' if doc_type in ['pdf', 'docx', 'xlsx'] else 'LOW',
                'recommendation': f'Review {doc_type} files for sensitive information exposure'
            }
            findings.append(finding)
            self.public_docs.append(finding)
        
        return {
            'test_name': 'Public Document Discovery (WSTG-4.1.1)',
            'domain': self.base_domain,
            'document_findings': findings,
            'total_document_types': len(document_types),
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.1.1'
        }
    
    def discover_indexed_pages(self) -> Dict[str, Any]:
        """
        WSTG 4.1.1: Identify publicly indexed pages
        Estimates pages indexed in search engines
        """
        search_queries = [
            f'site:{self.base_domain}',
            f'site:{self.base_domain} -www',
            f'site:{self.base_domain} inurl:admin',
            f'site:{self.base_domain} inurl:api',
            f'site:{self.base_domain} inurl:test',
            f'site:{self.base_domain} inurl:staging',
        ]
        
        indexed_analysis = {
            'domain': self.base_domain,
            'query_patterns': [],
            'estimated_pages': 0,  # Would require API integration to get actual count
            'sensitive_paths_detected': []
        }
        
        for query in search_queries:
            indexed_analysis['query_patterns'].append({
                'query': query,
                'purpose': self._describe_query_purpose(query)
            })
        
        self.indexed_pages = search_queries
        
        return {
            'test_name': 'Indexed Pages Discovery (WSTG-4.1.1)',
            'domain': self.base_domain,
            'analysis': indexed_analysis,
            'recommendations': [
                'Review Google Search Console for indexed pages',
                'Check for sensitive pages in search results',
                'Monitor Bing Webmaster Tools for exposed content',
                'Use robots.txt to exclude sensitive paths'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.1.1'
        }
    
    def discover_public_repositories(self) -> Dict[str, Any]:
        """
        WSTG 4.1.1: Discover public code repositories
        Identifies source code exposure through public repositories
        """
        repo_patterns = [
            f'{self.base_domain.replace(".", "-")}',
            self.base_domain.split('.')[0],
            self.target_domain.split('.')[0] if self.target_domain else '',
        ]
        
        repositories = {
            'github': [],
            'gitlab': [],
            'bitbucket': [],
            'gitea': []
        }
        
        # Build query patterns for each platform
        for pattern in repo_patterns:
            if pattern:
                repositories['github'].append({
                    'query': f'GitHub search: {pattern}',
                    'url': f'https://github.com/search?q={pattern}',
                    'search_term': pattern
                })
                repositories['gitlab'].append({
                    'query': f'GitLab search: {pattern}',
                    'url': f'https://gitlab.com/search?search={pattern}',
                    'search_term': pattern
                })
        
        findings = []
        for platform, queries in repositories.items():
            if queries:
                findings.append({
                    'platform': platform,
                    'queries': queries,
                    'risk': 'HIGH' if platform in ['github', 'gitlab'] else 'MEDIUM',
                    'recommendation': f'Search {platform} for exposed repositories containing sensitive code'
                })
        
        self.public_repos = findings
        
        return {
            'test_name': 'Public Repository Discovery (WSTG-4.1.1)',
            'domain': self.base_domain,
            'repositories': findings,
            'total_platforms': len([f for f in findings if f['queries']]),
            'severity': 'HIGH',
            'wstg_reference': 'WSTG-4.1.1',
            'recommendations': [
                'Search GitHub, GitLab, Bitbucket for company repositories',
                'Check for hardcoded credentials in public repos',
                'Scan for configuration files with sensitive data',
                'Monitor for accidental commits of private keys'
            ]
        }
    
    def analyze_search_engine_exposure(self) -> Dict[str, Any]:
        """
        WSTG 4.1.1: Analyze overall search engine exposure
        Comprehensive assessment of search engine indexed content
        """
        exposure_categories = {
            'high_risk': [],
            'medium_risk': [],
            'low_risk': [],
            'informational': []
        }
        
        # High risk exposures
        exposure_categories['high_risk'] = [
            'Source code in search results',
            'Private keys or credentials',
            'Configuration files with secrets',
            'Database backups',
            'Admin interface URLs'
        ]
        
        # Medium risk exposures
        exposure_categories['medium_risk'] = [
            'Internal IP addresses',
            'Development domain names',
            'Staging environment details',
            'API documentation endpoints',
            'Internal employee information'
        ]
        
        # Low risk exposures
        exposure_categories['low_risk'] = [
            'Public documentation',
            'General company information',
            'Press releases',
            'Blog posts',
            'Public API endpoints'
        ]
        
        return {
            'test_name': 'Search Engine Exposure Analysis (WSTG-4.1.1)',
            'domain': self.base_domain,
            'exposure_summary': exposure_categories,
            'assessment': {
                'indexed_domain': True,
                'sensitive_content_risk': 'MEDIUM',
                'crawler_compliance': 'Check robots.txt and X-Robots-Tag headers'
            },
            'recommendations': [
                'Review robots.txt for unintended exclusions',
                'Monitor search engine console regularly',
                'Use X-Robots-Tag headers for sensitive pages',
                'Implement authentication for sensitive endpoints',
                'Scan public code repositories for credentials'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.1.1'
        }
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Execute all search engine reconnaissance tests"""
        results = {
            'category': 'Search Engine Reconnaissance',
            'domain': self.base_domain,
            'timestamp': self._get_timestamp(),
            'tests': [
                self.generate_google_dorks(),
                self.discover_public_documents(),
                self.discover_indexed_pages(),
                self.discover_public_repositories(),
                self.analyze_search_engine_exposure()
            ],
            'summary': {
                'google_dorks_generated': len(self.dorks_inventory),
                'document_types_checked': len(self.public_docs),
                'repository_platforms': len(self.public_repos),
                'total_findings': len(self.findings)
            },
            'wstg_coverage': 'WSTG-4.1.1 (Search Engine Discovery)'
        }
        return results
    
    @staticmethod
    def _describe_query_purpose(query: str) -> str:
        """Describe the purpose of a search query"""
        if 'admin' in query:
            return 'Identify administrative interfaces'
        elif 'api' in query:
            return 'Locate API endpoints'
        elif 'staging' in query:
            return 'Find development/staging environments'
        elif 'test' in query:
            return 'Locate test environments'
        else:
            return 'General domain index check'
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
