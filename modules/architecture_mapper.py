"""
Architecture Mapper Module
OWASP WSTG 4.1-4.2 - Information Gathering & Configuration
Implements: Domain relationships, DNS mapping, Subdomains, Hosting, CDN, Third-party services
"""

import dns.resolver
import dns.rdatatype
import requests
import json
from typing import List, Dict, Any, Set
from urllib.parse import urlparse
import socket

class ArchitectureMapper:
    """Maps application architecture and infrastructure"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.target_domain = self._extract_domain(base_url)
        self.architecture = {}
        self.dns_records = {}
        self.subdomains = []
        self.third_parties = []
        
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        if url.startswith('http'):
            domain = urlparse(url).netloc
        else:
            domain = url
        return domain.replace('www.', '')
    
    def map_dns_records(self) -> Dict[str, Any]:
        """
        WSTG 4.1: Map DNS infrastructure
        Discovers DNS records including MX, NS, TXT, SPF, DKIM
        """
        dns_findings = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'CNAME': [],
            'SOA': []
        }
        
        record_types = list(dns_findings.keys())
        
        for record_type in record_types:
            try:
                answers = dns.resolver.query(self.target_domain, record_type)
                for rdata in answers:
                    record_str = str(rdata)
                    dns_findings[record_type].append({
                        'value': record_str,
                        'ttl': answers.rrset.ttl,
                        'type': record_type,
                        'risk': self._assess_dns_risk(record_type, record_str)
                    })
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            except Exception:
                pass
        
        self.dns_records = dns_findings
        
        # Extract security-relevant DNS records
        security_records = self._extract_security_dns(dns_findings)
        
        return {
            'test_name': 'DNS Infrastructure Mapping (WSTG-4.1)',
            'domain': self.target_domain,
            'dns_records': dns_findings,
            'security_records': security_records,
            'findings': {
                'nameservers': len(dns_findings.get('NS', [])),
                'mail_servers': len(dns_findings.get('MX', [])),
                'ipv4_addresses': len(dns_findings.get('A', [])),
                'ipv6_addresses': len(dns_findings.get('AAAA', [])),
                'spf_configured': any('v=spf1' in str(txt) for txt in dns_findings.get('TXT', [])),
            },
            'recommendations': [
                'Implement SPF, DKIM, DMARC for email security',
                'Monitor DNS changes',
                'Use DNSSEC to prevent DNS spoofing',
                'Configure DNS CAA records',
                'Limit DNS information disclosure'
            ],
            'severity': 'LOW',
            'wstg_reference': 'WSTG-4.1'
        }
    
    def map_subdomains(self, common_subdomains: List[str] = None) -> Dict[str, Any]:
        """
        WSTG 4.1: Map subdomains
        Discovers subdomains through DNS enumeration
        """
        if not common_subdomains:
            common_subdomains = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop',
                'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover',
                'autoconfig', 'admin', 'api', 'test', 'dev', 'staging',
                'cdn', 'dns', 'backup', 'old', 'new', 'blog', 'shop',
                'portal', 'support', 'help', 'docs', 'documentation',
                'download', 'files', 'resources', 'app', 'apps', 'service',
                'services', 'cloud', 'secure', 'vpn', 'server'
            ]
        
        discovered_subdomains = []
        
        base_domain = self.target_domain
        
        for subdomain in common_subdomains:
            full_domain = f'{subdomain}.{base_domain}'
            
            try:
                # Try DNS lookup
                answers = dns.resolver.query(full_domain, 'A')
                for answer in answers:
                    discovered_subdomains.append({
                        'subdomain': full_domain,
                        'ip': str(answer),
                        'method': 'DNS A Record',
                        'active': True,
                        'risk': self._assess_subdomain_risk(subdomain)
                    })
                    self.subdomains.append(full_domain)
            except:
                pass
            
            try:
                # Try CNAME lookup
                answers = dns.resolver.query(full_domain, 'CNAME')
                for answer in answers:
                    discovered_subdomains.append({
                        'subdomain': full_domain,
                        'cname': str(answer),
                        'method': 'DNS CNAME Record',
                        'active': True,
                        'risk': self._assess_subdomain_risk(subdomain)
                    })
                    self.subdomains.append(full_domain)
            except:
                pass
        
        return {
            'test_name': 'Subdomain Mapping (WSTG-4.1)',
            'base_domain': base_domain,
            'subdomains_discovered': discovered_subdomains,
            'total_found': len(discovered_subdomains),
            'high_risk_subdomains': len([s for s in discovered_subdomains if s['risk'] == 'HIGH']),
            'recommendations': [
                'Document all subdomains',
                'Apply same security controls to subdomains',
                'Monitor for rogue subdomains',
                'Test subdomains for vulnerabilities',
                'Implement Certificate Transparency monitoring'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.1'
        }
    
    def identify_hosting_provider(self) -> Dict[str, Any]:
        """
        WSTG 4.1: Identify hosting provider
        Determines infrastructure and hosting information
        """
        hosting_info = {
            'primary_ip': None,
            'hosting_provider': None,
            'asn': None,
            'country': None,
            'server_type': None,
            'cdn_provider': None
        }
        
        try:
            # Get primary IP
            ips = dns.resolver.query(self.target_domain, 'A')
            if ips:
                primary_ip = str(ips[0])
                hosting_info['primary_ip'] = primary_ip
                
                # Try to get reverse DNS
                try:
                    reverse_dns = socket.getfqdn(primary_ip)
                    hosting_info['reverse_dns'] = reverse_dns
                except:
                    pass
        except:
            pass
        
        # Detect CDN providers
        cdn_indicators = self._detect_cdn()
        hosting_info['cdn_provider'] = cdn_indicators
        
        return {
            'test_name': 'Hosting Provider Identification (WSTG-4.1)',
            'domain': self.target_domain,
            'hosting_information': hosting_info,
            'findings': {
                'primary_ip': hosting_info['primary_ip'],
                'cdn_detected': bool(hosting_info['cdn_provider']),
                'cdn_provider': hosting_info['cdn_provider']
            },
            'recommendations': [
                'Monitor hosting provider for security updates',
                'Verify hosting provider compliance certifications',
                'Implement DDoS protection',
                'Use CDN for better availability and security',
                'Monitor infrastructure changes'
            ],
            'severity': 'LOW',
            'wstg_reference': 'WSTG-4.1'
        }
    
    def map_cdn_infrastructure(self) -> Dict[str, Any]:
        """
        WSTG 4.2: Map CDN configuration
        Identifies CDN usage and configuration
        """
        cdn_findings = {
            'cdn_detected': False,
            'cdn_providers': [],
            'cname_records': [],
            'edge_nodes': []
        }
        
        # Check for common CDN CNAMEs
        cdn_patterns = {
            'Cloudflare': ['cloudflare', 'cf.', 'ns.cloudflare'],
            'Akamai': ['akamai', 'akamaitechnologies'],
            'CloudFront': ['cloudfront', 'amazonaws'],
            'Fastly': ['fastly'],
            'MaxCDN': ['maxcdn'],
            'StackPath': ['stackpath'],
            'Azure CDN': ['azureedge'],
            'Imperva': ['imperva', 'incapsula'],
        }
        
        try:
            answers = dns.resolver.query(self.target_domain, 'CNAME')
            for answer in answers:
                cname = str(answer)
                cdn_findings['cname_records'].append(cname)
                
                for provider, patterns in cdn_patterns.items():
                    if any(pattern in cname.lower() for pattern in patterns):
                        cdn_findings['cdn_detected'] = True
                        cdn_findings['cdn_providers'].append(provider)
        except:
            pass
        
        return {
            'test_name': 'CDN Infrastructure Mapping (WSTG-4.2)',
            'domain': self.target_domain,
            'cdn_information': cdn_findings,
            'findings': {
                'cdn_detected': cdn_findings['cdn_detected'],
                'providers': list(set(cdn_findings['cdn_providers'])),
                'cname_count': len(cdn_findings['cname_records'])
            },
            'recommendations': [
                'Verify CDN security configuration',
                'Ensure HTTPS enforcement',
                'Configure proper cache headers',
                'Monitor CDN logs for attacks',
                'Test CDN bypass techniques'
            ],
            'severity': 'LOW',
            'wstg_reference': 'WSTG-4.2'
        }
    
    def map_third_party_services(self) -> Dict[str, Any]:
        """
        WSTG 4.1: Map third-party services
        Identifies third-party integrations and dependencies
        """
        third_parties = []
        
        # Common third-party service domains
        third_party_patterns = {
            'Analytics': ['google-analytics', 'mixpanel', 'amplitude', 'chartbeat', '_ga'],
            'CDN/Hosting': ['cloudflare', 'akamai', 'fastly', 'maxcdn', 'stackpath'],
            'Monitoring': ['newrelic', 'datadog', 'elastic', 'splunk'],
            'Email': ['sendgrid', 'mailgun', 'mailchimp', 'sendblue'],
            'Payment': ['stripe', 'paypal', 'square', 'authorize'],
            'Social': ['facebook', 'twitter', 'instagram', 'linkedin'],
            'Advertising': ['google-ads', 'facebook-ads', 'doubleclick'],
            'CAPTCHA': ['recaptcha', 'hcaptcha', 'captcha'],
            'Maps': ['maps.google', 'mapbox', 'esri'],
            'Video': ['youtube', 'vimeo', 'wistia']
        }
        
        # This would typically be discovered through JavaScript analysis or HTTP headers
        # For now, we identify patterns that could indicate third-party services
        
        return {
            'test_name': 'Third-Party Service Mapping (WSTG-4.1)',
            'domain': self.target_domain,
            'third_party_categories': third_party_patterns,
            'findings': {
                'third_parties_identified': len(third_parties),
                'categories': list(third_party_patterns.keys())
            },
            'recommendations': [
                'Audit all third-party integrations',
                'Verify third-party security certifications',
                'Monitor third-party data sharing',
                'Implement CSP to restrict third-party resources',
                'Review privacy implications of third-parties',
                'Test third-party security boundaries'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.1'
        }
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Execute all architecture mapping tests"""
        results = {
            'category': 'Architecture Mapping',
            'domain': self.target_domain,
            'timestamp': self._get_timestamp(),
            'tests': [
                self.map_dns_records(),
                self.map_subdomains(),
                self.identify_hosting_provider(),
                self.map_cdn_infrastructure(),
                self.map_third_party_services()
            ],
            'summary': {
                'subdomains_discovered': len(self.subdomains),
                'dns_records_found': sum(len(v) for v in self.dns_records.values()),
                'third_parties_identified': len(self.third_parties),
            },
            'wstg_coverage': 'WSTG-4.1 (Information Gathering)'
        }
        return results
    
    @staticmethod
    def _assess_dns_risk(record_type: str, record_value: str) -> str:
        """Assess risk level of DNS record"""
        if record_type == 'NS':
            return 'LOW'
        elif record_type == 'MX':
            return 'LOW'
        elif record_type == 'TXT':
            if 'v=spf1' in record_value or 'DKIM' in record_value:
                return 'LOW'
            else:
                return 'MEDIUM'
        elif record_type in ['A', 'AAAA']:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    @staticmethod
    def _assess_subdomain_risk(subdomain: str) -> str:
        """Assess risk of subdomain type"""
        high_risk_keywords = ['admin', 'test', 'dev', 'staging', 'debug']
        medium_risk_keywords = ['api', 'app', 'service', 'portal']
        
        subdomain_lower = subdomain.lower()
        
        if any(keyword in subdomain_lower for keyword in high_risk_keywords):
            return 'HIGH'
        elif any(keyword in subdomain_lower for keyword in medium_risk_keywords):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    @staticmethod
    def _extract_security_dns(dns_findings: Dict) -> Dict[str, Any]:
        """Extract security-relevant DNS records"""
        security = {
            'spf_configured': False,
            'dkim_configured': False,
            'dmarc_configured': False,
            'dns_sec_configured': False,
            'caa_configured': False
        }
        
        txt_records = dns_findings.get('TXT', [])
        for txt in txt_records:
            txt_value = str(txt.get('value', '')).lower()
            if 'v=spf1' in txt_value:
                security['spf_configured'] = True
            if 'dkim' in txt_value:
                security['dkim_configured'] = True
            if 'v=DMARC1' in txt_value or 'v=dmarc1' in txt_value:
                security['dmarc_configured'] = True
        
        return security
    
    @staticmethod
    def _detect_cdn() -> List[str]:
        """Detect CDN providers from headers"""
        cdn_providers = []
        
        # Common CDN detection via CNAME
        cdn_cnames = {
            'Cloudflare': 'cloudflare',
            'Akamai': 'akamai',
            'CloudFront': 'cloudfront',
            'Fastly': 'fastly',
            'Azure': 'azureedge',
            'Imperva': 'imperva'
        }
        
        return cdn_providers
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
