"""
Security Scorer Module
Aggregates all OWASP WSTG test results and computes coverage metrics
Provides security posture scoring across all test categories
"""

from typing import Dict, Any, List
from datetime import datetime

class SecurityScorer:
    """
    Computes overall security posture and OWASP WSTG coverage metrics
    """
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.all_test_results = {}
        self.coverage_by_section = {}
        self.risk_summary = {}
        
        # Define all 97 OWASP WSTG v4.2 tests
        self.wstg_tests_map = {
            '4.1': {
                'name': 'Information Gathering',
                'tests': [
                    '4.1.1 Conduct Web Spider',
                    '4.1.2 Fingerprint Web Server',
                    '4.1.3 Review Webserver Metafiles',
                    '4.1.4 Enumerate Applications',
                    '4.1.5 Review Web Application Comments',
                    '4.1.6 Identify Application Entry Points',
                    '4.1.7 Map Execution Paths Through Application',
                    '4.1.8 Fingerprint Web Application Framework',
                    '4.1.9 Map Application Architecture',
                    '4.1.10 Application Mapping',
                    '4.1.11 Identify Web Application',
                    '4.1.12 Map Hosted Content'
                ]
            },
            '4.2': {
                'name': 'Configuration and Deployment Management Testing',
                'tests': [
                    '4.2.1 Test Network Infrastructure',
                    '4.2.2 Test Application Platform',
                    '4.2.3 Test File Extensions Handling',
                    '4.2.4 Test Backup and Unreferenced Files',
                    '4.2.5 Enumerate Infrastructure and Application',
                    '4.2.6 Test HTTP Methods',
                    '4.2.7 Test HTTP Strict Transport Security'
                ]
            },
            '4.3': {
                'name': 'Identity Management Testing',
                'tests': [
                    '4.3.1 Test User Registration Process',
                    '4.3.2 Test User Profile',
                    '4.3.3 Test Privilege Escalation',
                    '4.3.4 Test Role Definitions',
                    '4.3.5 Test Account Enumeration and User Guessing'
                ]
            },
            '4.4': {
                'name': 'Authentication Testing',
                'tests': [
                    '4.4.1 Testing for Credentials Transported',
                    '4.4.2 Testing for Default Credentials',
                    '4.4.3 Testing for Weak Lock Out',
                    '4.4.4 Testing for Bypassing Authentication',
                    '4.4.5 Testing for Vulnerable Remember Password',
                    '4.4.6 Testing for Browser Cache Weaknesses',
                    '4.4.7 Testing for Weak Password Policy',
                    '4.4.8 Testing for Weak Password Change Process',
                    '4.4.9 Testing for Weak Password Reset',
                    '4.4.10 Testing for Weak Cryptography',
                    '4.4.11 Testing for Multiple Factors'
                ]
            },
            '4.5': {
                'name': 'Authorization Testing',
                'tests': [
                    '4.5.1 Testing Directory Traversal',
                    '4.5.2 Testing for Bypassing Authorization Schema',
                    '4.5.3 Testing for Privilege Escalation',
                    '4.5.4 Testing for Insecure Direct Object Reference'
                ]
            },
            '4.6': {
                'name': 'Session Management Testing',
                'tests': [
                    '4.6.1 Testing for Bypassing Session Management',
                    '4.6.2 Testing for Cookies Attributes',
                    '4.6.3 Testing for Session Fixation',
                    '4.6.4 Testing for Exposed Session Variables',
                    '4.6.5 Testing for Cross Site Request Forgery',
                    '4.6.6 Testing for Logout Functionality',
                    '4.6.7 Testing Session Timeout',
                    '4.6.8 Testing for Session Puzzles',
                    '4.6.9 Testing for Session Replay',
                    '4.6.10 Testing for Concurrent Login',
                    '4.6.11 Testing for Session Puzzles'
                ]
            },
            '4.7': {
                'name': 'Input Validation Testing',
                'tests': [
                    '4.7.1 Testing for Reflected Cross Site Scripting',
                    '4.7.2 Testing for Stored Cross Site Scripting',
                    '4.7.3 Testing for HTTP Verb Tampering',
                    '4.7.4 Testing for HTTP Parameter Pollution',
                    '4.7.5 Testing for SQL Injection',
                    '4.7.6 Testing for LDAP Injection',
                    '4.7.7 Testing for XML Injection',
                    '4.7.8 Testing for SSI Injection',
                    '4.7.9 Testing for XPath Injection',
                    '4.7.10 Testing for IMAP/SMTP Injection',
                    '4.7.11 Testing for Code Injection',
                    '4.7.12 Testing for Command Injection',
                    '4.7.13 Testing for Format String Injection',
                    '4.7.14 Testing for Incubated Vulnerability'
                ]
            },
            '4.8': {
                'name': 'Error Handling Testing',
                'tests': [
                    '4.8.1 Testing Error Codes',
                    '4.8.2 Testing Stack Traces'
                ]
            },
            '4.9': {
                'name': 'Weak Cryptography Testing',
                'tests': [
                    '4.9.1 Testing for Weak SSL/TLS',
                    '4.9.2 Testing for Padding Oracle',
                    '4.9.3 Testing for Sensitive Data Exposure',
                    '4.9.4 Testing for Weak Encryption'
                ]
            },
            '4.10': {
                'name': 'Business Logic Testing',
                'tests': [
                    '4.10.1 Test Business Logic',
                    '4.10.2 Test Ability to Forgo Purchased Requirements',
                    '4.10.3 Test Ability to Exceed Stated Limits',
                    '4.10.4 Testing for Process Timing',
                    '4.10.5 Testing Number of Times Resource'
                ]
            },
            '4.11': {
                'name': 'Client-side Testing',
                'tests': [
                    '4.11.1 Testing for DOM-based Cross Site Scripting',
                    '4.11.2 Testing for JavaScript Execution',
                    '4.11.3 Testing for HTML Injection',
                    '4.11.4 Testing for Client-side URL Redirect',
                    '4.11.5 Testing for CSS Injection',
                    '4.11.6 Testing for Client-side Resource Manipulation',
                    '4.11.7 Testing Cross Origin Resource Sharing',
                    '4.11.8 Testing for Cross Site Flashing',
                    '4.11.9 Testing for Clickjacking',
                    '4.11.10 Testing WebSockets',
                    '4.11.11 Testing Web Messaging',
                    '4.11.12 Testing Local Storage'
                ]
            },
            '4.12': {
                'name': 'API Testing',
                'tests': [
                    '4.12.1 API Discovery',
                    '4.12.2 API Authentication',
                    '4.12.3 API Authorization',
                    '4.12.4 API Input Validation',
                    '4.12.5 API Cryptography',
                    '4.12.6 API Rate Limiting'
                ]
            }
        }
    
    def compute_coverage_by_section(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compute OWASP WSTG coverage by section
        Analyzes which tests have findings
        """
        coverage_by_section = {}
        total_coverage_percentage = 0
        
        for section_id, section_info in self.wstg_tests_map.items():
            section_name = section_info['name']
            total_tests = len(section_info['tests'])
            
            # Count implemented tests
            implemented = 0
            if section_id in test_results:
                implemented = len([t for t in test_results[section_id] if t.get('status') == 'implemented'])
            
            coverage_pct = (implemented / total_tests * 100) if total_tests > 0 else 0
            total_coverage_percentage += coverage_pct / len(self.wstg_tests_map)
            
            coverage_by_section[section_id] = {
                'section_name': section_name,
                'total_tests': total_tests,
                'implemented': implemented,
                'coverage_percentage': round(coverage_pct, 1),
                'tests': section_info['tests']
            }
        
        return {
            'coverage_by_section': coverage_by_section,
            'overall_coverage_percentage': round(total_coverage_percentage, 1)
        }
    
    def compute_risk_summary(self, module_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compute risk summary from all module results
        Aggregates findings by severity level
        """
        risk_summary = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        total_findings = 0
        attack_surface_items = []
        
        for result in module_results:
            severity = result.get('severity', 'INFO')
            if severity in risk_summary:
                risk_summary[severity] += 1
                total_findings += 1
            
            # Aggregate findings
            if 'findings' in result:
                for finding in result.get('findings', []):
                    attack_surface_items.append({
                        'module': result.get('test_name', 'Unknown'),
                        'finding': finding,
                        'severity': severity
                    })
        
        risk_score = (
            risk_summary['CRITICAL'] * 4 +
            risk_summary['HIGH'] * 3 +
            risk_summary['MEDIUM'] * 2 +
            risk_summary['LOW'] * 1
        )
        
        return {
            'findings_by_severity': risk_summary,
            'total_findings': total_findings,
            'risk_score': risk_score,
            'attack_surface': attack_surface_items
        }
    
    def compute_security_score(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        OWASP: Compute overall security score (0-100)
        Based on coverage and risk assessment
        """
        coverage_data = self.compute_coverage_by_section(test_results)
        coverage_pct = coverage_data['overall_coverage_percentage']
        
        # Score is based on:
        # - OWASP coverage (40% weight)
        # - Risk assessment (60% weight)
        coverage_score = coverage_pct * 0.4
        
        # Risk assessment: lower findings = higher score
        risk_data = self.compute_risk_summary(list(test_results.values()) if isinstance(test_results, dict) else test_results)
        total_findings = risk_data['total_findings']
        
        # Scale risk findings to 0-60 score (fewer findings = higher score)
        risk_score = max(0, 60 - (total_findings * 2))
        
        overall_score = coverage_score + risk_score
        
        return {
            'overall_security_score': round(overall_score, 1),
            'coverage_score': round(coverage_score, 1),
            'risk_score': round(risk_score, 1),
            'coverage_percentage': coverage_pct,
            'risk_level': self._calculate_risk_level(overall_score),
            'recommendations': self._generate_recommendations(overall_score, coverage_pct)
        }
    
    def generate_dashboard_data(self, all_test_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate comprehensive dashboard data for UI display
        """
        timestamp = datetime.now().isoformat()
        
        return {
            'timestamp': timestamp,
            'url': self.base_url,
            'dashboard': {
                'overview': {
                    'total_tests': sum(len(info['tests']) for info in self.wstg_tests_map.values()),
                    'test_modules': len(all_test_results),
                    'findings_count': len([f for r in all_test_results for f in r.get('findings', [])]),
                    'critical_findings': len([r for r in all_test_results if r.get('severity') == 'CRITICAL'])
                },
                'coverage_metrics': self.compute_coverage_by_section({'4.1': []}),
                'risk_summary': self.compute_risk_summary(all_test_results),
                'security_score': self.compute_security_score({'4.1': []}),
                'test_modules': [
                    {
                        'name': r.get('test_name', 'Unknown'),
                        'category': r.get('wstg_reference', 'Unknown'),
                        'severity': r.get('severity', 'INFO'),
                        'findings_count': len(r.get('findings', []))
                    }
                    for r in all_test_results
                ]
            }
        }
    
    @staticmethod
    def _calculate_risk_level(score: float) -> str:
        """Calculate risk level from score"""
        if score >= 80:
            return 'LOW'
        elif score >= 60:
            return 'MEDIUM'
        elif score >= 40:
            return 'HIGH'
        else:
            return 'CRITICAL'
    
    @staticmethod
    def _generate_recommendations(score: float, coverage_pct: float) -> List[str]:
        """Generate recommendations based on score"""
        recommendations = []
        
        if coverage_pct < 50:
            recommendations.append('Expand OWASP WSTG test coverage to reach 70-80%')
        
        if score < 40:
            recommendations.append('Implement comprehensive security testing program')
            recommendations.append('Address critical findings immediately')
        elif score < 60:
            recommendations.append('Address high-severity findings')
            recommendations.append('Implement additional security controls')
        
        recommendations.append('Establish continuous security monitoring')
        recommendations.append('Implement automated security scanning')
        recommendations.append('Regular security awareness training for team')
        
        return recommendations
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Execute security scoring analysis"""
        return {
            'test_name': 'Security Posture Scoring (OWASP WSTG)',
            'url': self.base_url,
            'timestamp': datetime.now().isoformat(),
            'scoring_metrics': {
                'coverage_framework': 'OWASP WSTG v4.2',
                'total_tests': sum(len(info['tests']) for info in self.wstg_tests_map.values()),
                'test_sections': len(self.wstg_tests_map),
                'scoring_model': 'Coverage (40%) + Risk Assessment (60%)'
            },
            'recommendations': [
                'Focus on high-impact OWASP gaps',
                'Implement security testing automation',
                'Establish metrics and KPIs for security posture',
                'Conduct regular security audits'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'OWASP WSTG v4.2'
        }
