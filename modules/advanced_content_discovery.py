"""
Advanced Content Discovery Module
OWASP WSTG 4.2 - Configuration and Deployment Management
Implements: Sensitive file discovery, Backup files, Hidden endpoints, Admin paths
"""

import requests
import re
from typing import List, Dict, Any, Set
from urllib.parse import urljoin, urlparse
from pathlib import Path

class AdvancedContentDiscovery:
    """Advanced content discovery and enumeration"""
    
    def __init__(self, base_url: str, wordlist: List[str] = None):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.timeout = 5
        self.session.verify = False
        self.discovered_content = []
        self.wordlist = wordlist or self._get_default_wordlist()
        
    def _get_default_wordlist(self) -> List[str]:
        """Default wordlist for content discovery"""
        return [
            # Sensitive files
            '.htaccess', '.htpasswd', '.env', '.env.local', '.env.prod',
            'web.config', 'web.xml', 'config.php', 'database.yml', 'secrets.yaml',
            'credentials.json', '.aws', '.ssh', '.git/config', '.github',
            'package.json', 'package-lock.json', 'requirements.txt',
            
            # Backup files
            'backup', 'backup.sql', 'dump.sql', 'db.sql',
            'backup.zip', 'backup.tar.gz', 'backup.rar',
            
            # Admin paths
            'admin', 'administrator', 'wp-admin', 'admin.php',
            'phpmyadmin', 'cpanel', 'webmin',
            'administrator/login', 'admin/login',
            
            # API endpoints
            'api', 'v1', 'v2', 'v3', 'api/v1', 'api/v2',
            'swagger', 'openapi', 'graphql', 'rest',
            
            # Version control
            '.git', '.github', '.gitlab', '.gitignore',
            
            # Documentation
            'docs', 'documentation', 'api-docs', 'swagger.json',
            'openapi.json', 'README', 'CHANGELOG',
            
            # Common app files
            'index.html', 'index.php', 'web.php', 'app.php',
            'login.php', 'register.php', 'forgot-password.php',
            
            # Build/deployment
            'Dockerfile', 'docker-compose.yml', 'Jenkinsfile',
            'deploy.sh', 'build.xml', 'Makefile',
            
            # CDN/Static
            'static', 'public', 'assets', 'cdn', 'dist', 'build',
            
            # Staging/development
            'staging', 'dev', 'development', 'test', 'testing',
            'qa', 'uat', 'localhost', 'internal',
        ]
    
    def discover_sensitive_files(self) -> Dict[str, Any]:
        """
        WSTG 4.2.4: Discover sensitive files
        Attempts to locate configuration and credential files
        """
        sensitive_patterns = {
            'config_files': ['.env', '.env.local', 'web.config', 'config.php', 
                           'database.yml', 'secrets.yaml', 'credentials.json'],
            'version_control': ['.git', '.github', '.gitlab', '.gitignore', '.svn'],
            'credentials': ['.htaccess', '.htpasswd', '.aws', '.ssh'],
            'build_files': ['Dockerfile', 'docker-compose.yml', 'Jenkinsfile', 'package.json'],
            'backup_files': ['backup', 'backup.sql', 'dump.sql', 'db.sql'],
        }
        
        found_files = []
        
        for category, paths in sensitive_patterns.items():
            for path in paths:
                test_url = urljoin(self.base_url, f'/{path}')
                
                try:
                    response = self.session.head(test_url, timeout=3, allow_redirects=False)
                    
                    if response.status_code in [200, 403, 401]:
                        severity = 'CRITICAL' if response.status_code == 200 else 'MEDIUM'
                        found_files.append({
                            'file': path,
                            'url': test_url,
                            'status_code': response.status_code,
                            'category': category,
                            'severity': severity,
                            'accessible': response.status_code == 200
                        })
                        self.discovered_content.append({'type': 'sensitive_file', 'path': path})
                except:
                    pass
        
        return {
            'test_name': 'Sensitive File Discovery (WSTG-4.2.4)',
            'found_files': found_files,
            'total_found': len(found_files),
            'critical_files': len([f for f in found_files if f['severity'] == 'CRITICAL']),
            'recommendations': [
                'Remove or restrict access to all sensitive files',
                'Use .htaccess or web.config to deny access to configuration files',
                'Store secrets in environment variables, not in version control',
                'Remove version control directories from production'
            ],
            'severity': 'HIGH' if any(f['severity'] == 'CRITICAL' for f in found_files) else 'MEDIUM',
            'wstg_reference': 'WSTG-4.2.4'
        }
    
    def discover_backup_files(self) -> Dict[str, Any]:
        """
        WSTG 4.2.4: Discover backup and unreferenced files
        Searches for forgotten backup and temporary files
        """
        backup_patterns = [
            # Common backup extensions
            r'.*\.bak$', r'.*\.backup$', r'.*\.old$', r'.*\.orig$',
            r'.*\.tmp$', r'.*~$', r'.*\.copy$',
            
            # Database backups
            r'.*\.sql$', r'.*\.dump$', r'.*\.dmp$',
            
            # Archive files
            r'.*\.zip$', r'.*\.tar\.gz$', r'.*\.rar$', r'.*\.7z$',
            
            # Common backup locations
            r'backup.*', r'.*backup\.', r'old_.*', r'\..*\.bak',
        ]
        
        backup_paths = [
            'backup/', 'backups/', 'old/', '.backup', '.backups',
            'backup.sql', 'backup.zip', 'dump.sql',
            'web.config.bak', 'web.config.old', 'web.config~',
            'app.php.bak', 'config.php.bak', 'database.yml.bak'
        ]
        
        found_backups = []
        
        for path in backup_paths:
            test_url = urljoin(self.base_url, f'/{path}')
            try:
                response = self.session.get(test_url, timeout=3, allow_redirects=False)
                if response.status_code == 200:
                    found_backups.append({
                        'path': path,
                        'url': test_url,
                        'size': len(response.content),
                        'type': self._identify_backup_type(path),
                        'severity': 'HIGH'
                    })
                    self.discovered_content.append({'type': 'backup_file', 'path': path})
            except:
                pass
        
        return {
            'test_name': 'Backup File Discovery (WSTG-4.2.4)',
            'found_backups': found_backups,
            'total_found': len(found_backups),
            'recommendations': [
                'Remove all backup files from production servers',
                'Store backups securely, not accessible via web',
                'Use .htaccess to block backup file access',
                'Implement backup retention policy',
                'Monitor for new backup files'
            ],
            'severity': 'HIGH',
            'wstg_reference': 'WSTG-4.2.4'
        }
    
    def discover_hidden_endpoints(self) -> Dict[str, Any]:
        """
        WSTG 4.2.1-4.2.3: Discover hidden and unreferenced endpoints
        Maps application entry points not visible in UI
        """
        common_endpoints = [
            '/api', '/api/v1', '/api/v2', '/rest',
            '/admin', '/administrator', '/admin/panel',
            '/staging', '/dev', '/development', '/test', '/uat',
            '/wp-admin', '/phpmyadmin',
            '/console', '/actuator', '/debug',
            '/health', '/status', '/ping', '/alive',
            '/metrics', '/stats', '/monitoring',
            '/.well-known',
            '/swagger', '/swagger.json', '/swagger-ui', '/swagger-ui.html',
            '/api-docs', '/api-docs.json', '/graphql',
        ]
        
        hidden_endpoints = []
        
        for endpoint in common_endpoints:
            test_url = urljoin(self.base_url, endpoint)
            try:
                response = self.session.get(test_url, timeout=3, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 401, 403]:
                    endpoint_info = {
                        'path': endpoint,
                        'url': test_url,
                        'status_code': response.status_code,
                        'type': self._classify_endpoint(endpoint),
                        'accessible': response.status_code in [200, 301, 302],
                        'severity': 'HIGH' if 'admin' in endpoint else 'MEDIUM'
                    }
                    hidden_endpoints.append(endpoint_info)
                    self.discovered_content.append({'type': 'hidden_endpoint', 'path': endpoint})
            except:
                pass
        
        return {
            'test_name': 'Hidden Endpoint Discovery (WSTG-4.2.1)',
            'discovered_endpoints': hidden_endpoints,
            'total_found': len(hidden_endpoints),
            'by_type': self._group_by_type(hidden_endpoints),
            'recommendations': [
                'Remove debug and test endpoints from production',
                'Secure admin interfaces with strong authentication',
                'Document all API endpoints',
                'Use API gateway for centralized security',
                'Implement rate limiting on all endpoints'
            ],
            'severity': 'MEDIUM',
            'wstg_reference': 'WSTG-4.2.1'
        }
    
    def discover_admin_paths(self) -> Dict[str, Any]:
        """
        WSTG 4.2.1: Discover exposed administrative interfaces
        Searches for common admin panel locations
        """
        admin_paths = [
            '/admin', '/administrator', '/admin/panel', '/admin/dashboard',
            '/wp-admin', '/wp-login.php',
            '/phpmyadmin', '/adminer', '/pgadmin',
            '/cpanel', '/webmin', '/directadmin',
            '/admin.php', '/adm', '/adm/', '/administer',
            '/user/admin', '/usercp', '/moderator',
            '/management', '/management/console',
            '/admin/index.php', '/adm/index.php',
            '/controlpanel', '/control_panel',
            '/ispadmin', '/netadmin',
            '/cms/admin', '/cms/administrator',
            '/cms/backend', '/admin/login',
            '/admin/login.html', '/admin/login.php',
        ]
        
        admin_interfaces = []
        
        for path in admin_paths:
            test_url = urljoin(self.base_url, path)
            try:
                response = self.session.get(test_url, timeout=3, allow_redirects=False)
                
                # Check for admin interface indicators
                if response.status_code in [200, 301, 302, 401]:
                    if any(indicator in response.text.lower() for indicator in 
                           ['login', 'admin', 'dashboard', 'panel', 'console']):
                        admin_interfaces.append({
                            'path': path,
                            'url': test_url,
                            'status_code': response.status_code,
                            'requires_auth': response.status_code == 401,
                            'is_login_form': 'login' in response.text.lower(),
                            'severity': 'HIGH'
                        })
                        self.discovered_content.append({'type': 'admin_interface', 'path': path})
            except:
                pass
        
        return {
            'test_name': 'Admin Interface Discovery (WSTG-4.2.1)',
            'discovered_admin_paths': admin_interfaces,
            'total_found': len(admin_interfaces),
            'requires_auth': len([a for a in admin_interfaces if a['requires_auth']]),
            'recommendations': [
                'Require strong authentication for admin interfaces',
                'Implement IP whitelisting for admin access',
                'Use non-standard URLs for admin panels',
                'Deploy WAF rules for admin path protection',
                'Monitor admin interface access logs',
                'Implement rate limiting on login attempts',
                'Use MFA for admin account access'
            ],
            'severity': 'HIGH',
            'wstg_reference': 'WSTG-4.2.1'
        }
    
    def discover_public_asset_inventory(self) -> Dict[str, Any]:
        """
        WSTG 4.1: Discover public asset inventory
        Maps static and public assets
        """
        asset_paths = [
            '/assets', '/static', '/css', '/js', '/images', '/img',
            '/fonts', '/media', '/uploads', '/files', '/download',
            '/public', '/dist', '/build', '/lib', '/libs',
            '/vendor', '/node_modules', '/bower_components',
            '/cdn', '/resources', '/themes',
        ]
        
        asset_inventory = []
        
        for path in asset_paths:
            test_url = urljoin(self.base_url, path)
            try:
                response = self.session.get(test_url, timeout=3, allow_redirects=False)
                
                if response.status_code == 200:
                    # Check if directory listing is enabled
                    is_dir_listing = '<title>Index of' in response.text or \
                                    'Directory listing' in response.text
                    
                    asset_inventory.append({
                        'path': path,
                        'url': test_url,
                        'accessible': True,
                        'directory_listing': is_dir_listing,
                        'severity': 'MEDIUM' if is_dir_listing else 'LOW'
                    })
                    self.discovered_content.append({'type': 'asset_path', 'path': path})
            except:
                pass
        
        return {
            'test_name': 'Public Asset Inventory (WSTG-4.1)',
            'discovered_assets': asset_inventory,
            'total_found': len(asset_inventory),
            'directory_listing_enabled': len([a for a in asset_inventory if a['directory_listing']]),
            'recommendations': [
                'Disable directory listing on all web directories',
                'Use .htaccess: Options -Indexes',
                'Implement proper access controls for sensitive assets',
                'Use CDN for static asset delivery',
                'Cache assets with long expiration headers'
            ],
            'severity': 'LOW',
            'wstg_reference': 'WSTG-4.1'
        }
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Execute all advanced content discovery tests"""
        results = {
            'category': 'Advanced Content Discovery',
            'base_url': self.base_url,
            'timestamp': self._get_timestamp(),
            'tests': [
                self.discover_sensitive_files(),
                self.discover_backup_files(),
                self.discover_hidden_endpoints(),
                self.discover_admin_paths(),
                self.discover_public_asset_inventory()
            ],
            'summary': {
                'total_discovered': len(self.discovered_content),
                'sensitive_files': len([x for x in self.discovered_content if x['type'] == 'sensitive_file']),
                'backup_files': len([x for x in self.discovered_content if x['type'] == 'backup_file']),
                'hidden_endpoints': len([x for x in self.discovered_content if x['type'] == 'hidden_endpoint']),
                'admin_interfaces': len([x for x in self.discovered_content if x['type'] == 'admin_interface']),
                'asset_paths': len([x for x in self.discovered_content if x['type'] == 'asset_path']),
            },
            'wstg_coverage': 'WSTG-4.2 (Configuration & Deployment Management)'
        }
        return results
    
    @staticmethod
    def _identify_backup_type(path: str) -> str:
        """Identify backup file type"""
        if '.sql' in path:
            return 'Database Backup'
        elif any(x in path for x in ['.zip', '.tar.gz', '.rar', '.7z']):
            return 'Archive Backup'
        elif any(x in path for x in ['.bak', '.old', '.backup', '.copy']):
            return 'File Backup'
        else:
            return 'Unknown Backup'
    
    @staticmethod
    def _classify_endpoint(path: str) -> str:
        """Classify endpoint type"""
        if 'admin' in path:
            return 'Admin Interface'
        elif 'api' in path:
            return 'API Endpoint'
        elif any(x in path for x in ['staging', 'dev', 'test', 'uat']):
            return 'Development/Test Environment'
        elif any(x in path for x in ['health', 'status', 'ping', 'metrics']):
            return 'Monitoring Endpoint'
        elif 'swagger' in path or 'graphql' in path or 'api-docs' in path:
            return 'API Documentation'
        else:
            return 'Other'
    
    @staticmethod
    def _group_by_type(endpoints: List[Dict]) -> Dict[str, int]:
        """Group endpoints by type"""
        grouped = {}
        for endpoint in endpoints:
            endpoint_type = endpoint['type']
            grouped[endpoint_type] = grouped.get(endpoint_type, 0) + 1
        return grouped
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
