"""
OWASP WSTG v4.2 Module Integration Wrapper
Provides unified interface for all 10 OWASP security test modules
"""

import sys
import os
from datetime import datetime

# Add modules directory to path
modules_dir = os.path.join(os.path.dirname(__file__), 'modules')
if modules_dir not in sys.path:
    sys.path.insert(0, modules_dir)

# Import all 10 OWASP test modules
try:
    from search_engine_recon import SearchEngineRecon
    from advanced_content_discovery import AdvancedContentDiscovery
    from entry_point_mapper import EntryPointMapper
    from architecture_mapper import ArchitectureMapper
    from technology_intelligence import TechnologyIntelligence
    from client_side_assessor import ClientSideAssessor
    from api_discoverer import APIDiscoverer
    from session_assessor import SessionAssessor
    from error_handler_assessor import ErrorHandlerAssessor
    from security_scorer import SecurityScorer
except ImportError as e:
    print(f"Warning: Could not import OWASP modules: {e}")

# Module registry for scanner integration
OWASP_WSTG_MODULES = {
    'search_engine_recon': {
        'class': SearchEngineRecon,
        'wstg': 'WSTG-4.1',
        'category': 'Information Gathering',
        'description': 'Search engine reconnaissance and public information discovery'
    },
    'advanced_content_discovery': {
        'class': AdvancedContentDiscovery,
        'wstg': 'WSTG-4.2',
        'category': 'Configuration & Deployment Management',
        'description': 'Sensitive files, backups, hidden endpoints, and admin interfaces'
    },
    'entry_point_mapper': {
        'class': EntryPointMapper,
        'wstg': 'WSTG-4.7/4.12',
        'category': 'Input Validation & API Testing',
        'description': 'Forms, parameters, API endpoints, and upload capabilities'
    },
    'architecture_mapper': {
        'class': ArchitectureMapper,
        'wstg': 'WSTG-4.1',
        'category': 'Information Gathering',
        'description': 'Infrastructure mapping, subdomains, hosting, CDN, third-party services'
    },
    'technology_intelligence': {
        'class': TechnologyIntelligence,
        'wstg': 'WSTG-4.1',
        'category': 'Information Gathering',
        'description': 'Framework, CMS, and library detection with confidence scoring'
    },
    'client_side_assessor': {
        'class': ClientSideAssessor,
        'wstg': 'WSTG-4.11',
        'category': 'Client-side Testing',
        'description': 'CORS, clickjacking, storage, third-party JS, WebSockets'
    },
    'api_discoverer': {
        'class': APIDiscoverer,
        'wstg': 'WSTG-4.12',
        'category': 'API Testing',
        'description': 'Swagger, OpenAPI, GraphQL, and REST API discovery'
    },
    'session_assessor': {
        'class': SessionAssessor,
        'wstg': 'WSTG-4.6',
        'category': 'Session Management Testing',
        'description': 'Cookie attributes, session tokens, CSRF tokens, session fixation'
    },
    'error_handler_assessor': {
        'class': ErrorHandlerAssessor,
        'wstg': 'WSTG-4.8',
        'category': 'Error Handling Testing',
        'description': 'Debug pages, stack traces, verbose errors, information disclosure'
    },
    'security_scorer': {
        'class': SecurityScorer,
        'wstg': 'OWASP WSTG v4.2',
        'category': 'Security Scoring',
        'description': 'OWASP coverage metrics and security posture scoring'
    }
}


def run_owasp_module(base_url, module_name):
    """
    Execute a single OWASP module by name
    
    Args:
        base_url: Target URL to scan
        module_name: Name of module to run
    
    Returns:
        dict: Module results with test_name, findings, recommendations, severity, wstg_reference
    """
    if module_name not in OWASP_WSTG_MODULES:
        return {
            'error': f'Module not found: {module_name}',
            'available_modules': list(OWASP_WSTG_MODULES.keys())
        }
    
    module_info = OWASP_WSTG_MODULES[module_name]
    module_class = module_info['class']
    
    try:
        module_instance = module_class(base_url)
        return module_instance.run_all_tests()
    except Exception as e:
        return {
            'error': str(e),
            'module': module_name,
            'message': 'Module execution failed'
        }


def run_all_owasp_modules(base_url):
    """
    Execute all OWASP modules for comprehensive scan
    
    Args:
        base_url: Target URL to scan
    
    Returns:
        dict: Aggregated results from all modules
    """
    results = {
        'timestamp': datetime.now().isoformat(),
        'base_url': base_url,
        'modules_executed': [],
        'modules_failed': [],
        'total_findings': 0,
        'findings_by_severity': {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
    }
    
    for module_name, module_info in OWASP_WSTG_MODULES.items():
        try:
            module_instance = module_info['class'](base_url)
            module_results = module_instance.run_all_tests()
            
            results['modules_executed'].append({
                'name': module_name,
                'wstg': module_info['wstg'],
                'status': 'success',
                'results': module_results
            })
            
            # Count findings by severity
            severity = module_results.get('severity', 'INFO')
            if severity in results['findings_by_severity']:
                results['findings_by_severity'][severity] += 1
                
            results['total_findings'] += 1
            
        except Exception as e:
            results['modules_failed'].append({
                'name': module_name,
                'error': str(e)
            })
    
    return results


def get_module_info():
    """Get information about all available modules"""
    return {
        'total_modules': len(OWASP_WSTG_MODULES),
        'modules': [
            {
                'name': name,
                'wstg': info['wstg'],
                'category': info['category'],
                'description': info['description']
            }
            for name, info in OWASP_WSTG_MODULES.items()
        ]
    }


def get_module_by_wstg_section(section_id):
    """Get modules by WSTG section (e.g., '4.1', '4.6')"""
    matching = []
    for module_name, module_info in OWASP_WSTG_MODULES.items():
        if section_id in module_info['wstg']:
            matching.append({
                'name': module_name,
                'wstg': module_info['wstg'],
                'category': module_info['category'],
                'description': module_info['description']
            })
    return matching


# Wrapper functions for scanner.py integration
def run_search_engine_reconnaissance(url):
    """WSTG 4.1: Search engine reconnaissance"""
    return run_owasp_module(url, 'search_engine_recon')


def run_advanced_content_discovery(url):
    """WSTG 4.2: Advanced content and backup discovery"""
    return run_owasp_module(url, 'advanced_content_discovery')


def run_entry_point_mapping(url):
    """WSTG 4.7/4.12: Entry point and parameter mapping"""
    return run_owasp_module(url, 'entry_point_mapper')


def run_architecture_mapping(url):
    """WSTG 4.1: Infrastructure and architecture mapping"""
    return run_owasp_module(url, 'architecture_mapper')


def run_technology_intelligence(url):
    """WSTG 4.1: Technology and framework detection"""
    return run_owasp_module(url, 'technology_intelligence')


def run_client_side_assessment(url):
    """WSTG 4.11: Client-side security assessment"""
    return run_owasp_module(url, 'client_side_assessor')


def run_api_discovery(url):
    """WSTG 4.12: API endpoint discovery and analysis"""
    return run_owasp_module(url, 'api_discoverer')


def run_session_assessment(url):
    """WSTG 4.6: Session management assessment"""
    return run_owasp_module(url, 'session_assessor')


def run_error_handler_assessment(url):
    """WSTG 4.8: Error handling and information disclosure assessment"""
    return run_owasp_module(url, 'error_handler_assessor')


def run_security_scoring(url):
    """OWASP: Security posture scoring and coverage metrics"""
    return run_owasp_module(url, 'security_scorer')
