"""
OWASP WSTG v4.2 API Routes
REST endpoints for all 10 OWASP security test modules
"""

from flask import Blueprint, request, jsonify
from datetime import datetime

# Import OWASP integration
from owasp_wstg_integration import (
    run_search_engine_reconnaissance,
    run_advanced_content_discovery,
    run_entry_point_mapping,
    run_architecture_mapping,
    run_technology_intelligence,
    run_client_side_assessment,
    run_api_discovery,
    run_session_assessment,
    run_error_handler_assessment,
    run_security_scoring,
    run_authentication_assessment,
    run_authorization_assessment,
    run_input_validation_assessment,
    run_business_logic_assessment,
    run_session_enhancement_assessment,
    get_module_info,
    get_module_by_wstg_section,
    run_all_owasp_modules
)

# Create Blueprint for OWASP routes
owasp_routes = Blueprint('owasp', __name__, url_prefix='/api/owasp')


# ===========================
# Health Check
# ===========================
@owasp_routes.route('/health', methods=['GET'])
def health_check():
    """Health check for OWASP modules"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'OWASP WSTG v4.2 Modules'
    }), 200


# ===========================
# Module Information
# ===========================
@owasp_routes.route('/modules', methods=['GET'])
def get_modules():
    """Get list of available OWASP modules"""
    return jsonify(get_module_info()), 200


@owasp_routes.route('/modules/<section_id>', methods=['GET'])
def get_modules_by_section(section_id):
    """Get modules for specific WSTG section (e.g., 4.1)"""
    modules = get_module_by_wstg_section(section_id)
    return jsonify({
        'section': section_id,
        'modules': modules,
        'count': len(modules)
    }), 200


# ===========================
# Individual Module Endpoints
# ===========================
@owasp_routes.route('/search-engine-recon', methods=['POST'])
def search_engine_recon():
    """
    WSTG 4.1: Search engine reconnaissance
    Discovers information through search engines
    
    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    
    try:
        results = run_search_engine_reconnaissance(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@owasp_routes.route('/content-discovery', methods=['POST'])
def content_discovery():
    """
    WSTG 4.2: Advanced content discovery
    Enumerates sensitive files, backups, hidden endpoints
    
    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    
    try:
        results = run_advanced_content_discovery(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@owasp_routes.route('/entry-points', methods=['POST'])
def entry_points():
    """
    WSTG 4.7/4.12: Entry point mapping
    Maps forms, parameters, API endpoints, upload capabilities
    
    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    
    try:
        results = run_entry_point_mapping(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@owasp_routes.route('/architecture', methods=['POST'])
def architecture():
    """
    WSTG 4.1: Architecture and infrastructure mapping
    Maps DNS, subdomains, hosting, CDN, third-party services
    
    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    
    try:
        results = run_architecture_mapping(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@owasp_routes.route('/technologies', methods=['POST'])
def technologies():
    """
    WSTG 4.1: Technology intelligence
    Detects frameworks, CMS, libraries with confidence scoring
    
    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    
    try:
        results = run_technology_intelligence(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@owasp_routes.route('/client-side', methods=['POST'])
def client_side():
    """
    WSTG 4.11: Client-side security assessment
    Analyzes CORS, clickjacking, storage, third-party JS, WebSockets
    
    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    
    try:
        results = run_client_side_assessment(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@owasp_routes.route('/apis', methods=['POST'])
def apis():
    """
    WSTG 4.12: API discovery
    Discovers Swagger, OpenAPI, GraphQL, REST APIs
    
    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    
    try:
        results = run_api_discovery(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@owasp_routes.route('/sessions', methods=['POST'])
def sessions():
    """
    WSTG 4.6: Session management assessment
    Analyzes cookies, CSRF tokens, session fixation
    
    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    
    try:
        results = run_session_assessment(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@owasp_routes.route('/errors', methods=['POST'])
def errors():
    """
    WSTG 4.8: Error handling assessment
    Detects debug pages, stack traces, verbose errors
    
    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    
    try:
        results = run_error_handler_assessment(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@owasp_routes.route('/security-score', methods=['POST'])
def security_score():
    """
    OWASP: Security posture scoring
    Computes OWASP coverage and security metrics

    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL parameter required'}), 400

    try:
        results = run_security_scoring(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ===========================
# New Assessment Endpoints
# ===========================
@owasp_routes.route('/authentication-assessment', methods=['POST'])
def authentication_assessment():
    """
    WSTG-4.3/4.4: Authentication Assessment (Passive)
    Detects MFA, login forms, password reset, account lockout, weak auth

    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    try:
        results = run_authentication_assessment(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@owasp_routes.route('/authorization-assessment', methods=['POST'])
def authorization_assessment():
    """
    WSTG-4.5: Authorization Assessment (Passive)
    Detects IDOR, privilege escalation, forced browsing, missing access control

    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    try:
        results = run_authorization_assessment(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@owasp_routes.route('/input-validation-assessment', methods=['POST'])
def input_validation_assessment():
    """
    WSTG-4.7: Input Validation Assessment (Passive)
    Detects XSS, SQLi, SSRF, open redirect, file upload indicators

    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    try:
        results = run_input_validation_assessment(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@owasp_routes.route('/business-logic-assessment', methods=['POST'])
def business_logic_assessment():
    """
    WSTG-4.10: Business Logic Assessment (Passive)
    Detects workflow bypass, predictable identifiers, business process weaknesses

    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    try:
        results = run_business_logic_assessment(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@owasp_routes.route('/session-enhancement-assessment', methods=['POST'])
def session_enhancement_assessment():
    """
    WSTG-4.6: Session Management Enhancement (Passive)
    Analyzes session cookies, JWT tokens, logout, entropy, fixation

    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    try:
        results = run_session_enhancement_assessment(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ===========================
# Comprehensive Scan
# ===========================
@owasp_routes.route('/scan-comprehensive', methods=['POST'])
def scan_comprehensive():
    """
    Execute all 10 OWASP modules for comprehensive assessment

    JSON Body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json() or {}
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL parameter required'}), 400

    try:
        results = run_all_owasp_modules(url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ===========================
# Error Handlers
# ===========================
@owasp_routes.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'OWASP endpoint not found'}), 404


@owasp_routes.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500
