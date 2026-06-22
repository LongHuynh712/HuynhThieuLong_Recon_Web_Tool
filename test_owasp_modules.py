"""
OWASP WSTG v4.2 Module Test Script
Tests all 10 modules against sample URLs
Run: python test_owasp_modules.py
"""

import json
import sys
from datetime import datetime

# Import all modules
try:
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
        get_module_info,
        run_all_owasp_modules
    )
    print("✅ All OWASP modules imported successfully")
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)


def test_single_module(module_func, module_name, test_url):
    """Test a single module"""
    print(f"\n{'='*60}")
    print(f"Testing: {module_name}")
    print(f"{'='*60}")
    
    try:
        result = module_func(test_url)
        
        # Check result structure
        if 'error' in result:
            print(f"❌ ERROR: {result.get('error')}")
            return False
        
        # Print summary
        if 'test_name' in result:
            print(f"✅ Test Name: {result.get('test_name')}")
        
        if 'url' in result:
            print(f"✅ Target URL: {result.get('url')}")
        
        if 'wstg_reference' in result:
            print(f"✅ WSTG Reference: {result.get('wstg_reference')}")
        
        if 'severity' in result:
            print(f"✅ Severity: {result.get('severity')}")
        
        # Print findings summary
        if 'findings' in result:
            findings = result['findings']
            if isinstance(findings, list):
                print(f"✅ Findings Count: {len(findings)}")
                if findings and len(findings) > 0:
                    print(f"   First finding: {findings[0] if isinstance(findings[0], str) else 'Complex object'}")
        
        if 'recommendations' in result:
            recommendations = result['recommendations']
            if isinstance(recommendations, list):
                print(f"✅ Recommendations Count: {len(recommendations)}")
                if recommendations and len(recommendations) > 0:
                    print(f"   Sample: {recommendations[0]}")
        
        print(f"✅ Module executed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False


def main():
    """Run all tests"""
    # Test URL - can be changed to any target
    test_url = "https://example.com"
    
    print("\n" + "="*60)
    print("OWASP WSTG v4.2 Module Testing Suite")
    print("="*60)
    print(f"Test URL: {test_url}")
    print(f"Test Time: {datetime.now().isoformat()}")
    print(f"Total Modules: 10")
    
    # Test all individual modules
    modules_to_test = [
        (run_search_engine_reconnaissance, "Search Engine Reconnaissance (WSTG-4.1)"),
        (run_advanced_content_discovery, "Advanced Content Discovery (WSTG-4.2)"),
        (run_entry_point_mapping, "Entry Point Mapping (WSTG-4.7/4.12)"),
        (run_architecture_mapping, "Architecture Mapping (WSTG-4.1)"),
        (run_technology_intelligence, "Technology Intelligence (WSTG-4.1)"),
        (run_client_side_assessment, "Client-Side Assessment (WSTG-4.11)"),
        (run_api_discovery, "API Discovery (WSTG-4.12)"),
        (run_session_assessment, "Session Assessment (WSTG-4.6)"),
        (run_error_handler_assessment, "Error Handler Assessment (WSTG-4.8)"),
        (run_security_scoring, "Security Scoring (OWASP)")
    ]
    
    passed = 0
    failed = 0
    
    for module_func, module_name in modules_to_test:
        if test_single_module(module_func, module_name, test_url):
            passed += 1
        else:
            failed += 1
    
    # Test comprehensive scan
    print(f"\n{'='*60}")
    print("Testing: Comprehensive Scan (All 10 Modules)")
    print(f"{'='*60}")
    
    try:
        comprehensive_results = run_all_owasp_modules(test_url)
        
        print(f"✅ Comprehensive scan executed")
        print(f"✅ Modules executed: {len(comprehensive_results.get('modules_executed', []))}")
        print(f"✅ Modules failed: {len(comprehensive_results.get('modules_failed', []))}")
        print(f"✅ Total findings: {comprehensive_results.get('total_findings', 0)}")
        
        findings_by_severity = comprehensive_results.get('findings_by_severity', {})
        print(f"✅ Findings by severity: {findings_by_severity}")
        
        passed += 1
    except Exception as e:
        print(f"❌ Comprehensive scan failed: {e}")
        failed += 1
    
    # Print summary
    print(f"\n{'='*60}")
    print("Test Summary")
    print(f"{'='*60}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total:  {passed + failed}")
    
    # Get module info
    print(f"\n{'='*60}")
    print("Available Modules")
    print(f"{'='*60}")
    module_info = get_module_info()
    print(f"Total: {module_info['total_modules']}\n")
    
    for idx, module in enumerate(module_info['modules'], 1):
        print(f"{idx}. {module['name']}")
        print(f"   WSTG: {module['wstg']}")
        print(f"   Category: {module['category']}")
        print(f"   Description: {module['description']}\n")
    
    if failed == 0:
        print("✅ All tests passed!")
        return 0
    else:
        print(f"❌ {failed} test(s) failed")
        return 1


if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
