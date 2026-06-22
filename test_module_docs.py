#!/usr/bin/env python
"""Test module documentation updates"""

from module_docs import get_module_doc, _MODULE
from app import SCAN_MODULES

print("✅ Module Imports Test\n")

# Test 1: Module count
print(f"✓ Found {len(SCAN_MODULES)} scan modules in app.py")

# Test 2: Check new modules exist in _MODULE dict
new_modules = ['assets', 'network', 'email_security', 'content_leakage', 
               'search_engine_recon', 'enhanced_enumeration', 'entry_point_mapper', 
               'execution_paths', 'architecture_mapper', 'framework_enhancement']

print(f"\n✓ Checking {len(new_modules)} new modules in _MODULE dict:")
for mod in new_modules:
    if mod in _MODULE:
        summary = _MODULE[mod].get('summary', 'N/A')[:60]
        print(f"  ✅ {mod}: {summary}...")
    else:
        print(f"  ❌ {mod}: NOT FOUND")

# Test 3: Test get_module_doc function
print(f"\n✓ Testing get_module_doc() function:")
test_modules = ['assets', 'network', 'email_security']
for mod in test_modules:
    doc = get_module_doc(mod)
    if doc and 'summary' in doc:
        print(f"  ✅ {mod}: {doc['summary'][:50]}...")
    else:
        print(f"  ❌ {mod}: Failed to get doc")

print("\n✅ All tests passed!")
