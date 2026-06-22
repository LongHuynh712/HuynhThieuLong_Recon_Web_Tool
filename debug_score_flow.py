#!/usr/bin/env python3
"""Diagnostic script to trace score/grade data flow for old records."""

import json
import sys
from app import (
    load_history,
    build_summary_from_record,
    _parse_and_enrich_sections,
)
from platform_core import build_executive_summary

def trace_record_flow(url_filter="google.com"):
    """Trace data flow for a record matching URL filter."""
    print(f"\n{'='*80}")
    print(f"TRACING SCORE FLOW FOR: {url_filter}")
    print(f"{'='*80}\n")
    
    history = load_history()
    record = next((r for r in history if url_filter in r.get("url", "")), None)
    
    if not record:
        print(f"❌ No record found for {url_filter}")
        return
    
    print(f"✓ Found record: {record['url']} (ID: {record['id'][:8]}...)")
    print(f"  Timestamp: {record.get('timestamp')}")
    print(f"  Mode: {record.get('mode')}")
    
    # STEP 1: Check stored values in history
    print(f"\n{'─'*80}")
    print("STEP 1: STORED VALUES IN scan_history.json")
    print(f"{'─'*80}")
    print(f"  score:              {record.get('score', 'MISSING')}")
    print(f"  security_score:     {record.get('security_score', 'MISSING')}")
    print(f"  quality_score:      {record.get('quality_score', 'MISSING')}")
    print(f"  security_grade:     {record.get('security_grade', 'MISSING')}")
    print(f"  quality_grade:      {record.get('quality_grade', 'MISSING')}")
    print(f"  status:             {record.get('status', 'MISSING')}")
    has_report = bool(record.get('report'))
    print(f"  report:             {'✓ PRESENT' if has_report else '❌ MISSING'} ({len(record.get('report', ''))} chars)")
    
    # STEP 2: Call build_summary_from_record (as done in build_results_context)
    print(f"\n{'─'*80}")
    print("STEP 2: build_summary_from_record(record)")
    print(f"{'─'*80}")
    
    if not has_report:
        print("⚠️  WARNING: No report in record! Will use stored values fallback.")
    
    summary = build_summary_from_record(record)
    print(f"✓ Returned summary dict:")
    for key in ['score', 'security_score', 'quality_score', 'security_grade', 'quality_grade', 'status']:
        value = summary.get(key, 'MISSING')
        print(f"    {key:20s}: {value}")
    
    # STEP 3: Parse report (as done in build_results_context)
    print(f"\n{'─'*80}")
    print("STEP 3: _parse_and_enrich_sections(report)")
    print(f"{'─'*80}")
    
    report = record.get("report", "")
    sections = _parse_and_enrich_sections(report)
    print(f"✓ Parsed {len(sections)} sections from report")
    
    # Count severities
    severity_counts = {}
    for sec in sections:
        level = sec.get('severity_level', 'info').lower()
        severity_counts[level] = severity_counts.get(level, 0) + 1
    
    print(f"  Severity distribution:")
    for level in ['critical', 'high', 'medium', 'low', 'info']:
        count = severity_counts.get(level, 0)
        print(f"    {level:10s}: {count:3d}")
    
    # STEP 4: Build executive summary
    print(f"\n{'─'*80}")
    print("STEP 4: build_executive_summary(report, sections, summary, ...)")
    print(f"{'─'*80}")
    
    recommendations = record.get("recommendations", [])
    target_info = record.get("target_info", {})
    hostname = (target_info or {}).get("hostname") or record.get("url", "")
    
    executive = build_executive_summary(report, sections, summary, recommendations, hostname)
    
    print(f"✓ Returned executive dict:")
    for key in ['score', 'security_score', 'quality_score', 'security_grade', 'quality_grade', 'risk_level', 'status']:
        value = executive.get(key, 'MISSING')
        print(f"    {key:20s}: {value}")
    
    print(f"\n  Severity counts from executive:")
    counts = executive.get('severity_counts', {})
    for level in ['critical', 'high', 'medium', 'low', 'info']:
        count = counts.get(level, 0)
        print(f"    {level:10s}: {count}")
    
    # STEP 5: Summary
    print(f"\n{'─'*80}")
    print("STEP 5: DATA FLOW SUMMARY")
    print(f"{'─'*80}")
    
    old_score = record.get('score', 0)
    new_score = executive.get('security_score', 0)
    
    print(f"  Old stored score:        {old_score}")
    print(f"  New recomputed score:    {new_score}")
    print(f"  Score changed:           {'✓ YES' if old_score != new_score else '❌ NO (identical)'}")
    
    old_grade = record.get('security_grade', 'MISSING')
    new_grade = executive.get('security_grade', 'MISSING')
    
    print(f"  Old stored grade:        {old_grade}")
    print(f"  New recomputed grade:    {new_grade}")
    print(f"  Grade changed:           {'✓ YES' if old_grade != new_grade else '⚠️  NO (same or both missing)'}")
    
    if new_grade == "—" or new_grade == "MISSING" or not new_grade:
        print(f"  ❌ PROBLEM: Grade is empty/default!")
    elif not new_grade:
        print(f"  ❌ PROBLEM: Grade is None!")
    else:
        print(f"  ✓ Grade properly computed")
    
    print(f"\n" + "="*80)
    return {
        'old_score': old_score,
        'new_score': new_score,
        'old_grade': old_grade,
        'new_grade': new_grade,
        'severity_counts': executive.get('severity_counts', {}),
    }

if __name__ == "__main__":
    # Test multiple records
    test_urls = ["google.com", "x.com", "duck.com"]
    
    results = {}
    for url in test_urls:
        try:
            result = trace_record_flow(url)
            results[url] = result
        except Exception as e:
            print(f"\n❌ ERROR processing {url}: {e}")
            import traceback
            traceback.print_exc()
    
    # Summary table
    print(f"\n{'='*80}")
    print("SUMMARY TABLE")
    print(f"{'='*80}")
    print(f"{'URL':<20} {'Old Score':<12} {'New Score':<12} {'Grade':<8} {'Change':<8}")
    print(f"{'-'*80}")
    for url, data in results.items():
        if data:
            change = "✓ YES" if data['old_score'] != data['new_score'] else "NO"
            print(f"{url:<20} {data['old_score']:<12} {data['new_score']:<12} {str(data['new_grade']):<8} {change:<8}")
