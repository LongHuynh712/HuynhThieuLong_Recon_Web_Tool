#!/usr/bin/env python3
"""
Benchmark scan runner for ReconSight.
Scans a set of target domains and generates a comprehensive report.
"""

import sys
import time
import json
import re
from pathlib import Path
from datetime import datetime

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import scan function and utilities
from app import perform_scan
from platform_risk import compute_weighted_risk
from platform_core import count_severities, SEVERITY_LEVELS
from workspace_service import ensure_defaults

# Ensure data files exist
ensure_defaults()

# Target domains for benchmark
TARGETS = [
    "google.com",
    "github.com",
    "microsoft.com",
    "cloudflare.com",
    "openai.com"
]

def get_severity_reason(section):
    """Generate human-readable reason for high/critical severity assignment."""
    text = section.get('text', '')
    title = section.get('title', '')
    combined = f"{title}\n{text}".upper()

    # Check for critical first
    if re.search(r"\[FOUND\].*(?:BACKUP|\.ENV|\.GIT|PASSWORD|SECRET|API[_-]?KEY)", combined, re.I):
        return "Critical: Exposure of sensitive artifact (backup, .env, .git, credentials, or API key)"
    if "[ERROR]" in combined or "SEVERITY: HIGH" in combined:
        return "High: Error condition or critical security misconfiguration"
    if "[WARNING]" in combined or "SEVERITY: MEDIUM" in combined:
        return "Medium: Warning or missing important security feature"
    if "[MISSING]" in combined:
        key = title.lower()
        if any(w in key for w in ("ssl", "tls", "hsts", "csp", "security header", "x-frame")):
            return "Medium: Missing critical security header"
        else:
            return "Low: Missing optional security feature"
    return "Info: Informational finding"

def verify_findings_categorization(sections):
    """
    Verify that specific finding types are categorized as INFO.
    Returns a dict with verification results.
    """
    checks = {
        "discovery_findings": True,
        "dorks": True,
        "public_emails": True,
        "crossdomain_xml": True
    }

    for sec in sections:
        title = sec.get('title', '').lower()
        text = sec.get('text', '')
        severity = sec.get('severity_level', sec.get('severity', 'info'))

        # Discovery findings: ADMIN INTERFACES, SUBDOMAINS, COMMON PATHS, etc.
        if any(kw in title for kw in ["admin", "subdomain", "common paths", "sensitive files", "backup files", "http methods"]):
            if severity != "info":
                checks["discovery_findings"] = False

        # Dorks: GOOGLE DORK SUGGESTIONS
        if "google dork" in title:
            if severity != "info":
                checks["dorks"] = False

        # Public emails: EMAIL EXTRACTION
        if "email" in title:
            if severity != "info":
                checks["public_emails"] = False

        # crossdomain.xml: check if the section mentions crossdomain.xml and its severity
        if "crossdomain.xml" in text:
            if severity != "info":
                checks["crossdomain_xml"] = False

    return checks

def scan_target(url):
    """Run a full scan on the target URL and return structured results."""
    print(f"[*] Scanning {url} ...")
    start = time.time()
    try:
        result = perform_scan(url, scan_mode='full', selected_sections=[])
        duration = time.time() - start
        print(f"    Completed in {duration:.1f}s")
        return result, duration
    except Exception as e:
        print(f"    ERROR: {e}")
        return None, 0

def main():
    all_results = []

    print(f"\n===== ReconSight Benchmark Scans =====")
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    for url in TARGETS:
        result, duration = scan_target(url)
        if result is None:
            all_results.append({"url": url, "error": "Scan failed"})
            continue

        summary = result.get('summary', {})
        sections = result.get('sections', [])
        metrics = result.get('metrics', {})

        # Compute risk
        risk = compute_weighted_risk(sections, summary, asset_criticality='normal')

        # Severity counts
        sev_counts = count_severities(sections)

        # Collect high/critical findings with evidence and reasons
        high_critical = []
        for sec in sections:
            sev = sec.get('severity_level', sec.get('severity', 'info'))
            if sev in ('critical', 'high'):
                evidence = sec.get('text', '')[:500]  # first 500 chars
                reason = get_severity_reason(sec)
                high_critical.append({
                    'title': sec.get('title'),
                    'severity': sev,
                    'evidence': evidence,
                    'reason': reason
                })

        # Verify categorization
        verification = verify_findings_categorization(sections)

        all_results.append({
            'url': url,
            'security_score': summary.get('security_score'),
            'quality_score': summary.get('quality_score'),
            'risk_index': risk.get('risk_index'),
            'risk_tier': risk.get('risk_tier'),
            'severity_counts': sev_counts,
            'high_critical_findings': high_critical,
            'verification': verification,
            'metrics': metrics,
            'duration': duration
        })

    # Generate report
    print("\n\n===== BENCHMARK REPORT =====\n")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Targets: {len(TARGETS)}\n")

    # Summary table
    print("{:<25} {:<12} {:<12} {:<10} {:<10} {:<10}".format(
        "Domain", "Sec Score", "Risk Index", "Critical", "High", "Medium"))
    print("-" * 85)

    for r in all_results:
        if 'error' in r:
            print(f"{r['url']:<25} SCAN FAILED")
            continue
        counts = r['severity_counts']
        print(f"{r['url']:<25} {r['security_score']:<12} {r['risk_index']:<12} ({r['risk_tier']}) "
              f"{counts.get('critical',0):<10} {counts.get('high',0):<10} {counts.get('medium',0):<10}")

    # Verification summary
    print("\n\n=== CATEGORIZATION VERIFICATION ===")
    for r in all_results:
        if 'error' in r:
            continue
        v = r['verification']
        print(f"\n{r['url']}:")
        print(f"  Discovery findings INFO: {'OK' if v['discovery_findings'] else 'FAIL'}")
        print(f"  Dorks INFO: {'OK' if v['dorks'] else 'FAIL'}")
        print(f"  Public emails INFO: {'OK' if v['public_emails'] else 'FAIL'}")
        print(f"  crossdomain.xml INFO: {'OK' if v['crossdomain_xml'] else 'FAIL'}")

    # High/Critical findings details
    print("\n\n=== HIGH/CRITICAL FINDINGS ====")
    for r in all_results:
        if 'error' in r:
            continue
        hc = r['high_critical_findings']
        if not hc:
            print(f"\n{r['url']}: No high/critical findings.")
            continue

        print(f"\n{r['url']}:")
        for i, f in enumerate(hc, 1):
            print(f"  {i}. [{f['severity'].upper()}] {f['title']}")
            print(f"     Reason: {f['reason']}")
            # Show evidence snippet (first 200 chars, single line)
            snippet = f['evidence'].replace('\n', ' ')[:200]
            print(f"     Evidence: {snippet}...")

    # Consistency check
    print("\n\n=== CONSISTENCY CHECK ===")
    for r in all_results:
        if 'error' in r:
            continue
        sec = r['security_score']
        risk = r['risk_tier']
        consistent = True
        if sec >= 90 and risk not in ('Low', 'Moderate'):
            consistent = False
        elif sec >= 80 and risk not in ('Low', 'Moderate', 'Elevated'):
            consistent = False
        elif sec >= 70 and risk not in ('Low', 'Moderate', 'Elevated', 'High'):
            consistent = False
        elif sec < 50 and risk not in ('Critical', 'High'):
            consistent = False
        status = "OK" if consistent else "REVIEW"
        print(f"{r['url']}: Sec Score {sec} vs Risk {risk} -> {status}")

    # Save full results
    out_path = PROJECT_ROOT / "benchmark_results.json"
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"\nFull results saved to: {out_path}")

    print("\n===== End of Report =====")

if __name__ == "__main__":
    main()
