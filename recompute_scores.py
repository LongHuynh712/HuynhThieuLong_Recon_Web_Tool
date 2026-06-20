import json
from app import build_summary_from_record, load_history, _parse_and_enrich_sections
from platform_core import build_executive_summary

HISTORY_FILE = 'scan_history.json'

def find_record_by_domain(domain):
    history = load_history()
    for r in history:
        url = r.get('url','')
        if domain in url:
            return r
    return None


def compute_report_summary(record):
    report = record.get('report','')
    sections = _parse_and_enrich_sections(report)
    old_summary = {
        'score': record.get('score', 0),
        'security_score': record.get('security_score', record.get('score', 0)),
        'quality_score': record.get('quality_score', 100),
    }
    new_summary = build_summary_from_record(record)
    executive_old = build_executive_summary(record.get('report',''), sections, old_summary, record.get('recommendations', []), record.get('url',''))
    executive_new = build_executive_summary(record.get('report',''), sections, new_summary, record.get('recommendations', []), record.get('url',''))
    # gather findings that changed severity
    changed = []
    parsed = sections
    for sec in parsed:
        old_level = sec.get('severity')
        new_level = sec.get('severity_level')
        if old_level and new_level and old_level.lower() != new_level.lower():
            changed.append({'title': sec.get('title'), 'old': old_level, 'new': new_level})
    return {
        'url': record.get('url'),
        'old_summary': old_summary,
        'new_summary': new_summary,
        'old_risk': executive_old.get('risk_level'),
        'new_risk': executive_new.get('risk_level'),
        'changed_findings': changed,
    }


def main():
    domains = ['google.com','x.com']
    results = {}
    history = load_history()
    for d in domains:
        rec = find_record_by_domain(d)
        if not rec:
            print(f'No history record found for {d}')
            continue
        res = compute_report_summary(rec)
        results[d] = res
        print('---')
        print('URL:', res['url'])
        print('Old Score:', res['old_summary'])
        print('New Score:', res['new_summary'])
        print('Old Risk Level:', res['old_risk'])
        print('New Risk Level:', res['new_risk'])
        print('Changed Findings:')
        for c in res['changed_findings']:
            print('-', c['title'], c['old'], '->', c['new'])

if __name__ == '__main__':
    main()
