import json
from app import parse_report, build_summary
from platform_risk import classify_section_impact

with open('scan_history.json', 'r', encoding='utf-8') as f:
    history = json.load(f)

def find_entry(history):
    for entry in history:
        url = entry.get('url', '').lower()
        if url in ('https://x.com', 'http://x.com', 'x.com'):
            return entry
    return next((entry for entry in history if 'x.com' in entry.get('url','').lower()), None)

entry = find_entry(history)
print('Found entry:', bool(entry))
if not entry:
    raise SystemExit('No X.com entry found')

report = entry.get('report', '')
summary = build_summary(report)
sections = parse_report(report)
print('Computed summary:')
for key in ('score', 'security_score', 'quality_score', 'security_grade', 'quality_grade', 'status', 'missing', 'warning', 'error', 'found', 'redirects'):
    print(f'  {key}:', summary.get(key))

print('\nSecurity section details:')
sec_count = 0
for sec in sections:
    impact = classify_section_impact(sec)
    if impact != 'security':
        continue
    sec_count += 1
    title = sec.get('title') or '<no title>'
    severity = sec.get('severity_level') or sec.get('severity') or 'info'
    text = (sec.get('text') or '').strip().replace('\n', ' | ')
    print(f'---\nTitle: {title}\nSeverity: {severity}\nText: {text[:240]}')

print('\nTotal security sections:', sec_count)
print('Raw report length:', len(report))
print('URL:', entry.get('url'))
