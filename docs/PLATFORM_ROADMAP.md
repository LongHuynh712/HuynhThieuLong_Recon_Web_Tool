# ReconSight Platform Roadmap

## Current architecture

| Layer | Files |
|-------|--------|
| Flask app | `app.py`, `api_routes.py`, `api_handlers.py` |
| Scanner | `scanner.py`, `webcheck_checks.py`, `browser_service.py` |
| UI | `templates/index.html`, `static/style.css`, `ui-enhancements.css`, `light-theme.css`, `platform.css` |
| Client | `script.js`, `scan_jobs.js`, `app-ui.js`, `platform.js`, `dashboard.js` |
| Docs | `module_docs.py`, `module_help.js` |

## Phase 1 — Platform shell (done in this iteration)

- Extended severity: Info, Low, Medium, High, Critical (`platform_core.py`)
- Executive summary + severity stat cards on results
- History dashboard: search, score filter, sort
- Quick actions: recent targets, favorites (localStorage)
- Scan live log panel (wired from API jobs)
- Severity distribution chart (Chart.js)
- Professional HTML export template
- `platform.css` / `platform.js` for animations and dashboard polish

## Phase 2 — Reporting & compliance ✅

- PDF executive cover page + severity table (`platform_export.build_professional_pdf`)
- Scheduled scans (`schedule_service.py`, `/api/schedules`, UI panel)
- Compare two history runs (`platform_compare.py`, `/api/history/compare`)
- Export JSON + SARIF 2.1 (`format=json`, `format=sarif`)
- CWE references on sections (`platform_compliance.py`)

## Phase 3 — Operations ✅

- Workspaces & local users (`workspace_service.py`, `data/`)
- Scan queue + background worker (`queue_service.py`, `/api/queue`)
- Outbound webhooks (`webhook_service.py`, `/api/webhooks`)
- Module health (`health_service.py`, `/api/health`)
- Audit log 500-line retention (`audit_service.py`, `logs/audit.jsonl`)

## Phase 4 — Intelligence ✅

- Weighted risk index + composite score (`platform_risk.py`, asset criticality on scan form)
- Trend analytics 30/90 days (`platform_analytics.py`, charts + `/api/analytics/trends`)
- Slack / Teams / Jira notifications (`integration_service.py`, `/api/integrations`)

## UI polish (dashboard premium)

- Fixed chart canvas blowout (`dashboard-premium.css`, `chart-canvas-slot`)
- KPI strip, collapsible Ops/Intel hubs, activity feed
- CSV export, text overflow safety for URLs/certs/long reports
- `dashboard-enhancements.js` — chart empty states & sizing

## Non-goals

- Do not remove existing scan modules, API jobs, or export formats
- Do not break server-side full scan POST workflow
