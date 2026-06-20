"""
Slack, Teams, Jira-style notifications (Phase 4 pack on Phase 3 hooks).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

INTEGRATIONS_FILE = Path("data/integrations.json")

DEFAULT_INTEGRATIONS = {
    "slack": {"enabled": False, "webhook_url": ""},
    "teams": {"enabled": False, "webhook_url": ""},
    "jira": {"enabled": False, "webhook_url": "", "project_key": ""},
}


def load_integrations() -> dict:
    if not INTEGRATIONS_FILE.exists():
        return dict(DEFAULT_INTEGRATIONS)
    try:
        with INTEGRATIONS_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        merged = dict(DEFAULT_INTEGRATIONS)
        merged.update(data)
        return merged
    except Exception:
        return dict(DEFAULT_INTEGRATIONS)


def save_integrations(config: dict) -> dict:
    INTEGRATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    merged = dict(DEFAULT_INTEGRATIONS)
    for key in DEFAULT_INTEGRATIONS:
        if key in config and isinstance(config[key], dict):
            merged[key] = {**DEFAULT_INTEGRATIONS[key], **config[key]}
    with INTEGRATIONS_FILE.open("w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)
    return merged


def _post_json(url: str, payload: dict) -> bool:
    if not url:
        return False
    try:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def notify_scan_complete(scan_payload: dict[str, Any]) -> dict[str, bool]:
    """Send scan summary to configured channels."""
    cfg = load_integrations()
    results = {}
    hostname = scan_payload.get("hostname") or scan_payload.get("url", "")
    score = scan_payload.get("score", "—")
    risk = scan_payload.get("risk_level", "—")
    text = f"ReconSight scan complete: {hostname} — Score {score}/100 — Risk {risk}"

    slack = cfg.get("slack", {})
    if slack.get("enabled") and slack.get("webhook_url"):
        results["slack"] = _post_json(
            slack["webhook_url"],
            {"text": text, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": f"*{text}*"}}]},
        )

    teams = cfg.get("teams", {})
    if teams.get("enabled") and teams.get("webhook_url"):
        results["teams"] = _post_json(
            teams["webhook_url"],
            {"@type": "MessageCard", "summary": "ReconSight Scan", "text": text},
        )

    jira = cfg.get("jira", {})
    if jira.get("enabled") and jira.get("webhook_url"):
        results["jira"] = _post_json(
            jira["webhook_url"],
            {
                "project": jira.get("project_key", "SEC"),
                "summary": f"[ReconSight] {hostname} — score {score}",
                "description": text,
                "labels": ["reconsight", "security-scan"],
            },
        )

    return results
