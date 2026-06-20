"""
Outbound webhooks (Phase 3).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

WEBHOOKS_FILE = Path("data/webhooks.json")


def _load() -> list[dict]:
    if not WEBHOOKS_FILE.exists():
        return []
    try:
        with WEBHOOKS_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save(items: list[dict]) -> None:
    WEBHOOKS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with WEBHOOKS_FILE.open("w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2)


def list_webhooks() -> list[dict]:
    return _load()


def add_webhook(url: str, events: list[str] | None = None, label: str = "") -> dict:
    import uuid
    import time

    items = _load()
    entry = {
        "id": str(uuid.uuid4())[:8],
        "url": url.strip(),
        "label": label or url[:40],
        "events": events or ["scan.complete"],
        "enabled": True,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    items.append(entry)
    _save(items)
    return entry


def delete_webhook(webhook_id: str) -> bool:
    items = _load()
    new_items = [w for w in items if w.get("id") != webhook_id]
    if len(new_items) == len(items):
        return False
    _save(new_items)
    return True


def toggle_webhook(webhook_id: str) -> dict | None:
    items = _load()
    for w in items:
        if w.get("id") == webhook_id:
            w["enabled"] = not w.get("enabled", True)
            _save(items)
            return w
    return None


def dispatch_event(event: str, payload: dict[str, Any]) -> list[dict]:
    """POST to all enabled webhooks subscribed to event."""
    results = []
    body = json.dumps({"event": event, "payload": payload}, ensure_ascii=False).encode("utf-8")
    for hook in _load():
        if not hook.get("enabled", True):
            continue
        if event not in (hook.get("events") or []):
            continue
        url = hook.get("url", "")
        if not url:
            continue
        result = {"id": hook.get("id"), "url": url, "ok": False}
        try:
            req = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "ReconSight/3.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                result["ok"] = 200 <= resp.status < 300
                result["status"] = resp.status
        except urllib.error.HTTPError as e:
            result["status"] = e.code
            result["error"] = str(e.reason)
        except Exception as e:
            result["error"] = str(e)
        results.append(result)
    return results
