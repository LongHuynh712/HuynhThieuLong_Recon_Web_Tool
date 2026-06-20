"""
Scan queue (Phase 3) — FIFO background processing.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

QUEUE_FILE = Path("data/scan_queue.json")
_queue_lock = threading.Lock()
_worker_started = False


def _load_queue() -> list[dict]:
    if not QUEUE_FILE.exists():
        return []
    try:
        with QUEUE_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_queue(items: list[dict]) -> None:
    QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with QUEUE_FILE.open("w", encoding="utf-8") as f:
        json.dump(items[-50:], f, ensure_ascii=False, indent=2)


def list_queue() -> list[dict]:
    with _queue_lock:
        return dedupe_queue_items(_load_queue())


def _normalize_queue_url(url: str) -> str:
    raw = (url or "").strip().lower()
    if raw.startswith("http://"):
        raw = raw[7:]
    elif raw.startswith("https://"):
        raw = raw[8:]
    return raw.rstrip("/") or raw


def dedupe_queue_items(items: list[dict]) -> list[dict]:
    """Keep first occurrence of each queue id when rendering or listing."""
    seen: set[str] = set()
    out: list[dict] = []
    for item in items:
        item_id = str(item.get("id") or "")
        if not item_id or item_id in seen:
            continue
        seen.add(item_id)
        out.append(item)
    return out


def _find_active_duplicate(
    items: list[dict],
    url: str,
    scan_mode: str,
    workspace_id: str,
) -> dict | None:
    target = _normalize_queue_url(url)
    mode = (scan_mode or "full").lower()
    ws = workspace_id or ""
    for item in items:
        if item.get("status") not in ("pending", "running"):
            continue
        if (
            _normalize_queue_url(item.get("url", "")) == target
            and (item.get("scan_mode") or "full").lower() == mode
            and (item.get("workspace_id") or "") == ws
        ):
            return item
    return None


def enqueue_scan(
    url: str,
    scan_mode: str = "full",
    modules: list[str] | None = None,
    workspace_id: str = "",
    priority: int = 0,
) -> tuple[dict, bool]:
    """
    Add a scan to the queue.
    Returns (entry, created). If an identical pending/running item exists, returns it with created=False.
    """
    with _queue_lock:
        items = _load_queue()
        existing = _find_active_duplicate(items, url, scan_mode, workspace_id)
        if existing:
            return existing, False

        entry = {
            "id": str(uuid.uuid4()),
            "url": url.strip(),
            "scan_mode": scan_mode,
            "modules": modules or [],
            "workspace_id": workspace_id,
            "priority": priority,
            "status": "pending",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "started_at": None,
            "finished_at": None,
            "record_id": None,
            "error": None,
        }
        items.append(entry)
        items.sort(key=lambda x: (-x.get("priority", 0), x.get("created_at", "")))
        _save_queue(items)
        return entry, True


def cancel_queue_item(item_id: str) -> bool:
    with _queue_lock:
        items = _load_queue()
        for item in items:
            if item.get("id") == item_id and item.get("status") == "pending":
                item["status"] = "cancelled"
                _save_queue(items)
                return True
        return False


def process_next(run_scan: Callable[[dict], dict | None]) -> dict | None:
    """Process one pending item; returns processed entry or None."""
    with _queue_lock:
        items = _load_queue()
        target = next((i for i in items if i.get("status") == "pending"), None)
        if not target:
            return None
        target["status"] = "running"
        target["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        _save_queue(items)

    try:
        result = run_scan(target)
        with _queue_lock:
            items = _load_queue()
            for item in items:
                if item.get("id") == target["id"]:
                    item["status"] = "completed" if result else "failed"
                    item["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    if result:
                        item["record_id"] = result.get("record_id")
                        item["score"] = (result.get("summary") or {}).get("score")
                    else:
                        item["error"] = "Scan returned no result"
                    _save_queue(items)
                    return item
    except Exception as exc:
        with _queue_lock:
            items = _load_queue()
            for item in items:
                if item.get("id") == target["id"]:
                    item["status"] = "failed"
                    item["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    item["error"] = str(exc)
                    _save_queue(items)
                    return item
    return None


def start_queue_worker(app, run_scan: Callable[[dict], dict | None], interval: int = 15) -> None:
    global _worker_started
    if _worker_started:
        return
    _worker_started = True

    def loop():
        while True:
            try:
                with app.app_context():
                    process_next(run_scan)
            except Exception:
                pass
            time.sleep(interval)

    threading.Thread(target=loop, daemon=True, name="reconsight-queue").start()
