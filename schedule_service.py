"""
Scheduled scans (Phase 2) — lightweight JSON-backed scheduler.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

SCHEDULES_FILE = Path("scan_schedules.json")
_TICK_SECONDS = 60
_scheduler_started = False
_scheduler_lock = threading.Lock()


def load_schedules() -> list[dict]:
    if not SCHEDULES_FILE.exists():
        return []
    try:
        with SCHEDULES_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else data.get("schedules", [])
    except Exception:
        return []


def save_schedules(schedules: list[dict]) -> None:
    SCHEDULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with SCHEDULES_FILE.open("w", encoding="utf-8") as f:
        json.dump(schedules, f, ensure_ascii=False, indent=2)


def add_schedule(
    url: str,
    interval_hours: float = 24,
    scan_mode: str = "full",
    modules: list[str] | None = None,
    label: str = "",
) -> dict:
    schedules = load_schedules()
    now = time.time()
    entry = {
        "id": str(uuid.uuid4()),
        "url": url.strip(),
        "label": label or url.strip(),
        "interval_hours": max(1, float(interval_hours)),
        "scan_mode": scan_mode if scan_mode in ("full", "quick") else "full",
        "modules": modules or [],
        "enabled": True,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "last_run": None,
        "last_score": None,
        "last_status": None,
        "next_run": now,
    }
    schedules.append(entry)
    save_schedules(schedules)
    return entry


def delete_schedule(schedule_id: str) -> bool:
    schedules = load_schedules()
    new_list = [s for s in schedules if s.get("id") != schedule_id]
    if len(new_list) == len(schedules):
        return False
    save_schedules(new_list)
    return True


def toggle_schedule(schedule_id: str, enabled: bool | None = None) -> dict | None:
    schedules = load_schedules()
    for s in schedules:
        if s.get("id") == schedule_id:
            if enabled is None:
                s["enabled"] = not s.get("enabled", True)
            else:
                s["enabled"] = bool(enabled)
            if s["enabled"] and not s.get("next_run"):
                s["next_run"] = time.time()
            save_schedules(schedules)
            return s
    return None


def _update_schedule_after_run(schedule_id: str, score: int | None, status: str | None) -> None:
    schedules = load_schedules()
    now = time.time()
    for s in schedules:
        if s.get("id") == schedule_id:
            s["last_run"] = time.strftime("%Y-%m-%d %H:%M:%S")
            s["last_score"] = score
            s["last_status"] = status
            s["next_run"] = now + float(s.get("interval_hours", 24)) * 3600
            break
    save_schedules(schedules)


def process_due_schedules(run_scan: Callable[[dict], dict | None]) -> int:
    """Run all due schedules; returns count executed."""
    schedules = load_schedules()
    now = time.time()
    ran = 0
    for s in schedules:
        if not s.get("enabled", True):
            continue
        next_run = float(s.get("next_run") or 0)
        if now < next_run:
            continue
        try:
            result = run_scan(s)
            score = None
            status = None
            if result and result.get("summary"):
                score = result["summary"].get("score")
                status = result["summary"].get("status")
            _update_schedule_after_run(s.get("id"), score, status)
            ran += 1
        except Exception:
            s["next_run"] = now + 300
    if ran:
        save_schedules(schedules)
    return ran


def start_scheduler(app, run_scan: Callable[[dict], dict | None]) -> None:
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        _scheduler_started = True

    def loop():
        while True:
            try:
                with app.app_context():
                    process_due_schedules(run_scan)
            except Exception:
                pass
            time.sleep(_TICK_SECONDS)

    t = threading.Thread(target=loop, daemon=True, name="reconsight-scheduler")
    t.start()
