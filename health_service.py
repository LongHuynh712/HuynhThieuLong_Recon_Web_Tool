"""
Module & service health monitor (Phase 3).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable


def build_health_status(
    *,
    api_job_count: int,
    puppeteer_check: Callable[[], bool],
    scan_modules_count: int,
    history_file: Path,
    schedules_file: Path,
    queue_file: Path,
) -> dict[str, Any]:
    checks: list[dict] = []

    def add(name: str, status: str, message: str, latency_ms: float | None = None):
        checks.append(
            {
                "name": name,
                "status": status,
                "message": message,
                "latency_ms": latency_ms,
            }
        )

    add("api_registry", "ok" if api_job_count > 0 else "warn", f"{api_job_count} API checks registered")

    t1 = time.perf_counter()
    try:
        pup_ok = puppeteer_check()
        add(
            "puppeteer",
            "ok" if pup_ok else "warn",
            "Browser module ready" if pup_ok else "Puppeteer not installed (cd browser && npm install)",
            round((time.perf_counter() - t1) * 1000, 1),
        )
    except Exception as e:
        add("puppeteer", "error", str(e))

    add("scanner_modules", "ok", f"{scan_modules_count} scan modules configured")

    for label, path in (
        ("history_store", history_file),
        ("schedules_store", schedules_file),
        ("queue_store", queue_file),
    ):
        parent = path.parent
        if parent.exists() or path.exists():
            add(label, "ok", f"Data path: {path}")
        else:
            add(label, "ok", f"Will create on first use: {path}")

    statuses = [c["status"] for c in checks]
    overall = "healthy"
    if "error" in statuses:
        overall = "degraded"
    elif "warn" in statuses:
        overall = "warning"

    return {
        "status": overall,
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "checks": checks,
    }
