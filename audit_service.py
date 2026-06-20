"""
Audit log with retention (Phase 3).
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

AUDIT_FILE = Path("logs/audit.jsonl")
MAX_AUDIT_LINES = 500


def _ensure_log_dir() -> None:
    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)


def audit_log(
    action: str,
    *,
    actor: str = "system",
    workspace_id: str = "",
    detail: dict | None = None,
    status: str = "ok",
) -> dict:
    _ensure_log_dir()
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ts": time.time(),
        "action": action,
        "actor": actor,
        "workspace_id": workspace_id,
        "status": status,
        "detail": detail or {},
    }
    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    _trim_audit_file()
    return entry


def _trim_audit_file() -> None:
    if not AUDIT_FILE.exists():
        return
    try:
        lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()
        if len(lines) <= MAX_AUDIT_LINES:
            return
        keep = lines[-MAX_AUDIT_LINES:]
        AUDIT_FILE.write_text("\n".join(keep) + "\n", encoding="utf-8")
    except Exception:
        pass


def load_audit_entries(limit: int = 50) -> list[dict]:
    if not AUDIT_FILE.exists():
        return []
    try:
        lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()
        entries = []
        for line in reversed(lines[-limit:]):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries
    except Exception:
        return []
