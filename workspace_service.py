"""
Workspaces & local team users (Phase 3) — file-backed, no external auth.
"""

from __future__ import annotations

import json
import secrets
import time
import uuid
from pathlib import Path
from typing import Any

DATA_DIR = Path("data")
WORKSPACES_FILE = DATA_DIR / "workspaces.json"
USERS_FILE = DATA_DIR / "users.json"
CONFIG_FILE = DATA_DIR / "platform_config.json"


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path: Path, data: Any) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def ensure_defaults() -> None:
    workspaces = _load_json(WORKSPACES_FILE, None)
    if not workspaces:
        default_ws = {
            "id": "default",
            "name": "Default Team",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        _save_json(WORKSPACES_FILE, [default_ws])

    users = _load_json(USERS_FILE, None)
    if not users:
        _save_json(
            USERS_FILE,
            [
                {
                    "id": "admin",
                    "name": "Admin",
                    "email": "admin@local",
                    "role": "admin",
                    "workspace_ids": ["default"],
                    "api_key": secrets.token_hex(16),
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
            ],
        )

    config = _load_json(CONFIG_FILE, None)
    if not config:
        _save_json(
            CONFIG_FILE,
            {
                "active_workspace_id": "default",
                "active_user_id": "admin",
            },
        )


def load_workspaces() -> list[dict]:
    ensure_defaults()
    return _load_json(WORKSPACES_FILE, [])


def load_users() -> list[dict]:
    ensure_defaults()
    return _load_json(USERS_FILE, [])


def get_active_workspace_id() -> str:
    ensure_defaults()
    config = _load_json(CONFIG_FILE, {})
    return config.get("active_workspace_id", "default")


def set_active_workspace(workspace_id: str) -> bool:
    workspaces = load_workspaces()
    if not any(w.get("id") == workspace_id for w in workspaces):
        return False
    config = _load_json(CONFIG_FILE, {})
    config["active_workspace_id"] = workspace_id
    _save_json(CONFIG_FILE, config)
    return True


def get_active_user() -> dict | None:
    ensure_defaults()
    config = _load_json(CONFIG_FILE, {})
    uid = config.get("active_user_id", "admin")
    return next((u for u in load_users() if u.get("id") == uid), None)


def set_active_user(user_id: str) -> bool:
    if not any(u.get("id") == user_id for u in load_users()):
        return False
    config = _load_json(CONFIG_FILE, {})
    config["active_user_id"] = user_id
    _save_json(CONFIG_FILE, config)
    return True


def create_workspace(name: str) -> dict:
    workspaces = load_workspaces()
    entry = {
        "id": str(uuid.uuid4())[:8],
        "name": name.strip() or "Workspace",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    workspaces.append(entry)
    _save_json(WORKSPACES_FILE, workspaces)
    return entry


def create_user(name: str, email: str, role: str = "analyst") -> dict:
    users = load_users()
    if role not in ("admin", "analyst", "viewer"):
        role = "analyst"
    entry = {
        "id": str(uuid.uuid4())[:8],
        "name": name.strip() or "User",
        "email": email.strip() or f"user-{uuid.uuid4().hex[:6]}@local",
        "role": role,
        "workspace_ids": [get_active_workspace_id()],
        "api_key": secrets.token_hex(16),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    users.append(entry)
    _save_json(USERS_FILE, users)
    return entry


def verify_api_key(api_key: str) -> dict | None:
    if not api_key:
        return None
    return next((u for u in load_users() if u.get("api_key") == api_key), None)


def delete_workspace(workspace_id: str) -> tuple[bool, str]:
    """
    Delete a workspace.
    Returns (success, message).
    """
    workspaces = load_workspaces()

    # Check if workspace exists
    workspace = next((w for w in workspaces if w.get("id") == workspace_id), None)
    if not workspace:
        return False, "Workspace not found"

    # Prevent deleting the last workspace
    if len(workspaces) <= 1:
        return False, "Cannot delete the last workspace"

    # Remove the workspace
    workspaces = [w for w in workspaces if w.get("id") != workspace_id]
    _save_json(WORKSPACES_FILE, workspaces)

    # If the deleted workspace was active, switch to another one
    active_workspace_id = get_active_workspace_id()
    if active_workspace_id == workspace_id:
        # Switch to first available workspace
        if workspaces:
            set_active_workspace(workspaces[0].get("id"))

    # Remove workspace from all users
    users = load_users()
    for user in users:
        if workspace_id in user.get("workspace_ids", []):
            user["workspace_ids"] = [w for w in user.get("workspace_ids", []) if w != workspace_id]
            # Ensure user still has at least one workspace
            if not user.get("workspace_ids"):
                user["workspace_ids"] = [workspaces[0].get("id")] if workspaces else []
    _save_json(USERS_FILE, users)

    return True, f"Workspace '{workspace.get('name')}' deleted"


def delete_user(user_id: str, deleting_user_id: str = None) -> tuple[bool, str]:
    """
    Delete a user.
    Returns (success, message).
    """
    users = load_users()

    # Check if user exists
    user_to_delete = next((u for u in users if u.get("id") == user_id), None)
    if not user_to_delete:
        return False, "User not found"

    # Prevent deleting the last admin user
    if user_to_delete.get("role") == "admin":
        admin_count = sum(1 for u in users if u.get("role") == "admin")
        if admin_count <= 1:
            return False, "Cannot delete the last admin user"

    # Prevent user from deleting themselves (optional, but good practice)
    if deleting_user_id and user_id == deleting_user_id:
        return False, "Cannot delete your own account"

    # Remove the user
    users = [u for u in users if u.get("id") != user_id]
    _save_json(USERS_FILE, users)

    # If the deleted user was active, switch to another user
    active_user = get_active_user()
    if active_user and active_user.get("id") == user_id:
        # Switch to first available user
        if users:
            set_active_user(users[0].get("id"))

    return True, f"User '{user_to_delete.get('name')}' deleted"
