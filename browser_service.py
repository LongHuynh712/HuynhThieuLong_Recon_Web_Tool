"""Puppeteer bridge — invokes browser/run.mjs via Node.js."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from pathlib import Path

BROWSER_DIR = Path(__file__).resolve().parent / "browser"
RUN_SCRIPT = BROWSER_DIR / "run.mjs"
DEFAULT_TIMEOUT = int(os.environ.get("PUPPETEER_TIMEOUT", "90"))


def _find_node():
    return os.environ.get("NODE_PATH") or shutil.which("node") or shutil.which("node.exe")


def _parse_stdout(stdout):
    text = (stdout or "").strip()
    if not text:
        return None
    # JSON is always the last line (Node may log warnings before it on stderr)
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    return json.loads(text)


def _load_screenshot_from_result(data):
    """Read PNG from temp file path returned by run.mjs (avoids huge stdout on Windows)."""
    shot_path = data.get("screenshotPath") or data.get("screenshot_path")
    if not shot_path:
        if data.get("image"):
            return data["image"]
        if data.get("screenshot") and isinstance(data["screenshot"], str):
            return data["screenshot"]
        return None

    path = Path(shot_path)
    try:
        if path.exists():
            encoded = base64.b64encode(path.read_bytes()).decode("ascii")
            return encoded
    finally:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
    return None


def _normalize_browser_result(data):
    if not isinstance(data, dict):
        return {"error": "Invalid Puppeteer response"}
    screenshot_b64 = _load_screenshot_from_result(data)
    if screenshot_b64:
        data["screenshot"] = screenshot_b64
        if "image" not in data:
            data["image"] = screenshot_b64
    return data


def puppeteer_available():
    if not _find_node() or not RUN_SCRIPT.exists():
        return False
    try:
        result = run_action("ping", "https://example.com", timeout=15)
        return result.get("status") == "ok" and "error" not in result
    except Exception:
        return False


def run_action(action, url, timeout=None):
    node = _find_node()
    if not node:
        return {"error": "Node.js not found. Install Node.js 18+ from https://nodejs.org/"}
    if not RUN_SCRIPT.exists():
        return {"error": f"Missing {RUN_SCRIPT}"}

    cmd = [node, str(RUN_SCRIPT), action, url]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout or DEFAULT_TIMEOUT,
            cwd=str(BROWSER_DIR),
            env={**os.environ, "NODE_NO_WARNINGS": "1", "PYTHONIOENCODING": "utf-8"},
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Puppeteer timed out after {timeout or DEFAULT_TIMEOUT}s"}
    except Exception as exc:
        return {"error": str(exc)}

    stdout = proc.stdout or ""
    stderr = (proc.stderr or "").strip()

    if not stdout.strip():
        return {"error": stderr or f"Puppeteer exited with code {proc.returncode} (no output)"}

    try:
        data = _parse_stdout(stdout)
    except json.JSONDecodeError:
        return {"error": stdout[:500] or stderr or "Invalid JSON from Puppeteer"}

    data = _normalize_browser_result(data)

    if proc.returncode != 0 and "error" not in data and not data.get("skipped"):
        data["error"] = stderr or f"exit code {proc.returncode}"
    return data


def browser_screenshot(url):
    return run_action("screenshot", url)


def browser_cookies(url):
    return run_action("cookies", url)


def browser_scan(url):
    """Single Puppeteer session: screenshot + cookies + tech hints."""
    return run_action("scan", url)


def format_browser_cookies_report(client_cookies):
    lines = ["\n========== BROWSER COOKIES (Puppeteer) ==========\n"]
    if not client_cookies:
        lines.append("[INFO] No browser cookies captured\n")
        return "".join(lines)

    for cookie in client_cookies:
        name = cookie.get("name", "?")
        flags = []
        if cookie.get("secure"):
            flags.append("Secure")
        if cookie.get("httpOnly"):
            flags.append("HttpOnly")
        if cookie.get("sameSite"):
            flags.append(f"SameSite={cookie['sameSite']}")
        flag_text = ", ".join(flags) if flags else "no flags"
        lines.append(f"[FOUND] {name} ({flag_text})\n")
        if cookie.get("domain"):
            lines.append(f"  domain: {cookie['domain']}\n")
        if cookie.get("expires") and cookie["expires"] > 0:
            lines.append(f"  expires: {cookie['expires']}\n")
    lines.append(f"\nTotal browser cookies: {len(client_cookies)}\n")
    return "".join(lines)


def format_screenshot_report():
    return "\n========== SCREENSHOT ==========\n[FOUND] Screenshot captured via Puppeteer\n"


def format_tech_hints_report(generators, script_sources):
    lines = ["\n========== BROWSER TECH HINTS ==========\n"]
    if generators:
        for gen in generators:
            lines.append(f"[FOUND] Generator meta: {gen}\n")
    if script_sources:
        lines.append(f"[FOUND] External scripts: {len(script_sources)}\n")
        for src in script_sources[:10]:
            lines.append(f"  - {src}\n")
    if not generators and not script_sources:
        lines.append("[INFO] No extra tech hints from browser\n")
    return "".join(lines)
