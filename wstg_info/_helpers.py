"""Shared helpers for WSTG INFO supplement modules."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from scanner import get_registered_domain, safe_request


def normalize_target_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        raise ValueError("URL is required")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def hostname_from_url(url: str) -> str:
    parsed = urlparse(normalize_target_url(url))
    host = parsed.hostname or ""
    return host.lower().lstrip(".")


def registered_domain_from_url(url: str) -> str:
    host = hostname_from_url(url)
    return get_registered_domain(host) or host


def fetch_page(url: str, method: str = "GET"):
    return safe_request(normalize_target_url(url), method=method)


SENSITIVE_PATH_HINTS = (
    "admin", "backup", "config", ".git", ".env", "staging", "dev", "test",
    "phpmyadmin", "wp-admin", "secret", "private", "internal", "api",
)
