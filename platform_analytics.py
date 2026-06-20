"""
Trend analytics 30/90 day (Phase 4).
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Any


def _parse_ts(record: dict) -> float | None:
    ts = record.get("ts")
    if ts:
        return float(ts)
    raw = record.get("timestamp", "")
    try:
        return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").timestamp()
    except Exception:
        return None


def trend_analytics(history: list[dict], days: int = 30) -> dict[str, Any]:
    days = max(1, min(365, int(days)))
    cutoff = time.time() - days * 86400
    points = []
    by_host: dict[str, list] = {}

    for record in history:
        t = _parse_ts(record)
        if t is None or t < cutoff:
            continue
        score = int(record.get("score", 0) or 0)
        host = (record.get("url") or "")[:80]
        label = record.get("timestamp", "")[:10]
        points.append(
            {
                "id": record.get("id"),
                "timestamp": record.get("timestamp"),
                "label": label,
                "score": score,
                "url": host,
            }
        )
        key = host.split("/")[2] if "://" in host else host
        by_host.setdefault(key, []).append(score)

    points.sort(key=lambda p: p.get("timestamp", ""))

    scores = [p["score"] for p in points]
    avg = round(sum(scores) / len(scores), 1) if scores else 0
    trend_dir = "stable"
    if len(scores) >= 2:
        delta = scores[-1] - scores[0]
        if delta > 5:
            trend_dir = "improving"
        elif delta < -5:
            trend_dir = "declining"

    host_stats = []
    for host, vals in by_host.items():
        if not host:
            continue
        host_stats.append(
            {
                "host": host[:40],
                "scans": len(vals),
                "avg_score": round(sum(vals) / len(vals), 1),
                "min": min(vals),
                "max": max(vals),
            }
        )
    host_stats.sort(key=lambda x: -x["scans"])

    return {
        "days": days,
        "scan_count": len(points),
        "average_score": avg,
        "trend_direction": trend_dir,
        "points": points,
        "host_stats": host_stats[:10],
        "distribution": _score_buckets(scores),
    }


def _score_buckets(scores: list[int]) -> dict[str, int]:
    buckets = {"0-49": 0, "50-69": 0, "70-84": 0, "85-100": 0}
    for s in scores:
        if s < 50:
            buckets["0-49"] += 1
        elif s < 70:
            buckets["50-69"] += 1
        elif s < 85:
            buckets["70-84"] += 1
        else:
            buckets["85-100"] += 1
    return buckets
