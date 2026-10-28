"""Process summary metrics — top processes by CPU and memory."""

from __future__ import annotations

from typing import Any

import psutil

_FIELDS = ["pid", "name", "username", "cpu_percent", "memory_percent"]


def collect() -> dict[str, Any]:
    """Return process_metrics record with count and top-10 by CPU."""
    procs: list[dict[str, Any]] = []
    for p in psutil.process_iter(_FIELDS):
        try:
            info = p.info  # type: ignore[attr-defined]
            procs.append(
                {
                    "pid": info["pid"],
                    "name": info["name"],
                    "user": info["username"],
                    "cpu_pct": round(info["cpu_percent"] or 0.0, 2),
                    "mem_pct": round(info["memory_percent"] or 0.0, 3),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    top10 = sorted(procs, key=lambda p: p["cpu_pct"], reverse=True)[:10]
    return {
        "type": "process_metrics",
        "metrics": {
            "process_count": len(procs),
            "top_processes": top10,
        },
    }
