"""Incident correlator: groups findings within 10-min window, computes priority score."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any, TypedDict

SEVERITY_WEIGHTS = {"critical": 40, "high": 20, "medium": 10, "low": 5}
CORRELATION_WINDOW_SEC = 600


class _CorrelationWindow(TypedDict):
    first_seen: datetime
    last_seen: datetime
    findings: list[dict[str, Any]]


def correlate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group findings within 10-min window per instance.

    Returns list of incident dicts: {incident_id, instance_id, status, priority_score,
                                      first_seen, last_seen, finding_count, evidence}.
    """
    by_instance: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        by_instance[str(f.get("instance_id", "unknown"))].append(f)

    incidents: list[dict[str, Any]] = []
    for instance_id, finds in by_instance.items():
        finds.sort(key=lambda x: str(x["timestamp"]))

        windows: list[_CorrelationWindow] = []
        for f in finds:
            ts = datetime.fromisoformat(str(f["timestamp"]))

            # Try to add to existing window
            added = False
            for w in windows:
                if (ts - w["first_seen"]).total_seconds() <= CORRELATION_WINDOW_SEC:
                    w["findings"].append(f)
                    w["last_seen"] = max(w["last_seen"], ts)
                    added = True
                    break

            if not added:
                windows.append(
                    {
                        "first_seen": ts,
                        "last_seen": ts,
                        "findings": [f],
                    }
                )

        for w in windows:
            severity_counts: dict[str, int] = defaultdict(int)
            for f in w["findings"]:
                severity_counts[str(f.get("severity", "low"))] += 1

            score = sum(SEVERITY_WEIGHTS.get(s, 0) * c for s, c in severity_counts.items())
            score = min(100, score)

            incidents.append(
                {
                    "incident_id": str(uuid.uuid4()),
                    "instance_id": instance_id,
                    "status": "open",
                    "priority_score": float(score),
                    "first_seen": w["first_seen"].isoformat(),
                    "last_seen": w["last_seen"].isoformat(),
                    "finding_count": len(w["findings"]),
                    "evidence": w["findings"],
                    "resolution_notes": None,
                }
            )

    return incidents
