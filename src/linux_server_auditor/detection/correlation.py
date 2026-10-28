"""Incident correlator: groups findings within 10-min window, computes priority score."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timedelta

SEVERITY_WEIGHTS = {"critical": 40, "high": 20, "medium": 10, "low": 5}
CORRELATION_WINDOW_SEC = 600


def correlate_findings(findings: list[dict]) -> list[dict]:
    """Group findings within 10-min window per instance.
    
    Returns list of incident dicts: {incident_id, instance_id, status, priority_score, 
                                      first_seen, last_seen, finding_count, evidence}.
    """
    by_instance = defaultdict(list)
    for f in findings:
        by_instance[f.get("instance_id", "unknown")].append(f)
    
    incidents = []
    for instance_id, finds in by_instance.items():
        finds.sort(key=lambda x: x["timestamp"])
        
        windows = []
        for f in finds:
            ts = datetime.fromisoformat(f["timestamp"].replace("Z", "+00:00"))
            
            # Try to add to existing window
            added = False
            for w in windows:
                if (ts - w["first_seen"]).total_seconds() <= CORRELATION_WINDOW_SEC:
                    w["findings"].append(f)
                    w["last_seen"] = max(w["last_seen"], ts)
                    added = True
                    break
            
            if not added:
                windows.append({
                    "first_seen": ts,
                    "last_seen": ts,
                    "findings": [f],
                })
        
        for w in windows:
            severity_counts = defaultdict(int)
            for f in w["findings"]:
                severity_counts[f.get("severity", "low")] += 1
            
            score = sum(SEVERITY_WEIGHTS.get(s, 0) * c for s, c in severity_counts.items())
            score = min(100, score)
            
            incidents.append({
                "incident_id": str(uuid.uuid4()),
                "instance_id": instance_id,
                "status": "open",
                "priority_score": float(score),
                "first_seen": w["first_seen"].isoformat(),
                "last_seen": w["last_seen"].isoformat(),
                "finding_count": len(w["findings"]),
                "evidence": w["findings"],
                "resolution_notes": None,
            })
    
    return incidents
