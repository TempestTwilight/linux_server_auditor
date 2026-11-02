"""Evaluation module — computes precision, recall, F1, latency, and scenario outcomes."""

from __future__ import annotations

import csv
import json
import sqlite3
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from linux_server_auditor.config import settings

_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB_PATH = _REPO_ROOT / settings["monitor"]["db_path"]
DEFAULT_GT_PATH = _REPO_ROOT / "data" / "ground_truth.csv"
DEFAULT_SUMMARY_PATH = _REPO_ROOT / "data" / "evaluation_summary.json"


def load_ground_truth(csv_path: Path | str = DEFAULT_GT_PATH) -> list[dict[str, Any]]:
    """Load ground_truth.csv as list of dicts."""
    p = Path(csv_path)
    if not p.exists():
        return []
    with p.open(newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def load_detections_from_db(db_path: Path | str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """Load all anomalies from anomaly_scores where is_anomaly = 1."""
    p = Path(db_path)
    if not p.exists():
        return []

    with sqlite3.connect(p) as conn:
        conn.row_factory = sqlite3.Row
        # Check if table exists
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='anomaly_scores'"
        ).fetchone()
        if not exists:
            return []

        rows = conn.execute(
            "SELECT * FROM anomaly_scores WHERE is_anomaly = 1 ORDER BY timestamp ASC"
        ).fetchall()
        return [dict(r) for r in rows]


def evaluate_scenarios(
    ground_truth: list[dict[str, Any]],
    detections: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute per-scenario match, detector-level metrics, and latency.

    Returns structured evaluation summary dict.
    """
    scenario_results: list[dict[str, Any]] = []
    detector_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    latencies: list[float] = []

    # Map detections to timestamp objects
    parsed_dets: list[dict[str, Any]] = []
    for d in detections:
        ts_str = str(d.get("timestamp", ""))
        try:
            ts = datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            continue
        det_id = str(d.get("feature") if d.get("detector") == "rule" else d.get("detector"))
        parsed_dets.append({**d, "_dt": ts, "_id": det_id})

    matched_det_indices: set[int] = set()

    # Evaluate each ground truth scenario
    for gt in ground_truth:
        scen_id = gt.get("scenario", "unknown")
        expected = gt.get("expected_rule_or_detector", "none")
        start_ts = datetime.fromisoformat(gt["start_time"])
        end_ts = datetime.fromisoformat(gt["end_time"])

        # Check for matching detections in window (with small grace period)
        found_match = False
        matching_dets: list[dict[str, Any]] = []
        first_det_time: datetime | None = None

        if expected == "none":
            # Baseline scenario: check if any unexpected alert fired
            for j, det in enumerate(parsed_dets):
                if start_ts <= det["_dt"] <= end_ts:
                    detector_stats[det["_id"]]["fp"] += 1
                    matched_det_indices.add(j)
                    matching_dets.append(det)

            passed = len(matching_dets) == 0
            scenario_results.append(
                {
                    "scenario": scen_id,
                    "description": gt.get("description", ""),
                    "expected": expected,
                    "observed": [d["_id"] for d in matching_dets] if matching_dets else ["none"],
                    "status": "PASS" if passed else "FAIL",
                    "latency_seconds": None,
                    "details": "No false alarms triggered during baseline window"
                    if passed
                    else f"Unexpected detections: {len(matching_dets)}",
                }
            )
            continue

        for j, det in enumerate(parsed_dets):
            if det["_id"] == expected and (
                start_ts - pd.Timedelta(seconds=10)
                <= det["_dt"]
                <= end_ts + pd.Timedelta(seconds=30)
            ):
                found_match = True
                matched_det_indices.add(j)
                matching_dets.append(det)
                if first_det_time is None or det["_dt"] < first_det_time:
                    first_det_time = det["_dt"]

        if found_match:
            detector_stats[expected]["tp"] += 1
            assert first_det_time is not None
            latency = max(0.0, (first_det_time - start_ts).total_seconds())
            latencies.append(latency)
            scenario_results.append(
                {
                    "scenario": scen_id,
                    "description": gt.get("description", ""),
                    "expected": expected,
                    "observed": [expected],
                    "status": "PASS",
                    "latency_seconds": round(latency, 1),
                    "details": f"Detected with latency {latency:.1f}s",
                }
            )
        else:
            detector_stats[expected]["fn"] += 1
            scenario_results.append(
                {
                    "scenario": scen_id,
                    "description": gt.get("description", ""),
                    "expected": expected,
                    "observed": ["none"],
                    "status": "FAIL",
                    "latency_seconds": None,
                    "details": "Expected detector did not trigger in time window",
                }
            )

    # Unmatched detections outside any scenario window are false positives
    for j, det in enumerate(parsed_dets):
        if j not in matched_det_indices:
            detector_stats[det["_id"]]["fp"] += 1

    # Compute precision, recall, F1 per detector
    detector_metrics: dict[str, dict[str, Any]] = {}
    total_tp = 0
    total_fp = 0
    total_fn = 0

    for det_id, counts in detector_stats.items():
        tp = counts["tp"]
        fp = counts["fp"]
        fn = counts["fn"]
        total_tp += tp
        total_fp += fp
        total_fn += fn

        p = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fn == 0 else 0.0)
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * p * r) / (p + r) if (p + r) > 0 else 0.0

        detector_metrics[det_id] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(p, 3),
            "recall": round(r, 3),
            "f1": round(f1, 3),
        }

    overall_p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    overall_r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    overall_f1 = (
        (2 * overall_p * overall_r) / (overall_p + overall_r)
        if (overall_p + overall_r) > 0
        else 0.0
    )

    median_lat = float(np.median(latencies)) if latencies else 0.0
    p95_lat = float(np.percentile(latencies, 95)) if latencies else 0.0

    passed_count = sum(1 for s in scenario_results if s["status"] == "PASS")

    return {
        "timestamp_utc": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "total_scenarios": len(ground_truth),
        "passed_scenarios": passed_count,
        "failed_scenarios": len(ground_truth) - passed_count,
        "overall": {
            "tp": total_tp,
            "fp": total_fp,
            "fn": total_fn,
            "precision": round(overall_p, 3),
            "recall": round(overall_r, 3),
            "f1": round(overall_f1, 3),
        },
        "latency": {
            "median_seconds": round(median_lat, 1),
            "p95_seconds": round(p95_lat, 1),
            "samples": len(latencies),
        },
        "per_detector": detector_metrics,
        "scenario_results": scenario_results,
        "caveat": "Results are derived from repeatable synthetic test fixtures and controlled scenarios. They validate code and detection rule behavior rather than real-world attack protection.",
    }


def run_full_evaluation(
    db_path: Path | str = DEFAULT_DB_PATH,
    gt_path: Path | str = DEFAULT_GT_PATH,
    output_path: Path | str = DEFAULT_SUMMARY_PATH,
) -> dict[str, Any]:
    """Execute evaluation and write summary JSON."""
    gt = load_ground_truth(gt_path)
    dets = load_detections_from_db(db_path)

    summary = evaluate_scenarios(gt, dets)

    out_p = Path(output_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    with out_p.open("w") as f:
        json.dump(summary, f, indent=2)

    return summary
