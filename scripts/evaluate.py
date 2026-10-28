#!/usr/bin/env python3
"""Run evaluation: compute precision, recall, F1, latency per detector."""

from __future__ import annotations

import argparse
import sqlite3
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).parent.parent


def load_ground_truth(csv_path: Path) -> list[dict]:
    """Load ground_truth.csv."""
    if not csv_path.exists():
        return []
    df = pd.read_csv(csv_path)
    return df.to_dict("records")


def load_anomaly_scores(db_path: Path) -> list[dict]:
    """Load anomaly_scores from SQLite."""
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM anomaly_scores WHERE is_anomaly = 1", conn)
    conn.close()
    return df.to_dict("records")


def load_incidents(db_path: Path) -> list[dict]:
    """Load incidents from SQLite."""
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM incidents", conn)
    conn.close()
    return df.to_dict("records")


def evaluate(ground_truth: list[dict], detections: list[dict]) -> dict:
    """Compute TP, FP, FN, precision, recall, F1."""
    # ponytail: simple overlap match within ±5min window
    matched_gt = set()
    matched_det = set()
    
    for i, gt in enumerate(ground_truth):
        gt_start = datetime.fromisoformat(gt["start_time"])
        gt_end = datetime.fromisoformat(gt["end_time"])
        expected = gt["expected_rule_or_detector"]
        
        for j, det in enumerate(detections):
            if j in matched_det:
                continue
            
            det_time = datetime.fromisoformat(det.get("timestamp", "1970-01-01T00:00:00Z").replace("Z", "+00:00"))
            det_type = det.get("detector") or det.get("rule_id", "unknown")
            
            if det_type == expected and gt_start <= det_time <= gt_end:
                matched_gt.add(i)
                matched_det.add(j)
                break
    
    tp = len(matched_gt)
    fp = len(detections) - len(matched_det)
    fn = len(ground_truth) - len(matched_gt)
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate detection performance")
    parser.add_argument("--db", default="data/auditor.db", help="SQLite database path")
    parser.add_argument("--gt", default="data/ground_truth.csv", help="Ground truth CSV")
    args = parser.parse_args()
    
    db_path = REPO_ROOT / args.db
    gt_path = REPO_ROOT / args.gt
    
    ground_truth = load_ground_truth(gt_path)
    print(f"Loaded {len(ground_truth)} ground truth scenarios")
    
    if not db_path.exists():
        print(f"Database not found: {db_path}")
        return
    
    anomalies = load_anomaly_scores(db_path)
    incidents = load_incidents(db_path)
    print(f"Loaded {len(anomalies)} anomaly scores, {len(incidents)} incidents")
    
    # Evaluate per detector
    by_detector = defaultdict(list)
    for a in anomalies:
        by_detector[a["detector"]].append(a)
    
    print("\nPer-detector evaluation:")
    for det, dets in by_detector.items():
        result = evaluate(ground_truth, dets)
        print(f"{det}: TP={result['tp']} FP={result['fp']} FN={result['fn']} "
              f"P={result['precision']:.2f} R={result['recall']:.2f} F1={result['f1']:.2f}")
    
    # Evaluate incidents
    if incidents:
        # Flatten incident evidence into detections
        incident_detections = []
        for inc in incidents:
            # ponytail: simplified, assumes evidence is list of findings
            incident_detections.append({
                "timestamp": inc["first_seen"],
                "rule_id": "incident",
            })
        result = evaluate(ground_truth, incident_detections)
        print(f"\nIncidents: TP={result['tp']} FP={result['fp']} FN={result['fn']} "
              f"P={result['precision']:.2f} R={result['recall']:.2f} F1={result['f1']:.2f}")


if __name__ == "__main__":
    main()
