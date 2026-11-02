#!/usr/bin/env python3
"""Run evaluation: compute precision, recall, F1, latency per detector against ground truth."""

from __future__ import annotations

import argparse
from pathlib import Path

from linux_server_auditor.config import settings
from linux_server_auditor.detection.evaluation import run_full_evaluation

REPO_ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate detection performance against ground truth"
    )
    parser.add_argument(
        "--db",
        default=settings.get("monitor", {}).get("db_path", "data/telemetry.db"),
        help="SQLite database path",
    )
    parser.add_argument(
        "--gt",
        default="data/ground_truth.csv",
        help="Ground truth CSV path",
    )
    parser.add_argument(
        "--output",
        default="data/evaluation_summary.json",
        help="Output evaluation summary JSON path",
    )
    args = parser.parse_args()

    db_path = REPO_ROOT / args.db
    gt_path = REPO_ROOT / args.gt
    out_path = REPO_ROOT / args.output

    if not db_path.exists():
        print(f"[!] Database not found: {db_path}")
        print(
            "    Tip: run 'python scripts/inject_scenario.py --all' or 'python scripts/inject_scenario.py --demo' first."
        )
        return

    if not gt_path.exists():
        print(f"[!] Ground truth CSV not found: {gt_path}")
        return

    summary = run_full_evaluation(db_path, gt_path, out_path)

    print("=" * 70)
    print("  LINUX SERVER AUDITOR — EVALUATION SUMMARY (TARGET B)")
    print("=" * 70)
    print(f"Timestamp:       {summary['timestamp_utc']}")
    print(
        f"Scenarios Total: {summary['total_scenarios']}  |  Passed: {summary['passed_scenarios']}  |  Failed: {summary['failed_scenarios']}"
    )
    print(
        f"Overall Metrics: Precision = {summary['overall']['precision']:.2f}  |  Recall = {summary['overall']['recall']:.2f}  |  F1 = {summary['overall']['f1']:.2f}"
    )
    print(
        f"Latency:         Median = {summary['latency']['median_seconds']}s  |  P95 = {summary['latency']['p95_seconds']}s"
    )
    print("-" * 70)
    print(
        f"{'Detector / Rule':<18} {'TP':<5} {'FP':<5} {'FN':<5} {'Precision':<10} {'Recall':<8} {'F1':<6}"
    )
    print("-" * 70)

    for det_id, metrics in summary["per_detector"].items():
        print(
            f"{det_id:<18} "
            f"{metrics['tp']:<5} "
            f"{metrics['fp']:<5} "
            f"{metrics['fn']:<5} "
            f"{metrics['precision']:<10.2f} "
            f"{metrics['recall']:<8.2f} "
            f"{metrics['f1']:<6.2f}"
        )

    print("-" * 70)
    print("Scenario Results:")
    for s in summary["scenario_results"]:
        status_tag = "[PASS]" if s["status"] == "PASS" else "[FAIL]"
        lat = f"{s['latency_seconds']}s" if s["latency_seconds"] is not None else "N/A"
        print(
            f"  {status_tag:<7} {s['scenario']:<16} Expected: {s['expected']:<8} Latency: {lat:<6} ({s['details']})"
        )

    print("-" * 70)
    print(f"[+] Full evaluation summary written to: {out_path}")
    print(f"[*] Note: {summary['caveat']}")
    print("=" * 70)


if __name__ == "__main__":
    main()
