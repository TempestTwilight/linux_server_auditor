#!/usr/bin/env python3
"""Inject test scenarios (CPU spike, memory pressure, SSH brute-force, new port, service failure, file change).

Supports injecting into local SQLite database for Target B evaluation and demonstrations.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from linux_server_auditor.config import settings
from linux_server_auditor.scenarios import SCENARIO_CATALOG, populate_database
from linux_server_auditor.storage.database import Database

REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inject controlled test scenarios for Target B evaluation"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Generate full 2.5-hour baseline and all controlled anomaly scenarios into SQLite database",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Alias for --demo: inject complete suite of controlled scenarios",
    )
    parser.add_argument(
        "--db",
        default=settings.get("monitor", {}).get("db_path", "data/telemetry.db"),
        help="Path to target SQLite database",
    )
    parser.add_argument(
        "--host",
        default="demo-ec2-host",
        help="Monitored instance/host ID for injected records",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available controlled scenarios",
    )
    args = parser.parse_args()

    if args.list:
        print("Available Controlled Scenarios:")
        for s in SCENARIO_CATALOG:
            print(
                f"  [{s['id']}] {s['name']} (Severity: {s['severity']}, Expected: {s['expected_rule_or_detector']})"
            )
            print(f"      {s['description']}")
        return

    db_path = REPO_ROOT / args.db
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = Database(db_path)

    print(f"[*] Injecting controlled test scenarios into {db_path}...")
    summary = populate_database(db, instance_id=args.host, write_ground_truth=True)

    print("[+] Scenarios injected successfully!")
    print(f"    - System metric samples: {summary['metrics_inserted']}")
    print(f"    - Security event records: {summary['security_events_inserted']}")
    print(f"    - Ground truth scenarios: {summary['scenarios_generated']}")
    print(f"    - Metric anomalies detected: {summary['detection_results']['metric_anomalies']}")
    print(f"    - Security rule findings: {summary['detection_results']['security_findings']}")
    print(
        f"    - Correlated incidents: {summary['detection_results']['total_correlated_incidents']}"
    )
    print("[+] Ground truth recorded to data/ground_truth.csv")
    print("[+] Ready to evaluate: run 'python scripts/evaluate.py'")


if __name__ == "__main__":
    main()
