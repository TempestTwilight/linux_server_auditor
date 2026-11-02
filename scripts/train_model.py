#!/usr/bin/env python3
"""Train Isolation Forest on baseline data, save to models/."""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd

from linux_server_auditor.detection.isolation_forest import train_model

REPO_ROOT = Path(__file__).parent.parent


def main():
    parser = argparse.ArgumentParser(
        description="Train Isolation Forest on baseline metrics (from CSV or SQLite)"
    )
    parser.add_argument("--csv", default=None, help="Path to baseline metrics CSV")
    parser.add_argument(
        "--from-db",
        action="store_true",
        help="Train model directly from metric_samples table in SQLite",
    )
    parser.add_argument(
        "--db",
        default="data/telemetry.db",
        help="Path to SQLite database if --from-db is used",
    )
    parser.add_argument(
        "--instance-id",
        default=None,
        help="Filter database samples by instance_id (e.g. baseline host)",
    )
    parser.add_argument(
        "--contamination", type=float, default=0.02, help="Expected anomaly fraction"
    )
    parser.add_argument(
        "--output", default="models/iforest_baseline.joblib", help="Output model path"
    )
    args = parser.parse_args()

    if args.from_db:
        import sqlite3

        db_path = REPO_ROOT / args.db
        if not db_path.exists():
            print(f"Error: DB file {db_path} does not exist.")
            return
        query = "SELECT * FROM metric_samples"
        params: list = []
        if args.instance_id:
            query += " WHERE instance_id = ?"
            params.append(args.instance_id)
        with sqlite3.connect(db_path) as conn:
            df = pd.read_sql_query(query, conn, params=params)
        print(f"Loaded {len(df)} samples from {db_path} (instance: {args.instance_id or 'all'})")
    elif args.csv:
        csv_path = REPO_ROOT / args.csv if not Path(args.csv).is_absolute() else Path(args.csv)
        df = pd.read_csv(csv_path)
        print(f"Loaded {len(df)} samples from {csv_path}")
    else:
        print("Error: Specify either --csv <path> or --from-db")
        return

    model, features = train_model(df, contamination=args.contamination)

    output_path = REPO_ROOT / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, output_path)
    meta_path = output_path.with_suffix(".meta.joblib")
    joblib.dump(
        {
            "features": features,
            "model_version": "iforest_v1",
            "contamination": args.contamination,
        },
        meta_path,
    )

    print(f"Model saved to {output_path}")
    print(f"Features: {features}")


if __name__ == "__main__":
    main()
