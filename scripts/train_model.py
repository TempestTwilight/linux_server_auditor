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
    parser = argparse.ArgumentParser(description="Train Isolation Forest on baseline metrics")
    parser.add_argument("--csv", required=True, help="Path to baseline metrics CSV")
    parser.add_argument("--contamination", type=float, default=0.02, help="Expected anomaly fraction")
    parser.add_argument("--output", default="models/iforest_baseline.joblib", help="Output model path")
    args = parser.parse_args()
    
    df = pd.read_csv(args.csv)
    print(f"Loaded {len(df)} samples from {args.csv}")
    
    model, features = train_model(df, contamination=args.contamination)
    
    output_path = REPO_ROOT / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    joblib.dump(model, output_path)
    meta_path = output_path.with_suffix(".meta.joblib")
    joblib.dump({
        "features": features,
        "model_version": "iforest_v1",
        "contamination": args.contamination,
    }, meta_path)
    
    print(f"Model saved to {output_path}")
    print(f"Features: {features}")


if __name__ == "__main__":
    main()
