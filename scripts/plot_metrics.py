#!/usr/bin/env python3
"""plot_metrics.py — reads JSONL batches from data/raw/ and plots system metrics.

Usage:
    uv run scripts/plot_metrics.py                  # reads all batches in data/raw/
    uv run scripts/plot_metrics.py data/raw/batch_*.jsonl  # explicit files
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px

_REPO_ROOT = Path(__file__).parent.parent
_RAW_DIR = _REPO_ROOT / "data" / "raw"

METRICS = [
    "cpu_percent",
    "memory_used_percent",
    "disk_used_percent",
    "network_rx_bytes_per_sec",
    "network_tx_bytes_per_sec",
    "load_1m_per_cpu",
    "process_count",
]


def load_jsonl(*paths: Path) -> pd.DataFrame:
    rows = []
    for p in paths:
        with p.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("type") != "system_metrics":
                    continue
                row = {"timestamp": rec["timestamp"]}
                row.update(rec.get("metrics", {}))
                rows.append(row)
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df.sort_values("timestamp")


def main() -> None:
    files = (
        [Path(p) for p in sys.argv[1:]] if sys.argv[1:] else sorted(_RAW_DIR.glob("batch_*.jsonl"))
    )
    if not files:
        print(f"No JSONL files found in {_RAW_DIR}. Run: linux-server-auditor collect-once")
        sys.exit(1)

    df = load_jsonl(*files)
    if df.empty:
        print("No system_metrics records found.")
        sys.exit(1)

    print(f"Loaded {len(df)} system_metrics records from {len(files)} file(s).")
    print(df[["timestamp", *METRICS]].tail())

    for metric in METRICS:
        if metric not in df.columns:
            continue
        fig = px.line(df, x="timestamp", y=metric, title=metric)
        fig.show()


if __name__ == "__main__":
    main()
