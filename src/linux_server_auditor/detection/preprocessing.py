"""Prepare DataFrames from SQLite for detectors."""

from __future__ import annotations

import pandas as pd

METRIC_COLUMNS = [
    "cpu_percent",
    "memory_used_percent",
    "swap_used_percent",
    "disk_used_percent",
    "load_1m_per_cpu",
    "network_rx_bytes_per_sec",
    "network_tx_bytes_per_sec",
    "process_count",
]


def prepare_metrics(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure timestamp is datetime and drop nulls."""
    df = df.copy()
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.dropna(subset=METRIC_COLUMNS)
