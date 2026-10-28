"""Robust MAD (Median Absolute Deviation) detector."""

from __future__ import annotations

import pandas as pd

from linux_server_auditor.config import thresholds
from linux_server_auditor.detection.preprocessing import METRIC_COLUMNS

MAD_SCALE = 1.4826  # for normal distribution
# ponytail: global MAD over full df; per-window upgrade when streaming large history needed


def detect_mad(df: pd.DataFrame, window_hours: float = 1.0) -> list[dict]:
    """Flag anomalies if |value - median| / MAD > threshold.

    Uses whole-df MAD as baseline (robust for short batches).
    Returns list of {instance_id, timestamp, detector, feature, value, score, threshold, is_anomaly}.
    """
    results = []

    for col in METRIC_COLUMNS:
        if col not in df.columns:
            continue

        series = df[col].dropna()
        if len(series) < 2:
            continue

        median = series.median()
        mad = (series - median).abs().median() * MAD_SCALE

        if mad == 0:
            # All values identical except outliers — fall back to mean absolute deviation
            mad = (series - median).abs().mean()
            if mad == 0:
                continue

        score = (series - median).abs() / mad

        thresh = thresholds.get(col, 6.0)
        for idx in score[score > thresh].index:
            results.append({
                "instance_id": df.loc[idx, "instance_id"] if "instance_id" in df.columns else "unknown",
                "timestamp": df.loc[idx, "timestamp"] if "timestamp" in df.columns else None,
                "detector": "mad",
                "feature": col,
                "value": float(df.loc[idx, col]),
                "score": float(score.loc[idx]),
                "threshold": thresh,
                "is_anomaly": True,
                "model_version": "mad_v1",
            })

    return results
