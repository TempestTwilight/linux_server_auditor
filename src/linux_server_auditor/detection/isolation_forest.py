"""Isolation Forest detector wrapper."""

from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from linux_server_auditor.detection.preprocessing import METRIC_COLUMNS


def train_model(df: pd.DataFrame, contamination: float = 0.02) -> tuple[IsolationForest, list[str]]:
    """Train IsolationForest on metric columns."""
    features = [c for c in METRIC_COLUMNS if c in df.columns]
    X = df[features].dropna()
    
    model = IsolationForest(
        n_estimators=100,
        max_samples="auto",
        random_state=42,
        contamination=contamination,
    )
    model.fit(X)
    return model, features


def detect_iforest(df: pd.DataFrame, model_path: Path | str) -> list[dict]:
    """Score with pre-trained IsolationForest.
    
    Returns list of {instance_id, timestamp, detector, feature, value, score, threshold, is_anomaly}.
    decision_function: negative → anomaly, positive → normal. Lower = more anomalous.
    """
    model_path = Path(model_path)
    model = joblib.load(model_path)
    meta_path = model_path.with_suffix(".meta.joblib")
    meta = joblib.load(meta_path) if meta_path.exists() else {}
    features = meta.get("features", METRIC_COLUMNS)
    
    X = df[[c for c in features if c in df.columns]].dropna()
    if X.empty:
        return []
    
    scores = model.decision_function(X)
    predictions = model.predict(X)  # -1 = anomaly, 1 = normal
    
    results = []
    for i, idx in enumerate(X.index):
        is_anom = predictions[i] == -1
        results.append({
            "instance_id": df.loc[idx, "instance_id"] if "instance_id" in df.columns else "unknown",
            "timestamp": df.loc[idx, "timestamp"] if "timestamp" in df.columns else None,
            "detector": "iforest",
            "feature": "multivariate",
            "value": None,
            "score": float(-scores[i]),  # invert so high = anomalous
            "threshold": 0.0,  # predict() already applied threshold
            "is_anomaly": is_anom,
            "model_version": meta.get("model_version", "iforest_v1"),
        })
    
    return results
