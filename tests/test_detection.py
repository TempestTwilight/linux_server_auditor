"""Tests for statistical and isolation forest detectors."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pandas as pd
import pytest

from linux_server_auditor.detection.isolation_forest import detect_iforest, train_model
from linux_server_auditor.detection.preprocessing import METRIC_COLUMNS, prepare_metrics
from linux_server_auditor.detection.statistical import detect_mad


@pytest.fixture
def sample_metrics():
    """Normal metrics + one spike."""
    data = {
        "instance_id": ["i-123"] * 11,
        "timestamp": pd.date_range("2026-01-01", periods=11, freq="30s"),
        "cpu_percent": [10.0] * 10 + [95.0],
        "memory_used_percent": [50.0] * 11,
        "swap_used_percent": [5.0] * 11,
        "disk_used_percent": [40.0] * 11,
        "load_1m_per_cpu": [1.0] * 11,
        "network_rx_bytes_per_sec": [1000.0] * 11,
        "network_tx_bytes_per_sec": [500.0] * 11,
        "process_count": [150.0] * 11,
    }
    return pd.DataFrame(data)


def test_prepare_metrics(sample_metrics):
    df = prepare_metrics(sample_metrics)
    assert not df.empty
    assert "timestamp" in df.columns
    assert str(df["timestamp"].dtype).startswith("datetime64")


def test_detect_mad(sample_metrics):
    anomalies = detect_mad(sample_metrics, window_hours=0.01)
    assert len(anomalies) >= 1
    cpu_anoms = [a for a in anomalies if a["feature"] == "cpu_percent"]
    assert len(cpu_anoms) >= 1
    assert cpu_anoms[0]["is_anomaly"]
    assert cpu_anoms[0]["score"] > cpu_anoms[0]["threshold"]


def test_train_and_detect_iforest(tmp_path, sample_metrics):
    model, features = train_model(sample_metrics)
    assert model is not None
    assert "cpu_percent" in features
    
    import joblib
    model_path = tmp_path / "test.joblib"
    meta_path = tmp_path / "test.meta.joblib"
    joblib.dump(model, model_path)
    joblib.dump({"features": features, "model_version": "test_v1"}, meta_path)
    
    anomalies = detect_iforest(sample_metrics, model_path)
    assert isinstance(anomalies, list)
    if anomalies:
        assert "detector" in anomalies[0]
        assert anomalies[0]["detector"] == "iforest"
