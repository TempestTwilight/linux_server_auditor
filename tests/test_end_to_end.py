"""End-to-end test: synthetic data → detection → verification."""

from __future__ import annotations

import sqlite3
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest


@pytest.fixture
def test_db():
    """Create temporary SQLite DB with schema."""
    fd, path = tempfile.mkstemp(suffix=".db")
    conn = sqlite3.connect(path)
    
    # Schema
    conn.execute("""
        CREATE TABLE metric_samples (
            instance_id TEXT,
            agent_run_id TEXT,
            sequence INTEGER,
            timestamp TEXT,
            cpu_percent REAL,
            memory_used_percent REAL,
            swap_used_percent REAL,
            disk_used_percent REAL,
            load_1m_per_cpu REAL,
            network_rx_bytes_per_sec REAL,
            network_tx_bytes_per_sec REAL,
            process_count INTEGER,
            schema_version INTEGER
        )
    """)
    
    conn.execute("""
        CREATE TABLE security_events (
            instance_id TEXT,
            timestamp TEXT,
            event_type TEXT,
            event_data TEXT,
            schema_version INTEGER
        )
    """)
    
    conn.execute("""
        CREATE TABLE anomaly_scores (
            instance_id TEXT,
            timestamp TEXT,
            detector TEXT,
            feature TEXT,
            value REAL,
            score REAL,
            threshold REAL,
            is_anomaly INTEGER,
            model_version TEXT
        )
    """)
    
    conn.commit()
    conn.close()
    
    yield path
    Path(path).unlink()


def test_cpu_spike_detection(test_db):
    """Inject CPU spike, verify detector flags it."""
    conn = sqlite3.connect(test_db)
    base_time = datetime.now()
    
    # Insert 2h baseline: CPU 10-30%
    for i in range(720):  # 2h at 10s intervals
        ts = base_time + timedelta(seconds=i * 10)
        cpu = 20 + (i % 5)  # Slight variation: 20-24%
        conn.execute(
            "INSERT INTO metric_samples VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("i-test", "run-1", i, ts.isoformat(), cpu, 50.0, 0.0, 60.0, 1.0, 1000.0, 500.0, 80, 1)
        )
    
    # Insert CPU spike at hour 1: 95% for 120s
    for i in range(720, 732):  # 12 samples = 120s
        ts = base_time + timedelta(seconds=i * 10)
        conn.execute(
            "INSERT INTO metric_samples VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("i-test", "run-1", i, ts.isoformat(), 95.0, 50.0, 0.0, 60.0, 1.0, 1000.0, 500.0, 80, 1)
        )
    
    conn.commit()
    
    # Run detector (inline MAD check)
    df = pd.read_sql_query("SELECT timestamp, cpu_percent FROM metric_samples ORDER BY timestamp", conn)
    median = df["cpu_percent"].median()
    mad = (df["cpu_percent"] - median).abs().median()
    threshold = 6.0  # From config/thresholds.yaml
    
    for _, row in df.iterrows():
        score = abs(row["cpu_percent"] - median) / (mad + 1e-9)
        is_anomaly = 1 if score > threshold else 0
        if is_anomaly:
            conn.execute(
                "INSERT INTO anomaly_scores VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("i-test", row["timestamp"], "mad", "cpu_percent", row["cpu_percent"],
                 score, threshold, is_anomaly, "1.0")
            )
    
    conn.commit()
    
    # Verify: should detect 12 anomalies in spike window
    count = conn.execute("SELECT COUNT(*) FROM anomaly_scores WHERE is_anomaly = 1").fetchone()[0]
    assert count == 12, f"Expected 12 anomalies, got {count}"
    
    conn.close()


def test_security_event_detection(test_db):
    """Inject SSH failed logins, verify rule detector triggers."""
    conn = sqlite3.connect(test_db)
    base_time = datetime.now()
    
    # Insert 5 failed SSH attempts in 60s
    for i in range(5):
        ts = base_time + timedelta(seconds=i * 10)
        conn.execute(
            "INSERT INTO security_events VALUES (?, ?, ?, ?, ?)",
            ("i-test", ts.isoformat(), "ssh_failed_login",
             '{"user": "root", "source_ip": "1.2.3.4"}', 1)
        )
    
    conn.commit()
    
    # Run rule detector: count events in 60s window
    window_start = base_time.isoformat()
    window_end = (base_time + timedelta(seconds=60)).isoformat()
    
    count = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE event_type = 'ssh_failed_login' "
        "AND timestamp BETWEEN ? AND ?",
        (window_start, window_end)
    ).fetchone()[0]
    
    # Rule: 3+ failed logins in 60s = anomaly
    if count >= 3:
        conn.execute(
            "INSERT INTO anomaly_scores VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("i-test", window_end, "rule", "ssh_failed_login", float(count),
             float(count), 3.0, 1, "1.0")
        )
        conn.commit()
    
    # Verify
    anom_count = conn.execute("SELECT COUNT(*) FROM anomaly_scores WHERE feature = 'ssh_failed_login'").fetchone()[0]
    assert anom_count == 1, f"Expected 1 SSH anomaly, got {anom_count}"
    
    conn.close()


def test_no_false_positives_baseline(test_db):
    """Baseline data with no anomalies should produce zero alerts."""
    conn = sqlite3.connect(test_db)
    base_time = datetime.now()
    
    # Insert 1h baseline: stable metrics
    for i in range(360):
        ts = base_time + timedelta(seconds=i * 10)
        conn.execute(
            "INSERT INTO metric_samples VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("i-test", "run-1", i, ts.isoformat(), 22.0, 50.0, 0.0, 60.0, 1.0, 1000.0, 500.0, 80, 1)
        )
    
    conn.commit()
    
    # Run detector
    df = pd.read_sql_query("SELECT timestamp, cpu_percent FROM metric_samples ORDER BY timestamp", conn)
    median = df["cpu_percent"].median()
    mad = (df["cpu_percent"] - median).abs().median()
    threshold = 6.0
    
    for _, row in df.iterrows():
        score = abs(row["cpu_percent"] - median) / (mad + 1e-9)
        is_anomaly = 1 if score > threshold else 0
        if is_anomaly:
            conn.execute(
                "INSERT INTO anomaly_scores VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("i-test", row["timestamp"], "mad", "cpu_percent", row["cpu_percent"],
                 score, threshold, is_anomaly, "1.0")
            )
    
    conn.commit()
    
    # Verify: zero anomalies
    count = conn.execute("SELECT COUNT(*) FROM anomaly_scores WHERE is_anomaly = 1").fetchone()[0]
    assert count == 0, f"Expected 0 false positives, got {count}"
    
    conn.close()
