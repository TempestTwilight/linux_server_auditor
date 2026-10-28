"""Dashboard queries — return DataFrames and dicts for Streamlit."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pandas as pd


def get_latest_telemetry(db_path: str | Path) -> dict:
    """Return timestamp of most recent metric sample and whether data is stale."""
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT MAX(timestamp) FROM metric_samples"
        ).fetchone()
        latest = row[0] if row[0] else None
        return {"latest_timestamp": latest}


def get_metrics_timeseries(db_path: str | Path, hours: int = 6) -> pd.DataFrame:
    """Return metric samples for the last N hours."""
    query = f"""
        SELECT timestamp, cpu_percent, memory_used_percent, disk_used_percent,
               network_rx_bytes_per_sec, network_tx_bytes_per_sec
        FROM metric_samples
        WHERE timestamp >= datetime('now', '-{hours} hours')
        ORDER BY timestamp
    """
    with sqlite3.connect(db_path) as conn:
        return pd.read_sql_query(query, conn, parse_dates=["timestamp"])


def get_anomalies(db_path: str | Path, hours: int = 24) -> pd.DataFrame:
    """Return anomalies from the last N hours."""
    query = f"""
        SELECT timestamp, detector, feature, value, score, threshold, model_version
        FROM anomaly_scores
        WHERE is_anomaly = 1
          AND timestamp >= datetime('now', '-{hours} hours')
        ORDER BY timestamp DESC
    """
    with sqlite3.connect(db_path) as conn:
        df = pd.read_sql_query(query, conn, parse_dates=["timestamp"])
        return df if not df.empty else pd.DataFrame()


def get_incidents(db_path: str | Path) -> pd.DataFrame:
    """Return all incidents sorted by priority."""
    query = """
        SELECT incident_id, instance_id, status, priority_score,
               first_seen, last_seen, finding_count, resolution_notes
        FROM incidents
        ORDER BY priority_score DESC, last_seen DESC
    """
    with sqlite3.connect(db_path) as conn:
        df = pd.read_sql_query(query, conn, parse_dates=["first_seen", "last_seen"])
        return df if not df.empty else pd.DataFrame()


def get_security_events(db_path: str | Path, hours: int = 24) -> pd.DataFrame:
    """Return security events from the last N hours."""
    query = f"""
        SELECT timestamp, event_type, event_data
        FROM security_events
        WHERE timestamp >= datetime('now', '-{hours} hours')
        ORDER BY timestamp DESC
    """
    with sqlite3.connect(db_path) as conn:
        df = pd.read_sql_query(query, conn, parse_dates=["timestamp"])
        return df if not df.empty else pd.DataFrame()
