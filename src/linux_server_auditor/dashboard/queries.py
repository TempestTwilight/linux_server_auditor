"""Dashboard queries — return DataFrames and dicts for Streamlit."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pandas as pd


def get_latest_telemetry(db_path: str | Path) -> dict[str, Any]:
    """Return timestamp of most recent metric sample and host information."""
    p = Path(db_path)
    if not p.exists():
        return {"latest_timestamp": None, "instance_id": None, "is_demo": False}

    with sqlite3.connect(p) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT timestamp, instance_id FROM metric_samples ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
        if not row:
            return {"latest_timestamp": None, "instance_id": None, "is_demo": False}
        ts = row["timestamp"]
        iid = row["instance_id"]
        is_demo = bool(iid and "demo" in iid.lower())
        return {"latest_timestamp": ts, "instance_id": iid, "is_demo": is_demo}


def get_latest_metrics(db_path: str | Path) -> dict[str, Any]:
    """Return latest metric readings as dict."""
    p = Path(db_path)
    if not p.exists():
        return {}

    with sqlite3.connect(p) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT timestamp, instance_id, cpu_percent, memory_used_percent,
                   swap_used_percent, disk_used_percent, load_1m_per_cpu,
                   process_count, network_rx_bytes_per_sec, network_tx_bytes_per_sec
            FROM metric_samples
            ORDER BY timestamp DESC LIMIT 1
            """
        ).fetchone()
        return dict(row) if row else {}


def get_metrics_timeseries(db_path: str | Path, hours: int = 6) -> pd.DataFrame:
    """Return metric samples for the last N hours (or recent history if empty)."""
    p = Path(db_path)
    if not p.exists():
        return pd.DataFrame()

    with sqlite3.connect(p) as conn:
        cols = """timestamp, cpu_percent, memory_used_percent, swap_used_percent,
                  disk_used_percent, load_1m_per_cpu, process_count,
                  network_rx_bytes_per_sec, network_tx_bytes_per_sec"""
        query = f"""
            SELECT {cols}
            FROM metric_samples
            WHERE timestamp >= datetime('now', '-{hours} hours')
            ORDER BY timestamp ASC
        """
        df = pd.read_sql_query(query, conn, parse_dates=["timestamp"])
        if df.empty:
            # Fall back to latest 500 samples
            fallback_query = f"""
                SELECT {cols} FROM (
                    SELECT {cols} FROM metric_samples ORDER BY timestamp DESC LIMIT 500
                ) ORDER BY timestamp ASC
            """
            df = pd.read_sql_query(fallback_query, conn, parse_dates=["timestamp"])
        return df


def get_anomalies(db_path: str | Path, hours: int = 24) -> pd.DataFrame:
    """Return anomalies from the last N hours (or recent history if empty)."""
    p = Path(db_path)
    if not p.exists():
        return pd.DataFrame()

    with sqlite3.connect(p) as conn:
        cols = "timestamp, instance_id, detector, feature, value, score, threshold, model_version"
        query = f"""
            SELECT {cols}
            FROM anomaly_scores
            WHERE is_anomaly = 1
              AND timestamp >= datetime('now', '-{hours} hours')
            ORDER BY timestamp DESC
        """
        df = pd.read_sql_query(query, conn, parse_dates=["timestamp"])
        if df.empty:
            fallback = f"""
                SELECT {cols} FROM anomaly_scores
                WHERE is_anomaly = 1
                ORDER BY timestamp DESC LIMIT 200
            """
            df = pd.read_sql_query(fallback, conn, parse_dates=["timestamp"])
        return df


def get_incidents(db_path: str | Path) -> pd.DataFrame:
    """Return all incidents sorted by priority."""
    p = Path(db_path)
    if not p.exists():
        return pd.DataFrame()

    query = """
        SELECT incident_id, instance_id, status, priority_score,
               first_seen, last_seen, finding_count, evidence, resolution_notes
        FROM incidents
        ORDER BY priority_score DESC, last_seen DESC
    """
    with sqlite3.connect(p) as conn:
        df = pd.read_sql_query(query, conn, parse_dates=["first_seen", "last_seen"])
        return df if not df.empty else pd.DataFrame()


def get_security_events(db_path: str | Path, hours: int = 24) -> pd.DataFrame:
    """Return security events from the last N hours."""
    p = Path(db_path)
    if not p.exists():
        return pd.DataFrame()

    with sqlite3.connect(p) as conn:
        query = f"""
            SELECT timestamp, instance_id, event_type, event_data
            FROM security_events
            WHERE timestamp >= datetime('now', '-{hours} hours')
            ORDER BY timestamp DESC
        """
        df = pd.read_sql_query(query, conn, parse_dates=["timestamp"])
        if df.empty:
            fallback = """
                SELECT timestamp, instance_id, event_type, event_data
                FROM security_events
                ORDER BY timestamp DESC LIMIT 200
            """
            df = pd.read_sql_query(fallback, conn, parse_dates=["timestamp"])
        return df


def get_evaluation_summary(summary_path: str | Path | None = None) -> dict[str, Any] | None:
    """Read data/evaluation_summary.json if present."""
    if summary_path is None:
        summary_path = Path(__file__).resolve().parents[3] / "data" / "evaluation_summary.json"
    p = Path(summary_path)
    if not p.exists():
        return None
    try:
        with p.open() as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
