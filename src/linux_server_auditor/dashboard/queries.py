"""Dashboard queries — return DataFrames and dicts for Streamlit."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pandas as pd

from linux_server_auditor.detection.engine import run_detection
from linux_server_auditor.ingestion.s3_poller import S3Poller
from linux_server_auditor.storage.database import Database


def get_available_instances(db_path: str | Path) -> list[str]:
    """Return all unique instance IDs present in database, newest first."""
    p = Path(db_path)
    if not p.exists():
        return []
    with sqlite3.connect(p) as conn:
        rows = conn.execute(
            """
            SELECT instance_id, MAX(timestamp) as last_seen
            FROM metric_samples
            GROUP BY instance_id
            ORDER BY last_seen DESC
            """
        ).fetchall()
        return [r[0] for r in rows if r[0]]


def sync_and_detect(db_path: str | Path, instance_id: str | None = None) -> dict[str, Any]:
    """Sync new batches from S3 and run detection pipeline."""
    db = Database(Path(db_path))
    poller = S3Poller(db)
    stored = poller.poll_once()
    det = run_detection(db, instance_id=instance_id)
    return {"records_stored": stored, "detection": det}


def get_latest_telemetry(db_path: str | Path, instance_id: str | None = None) -> dict[str, Any]:
    """Return timestamp of most recent metric sample and host information."""
    p = Path(db_path)
    if not p.exists():
        return {"latest_timestamp": None, "instance_id": None, "is_demo": False}

    with sqlite3.connect(p) as conn:
        conn.row_factory = sqlite3.Row
        query = "SELECT timestamp, instance_id FROM metric_samples"
        params: list[Any] = []
        if instance_id:
            query += " WHERE instance_id = ?"
            params.append(instance_id)
        query += " ORDER BY timestamp DESC LIMIT 1"

        row = conn.execute(query, params).fetchone()
        if not row:
            return {"latest_timestamp": None, "instance_id": None, "is_demo": False}
        ts = row["timestamp"]
        iid = row["instance_id"]
        is_demo = bool(iid and "demo" in iid.lower())
        return {"latest_timestamp": ts, "instance_id": iid, "is_demo": is_demo}


def get_latest_metrics(db_path: str | Path, instance_id: str | None = None) -> dict[str, Any]:
    """Return latest metric readings as dict."""
    p = Path(db_path)
    if not p.exists():
        return {}

    with sqlite3.connect(p) as conn:
        conn.row_factory = sqlite3.Row
        query = """
            SELECT timestamp, instance_id, cpu_percent, memory_used_percent,
                   swap_used_percent, disk_used_percent, load_1m_per_cpu,
                   process_count, network_rx_bytes_per_sec, network_tx_bytes_per_sec
            FROM metric_samples
        """
        params: list[Any] = []
        if instance_id:
            query += " WHERE instance_id = ?"
            params.append(instance_id)
        query += " ORDER BY timestamp DESC LIMIT 1"

        row = conn.execute(query, params).fetchone()
        return dict(row) if row else {}


def get_metrics_timeseries(
    db_path: str | Path, hours: int = 2, instance_id: str | None = None
) -> pd.DataFrame:
    """Return metric samples for the past N hours (or recent window if empty)."""
    p = Path(db_path)
    if not p.exists():
        return pd.DataFrame()

    with sqlite3.connect(p) as conn:
        cols = """
            timestamp, instance_id, cpu_percent, memory_used_percent,
            swap_used_percent, disk_used_percent, load_1m_per_cpu,
            process_count, network_rx_bytes_per_sec, network_tx_bytes_per_sec
        """
        where_clauses = ["timestamp >= datetime('now', ?)"]
        params: list[Any] = [f"-{hours} hours"]
        if instance_id:
            where_clauses.append("instance_id = ?")
            params.append(instance_id)

        query = f"""
            SELECT {cols}
            FROM metric_samples
            WHERE {" AND ".join(where_clauses)}
            ORDER BY timestamp ASC
        """
        df = pd.read_sql_query(query, conn, params=params, parse_dates=["timestamp"])
        if df.empty:
            # Fallback to last 500 samples
            fallback_query = f"SELECT {cols} FROM metric_samples"
            fb_params: list[Any] = []
            if instance_id:
                fallback_query += " WHERE instance_id = ?"
                fb_params.append(instance_id)
            fallback_query += " ORDER BY timestamp DESC LIMIT 500"

            df = pd.read_sql_query(
                fallback_query, conn, params=fb_params, parse_dates=["timestamp"]
            )
            if not df.empty:
                df = df.sort_values("timestamp").reset_index(drop=True)
        return df


def get_anomalies(
    db_path: str | Path, hours: int = 24, instance_id: str | None = None
) -> pd.DataFrame:
    """Return anomalies from the last N hours (or recent history if empty)."""
    p = Path(db_path)
    if not p.exists():
        return pd.DataFrame()

    with sqlite3.connect(p) as conn:
        cols = "timestamp, instance_id, detector, feature, value, score, threshold, model_version"
        where_clauses = ["is_anomaly = 1", "timestamp >= datetime('now', ?)"]
        params: list[Any] = [f"-{hours} hours"]
        if instance_id:
            where_clauses.append("instance_id = ?")
            params.append(instance_id)

        query = f"""
            SELECT {cols}
            FROM anomaly_scores
            WHERE {" AND ".join(where_clauses)}
            ORDER BY timestamp DESC
        """
        df = pd.read_sql_query(query, conn, params=params, parse_dates=["timestamp"])
        if df.empty:
            fb = f"SELECT {cols} FROM anomaly_scores WHERE is_anomaly = 1"
            fb_params: list[Any] = []
            if instance_id:
                fb += " AND instance_id = ?"
                fb_params.append(instance_id)
            fb += " ORDER BY timestamp DESC LIMIT 200"
            df = pd.read_sql_query(fb, conn, params=fb_params, parse_dates=["timestamp"])
        return df


def get_incidents(db_path: str | Path, instance_id: str | None = None) -> pd.DataFrame:
    """Return all incidents sorted by priority."""
    p = Path(db_path)
    if not p.exists():
        return pd.DataFrame()

    query = """
        SELECT incident_id, instance_id, status, priority_score,
               first_seen, last_seen, finding_count, evidence, resolution_notes
        FROM incidents
    """
    params: list[Any] = []
    if instance_id:
        query += " WHERE instance_id = ?"
        params.append(instance_id)
    query += " ORDER BY priority_score DESC, last_seen DESC"

    with sqlite3.connect(p) as conn:
        df = pd.read_sql_query(query, conn, params=params, parse_dates=["first_seen", "last_seen"])
        return df if not df.empty else pd.DataFrame()


def get_security_events(
    db_path: str | Path, hours: int = 24, instance_id: str | None = None
) -> pd.DataFrame:
    """Return security events from the last N hours."""
    p = Path(db_path)
    if not p.exists():
        return pd.DataFrame()

    with sqlite3.connect(p) as conn:
        query = """
            SELECT timestamp, instance_id, event_type, event_data
            FROM security_events
        """
        params: list[Any] = []
        if instance_id:
            query += " WHERE instance_id = ?"
            params.append(instance_id)
        query += " ORDER BY timestamp DESC LIMIT 100"

        df = pd.read_sql_query(query, conn, params=params, parse_dates=["timestamp"])
        return df if not df.empty else pd.DataFrame()


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
