"""Repository functions for CRUD operations."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone

_utcnow = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
from typing import Any

from linux_server_auditor.storage.database import Database

# ── metric_samples ─────────────────────────────────────────────────────


def insert_metric_sample(db: Database, record: dict[str, Any]) -> bool:
    """Insert a metric sample. Returns True if inserted, False if duplicate."""
    m = record["metrics"]
    try:
        db.conn.execute(
            """
            INSERT OR IGNORE INTO metric_samples
            (instance_id, agent_run_id, sequence, timestamp,
             cpu_percent, memory_used_percent, swap_used_percent, disk_used_percent,
             load_1m_per_cpu, network_rx_bytes_per_sec, network_tx_bytes_per_sec,
             process_count, schema_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["instance_id"],
                record["agent_run_id"],
                record["sequence"],
                record["timestamp"],
                m.get("cpu_percent"),
                m.get("memory_used_percent"),
                m.get("swap_used_percent"),
                m.get("disk_used_percent"),
                m.get("load_1m_per_cpu"),
                m.get("network_rx_bytes_per_sec"),
                m.get("network_tx_bytes_per_sec"),
                m.get("process_count"),
                record.get("schema_version", 1),
            ),
        )
        return db.conn.execute("SELECT changes()").fetchone()[0] > 0
    except sqlite3.IntegrityError:
        return False


def get_metric_samples(
    db: Database,
    instance_id: str,
    since: str | None = None,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    """Fetch metric samples for an instance."""
    if since:
        rows = db.conn.execute(
            """
            SELECT * FROM metric_samples
            WHERE instance_id = ? AND timestamp >= ?
            ORDER BY timestamp DESC LIMIT ?
            """,
            (instance_id, since, limit),
        ).fetchall()
    else:
        rows = db.conn.execute(
            """
            SELECT * FROM metric_samples
            WHERE instance_id = ?
            ORDER BY timestamp DESC LIMIT ?
            """,
            (instance_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


# ── security_events ─────────────────────────────────────────────────────


def insert_security_event(db: Database, record: dict[str, Any]) -> bool:
    """Insert a security event. Returns True if inserted."""
    event_data = record.get("metrics", {})
    try:
        db.conn.execute(
            """
            INSERT INTO security_events
            (instance_id, timestamp, event_type, event_data, schema_version)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                record["instance_id"],
                record["timestamp"],
                record["type"],
                json.dumps(event_data),
                record.get("schema_version", 1),
            ),
        )
        return True
    except sqlite3.IntegrityError:
        return False


def get_security_events(
    db: Database,
    instance_id: str,
    event_type: str | None = None,
    since: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Fetch security events for an instance."""
    conditions = ["instance_id = ?"]
    params: list[Any] = [instance_id]
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if since:
        conditions.append("timestamp >= ?")
        params.append(since)
    params.append(limit)

    rows = db.conn.execute(
        f"""
        SELECT * FROM security_events
        WHERE {' AND '.join(conditions)}
        ORDER BY timestamp DESC LIMIT ?
        """,
        params,
    ).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["event_data"] = json.loads(d["event_data"])
        results.append(d)
    return results


# ── processed_batches ───────────────────────────────────────────────────


def is_batch_processed(db: Database, s3_key: str) -> bool:
    """Check if an S3 batch has already been processed."""
    row = db.conn.execute(
        "SELECT 1 FROM processed_batches WHERE s3_key = ?", (s3_key,)
    ).fetchone()
    return row is not None


def mark_batch_processed(
    db: Database, s3_key: str, etag: str | None, record_count: int
) -> None:
    """Mark an S3 batch as processed."""
    db.conn.execute(
        """
        INSERT OR REPLACE INTO processed_batches (s3_key, etag, processed_at, record_count)
        VALUES (?, ?, ?, ?)
        """,
        (s3_key, etag, _utcnow(), record_count),
    )


# ── monitor_heartbeats ─────────────────────────────────────────────────


def record_heartbeat(db: Database, status: str = "alive") -> None:
    """Record a monitor heartbeat."""
    db.conn.execute(
        "INSERT OR REPLACE INTO monitor_heartbeats (timestamp, status) VALUES (?, ?)",
        (datetime.utcnow().isoformat(), status),
    )


def get_last_heartbeat(db: Database) -> dict[str, Any] | None:
    """Get the most recent heartbeat."""
    row = db.conn.execute(
        "SELECT * FROM monitor_heartbeats ORDER BY timestamp DESC LIMIT 1"
    ).fetchone()
    return dict(row) if row else None


# ── incidents ───────────────────────────────────────────────────────────


def create_incident(
    db: Database,
    instance_id: str,
    priority_score: float,
    evidence: dict[str, Any],
) -> str:
    """Create a new incident. Returns incident_id."""
    incident_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    db.conn.execute(
        """
        INSERT INTO incidents
        (incident_id, instance_id, status, priority_score, first_seen, last_seen, evidence)
        VALUES (?, ?, 'open', ?, ?, ?, ?)
        """,
        (incident_id, instance_id, priority_score, now, now, json.dumps(evidence)),
    )
    return incident_id


def get_open_incidents(db: Database, instance_id: str | None = None) -> list[dict[str, Any]]:
    """Fetch all open incidents."""
    if instance_id:
        rows = db.conn.execute(
            """
            SELECT * FROM incidents
            WHERE instance_id = ? AND status = 'open'
            ORDER BY priority_score DESC
            """,
            (instance_id,),
        ).fetchall()
    else:
        rows = db.conn.execute(
            """
            SELECT * FROM incidents WHERE status = 'open'
            ORDER BY priority_score DESC
            """
        ).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["evidence"] = json.loads(d["evidence"]) if d["evidence"] else {}
        results.append(d)
    return results


# ── anomaly_scores ─────────────────────────────────────────────────────


def insert_anomaly_score(
    db: Database,
    instance_id: str,
    timestamp: str,
    detector: str,
    feature: str,
    value: float,
    score: float,
    threshold: float,
    is_anomaly: bool,
    model_version: str | None = None,
) -> None:
    """Insert an anomaly score."""
    db.conn.execute(
        """
        INSERT INTO anomaly_scores
        (instance_id, timestamp, detector, feature, value, score, threshold, is_anomaly, model_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            instance_id,
            timestamp,
            detector,
            feature,
            value,
            score,
            threshold,
            int(is_anomaly),
            model_version,
        ),
    )


def commit(db: Database) -> None:
    """Commit current transaction."""
    db.conn.commit()
