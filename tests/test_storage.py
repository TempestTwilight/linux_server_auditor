"""Tests for SQLite storage layer."""

from __future__ import annotations

from datetime import datetime

import pytest

from linux_server_auditor.storage.database import Database
from linux_server_auditor.storage.repositories import (
    commit,
    create_incident,
    get_last_heartbeat,
    get_metric_samples,
    get_open_incidents,
    get_security_events,
    insert_metric_sample,
    insert_security_event,
    is_batch_processed,
    mark_batch_processed,
    record_heartbeat,
)


@pytest.fixture
def db(tmp_path):
    """In-memory test database."""
    d = Database(db_path=tmp_path / "test.db")
    yield d
    d.close()


def _metric_record(sequence=1, instance_id="i-001", agent_run_id="run-1", **extra):
    return {
        "schema_version": 1,
        "record_id": f"rec-{sequence}",
        "instance_id": instance_id,
        "agent_run_id": agent_run_id,
        "sequence": sequence,
        "timestamp": "2026-10-18T09:00:10Z",
        "type": "system_metrics",
        "metrics": {
            "cpu_percent": 21.4,
            "memory_used_percent": 55.0,
            "swap_used_percent": 0.0,
            "disk_used_percent": 30.0,
            "load_1m_per_cpu": 0.5,
            "network_rx_bytes_per_sec": 1000.0,
            "network_tx_bytes_per_sec": 500.0,
            "process_count": 100,
        },
        **extra,
    }


def _security_record(record_type="security_signals", sequence=1, instance_id="i-001"):
    return {
        "schema_version": 1,
        "record_id": f"sec-{sequence}",
        "instance_id": instance_id,
        "agent_run_id": "run-1",
        "sequence": sequence,
        "timestamp": "2026-10-18T09:00:10Z",
        "type": record_type,
        "metrics": {"signal": "test"},
    }


# ── metric_samples ─────────────────────────────────────────────────────


def test_insert_metric_sample(db):
    rec = _metric_record()
    result = insert_metric_sample(db, rec)
    commit(db)
    assert result is True


def test_insert_duplicate_metric_sample_ignored(db):
    rec = _metric_record()
    insert_metric_sample(db, rec)
    result = insert_metric_sample(db, rec)  # same key
    commit(db)
    assert result is False


def test_get_metric_samples(db):
    for i in range(3):
        insert_metric_sample(db, _metric_record(sequence=i))
    commit(db)

    samples = get_metric_samples(db, "i-001")
    assert len(samples) == 3


def test_get_metric_samples_with_since(db):
    insert_metric_sample(db, _metric_record(sequence=1, timestamp="2026-10-18T08:00:00Z"))
    insert_metric_sample(db, _metric_record(sequence=2, timestamp="2026-10-18T10:00:00Z"))
    commit(db)

    samples = get_metric_samples(db, "i-001", since="2026-10-18T09:00:00Z")
    assert len(samples) == 1


def test_get_metric_samples_limit(db):
    for i in range(10):
        insert_metric_sample(db, _metric_record(sequence=i))
    commit(db)

    samples = get_metric_samples(db, "i-001", limit=5)
    assert len(samples) == 5


# ── security_events ─────────────────────────────────────────────────────


def test_insert_security_event(db):
    rec = _security_record()
    result = insert_security_event(db, rec)
    commit(db)
    assert result is True


def test_get_security_events(db):
    for i in range(3):
        insert_security_event(db, _security_record(sequence=i))
    commit(db)

    events = get_security_events(db, "i-001")
    assert len(events) == 3


def test_get_security_events_by_type(db):
    insert_security_event(db, _security_record(record_type="security_signals", sequence=1))
    insert_security_event(db, _security_record(record_type="file_integrity", sequence=2))
    commit(db)

    events = get_security_events(db, "i-001", event_type="security_signals")
    assert len(events) == 1
    assert events[0]["event_type"] == "security_signals"


def test_security_event_data_is_dict(db):
    insert_security_event(db, _security_record())
    commit(db)

    events = get_security_events(db, "i-001")
    assert isinstance(events[0]["event_data"], dict)


# ── processed_batches ───────────────────────────────────────────────────


def test_is_batch_processed_false_initially(db):
    assert not is_batch_processed(db, "telemetry/i-001/batch1.jsonl")


def test_mark_and_check_batch_processed(db):
    key = "telemetry/i-001/batch1.jsonl"
    mark_batch_processed(db, key, "etag-123", 42)
    commit(db)
    assert is_batch_processed(db, key)


# ── monitor_heartbeats ─────────────────────────────────────────────────


def test_record_heartbeat(db):
    record_heartbeat(db)
    commit(db)

    hb = get_last_heartbeat(db)
    assert hb is not None
    assert hb["status"] == "alive"


def test_heartbeat_custom_status(db):
    record_heartbeat(db, status="degraded")
    commit(db)

    hb = get_last_heartbeat(db)
    assert hb["status"] == "degraded"


# ── incidents ───────────────────────────────────────────────────────────


def test_create_and_get_incident(db):
    incident_id = create_incident(db, "i-001", priority_score=8.5, evidence={"anomaly": "cpu"})
    commit(db)

    incidents = get_open_incidents(db, "i-001")
    assert len(incidents) == 1
    assert incidents[0]["incident_id"] == incident_id
    assert incidents[0]["priority_score"] == 8.5
    assert incidents[0]["evidence"]["anomaly"] == "cpu"


def test_no_open_incidents(db):
    incidents = get_open_incidents(db, "i-001")
    assert incidents == []


# ── retention ───────────────────────────────────────────────────────────


def test_retention_deletes_old_records(db, monkeypatch):
    # Inject short retention via monkeypatching settings
    from linux_server_auditor.config import settings
    original = settings["monitor"]["retention_days"]
    settings["monitor"]["retention_days"] = 0  # Delete everything

    insert_metric_sample(db, _metric_record(timestamp="2026-01-01T00:00:00Z"))
    commit(db)

    deleted = db.run_retention()
    settings["monitor"]["retention_days"] = original  # Restore
    assert deleted > 0
