"""Tests for record and batch validation."""

from __future__ import annotations

import json

from linux_server_auditor.ingestion.validator import (
    MAX_BATCH_SIZE,
    MAX_RECORD_SIZE,
    validate_batch,
    validate_record,
)


def _good_record(**overrides) -> dict:
    rec = {
        "schema_version": 1,
        "record_id": "abc-123",
        "agent_run_id": "run-456",
        "instance_id": "i-001",
        "timestamp": "2026-10-18T09:00:10Z",
        "sequence": 42,
        "type": "system_metrics",
        "metrics": {"cpu_percent": 21.4},
    }
    rec.update(overrides)
    return rec


def test_valid_record():
    assert validate_record(_good_record()) == []


def test_missing_required_fields():
    rec = _good_record()
    del rec["record_id"]
    errors = validate_record(rec)
    assert any("record_id" in e for e in errors)


def test_invalid_type():
    rec = _good_record(type="unknown_type")
    errors = validate_record(rec)
    assert any("Invalid type" in e for e in errors)


def test_invalid_timestamp_format():
    rec = _good_record(timestamp="not-a-date")
    errors = validate_record(rec)
    assert any("timestamp" in e for e in errors)


def test_valid_timestamp_with_offset():
    # ISO 8601 with Z suffix
    assert validate_record(_good_record(timestamp="2026-10-18T09:00:10Z")) == []


def test_record_size_too_large():
    big_record = _good_record()
    errors = validate_record(big_record, size_bytes=MAX_RECORD_SIZE + 1)
    assert any("size" in e.lower() for e in errors)


def test_batch_valid():
    records = [_good_record(sequence=i) for i in range(5)]
    valid, errors = validate_batch(records)
    assert len(valid) == 5
    assert errors == []


def test_batch_size_too_large():
    records = [_good_record()]
    valid, errors = validate_batch(records, total_bytes=MAX_BATCH_SIZE + 1)
    assert valid == []
    assert any("Batch size" in e for e in errors)


def test_batch_partial_valid():
    records = [
        _good_record(sequence=1),
        _good_record(sequence=2, type="bad_type"),
        _good_record(sequence=3),
    ]
    valid, errors = validate_batch(records)
    assert len(valid) == 2
    assert len(errors) == 1  # One invalid type error


def test_sequence_must_be_int():
    rec = _good_record(sequence="not-an-int")
    errors = validate_record(rec)
    assert any("sequence" in e for e in errors)


def test_schema_version_must_be_int():
    rec = _good_record(schema_version="1")
    errors = validate_record(rec)
    assert any("schema_version" in e for e in errors)


def test_all_valid_types():
    for rtype in ("system_metrics", "process_metrics", "security_signals", "file_integrity"):
        errors = validate_record(_good_record(type=rtype))
        assert errors == [], f"Expected no errors for type {rtype}: {errors}"
