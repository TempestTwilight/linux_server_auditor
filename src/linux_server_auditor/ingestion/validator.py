"""Schema validation for incoming telemetry records."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

log = logging.getLogger(__name__)

REQUIRED_FIELDS = ["schema_version", "record_id", "instance_id", "timestamp", "sequence", "type", "metrics"]
VALID_TYPES = {"system_metrics", "process_metrics", "security_signals", "file_integrity"}
MAX_RECORD_SIZE = 4096  # 4KB
MAX_BATCH_SIZE = 1024 * 1024  # 1MB


class ValidationError(Exception):
    """Record validation failed."""
    pass


def validate_record(record: dict[str, Any], size_bytes: int | None = None) -> list[str]:
    """Validate a single record. Returns list of errors (empty = valid)."""
    errors: list[str] = []

    # Size check
    if size_bytes is not None and size_bytes > MAX_RECORD_SIZE:
        errors.append(f"Record size {size_bytes} exceeds {MAX_RECORD_SIZE} bytes")

    # Required fields
    for field in REQUIRED_FIELDS:
        if field not in record:
            errors.append(f"Missing required field: {field}")

    if errors:
        return errors

    # Type check
    if record["type"] not in VALID_TYPES:
        errors.append(f"Invalid type: {record['type']}, expected one of {VALID_TYPES}")

    # Timestamp format (ISO 8601 UTC)
    try:
        ts = record["timestamp"]
        # Accept both with and without Z suffix
        if ts.endswith("Z"):
            datetime.fromisoformat(ts[:-1] + "+00:00")
        else:
            datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        errors.append(f"Invalid timestamp format: {record.get('timestamp')}")

    # Schema version
    if not isinstance(record.get("schema_version"), int):
        errors.append("schema_version must be an integer")

    # Sequence
    if not isinstance(record.get("sequence"), int):
        errors.append("sequence must be an integer")

    return errors


def validate_batch(records: list[dict[str, Any]], total_bytes: int | None = None) -> tuple[list[dict[str, Any]], list[str]]:
    """Validate a batch of records. Returns (valid_records, all_errors)."""
    all_errors: list[str] = []

    if total_bytes is not None and total_bytes > MAX_BATCH_SIZE:
        all_errors.append(f"Batch size {total_bytes} exceeds {MAX_BATCH_SIZE} bytes")
        return [], all_errors

    valid_records: list[dict[str, Any]] = []
    for i, record in enumerate(records):
        errors = validate_record(record)
        if errors:
            for err in errors:
                all_errors.append(f"Record {i}: {err}")
        else:
            valid_records.append(record)

    return valid_records, all_errors
