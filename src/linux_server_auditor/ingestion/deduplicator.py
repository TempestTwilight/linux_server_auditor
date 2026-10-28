"""Deduplication using (instance_id, agent_run_id, sequence) key."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

log = logging.getLogger(__name__)


def dedup_key(record: dict[str, Any]) -> tuple[str, str, int]:
    """Extract the deduplication key from a record."""
    return (record["instance_id"], record["agent_run_id"], record["sequence"])


def record_hash(record: dict[str, Any]) -> str:
    """Compute a hash of the record content for change detection."""
    # Normalize record for hashing (remove non-deterministic fields if needed)
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def deduplicate(
    records: list[dict[str, Any]],
    seen_keys: set[tuple[str, str, int]],
    content_hashes: dict[tuple[str, str, int], str] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Deduplicate records against already-seen keys.
    Returns (unique_records, errors).

    If content_hashes is provided, detects content changes for same key
    and logs a validation error (rejects the duplicate).
    """
    unique: list[dict[str, Any]] = []
    errors: list[str] = []
    check_content = content_hashes is not None

    for record in records:
        key = dedup_key(record)

        if key in seen_keys:
            # Duplicate key - check if content differs
            if check_content and content_hashes is not None:
                old_hash = content_hashes.get(key)
                new_hash = record_hash(record)
                if old_hash and old_hash != new_hash:
                    errors.append(
                        f"Duplicate key with different content: {key}, "
                        f"old_hash={old_hash}, new_hash={new_hash}"
                    )
            # Skip duplicate either way
            continue

        seen_keys.add(key)
        if check_content and content_hashes is not None:
            content_hashes[key] = record_hash(record)
        unique.append(record)

    return unique, errors


class DedupTracker:
    """Stateful deduplication tracker."""

    def __init__(self) -> None:
        self.seen_keys: set[tuple[str, str, int]] = set()
        self.content_hashes: dict[tuple[str, str, int], str] = {}

    def filter(self, records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
        """Filter records, tracking seen keys. Returns (unique, errors)."""
        return deduplicate(records, self.seen_keys, self.content_hashes)

    def reset(self) -> None:
        """Clear all tracked state."""
        self.seen_keys.clear()
        self.content_hashes.clear()
