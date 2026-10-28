"""Tests for deduplication logic."""

from __future__ import annotations

from linux_server_auditor.ingestion.deduplicator import DedupTracker, deduplicate, dedup_key


def _rec(instance_id="i-001", agent_run_id="run-1", sequence=1, **extra):
    return {
        "instance_id": instance_id,
        "agent_run_id": agent_run_id,
        "sequence": sequence,
        "type": "system_metrics",
        "metrics": {"cpu_percent": 10.0},
        **extra,
    }


def test_dedup_key():
    rec = _rec()
    assert dedup_key(rec) == ("i-001", "run-1", 1)


def test_unique_records_pass_through():
    records = [_rec(sequence=i) for i in range(5)]
    seen: set = set()
    unique, errors = deduplicate(records, seen)
    assert len(unique) == 5
    assert errors == []


def test_duplicate_same_batch_skipped():
    records = [_rec(sequence=1), _rec(sequence=1), _rec(sequence=2)]
    seen: set = set()
    unique, errors = deduplicate(records, seen)
    assert len(unique) == 2  # sequence 1 deduplicated, 2 kept
    assert errors == []


def test_duplicate_cross_batch_skipped():
    seen: set = set()
    batch1 = [_rec(sequence=1), _rec(sequence=2)]
    unique1, _ = deduplicate(batch1, seen)
    assert len(unique1) == 2

    batch2 = [_rec(sequence=1), _rec(sequence=3)]  # 1 is dupe
    unique2, _ = deduplicate(batch2, seen)
    assert len(unique2) == 1  # only sequence 3 is new


def test_content_hash_change_detected():
    """Same key with different content should produce a validation error."""
    seen: set = set()
    hashes: dict = {}
    r1 = _rec(sequence=1, metrics={"cpu_percent": 10.0})
    r2 = _rec(sequence=1, metrics={"cpu_percent": 99.9})  # same key, different content

    unique1, errors1 = deduplicate([r1], seen, hashes)
    assert len(unique1) == 1
    assert errors1 == []

    # Now insert dupe with different content
    unique2, errors2 = deduplicate([r2], seen, hashes)
    assert len(unique2) == 0
    assert any("different content" in e for e in errors2)


def test_dedup_tracker_stateful():
    tracker = DedupTracker()
    batch1 = [_rec(sequence=i) for i in range(3)]
    unique, errors = tracker.filter(batch1)
    assert len(unique) == 3

    batch2 = [_rec(sequence=i) for i in range(1, 5)]  # 1,2 already seen; 3,4 new
    unique2, errors2 = tracker.filter(batch2)
    assert len(unique2) == 2  # sequences 3 and 4 are new


def test_dedup_tracker_reset():
    tracker = DedupTracker()
    tracker.filter([_rec(sequence=1)])
    tracker.reset()
    unique, _ = tracker.filter([_rec(sequence=1)])
    assert len(unique) == 1  # seen after reset


def test_different_instance_ids_not_deduped():
    records = [
        _rec(instance_id="i-001", sequence=1),
        _rec(instance_id="i-002", sequence=1),
    ]
    seen: set = set()
    unique, errors = deduplicate(records, seen)
    assert len(unique) == 2


def test_different_agent_run_ids_not_deduped():
    records = [
        _rec(agent_run_id="run-1", sequence=1),
        _rec(agent_run_id="run-2", sequence=1),
    ]
    seen: set = set()
    unique, errors = deduplicate(records, seen)
    assert len(unique) == 2
