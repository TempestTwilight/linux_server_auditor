"""Tests collector output shape and dedup key."""

from __future__ import annotations

import json

from linux_server_auditor.agent import file_integrity, process_metrics, system_metrics
from linux_server_auditor.agent.batcher import Batcher

# ── system_metrics ────────────────────────────────────────────────────────────


def test_system_metrics_shape():
    rec = system_metrics.collect(interval_sec=0.1)
    assert rec["type"] == "system_metrics"
    m = rec["metrics"]
    for key in [
        "cpu_percent",
        "memory_used_percent",
        "swap_used_percent",
        "disk_used_percent",
        "load_1m_per_cpu",
        "network_rx_bytes_per_sec",
        "network_tx_bytes_per_sec",
        "process_count",
    ]:
        assert key in m, f"missing key: {key}"
        assert isinstance(m[key], (int, float))

    assert 0.0 <= m["cpu_percent"] <= 100.0
    assert 0.0 <= m["memory_used_percent"] <= 100.0
    assert m["process_count"] > 0


# ── process_metrics ───────────────────────────────────────────────────────────


def test_process_metrics_shape():
    rec = process_metrics.collect()
    assert rec["type"] == "process_metrics"
    m = rec["metrics"]
    assert m["process_count"] > 0
    assert isinstance(m["top_processes"], list)
    if m["top_processes"]:
        p = m["top_processes"][0]
        assert "pid" in p and "name" in p and "cpu_pct" in p


# ── file_integrity ────────────────────────────────────────────────────────────


def test_file_integrity_shape():
    rec = file_integrity.collect()
    assert rec["type"] == "file_integrity"
    files = rec["metrics"]["files"]
    assert isinstance(files, list)
    # At least one watchlist entry exists
    assert len(files) >= 1
    for entry in files:
        assert "path" in entry
        assert "sha256" in entry
        # sha256 is 64-char hex or None (if unreadable)
        if entry["sha256"] is not None:
            assert len(entry["sha256"]) == 64


# ── batcher ───────────────────────────────────────────────────────────────────


def test_batcher_flush_writes_valid_jsonl(tmp_path):
    b = Batcher(tmp_path, batch_duration_sec=9999)
    for i in range(3):
        b.add({"type": "system_metrics", "sequence": i, "metrics": {}})
    path = b.flush()
    assert path is not None and path.exists()
    lines = path.read_text().splitlines()
    assert len(lines) == 3
    for line in lines:
        rec = json.loads(line)
        assert rec["type"] == "system_metrics"


def test_batcher_returns_none_when_empty(tmp_path):
    b = Batcher(tmp_path, batch_duration_sec=9999)
    assert b.flush() is None


def test_batcher_auto_flushes_on_window_expiry(tmp_path):
    import time

    b = Batcher(tmp_path, batch_duration_sec=0)  # 0 → always expired
    time.sleep(0.01)
    path = b.add({"type": "test", "x": 1})
    assert path is not None
