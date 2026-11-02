"""Controlled test scenarios generator and injector for Target B evaluation."""

from __future__ import annotations

import csv
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from linux_server_auditor.detection.engine import run_detection
from linux_server_auditor.storage.database import Database
from linux_server_auditor.storage.repositories import (
    commit,
    insert_metric_sample,
    insert_security_event,
)

log = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[2]
GROUND_TRUTH_CSV = _REPO_ROOT / "data" / "ground_truth.csv"

# Catalog of controlled test scenarios
SCENARIO_CATALOG: list[dict[str, Any]] = [
    {
        "id": "SCEN-NORMAL-01",
        "name": "Normal Baseline Operation",
        "category": "health",
        "expected_rule_or_detector": "none",
        "expected_detection": False,
        "description": "Stable resource metrics with no anomalies. Verifies zero false positives on baseline.",
        "severity": "none",
    },
    {
        "id": "SCEN-CPU-01",
        "name": "Sustained High CPU Utilization",
        "category": "health",
        "expected_rule_or_detector": "mad",
        "feature": "cpu_percent",
        "expected_detection": True,
        "description": "Simulates compute exhaustion / runaway process (CPU ~95% for 120s).",
        "severity": "high",
    },
    {
        "id": "SCEN-MEM-01",
        "name": "Memory Pressure",
        "category": "health",
        "expected_rule_or_detector": "mad",
        "feature": "memory_used_percent",
        "expected_detection": True,
        "description": "Simulates memory leak / memory exhaustion (Memory ~95% for 120s).",
        "severity": "high",
    },
    {
        "id": "SCEN-SSH-01",
        "name": "SSH Brute-Force Authentication Attack",
        "category": "security",
        "expected_rule_or_detector": "SSH-001",
        "expected_detection": True,
        "description": "Repeated SSH failed logins (6 failures in 60s from 192.168.1.100).",
        "severity": "high",
    },
    {
        "id": "SCEN-NET-01",
        "name": "Unauthorized Listening Port",
        "category": "security",
        "expected_rule_or_detector": "NET-001",
        "expected_detection": True,
        "description": "New listening port 4444/tcp opened outside inventory baseline.",
        "severity": "medium",
    },
    {
        "id": "SCEN-SVC-01",
        "name": "Watched Service Failure",
        "category": "security",
        "expected_rule_or_detector": "SVC-001",
        "expected_detection": True,
        "description": "Watched critical service 'nginx' transitioned to 'failed' state.",
        "severity": "high",
    },
    {
        "id": "SCEN-FIM-01",
        "name": "Critical File Integrity Violation",
        "category": "security",
        "expected_rule_or_detector": "FIM-001",
        "expected_detection": True,
        "description": "SHA-256 hash changed on watched system file /etc/passwd.",
        "severity": "critical",
    },
]


def record_ground_truth(
    records: list[dict[str, Any]],
    csv_path: Path = GROUND_TRUTH_CSV,
) -> None:
    """Write scenario records to ground_truth.csv."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "scenario",
        "instance_id",
        "start_time",
        "end_time",
        "expected_rule_or_detector",
        "severity",
        "description",
    ]
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow(
                {
                    "scenario": r["scenario"],
                    "instance_id": r.get("instance_id", "demo-ec2-host"),
                    "start_time": r["start_time"],
                    "end_time": r["end_time"],
                    "expected_rule_or_detector": r["expected_rule_or_detector"],
                    "severity": r.get("severity", "medium"),
                    "description": r.get("description", ""),
                }
            )


def generate_scenario_dataset(
    instance_id: str = "demo-ec2-host",
    base_time: datetime | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Generate metric records, security event records, and ground truth entries.

    Returns: (metric_records, security_records, ground_truth_records)
    """
    if base_time is None:
        base_time = datetime.now(UTC) - timedelta(hours=3)

    metrics_list: list[dict[str, Any]] = []
    sec_events_list: list[dict[str, Any]] = []
    ground_truth_list: list[dict[str, Any]] = []

    # 1. Generate 2.5 hours of baseline metrics (900 samples at 10s intervals)
    seq = 0
    run_id = "agent-run-demo-01"

    # Baseline: 0 to 500 (5000s ~ 83 min)
    for i in range(500):
        seq += 1
        ts = (
            (base_time + timedelta(seconds=i * 10))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        # stable baseline with small random-like variations
        cpu = 18.0 + (i % 7) * 0.8
        mem = 44.0 + (i % 5) * 0.5
        disk = 52.0
        load = 0.85 + (i % 4) * 0.05
        net_rx = 1200.0 + (i % 10) * 50
        net_tx = 600.0 + (i % 10) * 30
        procs = 88 + (i % 3)

        rec = {
            "schema_version": 1,
            "type": "system_metrics",
            "instance_id": instance_id,
            "agent_run_id": run_id,
            "sequence": seq,
            "timestamp": ts,
            "metrics": {
                "cpu_percent": round(cpu, 1),
                "memory_used_percent": round(mem, 1),
                "swap_used_percent": 0.0,
                "disk_used_percent": round(disk, 1),
                "load_1m_per_cpu": round(load, 2),
                "network_rx_bytes_per_sec": round(net_rx, 1),
                "network_tx_bytes_per_sec": round(net_tx, 1),
                "process_count": procs,
            },
        }
        metrics_list.append(rec)

    # Record SCEN-NORMAL-01 ground truth (first 30 minutes)
    ground_truth_list.append(
        {
            "scenario": "SCEN-NORMAL-01",
            "instance_id": instance_id,
            "start_time": base_time.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "end_time": (base_time + timedelta(minutes=30))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "expected_rule_or_detector": "none",
            "severity": "none",
            "description": "Baseline normal operation (no alert expected).",
        }
    )

    # 2. SCEN-CPU-01: Sustained High CPU (12 samples = 120s)
    cpu_start_ts = base_time + timedelta(seconds=500 * 10)
    cpu_end_ts = cpu_start_ts + timedelta(seconds=120)
    for i in range(12):
        seq += 1
        ts = (
            (cpu_start_ts + timedelta(seconds=i * 10))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        rec = {
            "schema_version": 1,
            "type": "system_metrics",
            "instance_id": instance_id,
            "agent_run_id": run_id,
            "sequence": seq,
            "timestamp": ts,
            "metrics": {
                "cpu_percent": 96.5,
                "memory_used_percent": 48.0,
                "swap_used_percent": 0.0,
                "disk_used_percent": 52.0,
                "load_1m_per_cpu": 3.8,
                "network_rx_bytes_per_sec": 1400.0,
                "network_tx_bytes_per_sec": 700.0,
                "process_count": 92,
            },
        }
        metrics_list.append(rec)

    ground_truth_list.append(
        {
            "scenario": "SCEN-CPU-01",
            "instance_id": instance_id,
            "start_time": cpu_start_ts.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "end_time": cpu_end_ts.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expected_rule_or_detector": "mad",
            "severity": "high",
            "description": "Sustained high CPU spike (~96.5% for 120s).",
        }
    )

    # Cooldown (20 samples)
    post_cpu_ts = cpu_end_ts
    for i in range(20):
        seq += 1
        ts = (
            (post_cpu_ts + timedelta(seconds=i * 10))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        rec = {
            "schema_version": 1,
            "type": "system_metrics",
            "instance_id": instance_id,
            "agent_run_id": run_id,
            "sequence": seq,
            "timestamp": ts,
            "metrics": {
                "cpu_percent": 21.0,
                "memory_used_percent": 46.0,
                "swap_used_percent": 0.0,
                "disk_used_percent": 52.0,
                "load_1m_per_cpu": 0.9,
                "network_rx_bytes_per_sec": 1200.0,
                "network_tx_bytes_per_sec": 600.0,
                "process_count": 88,
            },
        }
        metrics_list.append(rec)

    # 3. SCEN-MEM-01: Memory Pressure (12 samples = 120s)
    mem_start_ts = post_cpu_ts + timedelta(seconds=200)
    mem_end_ts = mem_start_ts + timedelta(seconds=120)
    for i in range(12):
        seq += 1
        ts = (
            (mem_start_ts + timedelta(seconds=i * 10))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        rec = {
            "schema_version": 1,
            "type": "system_metrics",
            "instance_id": instance_id,
            "agent_run_id": run_id,
            "sequence": seq,
            "timestamp": ts,
            "metrics": {
                "cpu_percent": 22.0,
                "memory_used_percent": 95.8,
                "swap_used_percent": 15.0,
                "disk_used_percent": 52.0,
                "load_1m_per_cpu": 1.1,
                "network_rx_bytes_per_sec": 1300.0,
                "network_tx_bytes_per_sec": 650.0,
                "process_count": 94,
            },
        }
        metrics_list.append(rec)

    ground_truth_list.append(
        {
            "scenario": "SCEN-MEM-01",
            "instance_id": instance_id,
            "start_time": mem_start_ts.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "end_time": mem_end_ts.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expected_rule_or_detector": "mad",
            "severity": "high",
            "description": "High memory pressure (~95.8% for 120s).",
        }
    )

    # Continue baseline to present time (100 samples)
    post_mem_ts = mem_end_ts
    for i in range(100):
        seq += 1
        ts = (
            (post_mem_ts + timedelta(seconds=i * 10))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        rec = {
            "schema_version": 1,
            "type": "system_metrics",
            "instance_id": instance_id,
            "agent_run_id": run_id,
            "sequence": seq,
            "timestamp": ts,
            "metrics": {
                "cpu_percent": 20.0,
                "memory_used_percent": 45.0,
                "swap_used_percent": 0.0,
                "disk_used_percent": 52.0,
                "load_1m_per_cpu": 0.88,
                "network_rx_bytes_per_sec": 1250.0,
                "network_tx_bytes_per_sec": 620.0,
                "process_count": 89,
            },
        }
        metrics_list.append(rec)

    # 4. SCEN-SSH-01: SSH Brute-Force (6 failed logins in 60s)
    ssh_start_ts = post_mem_ts + timedelta(seconds=300)
    ssh_end_ts = ssh_start_ts + timedelta(seconds=60)
    for i in range(6):
        ts = (
            (ssh_start_ts + timedelta(seconds=i * 8))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        sec_rec = {
            "schema_version": 1,
            "type": "ssh_failed_login",
            "instance_id": instance_id,
            "timestamp": ts,
            "metrics": {
                "source_ip": "192.168.1.100",
                "user": "admin",
                "port": 22,
                "auth_method": "password",
            },
        }
        sec_events_list.append(sec_rec)

    ground_truth_list.append(
        {
            "scenario": "SCEN-SSH-01",
            "instance_id": instance_id,
            "start_time": ssh_start_ts.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "end_time": ssh_end_ts.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expected_rule_or_detector": "SSH-001",
            "severity": "high",
            "description": "Repeated SSH authentication failure brute-force attempts.",
        }
    )

    # 5. SCEN-NET-01: Unauthorized Listening Port
    net_ts = ssh_end_ts + timedelta(seconds=200)
    sec_events_list.append(
        {
            "schema_version": 1,
            "type": "listening_ports",
            "instance_id": instance_id,
            "timestamp": net_ts.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "metrics": {
                "port": 4444,
                "proto": "tcp",
                "pid": 31337,
                "name": "nc",
            },
        }
    )
    ground_truth_list.append(
        {
            "scenario": "SCEN-NET-01",
            "instance_id": instance_id,
            "start_time": (net_ts - timedelta(seconds=10))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "end_time": (net_ts + timedelta(seconds=30))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "expected_rule_or_detector": "NET-001",
            "severity": "medium",
            "description": "Unauthorized listening port 4444/tcp detected.",
        }
    )

    # 6. SCEN-SVC-01: Watched Service Failure
    svc_ts = net_ts + timedelta(seconds=200)
    sec_events_list.append(
        {
            "schema_version": 1,
            "type": "service_status",
            "instance_id": instance_id,
            "timestamp": svc_ts.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "metrics": {
                "service": "nginx",
                "state": "failed",
            },
        }
    )
    ground_truth_list.append(
        {
            "scenario": "SCEN-SVC-01",
            "instance_id": instance_id,
            "start_time": (svc_ts - timedelta(seconds=10))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "end_time": (svc_ts + timedelta(seconds=30))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "expected_rule_or_detector": "SVC-001",
            "severity": "high",
            "description": "Critical service 'nginx' entered failed state.",
        }
    )

    # 7. SCEN-FIM-01: Critical File Integrity Change
    fim_ts = svc_ts + timedelta(seconds=200)
    sec_events_list.append(
        {
            "schema_version": 1,
            "type": "file_integrity",
            "instance_id": instance_id,
            "timestamp": fim_ts.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "metrics": {
                "path": "/etc/passwd",
                "old_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
                "new_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
        }
    )
    ground_truth_list.append(
        {
            "scenario": "SCEN-FIM-01",
            "instance_id": instance_id,
            "start_time": (fim_ts - timedelta(seconds=10))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "end_time": (fim_ts + timedelta(seconds=30))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "expected_rule_or_detector": "FIM-001",
            "severity": "critical",
            "description": "File integrity change on /etc/passwd.",
        }
    )

    return metrics_list, sec_events_list, ground_truth_list


def populate_database(
    db: Database,
    instance_id: str = "demo-ec2-host",
    base_time: datetime | None = None,
    write_ground_truth: bool = True,
    clear_existing: bool = True,
) -> dict[str, Any]:
    """Populate database with controlled scenarios and run detection pipeline."""
    if clear_existing:
        db.conn.execute("DELETE FROM metric_samples WHERE instance_id = ?", (instance_id,))
        db.conn.execute("DELETE FROM security_events WHERE instance_id = ?", (instance_id,))
        db.conn.execute("DELETE FROM anomaly_scores WHERE instance_id = ?", (instance_id,))
        db.conn.execute("DELETE FROM incidents WHERE instance_id = ?", (instance_id,))
        commit(db)

    metrics, sec_events, gt = generate_scenario_dataset(
        instance_id=instance_id, base_time=base_time
    )

    metrics_inserted = 0
    for m in metrics:
        if insert_metric_sample(db, m):
            metrics_inserted += 1

    events_inserted = 0
    for e in sec_events:
        if insert_security_event(db, e):
            events_inserted += 1

    commit(db)

    if write_ground_truth:
        record_ground_truth(gt)

    # Run detection engine immediately
    det_results = run_detection(db, instance_id=instance_id)

    return {
        "metrics_inserted": metrics_inserted,
        "security_events_inserted": events_inserted,
        "scenarios_generated": len(gt),
        "detection_results": det_results,
    }
