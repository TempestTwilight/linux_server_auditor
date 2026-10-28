#!/usr/bin/env python3
"""Inject test scenarios (CPU spike, memory leak, SSH brute-force, new port, service stop, file change)."""

from __future__ import annotations

import csv
import hashlib
import socket
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
GROUND_TRUTH_CSV = REPO_ROOT / "data" / "ground_truth.csv"


def inject_cpu_spike(duration_sec: int = 30):
    """Busy loop CPU spike."""
    print(f"Injecting CPU spike for {duration_sec}s...")
    start = time.time()
    while time.time() - start < duration_sec:
        _ = sum(i**2 for i in range(10000))
    print("CPU spike complete.")
    return "cpu_spike", "mad"


def inject_memory_pressure(duration_sec: int = 30, size_mb: int = 100):
    """Allocate large array."""
    print(f"Injecting memory pressure ({size_mb}MB) for {duration_sec}s...")
    data = bytearray(size_mb * 1024 * 1024)
    time.sleep(duration_sec)
    del data
    print("Memory pressure complete.")
    return "memory_pressure", "mad"


def inject_ssh_brute_force(count: int = 10):
    """Write fake auth.log lines."""
    print(f"Injecting {count} fake SSH failed login events...")
    # ponytail: writes to tmp file, real scenario would inject into DB
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_auth.log")
    for i in range(count):
        tmp.write(f"Jan 1 12:00:{i:02d} host sshd[1234]: Failed password for invalid user admin from 192.168.1.100\n")
    tmp.close()
    print(f"Wrote fake auth.log to {tmp.name}")
    return "ssh_brute_force", "SSH-001"


def inject_new_port():
    """Start a socket server on random high port."""
    print("Injecting new listening port...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    print(f"Listening on port {port}. Press Ctrl+C to stop.")
    print("(In real scenario, this would be detected via listening_ports event)")
    try:
        time.sleep(60)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    return "new_listening_port", "NET-001"


def inject_file_change():
    """Modify a temp file's hash."""
    print("Injecting file integrity change...")
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_watchfile")
    tmp.write("original content")
    tmp.close()
    
    old_hash = hashlib.sha256(Path(tmp.name).read_bytes()).hexdigest()
    time.sleep(1)
    Path(tmp.name).write_text("modified content")
    new_hash = hashlib.sha256(Path(tmp.name).read_bytes()).hexdigest()
    
    print(f"File {tmp.name} hash changed: {old_hash[:8]} -> {new_hash[:8]}")
    return "file_integrity_change", "FIM-001"


def record_ground_truth(scenario: str, expected_detector: str, start_time: datetime, end_time: datetime):
    """Append to ground_truth.csv."""
    GROUND_TRUTH_CSV.parent.mkdir(parents=True, exist_ok=True)
    
    write_header = not GROUND_TRUTH_CSV.exists()
    with GROUND_TRUTH_CSV.open("a") as f:
        writer = csv.DictWriter(f, fieldnames=["scenario", "start_time", "end_time", "expected_rule_or_detector"])
        if write_header:
            writer.writeheader()
        writer.writerow({
            "scenario": scenario,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "expected_rule_or_detector": expected_detector,
        })


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Inject test scenarios")
    parser.add_argument("scenario", choices=["cpu_spike", "memory_pressure", "ssh_brute", "new_port", "file_change"])
    args = parser.parse_args()
    
    start = datetime.now(timezone.utc)
    
    if args.scenario == "cpu_spike":
        scenario, detector = inject_cpu_spike()
    elif args.scenario == "memory_pressure":
        scenario, detector = inject_memory_pressure()
    elif args.scenario == "ssh_brute":
        scenario, detector = inject_ssh_brute_force()
    elif args.scenario == "new_port":
        scenario, detector = inject_new_port()
    elif args.scenario == "file_change":
        scenario, detector = inject_file_change()
    
    end = datetime.now(timezone.utc)
    record_ground_truth(scenario, detector, start, end)
    print(f"Ground truth recorded to {GROUND_TRUTH_CSV}")


if __name__ == "__main__":
    main()
