"""System metrics collection via psutil.

Collected metrics per sample:
  cpu_percent, memory_used_percent, swap_used_percent,
  disk_used_percent, load_1m_per_cpu,
  network_rx_bytes_per_sec, network_tx_bytes_per_sec,
  process_count
"""

from __future__ import annotations

from typing import Any

import psutil


def _net_counters() -> tuple[int, int]:
    c = psutil.net_io_counters()
    return c.bytes_recv, c.bytes_sent


def collect(interval_sec: float = 1.0) -> dict[str, Any]:
    """Return one system_metrics record.

    Measures network delta over *interval_sec* so rx/tx are per-second rates.
    CPU percent is measured non-blocking (uses psutil interval internally).
    """
    rx0, tx0 = _net_counters()
    cpu = psutil.cpu_percent(interval=interval_sec)  # blocks for interval_sec
    rx1, tx1 = _net_counters()

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    load1, *_ = psutil.getloadavg()
    cpu_count = psutil.cpu_count(logical=True) or 1

    return {
        "type": "system_metrics",
        "metrics": {
            "cpu_percent": round(cpu, 2),
            "memory_used_percent": round(mem.percent, 2),
            "swap_used_percent": round(swap.percent, 2),
            "disk_used_percent": round(disk.percent, 2),
            "load_1m_per_cpu": round(load1 / cpu_count, 4),
            "network_rx_bytes_per_sec": round((rx1 - rx0) / interval_sec, 1),
            "network_tx_bytes_per_sec": round((tx1 - tx0) / interval_sec, 1),
            "process_count": len(psutil.pids()),
        },
    }
