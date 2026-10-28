"""Security signals: SSH failed logins, listening ports, service status."""

from __future__ import annotations

import re
import subprocess
from typing import Any

import psutil

# ── SSH failed logins ────────────────────────────────────────────────────────

_SSH_FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port \d+ ssh2"
)
_JOURNAL_CMD = ["journalctl", "-u", "ssh", "--since", "5 minutes ago", "--no-pager", "-q"]


def _ssh_failures() -> list[dict[str, Any]]:
    """Parse recent SSH failures from journald. Empty list if unavailable."""
    try:
        out = subprocess.check_output(_JOURNAL_CMD, text=True, stderr=subprocess.DEVNULL)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []
    events = []
    for line in out.splitlines():
        m = _SSH_FAIL_RE.search(line)
        if m:
            events.append({"user": m.group(1), "source_ip": m.group(2)})
    return events


# ── Listening ports ──────────────────────────────────────────────────────────


def _listening_ports() -> list[dict[str, Any]]:
    ports = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == psutil.CONN_LISTEN:
            try:
                proc = psutil.Process(conn.pid) if conn.pid else None
                name = proc.name() if proc else None
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = None
            laddr = conn.laddr
            ports.append(
                {
                    "port": laddr.port if laddr else None,
                    "proto": "tcp",
                    "pid": conn.pid,
                    "name": name,
                }
            )
    return ports


# ── Service status ───────────────────────────────────────────────────────────

_WATCHED_SERVICES = ["ssh", "sshd", "cron", "rsyslog"]


def _service_status() -> list[dict[str, Any]]:
    statuses = []
    for svc in _WATCHED_SERVICES:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", svc],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            statuses.append({"service": svc, "state": result.stdout.strip()})
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    return statuses


# ── Public API ────────────────────────────────────────────────────────────────


def collect() -> dict[str, Any]:
    return {
        "type": "security_signals",
        "metrics": {
            "ssh_failed_logins": _ssh_failures(),
            "listening_ports": _listening_ports(),
            "service_status": _service_status(),
        },
    }
