"""Package-level entry points."""

from __future__ import annotations

import sys


def main() -> None:
    """CLI entry point — runs the agent or monitor depending on argv."""
    if len(sys.argv) < 2 or sys.argv[1] not in {"agent", "monitor", "collect-once"}:
        print("usage: linux-server-auditor agent|monitor|collect-once")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd in {"agent", "collect-once"}:
        from linux_server_auditor.agent.collector import run

        run(once=cmd == "collect-once")
    elif cmd == "monitor":
        from linux_server_auditor.ingestion.s3_poller import run_poller

        run_poller()
