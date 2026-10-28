"""Main agent loop — orchestrates sampling, batching, uploading.

Run modes:
  run(once=False)  — continuous loop (Week 2+ / systemd service)
  run(once=True)   — single sample cycle, flush batch, exit (Week 1 / testing)
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any

from linux_server_auditor import config as cfg
from linux_server_auditor.agent import (
    file_integrity,
    process_metrics,
    security_signals,
    system_metrics,
)
from linux_server_auditor.agent.batcher import Batcher

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

_REPO_ROOT = Path(__file__).parents[3]  # agent → linux_server_auditor → src → repo root


def _instance_id() -> str:
    configured = cfg.settings["agent"].get("instance_id")
    if configured:
        return configured
    # On EC2, fetch from IMDSv2
    try:
        import urllib.request

        token_req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
            method="PUT",
        )
        with urllib.request.urlopen(token_req, timeout=2) as r:
            token = r.read().decode()
        meta_req = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/instance-id",
            headers={"X-aws-ec2-metadata-token": token},
        )
        with urllib.request.urlopen(meta_req, timeout=2) as r:
            return r.read().decode()
    except (OSError, ValueError):  # network unavailable, not on EC2, etc.
        return os.uname().nodename


def _make_record(payload: dict[str, Any], iid: str, run_id: str, seq: int) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "record_id": str(uuid.uuid4()),
        "agent_run_id": run_id,
        "instance_id": iid,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sequence": seq,
        **payload,
    }


def run(once: bool = False) -> None:
    acfg = cfg.settings["agent"]
    interval = acfg["sampling_interval_sec"]
    iid = _instance_id()
    run_id = str(uuid.uuid4())
    output_dir = _REPO_ROOT / acfg["local_queue_dir"].replace("data/", "data/raw/")
    batcher = Batcher(output_dir, batch_duration_sec=acfg["batch_duration_sec"])
    seq = 0

    log.info("agent start: instance=%s run=%s", iid, run_id)

    while True:
        seq += 1
        try:
            records = [
                _make_record(system_metrics.collect(interval_sec=1.0), iid, run_id, seq),
                _make_record(process_metrics.collect(), iid, run_id, seq),
                _make_record(security_signals.collect(), iid, run_id, seq),
                _make_record(file_integrity.collect(), iid, run_id, seq),
            ]
        except (OSError, RuntimeError):
            log.exception("collection error at seq=%d", seq)
            records = []

        for rec in records:
            batch_path = batcher.add(rec)
            if batch_path:
                log.info("batch ready: %s (%d bytes)", batch_path.name, batch_path.stat().st_size)
                # Week 2: uploader.upload(batch_path) goes here

        if once:
            path = batcher.flush()
            if path:
                log.info("flushed: %s", path)
            break

        sleep_for = max(0.0, interval - 1.0)  # subtract time already spent in cpu_percent
        time.sleep(sleep_for)
