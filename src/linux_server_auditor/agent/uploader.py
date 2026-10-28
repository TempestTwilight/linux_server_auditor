"""S3 uploader with exponential-backoff retries and bounded local queue.

Queue invariants:
- Files are moved to queue/ after first failed upload.
- Queue is capped at local_queue_max_bytes OR local_queue_max_age_sec.
- On overflow, oldest batches are deleted and a queue_overflow event is emitted.
- A batch is deleted from disk only after S3 returns success.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError

log = logging.getLogger(__name__)


class Uploader:
    def __init__(
        self,
        bucket: str,
        prefix: str,
        instance_id: str,
        queue_dir: Path,
        max_queue_bytes: int = 524_288_000,  # 500 MB
        max_queue_age_sec: int = 86_400,  # 24 h
        region: str = "ap-south-1",
    ) -> None:
        self._bucket = bucket
        self._prefix = prefix
        self._instance_id = instance_id
        self._queue = queue_dir
        self._queue.mkdir(parents=True, exist_ok=True)
        self._max_bytes = max_queue_bytes
        self._max_age = max_queue_age_sec
        self._s3 = boto3.client("s3", region_name=region)

    # ── public ────────────────────────────────────────────────────────────────

    def upload(self, batch_path: Path) -> bool:
        """Try to upload batch_path. Queue it on failure. Returns True on success."""
        self._drain_queue()
        return self._try_upload(batch_path, retries=3)

    # ── private ───────────────────────────────────────────────────────────────

    def _s3_key(self, path: Path) -> str:
        return f"{self._prefix}/{self._instance_id}/{path.name}"

    def _try_upload(self, path: Path, retries: int) -> bool:
        for attempt in range(retries):
            try:
                self._s3.upload_file(str(path), self._bucket, self._s3_key(path))
                path.unlink(missing_ok=True)
                return True
            except (BotoCoreError, ClientError, OSError) as e:
                wait = 2**attempt
                log.warning("upload attempt %d failed (%s); retrying in %ds", attempt + 1, e, wait)
                time.sleep(wait)
        self._enqueue(path)
        return False

    def _enqueue(self, path: Path) -> None:
        dest = self._queue / path.name
        path.rename(dest)
        log.info("queued %s", dest.name)
        self._enforce_queue_limit()

    def _drain_queue(self) -> None:
        for f in sorted(self._queue.glob("batch_*.jsonl")):
            if self._try_upload(f, retries=1):
                log.info("drained queued batch %s", f.name)

    def _enforce_queue_limit(self) -> None:
        files = sorted(self._queue.glob("batch_*.jsonl"), key=lambda f: f.stat().st_mtime)
        now = time.time()
        total = sum(f.stat().st_size for f in files)
        overflow = False
        while files and (
            total > self._max_bytes or (now - files[0].stat().st_mtime) > self._max_age
        ):
            oldest = files.pop(0)
            total -= oldest.stat().st_size
            oldest.unlink(missing_ok=True)
            overflow = True
            log.error("queue overflow: evicted %s", oldest.name)
        if overflow:
            self._emit_overflow_event()

    def _emit_overflow_event(self) -> None:
        record = {
            "schema_version": 1,
            "record_id": str(uuid.uuid4()),
            "type": "queue_overflow",
            "instance_id": self._instance_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        log.error("queue_overflow event: %s", json.dumps(record))
