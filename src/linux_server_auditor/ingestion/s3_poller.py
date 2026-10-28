"""S3 poller — downloads telemetry batches, validates, deduplicates, persists to SQLite."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

from linux_server_auditor.config import settings
from linux_server_auditor.ingestion.deduplicator import DedupTracker, dedup_key
from linux_server_auditor.ingestion.validator import validate_batch
from linux_server_auditor.storage.database import Database
from linux_server_auditor.storage.repositories import (
    commit,
    insert_metric_sample,
    insert_security_event,
    is_batch_processed,
    mark_batch_processed,
    record_heartbeat,
)

log = logging.getLogger(__name__)

# Record type to handler mapping
METRIC_TYPES = {"system_metrics"}
SECURITY_TYPES = {"process_metrics", "security_signals", "file_integrity"}


class S3Poller:
    """Polls S3 for telemetry batches and persists to SQLite."""

    def __init__(self, db: Database | None = None) -> None:
        self.db = db or Database()
        self.dedup = DedupTracker()
        self._running = False

        s3_cfg = settings.get("s3", {})
        self.bucket = s3_cfg.get("bucket")
        self.prefix = s3_cfg.get("prefix", "telemetry")
        self.region = s3_cfg.get("region", "ap-south-1")
        self.poll_interval = settings.get("monitor", {}).get("s3_poll_interval_sec", 30)

        if not self.bucket:
            log.warning("S3 bucket not configured. Poller will not run.")
            self.s3 = None
        else:
            self.s3 = boto3.client("s3", region_name=self.region)

    def list_new_batches(self, instance_id: str | None = None) -> list[dict[str, Any]]:
        """List unprocessed S3 objects under prefix/instance_id/."""
        if not self.s3 or not self.bucket:
            return []

        prefix = f"{self.prefix}/"
        if instance_id:
            prefix = f"{self.prefix}/{instance_id}/"

        try:
            resp = self.s3.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
        except ClientError as e:
            log.error("Failed to list S3 objects: %s", e)
            return []

        contents = resp.get("Contents", [])
        batches = []
        for obj in contents:
            key = obj["Key"]
            if is_batch_processed(self.db, key):
                continue
            batches.append({
                "key": key,
                "etag": obj.get("ETag", "").strip('"'),
                "size": obj.get("Size", 0),
                "last_modified": obj.get("LastModified"),
            })
        return batches

    def download_batch(self, key: str) -> bytes | None:
        """Download a batch file from S3."""
        if not self.s3 or not self.bucket:
            return None
        try:
            resp = self.s3.get_object(Bucket=self.bucket, Key=key)
            return resp["Body"].read()
        except ClientError as e:
            log.error("Failed to download %s: %s", key, e)
            return None

    def parse_batch(self, data: bytes) -> list[dict[str, Any]]:
        """Parse JSONL batch data."""
        records = []
        for line in data.decode("utf-8").strip().split("\n"):
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                log.warning("Failed to parse JSON line: %s", e)
        return records

    def process_batch(self, key: str, etag: str | None, data: bytes) -> int:
        """Process a single batch. Returns count of stored records."""
        records = self.parse_batch(data)
        if not records:
            mark_batch_processed(self.db, key, etag, 0)
            commit(self.db)
            return 0

        # Validate
        valid_records, errors = validate_batch(records, len(data))
        for err in errors:
            log.warning("Validation error in %s: %s", key, err)

        if not valid_records:
            mark_batch_processed(self.db, key, etag, 0)
            commit(self.db)
            return 0

        # Deduplicate
        unique_records, dup_errors = self.dedup.filter(valid_records)
        for err in dup_errors:
            log.warning("Dedup error in %s: %s", key, err)

        # Store
        stored = 0
        for record in unique_records:
            rtype = record.get("type")
            if rtype in METRIC_TYPES:
                if insert_metric_sample(self.db, record):
                    stored += 1
            elif rtype in SECURITY_TYPES:
                if insert_security_event(self.db, record):
                    stored += 1
            else:
                log.debug("Unknown record type: %s", rtype)

        # Mark processed
        mark_batch_processed(self.db, key, etag, stored)
        commit(self.db)
        return stored

    def poll_once(self) -> int:
        """Single poll cycle. Returns total records stored."""
        if not self.s3 or not self.bucket:
            log.debug("S3 not configured, skipping poll")
            return 0

        batches = self.list_new_batches()
        if not batches:
            log.debug("No new batches to process")
            return 0

        total_stored = 0
        for batch in batches:
            key = batch["key"]
            etag = batch.get("etag")
            log.info("Processing batch: %s", key)

            data = self.download_batch(key)
            if data is None:
                continue

            stored = self.process_batch(key, etag, data)
            total_stored += stored
            log.info("Processed %s: %d records stored", key, stored)

        return total_stored

    def run(self) -> None:
        """Run the poller loop."""
        if not self.bucket:
            log.error("S3 bucket not configured. Set s3.bucket in config/settings.yaml")
            return

        self._running = True
        log.info("Starting S3 poller (bucket=%s, prefix=%s)", self.bucket, self.prefix)

        while self._running:
            try:
                record_heartbeat(self.db)
                commit(self.db)
                self.poll_once()
                self.db.run_retention()  # Run retention on each cycle
            except Exception as e:
                log.exception("Poller error: %s", e)

            time.sleep(self.poll_interval)

    def stop(self) -> None:
        """Stop the poller loop."""
        self._running = False


def run_poller() -> None:
    """Entry point for running the S3 poller."""
    poller = S3Poller()
    poller.run()
