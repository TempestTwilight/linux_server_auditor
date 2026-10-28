"""Batch writer — accumulates records for batch_duration_sec, flushes to JSONL file."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class Batcher:
    """Accumulates records into in-memory buffer, writes JSONL when window closes."""

    def __init__(self, output_dir: Path, batch_duration_sec: int = 30) -> None:
        self._out = output_dir
        self._out.mkdir(parents=True, exist_ok=True)
        self._duration = batch_duration_sec
        self._buf: list[dict[str, Any]] = []
        self._window_start = time.monotonic()

    def add(self, record: dict[str, Any]) -> Path | None:
        """Add record. Returns written file path if batch was flushed, else None."""
        self._buf.append(record)
        if time.monotonic() - self._window_start >= self._duration:
            return self.flush()
        return None

    def flush(self) -> Path | None:
        """Force-write current buffer. Returns path or None if buffer is empty."""
        if not self._buf:
            return None
        ts = int(time.time())
        path = self._out / f"batch_{ts}.jsonl"
        with path.open("w") as f:
            for rec in self._buf:
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")
        self._buf = []
        self._window_start = time.monotonic()
        return path
