"""Database wrapper with WAL mode and retention."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from linux_server_auditor.config import settings

log = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class Database:
    """SQLite database with WAL mode."""

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path or settings["monitor"]["db_path"])
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._init_schema()
        return self._conn

    def _init_schema(self) -> None:
        schema_sql = SCHEMA_PATH.read_text()
        self._conn.executescript(schema_sql)
        self._conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def run_retention(self) -> int:
        """Delete old records based on retention_days. Returns deleted count."""
        days = settings["monitor"]["retention_days"]
        cutoff = f"datetime('now', '-{days} days')"
        deleted = 0
        for table in ("metric_samples", "security_events"):
            cur = self.conn.execute(
                f"DELETE FROM {table} WHERE timestamp < {cutoff}"
            )
            deleted += cur.rowcount
        self.conn.commit()
        if deleted:
            log.info("Retention deleted %d records older than %d days", deleted, days)
        return deleted

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *args) -> None:
        self.close()
