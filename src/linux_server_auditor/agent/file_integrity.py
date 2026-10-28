"""File integrity monitoring — SHA-256 of watchlist paths."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).parents[3]  # agent → linux_server_auditor → src → repo root
_WATCHLIST_PATH = _REPO_ROOT / "config" / "file_watchlist.yaml"


def _load_watchlist() -> list[str]:
    with _WATCHLIST_PATH.open() as f:
        return yaml.safe_load(f) or []


def _sha256(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def collect() -> dict[str, Any]:
    watchlist = _load_watchlist()
    entries = [{"path": p, "sha256": _sha256(p)} for p in watchlist]
    return {
        "type": "file_integrity",
        "metrics": {"files": entries},
    }
