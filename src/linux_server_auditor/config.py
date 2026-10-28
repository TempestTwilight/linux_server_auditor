"""Config loader — reads config/settings.yaml relative to the repo root."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).parent.parent.parent  # linux_server_auditor → src → repo root
_CONFIG_DIR = _REPO_ROOT / "config"


def load(name: str = "settings") -> dict[str, Any]:
    path = _CONFIG_DIR / f"{name}.yaml"
    with path.open() as f:
        return yaml.safe_load(f)


# Module-level singletons so callers just do `from linux_server_auditor.config import settings`
settings: dict[str, Any] = load("settings")
thresholds: dict[str, Any] = load("thresholds")
