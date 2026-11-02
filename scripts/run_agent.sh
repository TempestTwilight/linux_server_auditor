#!/usr/bin/env bash
# run_agent.sh — For manual/dev runs. Activates venv and starts the agent loop.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT"
. .venv/bin/activate
exec linux-server-auditor agent
