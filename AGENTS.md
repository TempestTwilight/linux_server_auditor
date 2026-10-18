# Linux Server Health and Security Auditor

Academic cloud-computing project. A Python agent runs on an AWS EC2 Ubuntu instance, collects system metrics and security events, uploads batches to a private S3 bucket, and a separate Debian monitoring machine pulls them down, validates, stores in SQLite, runs detectors, and serves a local Streamlit dashboard. **Read-only** — no remote remediation actions.

## Architecture

```
EC2 (Ubuntu) → agent → S3 bucket → monitoring machine (Debian) → SQLite → detectors → Streamlit
```

Two deployment contexts, one codebase:
- **Agent** (runs on EC2): telemetry collection via `psutil`, batch upload via `boto3`
- **Monitor** (runs locally): S3 poller, schema validation, SQLite ingestion, statistical + ML detectors (IsolationForest via `scikit-learn`), incident correlator, Streamlit dashboard

## Dev environment

```bash
# Python 3.14.0 strictly required (.python-version pins it)
uv sync --all-groups        # install all deps including dev group
source .venv/bin/activate   # activate venv
```

AWS credentials must be in environment or `~/.aws/` before any S3 code runs. The agent uses an IAM role (EC2 instance profile); the monitoring machine uses an IAM user with read-only S3 access.

## Build & test

```bash
uv run pytest                        # run all tests
uv run pytest --cov=linux_server_auditor  # with coverage
uv run ruff check src/               # lint
uv run ruff format src/              # format (check only: --check)
uv run ty check src/                 # type check (ty, not mypy)
uv run linux-server-auditor          # CLI entry point
```

Streamlit dashboard (monitoring machine only):
```bash
uv run streamlit run src/linux_server_auditor/dashboard.py
```
Dashboard binds to `localhost` only — do not expose externally.

## Project layout

```
src/linux_server_auditor/
  __init__.py          # main() entry point
  agent/               # EC2-side: collection, batching, S3 upload
  monitor/             # Laptop-side: S3 poll, validation, SQLite, detectors
  dashboard.py         # Streamlit app
tests/
.planning/             # Design docs (gitignored, do not edit generated outputs)
```

## Conventions

- `src/` layout; package is `linux_server_auditor`
- Type checker is `ty` (not mypy); linter/formatter is `ruff`
- SQLite is the only database — no ORM
- Detectors are stateless functions over pandas DataFrames from SQLite queries
- Agent is read-only at runtime: no process kills, no firewall changes, no AWS mutations beyond S3 `PutObject`
- Batch format: NDJSON; each record has `timestamp` (ISO 8601 UTC), `host_id`, `metric_type`, and `value`

## Pitfalls

- `requires-python = "==3.14.0"` (exact pin) — `uv sync` will fail if your active Python differs; check `.python-version`
- `.planning/` is gitignored — do not put code or configs there
- Agent local queue caps at 500 MB or 24 h of batches; `queue_overflow` events mark data loss
- Telemetry marked **stale** after 5 min on dashboard — expected during dev when agent isn't running
- No `pip` module on system Python 3.14; always use `uv run` or activate the venv
- `boto3` calls require AWS credentials; tests touching S3 need mocking (e.g. `moto`)
