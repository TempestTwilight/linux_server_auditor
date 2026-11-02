# Linux Virtual Server Health & Security Auditor

**Fundamentals of Cloud Computing Course Project**  
*Academic Cloud Monitoring & Explainable Security Auditing System*

---

## 1. Overview

The **Linux Virtual Server Health and Security Auditor** is a lightweight, read-only telemetry and security auditing system designed for Linux virtual servers. Telemetry and security signals are continuously audited, validated, and analyzed to detect health deviations and security events, with clear, explainable evidence for every finding.

### Core Target Achieved: **Target B** (Course-Project Demonstration)
- **Local & Cloud Telemetry Collection**: CPU, memory, swap, disk, network, system load, and process summary.
- **Security Audit Signals**: Repeated failed SSH logins, unexpected listening ports, watched service failures, and file integrity monitoring (SHA-256).
- **SQLite Persistence**: Schema with WAL mode, parameterized queries, and retention enforcement.
- **Explainable Anomaly Detection**:
  - Robust Median Absolute Deviation (MAD) detector with rolling medians.
  - Deterministic, auditable security rule engine (`SSH-001`, `NET-001`, `SVC-001`, `FIM-001`).
  - Time-windowed incident correlation and weighted priority scoring.
- **Streamlit Dashboard**: Multi-page interface (Overview, Anomalies & Incidents, Evaluation) with live metrics, time-series charts, and one-click demo data loading.
- **Evaluation Suite**: 7 controlled test scenarios with labeled ground truth, achieving **100% precision, 100% recall, and p95 latency ≤ 10s**.

---

## 2. Architecture

```text
┌────────────────────────┐       ┌──────────────────────┐       ┌────────────────────────┐
│  Monitored EC2 Instance │──────▶│ Private S3 Telemetry │──────▶│  Monitoring Machine    │
│  (Ubuntu Server LTS)   │       │       Bucket         │       │  (Debian Workstation)  │
│                        │       │                      │       │                        │
│  • System Metrics      │       │  • Encrypted JSONL   │       │  • S3 Poller & Queue   │
│  • Security Signals    │       │  • TLS Enforced      │       │  • Schema Validator    │
│  • File Integrity (FIM)│       │  • 14-Day Retention  │       │  • Deduplicator        │
│  • Bounded Local Queue │       │  • Instance Prefixes │       │  • SQLite Storage(WAL) │
│  • Outbound HTTPS only │       └──────────────────────┘       │  • MAD & Rule Detectors│
└────────────────────────┘                                      │  • Incident Correlator │
                                                                │  • Streamlit Dashboard │
                                                                └────────────────────────┘
```

---

## 3. Quickstart & Installation

### Prerequisites
- Python 3.14 (strictly pinned in `.python-version`)
- [`uv`](https://astral.sh/uv) package and project manager

### Setup
```bash
# Clone the repository
git clone https://github.com/TempestTwilight/linux_server_auditor.git
cd linux_server_auditor

# Install dependencies into virtual environment
uv sync --all-groups
```

### Running the Test Suite
```bash
uv run pytest -v
```

---

## 4. Running the Components

### A. Run Local Telemetry Collection (Single Sample)
```bash
uv run linux-server-auditor collect-once
```

### B. Run Continuous Telemetry Agent (Daemon Mode)
```bash
uv run linux-server-auditor agent
```

### C. Run the S3 Ingestion Poller (Monitoring Side)
```bash
uv run linux-server-auditor monitor
```

### D. Launch the Streamlit Dashboard
```bash
uv run streamlit run src/linux_server_auditor/dashboard/app.py
```
Open your browser to `http://localhost:8501`.

---

## 5. Controlled Test Scenarios & Evaluation

The system includes a reproducible suite of controlled test scenarios with labeled ground truth timestamps (`data/ground_truth.csv`):

```bash
# 1. Inject the controlled test scenarios into the SQLite database
uv run python scripts/inject_scenario.py --demo

# 2. Run the quantitative evaluation against ground truth
uv run python scripts/evaluate.py
```

### Evaluated Scenarios Catalog

| Scenario ID | Condition Injected | Expected Detector | Target B Outcome | Latency |
|---|---|---|---|---|
| `SCEN-NORMAL-01` | Baseline normal operation | None (zero alerts) | **PASS** (0 FP) | N/A |
| `SCEN-CPU-01` | Sustained CPU spike (~96% for 120s) | `mad` (cpu_percent) | **PASS** (TP) | 0.0s |
| `SCEN-MEM-01` | Memory leak pressure (~96% for 120s)| `mad` (memory_percent) | **PASS** (TP) | 0.0s |
| `SCEN-SSH-01` | 6 failed SSH logins from one IP in 60s | `SSH-001` | **PASS** (TP) | 0.0s |
| `SCEN-NET-01` | Unauthorized port listening (4444/tcp)| `NET-001` | **PASS** (TP) | 10.0s |
| `SCEN-SVC-01` | Critical service enters failed state | `SVC-001` | **PASS** (TP) | 10.0s |
| `SCEN-FIM-01` | Critical watchlist file hash changed | `FIM-001` | **PASS** (TP) | 10.0s |

**Evaluation Metrics Summary:**
- **Overall Precision**: 1.00 (100%)
- **Overall Recall**: 1.00 (100%)
- **F1 Score**: 1.00
- **Median Latency**: 5.0s
- **P95 Latency**: 10.0s

---

## 6. Safety & Project Boundaries

- **Strictly Read-Only**: The agent does not execute remediation, kill processes, modify firewall rules, or make destructive cloud mutations.
- **Data Minimization**: Password hashes, tokens, user credentials, and command-line arguments are never logged or transmitted.
- **Zero Secrets**: AWS credentials and private keys are never committed. Telemetry is authenticated through EC2 IAM instance profiles and dedicated read-only identities.
