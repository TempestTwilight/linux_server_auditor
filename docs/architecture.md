# Architecture

## System Overview

The Linux Server Auditor is a distributed monitoring system for EC2 instances. It consists of:

1. **Agent** (on EC2): Collects system metrics and security events every 10s, batches telemetry into JSONL files every 30s, uploads to S3
2. **S3 bucket**: Persistent queue for telemetry (encrypted at rest, lifecycle policy for cleanup)
3. **Monitor** (on Debian workstation): Polls S3 every 30s, validates telemetry, stores in SQLite, runs anomaly detectors
4. **Dashboard** (Streamlit): Real-time visibility into system state, anomalies, and incidents

```
┌────────────────┐       ┌─────────────┐       ┌──────────────────┐
│  EC2 Instance  │──────▶│  S3 Bucket  │──────▶│ Monitor Machine  │
│                │       │             │       │  (Debian)        │
│  • Collector   │       │  • JSONL    │       │  • S3 Poller     │
│  • Batcher     │       │  • Prefix   │       │  • Validator     │
│  • Uploader    │       │  • Lifecycle│       │  • SQLite        │
└────────────────┘       └─────────────┘       │  • Detectors     │
                                                │  • Dashboard     │
                                                └──────────────────┘
```

## Components

### Agent (EC2)

- **system_metrics.py**: psutil-based CPU, memory, disk, network, load sampling
- **security_signals.py**: Monitors auth logs for failed SSH attempts, sudo events
- **file_integrity.py**: SHA256 hashes of critical system files
- **process_metrics.py**: Top processes by CPU/memory
- **batcher.py**: Aggregates samples into 30s JSONL batches with sequence numbers
- **uploader.py**: Uploads batches to S3, retries with exponential backoff, persists queue to disk

### Monitor (Debian)

- **s3_poller.py**: Lists S3 prefix, downloads new batches, deletes after processing
- **storage**: SQLite schema for metric_samples, security_events, anomaly_scores, incidents
- **detection**: Statistical detectors (MAD-based) and rule-based detectors (security events)

### Dashboard (Streamlit)

- **Overview**: Latest telemetry, 6h metric charts, connectivity status
- **Anomalies & Incidents**: Timeline, per-anomaly detail, incident list with priority
- **Evaluation**: Placeholder for test results (precision, recall, latency, overhead)

## Data Flow

1. Agent samples every 10s → in-memory batch
2. Every 30s: batch written to JSONL → uploaded to S3
3. Monitor polls S3 every 30s → downloads new batches → validates schema
4. Valid samples inserted into SQLite
5. Detectors run on new data → anomaly_scores and incidents tables updated
6. Dashboard queries SQLite for real-time display

## Technology Choices

- **Python 3.14**: Modern async support, type hints, performance
- **psutil**: Cross-platform system metrics (agent overhead ~2% CPU, 50 MB RAM)
- **boto3**: AWS SDK for S3 uploads/downloads (official, stable, IAM-integrated)
- **SQLite**: Embedded DB for monitor (low overhead, ACID, no server, sufficient for single-instance monitoring)
- **Streamlit**: Rapid dashboard development (reactive, no frontend code, built-in charting via plotly)
- **Pandas**: DataFrame API for query results (interoperates with SQLite and Streamlit)
- **Plotly**: Interactive charts (zoom, hover, responsive)

## Security Architecture

- **IAM Roles**: EC2 instance profile with write-only S3 access (PutObject on prefix), monitor credentials with read-delete access
- **Least Privilege**: Agent cannot read other instances' telemetry, monitor cannot write to S3
- **Encryption**: S3 bucket default encryption (SSE-S3), SQLite on encrypted filesystem
- **No Secrets in Code**: Credentials from environment (AWS_PROFILE, instance metadata service)
- **Audit Trail**: S3 access logs enabled, CloudTrail for API calls

## Scalability

Current design: single EC2 instance, single monitor. To scale:

- Multi-instance: Partition S3 prefix by instance_id, monitor filters by prefix
- Multi-monitor: Leader election (DynamoDB lock) or partition by instance
- Time-series DB: Migrate from SQLite to TimescaleDB/InfluxDB for multi-instance aggregation
