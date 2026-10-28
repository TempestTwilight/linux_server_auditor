-- SQLite schema for linux_server_auditor telemetry storage
-- Enable WAL mode for concurrent reads/writes

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

-- System metrics samples
CREATE TABLE IF NOT EXISTS metric_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL,
    agent_run_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    cpu_percent REAL,
    memory_used_percent REAL,
    swap_used_percent REAL,
    disk_used_percent REAL,
    load_1m_per_cpu REAL,
    network_rx_bytes_per_sec REAL,
    network_tx_bytes_per_sec REAL,
    process_count INTEGER,
    schema_version INTEGER NOT NULL DEFAULT 1,
    UNIQUE (instance_id, agent_run_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_metric_samples_instance_ts
    ON metric_samples (instance_id, timestamp);

-- Security events (SSH logins, listening ports, service status, file integrity)
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_data TEXT NOT NULL,  -- JSON blob
    schema_version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_security_events_instance_type_ts
    ON security_events (instance_id, event_type, timestamp);

-- Anomaly scores from detectors
CREATE TABLE IF NOT EXISTS anomaly_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    detector TEXT NOT NULL,
    feature TEXT NOT NULL,
    value REAL,
    score REAL NOT NULL,
    threshold REAL NOT NULL,
    is_anomaly INTEGER NOT NULL DEFAULT 0,
    model_version TEXT,
    schema_version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_anomaly_scores_instance_ts_detector
    ON anomaly_scores (instance_id, timestamp, detector);

-- Incidents (aggregated findings)
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,  -- UUID
    instance_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    priority_score REAL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    finding_count INTEGER NOT NULL DEFAULT 1,
    evidence TEXT,  -- JSON blob
    resolution_notes TEXT
);

-- Track processed S3 batches for deduplication
CREATE TABLE IF NOT EXISTS processed_batches (
    s3_key TEXT PRIMARY KEY,
    etag TEXT,
    processed_at TEXT NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0
);

-- Monitor heartbeat
CREATE TABLE IF NOT EXISTS monitor_heartbeats (
    timestamp TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'alive'
);
