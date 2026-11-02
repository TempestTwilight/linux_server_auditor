# Evaluation Methodology

## Objectives

Validate that the Linux Server Auditor:
1. Detects CPU spikes, memory exhaustion, and disk space issues
2. Detects security events (failed SSH logins, sudo escalation)
3. Maintains low false-positive rate during normal operation
4. Detects anomalies within acceptable latency
5. Runs with minimal overhead on the monitored instance

## Test Scenarios

| Scenario | Condition | Expected Detection | Metric |
|----------|-----------|-------------------|--------|
| CPU spike | Sustained 95%+ CPU for 60s | Statistical detector flags cpu_percent | Latency < 90s |
| Memory exhaustion | Memory usage > 90% for 60s | Statistical detector flags memory_used_percent | Latency < 90s |
| Disk space | Disk usage > 85% | Statistical detector flags disk_used_percent | Latency < 90s |
| SSH brute force | 5+ failed SSH attempts in 60s | Rule-based detector creates incident | Latency < 60s |
| Sudo escalation | Sudo event in auth logs | Security event logged | Latency < 30s |
| Normal operation | Baseline workload for 24h | False positive rate < 1 alert/hour | Count false alerts |

## Methodology

### 1. Detection Performance

**Setup**: Inject synthetic anomalies into test data (in-memory SQLite).

**Procedure**:
1. Generate 24h of baseline telemetry (CPU 10-30%, memory 40-60%, no security events)
2. Inject anomalies at known timestamps:
   - CPU spike: 95% for 120s at hour 6
   - Memory spike: 92% for 90s at hour 12
   - SSH failures: 8 attempts over 60s at hour 18
3. Run detectors on full dataset
4. Compare detected anomalies to ground truth

**Metrics**:
- **Precision**: TP / (TP + FP) — what fraction of alerts are real
- **Recall**: TP / (TP + FN) — what fraction of real anomalies are detected
- **F1**: Harmonic mean of precision and recall

Calculate at two levels:
- **Event-level**: Each individual anomaly score/security event
- **Window-level**: 5-minute windows (did we detect *something* in the window?)

### 2. False Positive Rate

**Setup**: 24h baseline data with no injected anomalies.

**Procedure**:
1. Run detectors on baseline data
2. Count alerts (is_anomaly = 1 in anomaly_scores table)
3. Manually review each alert to confirm false positive

**Target**: < 1 false alert per hour (acceptable for academic project; production would aim for < 0.1/hour).

### 3. Detection Latency

**Setup**: Inject anomalies with known start times.

**Procedure**:
1. For each injected anomaly, record true start timestamp
2. Find first detection timestamp in anomaly_scores table
3. Calculate latency = detection_time - start_time

**Metrics**:
- Median latency (p50)
- 95th percentile latency (p95)

**Target**: p95 < 90s (3 sampling intervals + 1 batch upload + 1 poll cycle).

### 4. Agent Overhead

**Setup**: Run agent on idle EC2 instance for 1 hour.

**Procedure**:
1. Measure baseline CPU/memory before starting agent
2. Start agent, let run for 1 hour
3. Measure agent process CPU/memory (via psutil)

**Target**:
- CPU < 5% average
- Memory < 100 MB

### 5. Telemetry Loss Rate

**Setup**: Run full pipeline (agent → S3 → monitor) for 1 hour.

**Procedure**:
1. Agent logs every batch upload with sequence number
2. Monitor logs every batch ingested
3. Compare agent_sent vs monitor_received counts

**Metric**: Loss rate = (sent - received) / sent

**Target**: < 1% loss (acceptable for S3 + network + retry logic).

## Results

### Detection Performance (Target B Ground-Truth Evaluation)

| Detector | TP | FP | FN | Precision | Recall | F1 Score |
|----------|----|----|----|-----------|--------|----------|
| Statistical (Robust MAD) | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| Rule: SSH-001 (Failed Logins) | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| Rule: NET-001 (New Port) | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| Rule: SVC-001 (Service Stopped) | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| Rule: FIM-001 (File Integrity) | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **Combined System** | **6** | **0** | **0** | **1.00** | **1.00** | **1.00** |

### Controlled Scenario Outcomes

| Scenario ID | Condition Tested | Expected Trigger | Observed Trigger | Outcome | Detection Latency |
|-------------|------------------|------------------|------------------|---------|-------------------|
| `SCEN-NORMAL-01` | Baseline normal operations (30m) | None (zero alerts) | None | **PASS** | N/A (0 FP) |
| `SCEN-CPU-01` | Sustained CPU spike (~96.5% for 120s) | `mad` (cpu_percent) | `mad` | **PASS** | 0.0s |
| `SCEN-MEM-01` | Memory pressure (~95.8% for 120s) | `mad` (memory_used_percent) | `mad` | **PASS** | 0.0s |
| `SCEN-SSH-01` | 6 failed SSH logins from 192.168.1.100 in 60s | `SSH-001` | `SSH-001` | **PASS** | 0.0s |
| `SCEN-NET-01` | Unauthorized listening port (4444/tcp) | `NET-001` | `NET-001` | **PASS** | 10.0s |
| `SCEN-SVC-01` | Critical service enters failed state | `SVC-001` | `SVC-001` | **PASS** | 10.0s |
| `SCEN-FIM-01` | Critical file (/etc/passwd) SHA256 modified | `FIM-001` | `FIM-001` | **PASS** | 10.0s |

### False Positive Rate

| Detector / Rule | Active Windows (Baseline) | False Alerts Triggered | Rate (alerts / hr) | Target Met |
|-----------------|---------------------------|------------------------|--------------------|------------|
| Statistical (MAD) | 500 samples (~83m) | 0 | 0.0 / hr | Yes (< 1.0/hr) |
| Security Rules | 500 samples (~83m) | 0 | 0.0 / hr | Yes (< 1.0/hr) |

### Detection Latency Summary

| Metric | Target | Measured (Controlled Scenarios) | Status |
|--------|--------|----------------------------------|--------|
| Median Latency (p50) | < 60.0s | 5.0s | **Met** |
| 95th Percentile Latency (p95) | < 180.0s | 10.0s | **Met** |

### Agent Runtime Overhead

| Metric | Measured on Monitored Server | Target Ceiling | Status |
|--------|------------------------------|----------------|--------|
| Agent CPU Utilization | ~0.8% - 1.4% avg | < 5.0% | **Met** |
| Memory Footprint (RSS) | ~32 MB | < 100 MB | **Met** |

## Discussion

- **Explainability**: Findings produced by the robust statistical detector provide clear deviation z-scores and baseline medians. Security rule findings include exact formatted evidence strings citing timestamps, source IPs, port numbers, or hash diffs.
- **Latency**: Sub-minute detection was achieved across all scenarios. System metric spikes are detected at the very first anomalous sample, while socket and file integrity changes trigger within 10 seconds of observation.
- **Read-Only Safety**: The agent observes and reports without modifying system services, firewalls, or processes, satisfying the course project read-only guarantee.
