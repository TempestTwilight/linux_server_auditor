# Threat Model

## Assets

1. **Telemetry data**: System metrics, security events (contains instance state, SSH attempts)
2. **AWS credentials**: IAM role for agent (S3 write), monitor credentials (S3 read/delete)
3. **EC2 instance**: Monitored server (compromise means attacker controls agent)
4. **S3 bucket**: Persistent telemetry queue
5. **Monitor machine**: Debian workstation with SQLite database and dashboard access
6. **Dashboard**: Web UI exposing real-time system state

## Threat Actors

1. **External attacker**: Network-based exploit targeting EC2 instance
2. **Insider with AWS console access**: Can read S3 bucket, modify IAM policies
3. **Misconfigured automation**: Scripts with over-permissioned IAM roles

## Attack Vectors and Mitigations

### 1. Telemetry Injection

**Vector**: Attacker writes fake telemetry to S3 to hide real attacks or trigger false alerts.

**Mitigation**:
- Agent IAM role: write-only to `s3://bucket/telemetry/{instance_id}/*`
- Monitor validates schema and timestamp ordering (rejects out-of-order batches)
- S3 object metadata includes upload timestamp (detect backdated files)

**Residual risk**: Compromised agent can inject malicious data. Detection: monitor verifies sequence numbers and checks for impossible metric values.

### 2. Telemetry Exfiltration

**Vector**: Attacker reads S3 bucket to learn instance state before attack.

**Mitigation**:
- S3 bucket policy: deny access except from agent and monitor roles
- SSE-S3 encryption at rest
- S3 access logs and CloudTrail enabled

**Residual risk**: Insider with AWS console access can read bucket. Detection: CloudTrail alerts on unexpected GetObject calls.

### 3. Denial of Service (Telemetry Loss)

**Vector**: Attacker floods S3 with large files or deletes telemetry batches.

**Mitigation**:
- Agent rate limits uploads (max 2/min)
- S3 versioning enabled (recover deleted objects)
- Monitor alerts on telemetry gaps > 5 min

**Residual risk**: Attacker with S3 DeleteObject permission can delete telemetry. Mitigation: S3 MFA Delete, audit DeleteObject calls.

### 4. Agent Compromise

**Vector**: Attacker gains root on EC2 instance, stops agent, or tampers with telemetry.

**Mitigation**:
- Agent runs as non-root user (read-only access to system metrics)
- Security events detect sudo escalation and auth log tampering
- File integrity checks on agent binary and config
- Monitor alerts on telemetry staleness (agent offline > 5 min)

**Residual risk**: Root attacker can bypass agent protections. Detection: out-of-band monitoring (AWS CloudWatch agent) and periodic forensic snapshots.

### 5. Monitor Compromise

**Vector**: Attacker gains access to monitor machine, reads SQLite DB, or injects false alerts.

**Mitigation**:
- Monitor runs on locked-down Debian workstation (SSH key-only, firewall)
- Dashboard binds to 127.0.0.1 (local-only access)
- SQLite on encrypted filesystem
- Monitor IAM credentials: read-only S3 access, no EC2/IAM permissions

**Residual risk**: Local attacker on monitor can read all telemetry. Mitigation: workstation hardening, disk encryption, audit logs.

### 6. Dashboard Access

**Vector**: Attacker accesses dashboard to learn system state.

**Mitigation**:
- Dashboard binds to localhost, access via SSH tunnel
- No authentication in dashboard (relies on SSH access control)

**Residual risk**: User with SSH access can view dashboard. Acceptable for academic project; production would add OAuth or reverse proxy with auth.

## Trust Boundaries

1. **EC2 instance → S3**: Untrusted (agent compromise means attacker controls data)
2. **S3 → Monitor**: Semi-trusted (S3 integrity relies on IAM and encryption)
3. **Monitor → Dashboard**: Trusted (both run on same machine)

## Out of Scope

- AWS account compromise (attacker with root AWS credentials can bypass all controls)
- Physical access to EC2 or monitor machines
- Side-channel attacks (Spectre, timing)
- DDoS against AWS infrastructure
- Supply chain attacks (compromised dependencies)
