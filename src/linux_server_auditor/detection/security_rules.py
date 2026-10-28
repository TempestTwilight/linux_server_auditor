"""Rule engine that evaluates SSH-001, NET-001, SVC-001, FIM-001."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from linux_server_auditor.config import _CONFIG_DIR

_RULES_PATH = _CONFIG_DIR / "security_rules.yaml"


def load_rules() -> list[dict]:
    """Load security_rules.yaml."""
    with _RULES_PATH.open() as f:
        return yaml.safe_load(f)


def evaluate_rules(events: list[dict], baseline_ports: set[tuple] | None = None) -> list[dict]:
    """Evaluate security rules against event list.
    
    events: list of {timestamp, event_type, event_data, instance_id}
    Returns list of {rule_id, severity, evidence, explanation, timestamp, instance_id}.
    """
    rules = load_rules()
    findings = []
    
    for rule in rules:
        rid = rule["id"]
        cond = rule["condition"]
        metric_type = cond["metric_type"]
        
        if rid == "SSH-001":
            findings.extend(_eval_ssh001(rule, events))
        elif rid == "NET-001":
            findings.extend(_eval_net001(rule, events, baseline_ports or set()))
        elif rid == "SVC-001":
            findings.extend(_eval_svc001(rule, events))
        elif rid == "FIM-001":
            findings.extend(_eval_fim001(rule, events))
    
    return findings


def _eval_ssh001(rule: dict, events: list[dict]) -> list[dict]:
    """Multiple failed SSH logins from one IP."""
    cond = rule["condition"]
    threshold = cond["count_threshold"]
    window_sec = cond["window_sec"]
    
    ssh_events = [e for e in events if e["event_type"] == "ssh_failed_login"]
    findings = []
    
    by_ip = defaultdict(list)
    for e in ssh_events:
        ip = e.get("event_data", {}).get("source_ip", "unknown")
        by_ip[ip].append(e)
    
    for ip, evts in by_ip.items():
        evts.sort(key=lambda x: x["timestamp"])
        for i, evt in enumerate(evts):
            t0 = datetime.fromisoformat(evt["timestamp"].replace("Z", "+00:00"))
            count = 1
            for j in range(i + 1, len(evts)):
                t1 = datetime.fromisoformat(evts[j]["timestamp"].replace("Z", "+00:00"))
                if (t1 - t0).total_seconds() <= window_sec:
                    count += 1
                else:
                    break
            
            if count >= threshold:
                evidence = rule["evidence_template"].format(
                    count=count, source_ip=ip, window_sec=window_sec
                )
                findings.append({
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "evidence": evidence,
                    "explanation": rule["explanation"],
                    "timestamp": evt["timestamp"],
                    "instance_id": evt.get("instance_id", "unknown"),
                })
                break  # one finding per IP
    
    return findings


def _eval_net001(rule: dict, events: list[dict], baseline_ports: set[tuple]) -> list[dict]:
    """New listening port not in baseline."""
    cond = rule["condition"]
    grace_sec = cond["grace_period_sec"]
    
    port_events = [e for e in events if e["event_type"] == "listening_ports"]
    findings = []
    
    for e in port_events:
        data = e.get("event_data", {})
        port = data.get("port")
        proto = data.get("proto", "tcp")
        pid = data.get("pid")
        name = data.get("name", "unknown")
        
        if (port, proto) not in baseline_ports:
            evidence = rule["evidence_template"].format(
                port=port, proto=proto, pid=pid, name=name
            )
            findings.append({
                "rule_id": rule["id"],
                "severity": rule["severity"],
                "evidence": evidence,
                "explanation": rule["explanation"],
                "timestamp": e["timestamp"],
                "instance_id": e.get("instance_id", "unknown"),
            })
    
    return findings


def _eval_svc001(rule: dict, events: list[dict]) -> list[dict]:
    """Service entered inactive or failed state."""
    cond = rule["condition"]
    bad_states = cond["states"]
    
    svc_events = [e for e in events if e["event_type"] == "service_status"]
    findings = []
    
    for e in svc_events:
        data = e.get("event_data", {})
        state = data.get("state")
        service = data.get("service", "unknown")
        
        if state in bad_states:
            evidence = rule["evidence_template"].format(service=service, state=state)
            findings.append({
                "rule_id": rule["id"],
                "severity": rule["severity"],
                "evidence": evidence,
                "explanation": rule["explanation"],
                "timestamp": e["timestamp"],
                "instance_id": e.get("instance_id", "unknown"),
            })
    
    return findings


def _eval_fim001(rule: dict, events: list[dict]) -> list[dict]:
    """File integrity violation."""
    fim_events = [e for e in events if e["event_type"] == "file_integrity"]
    findings = []
    
    for e in fim_events:
        data = e.get("event_data", {})
        path = data.get("path")
        old_hash = data.get("old_hash", "unknown")
        new_hash = data.get("new_hash", "unknown")
        
        evidence = rule["evidence_template"].format(
            path=path, old_hash=old_hash, new_hash=new_hash
        )
        findings.append({
            "rule_id": rule["id"],
            "severity": rule["severity"],
            "evidence": evidence,
            "explanation": rule["explanation"],
            "timestamp": e["timestamp"],
            "instance_id": e.get("instance_id", "unknown"),
        })
    
    return findings
