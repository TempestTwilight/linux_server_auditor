"""Tests for the four security rules."""

from __future__ import annotations

import pytest

from linux_server_auditor.detection.security_rules import evaluate_rules


def test_ssh001():
    """SSH-001: Multiple failed logins from one IP."""
    events = [
        {
            "event_type": "ssh_failed_login",
            "timestamp": "2026-01-01T12:00:00Z",
            "event_data": {"source_ip": "192.168.1.100"},
            "instance_id": "i-123",
        },
        {
            "event_type": "ssh_failed_login",
            "timestamp": "2026-01-01T12:01:00Z",
            "event_data": {"source_ip": "192.168.1.100"},
            "instance_id": "i-123",
        },
        {
            "event_type": "ssh_failed_login",
            "timestamp": "2026-01-01T12:02:00Z",
            "event_data": {"source_ip": "192.168.1.100"},
            "instance_id": "i-123",
        },
        {
            "event_type": "ssh_failed_login",
            "timestamp": "2026-01-01T12:03:00Z",
            "event_data": {"source_ip": "192.168.1.100"},
            "instance_id": "i-123",
        },
        {
            "event_type": "ssh_failed_login",
            "timestamp": "2026-01-01T12:04:00Z",
            "event_data": {"source_ip": "192.168.1.100"},
            "instance_id": "i-123",
        },
    ]
    
    findings = evaluate_rules(events)
    ssh_findings = [f for f in findings if f["rule_id"] == "SSH-001"]
    assert len(ssh_findings) >= 1
    assert ssh_findings[0]["severity"] == "high"
    assert "192.168.1.100" in ssh_findings[0]["evidence"]


def test_net001():
    """NET-001: New listening port."""
    baseline = {(22, "tcp"), (80, "tcp")}
    events = [
        {
            "event_type": "listening_ports",
            "timestamp": "2026-01-01T12:00:00Z",
            "event_data": {"port": 8080, "proto": "tcp", "pid": 1234, "name": "suspicious"},
            "instance_id": "i-123",
        }
    ]
    
    findings = evaluate_rules(events, baseline_ports=baseline)
    net_findings = [f for f in findings if f["rule_id"] == "NET-001"]
    assert len(net_findings) == 1
    assert "8080" in net_findings[0]["evidence"]


def test_svc001():
    """SVC-001: Service entered failed state."""
    events = [
        {
            "event_type": "service_status",
            "timestamp": "2026-01-01T12:00:00Z",
            "event_data": {"service": "nginx", "state": "failed"},
            "instance_id": "i-123",
        }
    ]
    
    findings = evaluate_rules(events)
    svc_findings = [f for f in findings if f["rule_id"] == "SVC-001"]
    assert len(svc_findings) == 1
    assert svc_findings[0]["severity"] == "high"
    assert "nginx" in svc_findings[0]["evidence"]


def test_fim001():
    """FIM-001: File hash changed."""
    events = [
        {
            "event_type": "file_integrity",
            "timestamp": "2026-01-01T12:00:00Z",
            "event_data": {
                "path": "/etc/passwd",
                "old_hash": "abc123",
                "new_hash": "def456",
            },
            "instance_id": "i-123",
        }
    ]
    
    findings = evaluate_rules(events)
    fim_findings = [f for f in findings if f["rule_id"] == "FIM-001"]
    assert len(fim_findings) == 1
    assert fim_findings[0]["severity"] == "critical"
    assert "/etc/passwd" in fim_findings[0]["evidence"]
