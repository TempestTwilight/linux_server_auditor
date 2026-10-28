"""Generate human-readable explanations for findings."""

from __future__ import annotations


def explain_finding(finding: dict) -> str:
    """Format a finding dict as readable text."""
    lines = []
    
    if "rule_id" in finding:
        lines.append(f"[{finding['severity'].upper()}] {finding['rule_id']}")
        lines.append(f"Evidence: {finding['evidence']}")
        lines.append(f"Explanation: {finding['explanation']}")
    elif "detector" in finding:
        det = finding["detector"]
        feat = finding["feature"]
        score = finding["score"]
        lines.append(f"Anomaly detected by {det} on {feat}")
        lines.append(f"Score: {score:.2f} (threshold: {finding.get('threshold', 'N/A')})")
        if finding.get("value") is not None:
            lines.append(f"Value: {finding['value']:.2f}")
    
    return "\n".join(lines)


def explain_incident(incident: dict) -> str:
    """Format an incident dict as readable text."""
    lines = [
        f"Incident {incident['incident_id']}",
        f"Instance: {incident['instance_id']}",
        f"Priority: {incident['priority_score']:.0f}/100",
        f"Status: {incident['status']}",
        f"First seen: {incident['first_seen']}",
        f"Last seen: {incident['last_seen']}",
        f"Findings: {incident['finding_count']}",
        "",
        "Details:",
    ]
    
    for f in incident.get("evidence", []):
        lines.append("  " + explain_finding(f).replace("\n", "\n  "))
        lines.append("")
    
    if incident.get("resolution_notes"):
        lines.append(f"Resolution: {incident['resolution_notes']}")
    
    return "\n".join(lines)
