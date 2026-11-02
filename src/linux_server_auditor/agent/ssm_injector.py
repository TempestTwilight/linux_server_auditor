"""Live scenario injector via AWS SSM or local mock."""

from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from linux_server_auditor.config import settings

log = logging.getLogger(__name__)

# Commands that trigger real detections on the monitored EC2 instance
SSM_COMMANDS: dict[str, dict[str, Any]] = {
    "cpu_spike": {
        "name": "CPU Stress (runaway compute)",
        "commands": [
            'nohup python3 -c "import time; t=time.time()+35; [x*x for x in iter(lambda:0,1) if time.time()<t]" >/dev/null 2>&1 &'
        ],
        "description": "Spins CPU at 100% for 35s to trigger Statistical (MAD) anomaly.",
    },
    "memory_pressure": {
        "name": "Memory Allocation (memory pressure)",
        "commands": [
            'nohup python3 -c "import time; b=bytearray(450*1024*1024); time.sleep(35)" >/dev/null 2>&1 &'
        ],
        "description": "Allocates 450MB RAM for 35s to elevate memory usage.",
    },
    "ssh_brute_force": {
        "name": "SSH Failed Logins (auth flood)",
        "commands": [
            'for i in $(seq 1 7); do logger -p auth.warning "Failed password for invalid user hacker$i from 198.51.100.42 port 54321 ssh2"; done'
        ],
        "description": "Injects failed SSH login events to trigger SSH-001 rule.",
    },
    "open_port": {
        "name": "Unauthorized Listening Port",
        "commands": [
            "nohup python3 -c \"import socket, time; s=socket.socket(); s.bind(('0.0.0.0', 4444)); s.listen(1); time.sleep(40)\" >/dev/null 2>&1 &"
        ],
        "description": "Binds TCP port 4444 to trigger NET-001 rule.",
    },
    "file_tamper": {
        "name": "Watched File Tampering (FIM)",
        "commands": [
            "echo '# audit probe' | sudo tee -a /etc/hosts >/dev/null",
            "sleep 35",
            "sudo sed -i '/# audit probe/d' /etc/hosts",
        ],
        "description": "Appends to /etc/hosts then restores it to trigger FIM-001 hash mismatch.",
    },
}


def trigger_ec2_scenario(scenario_key: str, instance_id: str | None = None) -> dict[str, Any]:
    """Send SSM command to EC2 instance to trigger live scenario."""
    if scenario_key not in SSM_COMMANDS:
        return {"success": False, "error": f"Unknown scenario: {scenario_key}"}

    cfg = SSM_COMMANDS[scenario_key]
    iid = instance_id or settings.get("agent", {}).get("instance_id")
    region = settings.get("s3", {}).get("region", "ap-southeast-2")

    if not iid:
        return {"success": False, "error": "No instance_id configured."}

    try:
        ssm = boto3.client("ssm", region_name=region)
        resp = ssm.send_command(
            InstanceIds=[iid],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": cfg["commands"]},
            Comment=f"Auditor live test: {scenario_key}",
        )
        cmd_id = resp["Command"]["CommandId"]
        return {
            "success": True,
            "command_id": cmd_id,
            "scenario": cfg["name"],
            "description": cfg["description"],
            "instance_id": iid,
        }
    except ClientError as e:
        log.exception("SSM send-command failed")
        return {"success": False, "error": str(e)}
