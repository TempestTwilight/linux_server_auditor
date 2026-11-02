"""Tests for SSM live scenario injector."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from linux_server_auditor.agent.ssm_injector import SSM_COMMANDS, trigger_ec2_scenario


def test_ssm_commands_catalog():
    """Verify supported live commands exist in catalog."""
    assert "cpu_spike" in SSM_COMMANDS
    assert "open_port" in SSM_COMMANDS
    assert "ssh_brute_force" in SSM_COMMANDS
    assert "file_tamper" in SSM_COMMANDS


def test_trigger_unknown_scenario():
    """Unknown scenario should return error."""
    res = trigger_ec2_scenario("non_existent_key", instance_id="i-test")
    assert not res["success"]
    assert "Unknown scenario" in res["error"]


@patch("linux_server_auditor.agent.ssm_injector.boto3.client")
def test_trigger_ec2_scenario_success(mock_boto):
    """Verify SSM send_command is invoked correctly."""
    mock_ssm = MagicMock()
    mock_ssm.send_command.return_value = {"Command": {"CommandId": "test-cmd-1234"}}
    mock_boto.return_value = mock_ssm

    res = trigger_ec2_scenario("cpu_spike", instance_id="i-1234567890abcdef0")
    assert res["success"]
    assert res["command_id"] == "test-cmd-1234"
    assert res["instance_id"] == "i-1234567890abcdef0"
    mock_ssm.send_command.assert_called_once()
