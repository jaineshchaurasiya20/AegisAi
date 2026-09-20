"""
AegisAI Unit & Integration Tests — AWS EventBridge Fleet Intelligence Synchronization
Tests:
  1. Event payload formatting and forensic signature schema validation.
  2. Mock boto3 EventBridge client verifying put_events parameters (Source, DetailType, Detail, BusName).
  3. Graceful fallback handling when AWS credentials or network connections are absent.
  4. End-to-end integration: RemediationExecutedEvent -> AuditorAgent -> EventBridge -> EventBus trace.
"""
import sys
from pathlib import Path

SERVER_ROOT = Path(__file__).resolve().parents[1]
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

import json
import asyncio
from unittest.mock import MagicMock
import pytest

from app.services.aws_service import AWSEventBridgeService, aws_eventbridge
from app.core.config import Settings
from app.agents.event_bus import EventBus
from app.agents.auditor import AuditorAgent
from app.agents.schemas import (
    RemediationExecutedEvent,
    ZeroDayThreatTrappedEvent,
    AgentTraceEvent,
    ActionType,
    ActionStatus,
)


def test_eventbridge_payload_formatting_and_schema():
    """Verify JSON structure and forensic metadata in zero-day signature payload."""
    custom_settings = Settings(
        AWS_REGION="us-east-1",
        AWS_EVENTBRIDGE_BUS_NAME="aegisai-fleet-bus",
        AWS_EVENTBRIDGE_ENABLED=True,
    )
    service = AWSEventBridgeService(settings=custom_settings)

    mock_events = MagicMock()
    mock_events.put_events.return_value = {
        "FailedEntryCount": 0,
        "Entries": [{"EventId": "eb-evt-12345-67890"}],
    }
    service.set_events_client(mock_events)

    threat_id = "zero-day-threat-omega-99"
    signature_data = {
        "sha256_fingerprint": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
        "entropy": 0.9421,
        "decoy_port": 2222,
        "trap_type": "FAKE_SSH",
        "command_executed": "uname -a; cat /etc/shadow",
        "hex_prefix": "7f454c46020101000000000000000000",
    }

    result = service.publish_zero_day_signature(threat_id, signature_data)

    assert result["success"] is True
    assert result["event_id"] == "eb-evt-12345-67890"
    assert result["source"] == "aegisai.deception"
    assert result["detail_type"] == "ZeroDayThreatTrapped"
    assert result["event_bus"] == "aegisai-fleet-bus"
    assert result["sha256_fingerprint"] == signature_data["sha256_fingerprint"]
    assert result["shannon_entropy"] == 0.9421

    # Verify boto3 put_events parameters
    mock_events.put_events.assert_called_once()
    _, kwargs = mock_events.put_events.call_args
    entries = kwargs["Entries"]
    assert len(entries) == 1

    entry = entries[0]
    assert entry["Source"] == "aegisai.deception"
    assert entry["DetailType"] == "ZeroDayThreatTrapped"
    assert entry["EventBusName"] == "aegisai-fleet-bus"

    detail = json.loads(entry["Detail"])
    assert detail["threat_id"] == threat_id
    assert detail["sha256_fingerprint"] == signature_data["sha256_fingerprint"]
    assert detail["shannon_entropy"] == 0.9421
    assert detail["decoy_port"] == 2222
    assert detail["trap_type"] == "FAKE_SSH"
    assert detail["sanitized_command"] == "uname -a; cat /etc/shadow"
    assert "timestamp_utc" in detail


def test_eventbridge_graceful_fallback_when_credentials_absent():
    """Verify that absent credentials or client failure falls back gracefully to LOCAL_RETRAINING_ONLY."""
    service = AWSEventBridgeService()
    service.set_events_client(None)
    service.get_events_client = lambda: None

    sig_data = {
        "rawPayload": "eval(base64_decode('...'))",
        "entropy": 0.85,
    }

    res = service.publish_zero_day_signature("threat-no-aws-1", sig_data)

    assert res["success"] is False
    assert res["fallback_mode"] == "LOCAL_RETRAINING_ONLY"
    assert "unavailable" in res["error"].lower()


def test_eventbridge_graceful_fallback_when_disabled():
    """Verify that disabled configuration immediately bypasses cloud calls."""
    custom_settings = Settings(AWS_EVENTBRIDGE_ENABLED=False)
    service = AWSEventBridgeService(settings=custom_settings)

    mock_events = MagicMock()
    service.set_events_client(mock_events)

    res = service.publish_zero_day_signature("threat-disabled", {"entropy": 0.9})

    assert res["success"] is False
    assert res["fallback_mode"] == "LOCAL_RETRAINING_ONLY"
    assert "disabled" in res["error"].lower()
    mock_events.put_events.assert_not_called()


def test_eventbridge_handles_put_events_failure_response():
    """Verify that FailedEntryCount > 0 from AWS returns fallback error without raising unhandled exceptions."""
    service = AWSEventBridgeService()
    mock_events = MagicMock()
    mock_events.put_events.return_value = {
        "FailedEntryCount": 1,
        "Entries": [{"ErrorCode": "AccessDeniedException", "ErrorMessage": "User is not authorized to perform: events:PutEvents"}],
    }
    service.set_events_client(mock_events)

    res = service.publish_zero_day_signature("threat-err-1", {"entropy": 0.89})

    assert res["success"] is False
    assert res["fallback_mode"] == "LOCAL_RETRAINING_ONLY"
    assert "not authorized" in res["error"].lower()


@pytest.mark.asyncio
async def test_auditor_agent_honeypot_triggers_eventbridge_and_eventbus_trace():
    """Verify AuditorAgent handle_remediation emits ZeroDayThreatTrappedEvent and EventBridge trace."""
    bus = EventBus()
    await bus.start()
    auditor = AuditorAgent(bus)

    # Mock EventBridge service
    mock_events = MagicMock()
    mock_events.put_events.return_value = {
        "FailedEntryCount": 0,
        "Entries": [{"EventId": "eb-test-flow-777"}],
    }
    aws_eventbridge.set_events_client(mock_events)

    trapped_events = []
    trace_events = []

    bus.subscribe(ZeroDayThreatTrappedEvent, lambda e: trapped_events.append(e))
    bus.subscribe(AgentTraceEvent, lambda e: trace_events.append(e))

    # Trigger honeypot entrapment remediation
    rem_event = RemediationExecutedEvent(
        source_investigation_event_id="inv-honeypot-100",
        process_pid=None,
        action_type=ActionType.HONEYPOT_REDIRECT,
        action_status=ActionStatus.SUCCESS,
        action_reason="Novel zero-day trapped in honeypot decoy",
        target="198.51.100.44:2121",
        feature_vector=[0.95, 0.88, 0.12],
        details={
            "threat_id": "threat-honeypot-live-100",
            "action_taken": "trapped_in_honeypot",
            "honeypot_capture": {
                "payloadHash": "d04b7f88e6a1234567890abcdef0123456789abcdef0123456789abcdef012",
                "entropy": 0.9123,
                "sourcePort": 2121,
                "trapType": "FAKE_FTP",
                "commandExecuted": "USER admin; PASS rogue_exploit_c2",
                "rawPayload": "USER admin\r\nPASS rogue_exploit_c2\r\n",
            },
        },
    )

    await auditor.handle_remediation(rem_event)
    await asyncio.sleep(0.1)

    # 1. Verify ZeroDayThreatTrappedEvent was emitted
    assert len(trapped_events) == 1
    zt = trapped_events[0]
    assert zt.threat_id == "threat-honeypot-live-100"
    assert zt.shannon_entropy == 0.9123
    assert zt.eventbridge_synced is True
    assert zt.eventbridge_event_id == "eb-test-flow-777"

    # 2. Verify AgentTraceEvent was emitted with EventBridge status
    eb_traces = [t for t in trace_events if "[AWS EventBridge]" in t.message]
    assert len(eb_traces) == 1
    trace = eb_traces[0]
    assert trace.status == "SUCCESS"
    assert "eb-test-flow-777" in trace.message
    assert trace.payload["eventbridge_synced"] is True
    assert trace.payload["source"] == "aegisai.deception"

    await bus.stop()
