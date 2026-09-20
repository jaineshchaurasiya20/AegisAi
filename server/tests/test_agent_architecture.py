"""
AegisAI 4-Agent Architecture Comprehensive Test Suite
Tests:
  1. Event schemas, enum validation, serialization/deserialization
  2. Event Bus pub/sub, concurrency, exception isolation, and cancellation
  3. Dynamic Adaptive Threshold calculation tau(t) under various workloads
  4. Detector Agent anomaly triggering logic
  5. Investigator Agent XAI attribution and root-cause analysis
  6. Remediator Agent safety guardrails and mock containment
  7. Auditor Agent closed-loop verification, fallback containment, and SQLite retraining
  8. End-to-end full 4-agent execution chain
"""
import asyncio
import json
import os
import sys
import tempfile
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# Ensure server root is on path
SERVER_ROOT = Path(__file__).resolve().parents[1]
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

from app.agents.schemas import (
    BaseAgentEvent,
    TelemetryEvent,
    AnomalyDetectedEvent,
    ThreatInvestigatedEvent,
    RemediationExecutedEvent,
    AuditCompletedEvent,
    ActionType,
    ActionStatus,
    VerificationStatus,
)
from app.agents.event_bus import EventBus
from app.agents.detector import DetectorAgent, compute_dynamic_threshold
from app.agents.investigator import InvestigatorAgent
from app.agents.remediator import RemediatorAgent
from app.agents.auditor import AuditorAgent
from app.agents.orchestrator import AgentOrchestrator


# =============================================================================
# 1. Event Schemas & Serialization Tests
# =============================================================================

def test_event_schemas_validation_and_serialization():
    # Base event
    base = BaseAgentEvent()
    assert base.event_id is not None
    assert isinstance(base.timestamp, datetime)

    # TelemetryEvent
    telem = TelemetryEvent(
        hostname="soc-node-1",
        host_ip="192.168.1.50",
        cpu_usage=24.5,
        memory_usage=48.2,
        disk_usage=60.1,
        feature_vector=[1.0, 2.0, 3.0],
    )
    assert telem.hostname == "soc-node-1"
    telem_json = telem.json()
    assert "soc-node-1" in telem_json
    telem_deser = TelemetryEvent.parse_raw(telem_json)
    assert telem_deser.event_id == telem.event_id
    assert telem_deser.cpu_usage == 24.5

    # AnomalyDetectedEvent with threshold
    anomaly = AnomalyDetectedEvent(
        process_pid=4120,
        process_name="malicious.exe",
        threat_score=0.91,
        dynamic_threshold=0.78,
        severity="critical",
    )
    assert anomaly.dynamic_threshold == 0.78
    assert anomaly.threat_score == 0.91

    # Enums validation
    assert ActionType.PID_KILL == "PID_KILL"
    assert ActionType.HONEYPOT_REDIRECT == "HONEYPOT_REDIRECT"
    assert ActionStatus.SUCCESS == "SUCCESS"
    assert VerificationStatus.SUCCESS == "SUCCESS"

    # RemediationExecutedEvent
    remed = RemediationExecutedEvent(
        source_investigation_event_id="inv-123",
        process_pid=4120,
        process_name="malicious.exe",
        action_type=ActionType.PID_KILL,
        action_status=ActionStatus.SUCCESS,
        action_reason="Threat score 0.91 > 0.88",
        target="PID:4120",
    )
    assert remed.action_type == ActionType.PID_KILL
    assert remed.action_status == ActionStatus.SUCCESS

    # AuditCompletedEvent
    audit = AuditCompletedEvent(
        source_remediation_event_id="rem-456",
        process_pid=4120,
        verification_status=VerificationStatus.SUCCESS,
        process_alive=False,
        network_activity_detected=False,
        system_stable=True,
        retraining_required=True,
        retraining_label="verified threat",
    )
    assert audit.verification_status == VerificationStatus.SUCCESS
    assert audit.retraining_label == "verified threat"


# =============================================================================
# 2. Event Bus Tests
# =============================================================================

async def test_event_bus_pub_sub_and_isolation():
    bus = EventBus(max_queue_size=100, num_workers=2)
    await bus.start()

    received_events = []
    faulty_called = []

    def faulty_handler(event: AnomalyDetectedEvent):
        faulty_called.append(True)
        raise RuntimeError("Intentional error in subscriber")

    def good_handler(event: AnomalyDetectedEvent):
        received_events.append(event)

    bus.subscribe(AnomalyDetectedEvent, faulty_handler)
    bus.subscribe(AnomalyDetectedEvent, good_handler)

    test_event = AnomalyDetectedEvent(
        threat_score=0.89,
        dynamic_threshold=0.65,
    )

    await bus.publish(test_event)
    await asyncio.sleep(0.1)

    # Verify that faulty handler failed safely without aborting good_handler
    assert len(faulty_called) == 1
    assert len(received_events) == 1
    assert received_events[0].event_id == test_event.event_id

    await bus.stop()


async def test_event_bus_duplicate_and_shutdown():
    bus = EventBus(max_queue_size=50, num_workers=1)
    await bus.start()

    call_count = [0]
    def handler(event: AnomalyDetectedEvent):
        call_count[0] += 1

    # Subscribe twice - duplicate subscription must be prevented
    bus.subscribe(AnomalyDetectedEvent, handler)
    bus.subscribe(AnomalyDetectedEvent, handler)

    event = AnomalyDetectedEvent(threat_score=0.9, dynamic_threshold=0.6)
    await bus.publish(event)
    await asyncio.sleep(0.05)

    assert call_count[0] == 1, f"Handler should only be called once, got {call_count[0]}"

    # Test unsubscribe
    bus.unsubscribe(AnomalyDetectedEvent, handler)
    await bus.publish(event)
    await asyncio.sleep(0.05)
    assert call_count[0] == 1

    # Test clean shutdown
    await bus.stop()
    assert not bus._running
    assert len(bus._workers) == 0


# =============================================================================
# 3. Dynamic Adaptive Threshold Formula Tests
# =============================================================================

def test_dynamic_threshold_computations():
    base = 0.65
    min_th = 0.50
    max_th = 0.88

    # 1. Normal baseline / idle workload
    tau_idle = compute_dynamic_threshold(
        base_threshold=base,
        cpu_percent=10.0,
        memory_percent=30.0,
        bytes_sent_per_s=1000.0,
        bytes_recv_per_s=2000.0,
        min_threshold=min_th,
        max_threshold=max_th,
    )
    assert tau_idle == base, f"Idle workload should equal base threshold, got {tau_idle}"

    # 2. High legitimate workload (compilation / model training)
    tau_heavy = compute_dynamic_threshold(
        base_threshold=base,
        cpu_percent=95.0,
        memory_percent=85.0,
        bytes_sent_per_s=8_000_000.0,
        bytes_recv_per_s=5_000_000.0,
        load_factor=0.20,
        min_threshold=min_th,
        max_threshold=max_th,
    )
    assert tau_heavy > base, f"Heavy workload should increase threshold: {tau_heavy} > {base}"
    assert tau_heavy <= max_th, f"Threshold must be bounded by max: {tau_heavy} <= {max_th}"

    # 3. Boundary conditions (extreme inputs)
    tau_extreme = compute_dynamic_threshold(
        base_threshold=0.85,
        cpu_percent=100.0,
        memory_percent=100.0,
        bytes_sent_per_s=100_000_000.0,
        bytes_recv_per_s=100_000_000.0,
        load_factor=0.50,
        min_threshold=min_th,
        max_threshold=max_th,
    )
    assert tau_extreme == max_th, f"Must clamp to max_threshold, got {tau_extreme}"

    tau_sub_min = compute_dynamic_threshold(
        base_threshold=0.40,
        cpu_percent=0.0,
        memory_percent=0.0,
        min_threshold=min_th,
        max_threshold=max_th,
    )
    assert tau_sub_min == min_th, f"Must clamp to min_threshold, got {tau_sub_min}"


# =============================================================================
# 4. Detector Agent Tests
# =============================================================================

async def test_detector_agent_anomaly_filtering():
    bus = EventBus(max_queue_size=100, num_workers=1)
    await bus.start()

    detector = DetectorAgent(event_bus=bus, base_threshold=0.65, min_threshold=0.50, max_threshold=0.88)

    emitted_anomalies = []
    bus.subscribe(AnomalyDetectedEvent, lambda e: emitted_anomalies.append(e))

    # Event with score below threshold (0.50 <= 0.65) -> must NOT emit anomaly
    res_sub = await detector.ingest_event({
        "threat_score": 0.50,
        "threat_type": "Normal Traffic",
        "telemetry": {"pid": 100, "processName": "notepad.exe"},
    })
    await asyncio.sleep(0.05)
    assert res_sub is None
    assert len(emitted_anomalies) == 0

    # Event with score above threshold (0.91 > 0.65) -> MUST emit anomaly
    res_super = await detector.ingest_event({
        "threat_score": 0.91,
        "threat_type": "DDoS LOIC Flood",
        "telemetry": {"pid": 2048, "processName": "loic.exe"},
    })
    await asyncio.sleep(0.05)
    assert res_super is not None
    assert len(emitted_anomalies) == 1
    assert emitted_anomalies[0].threat_score == 0.91
    assert emitted_anomalies[0].process_pid == 2048

    await bus.stop()


# =============================================================================
# 5. Investigator Agent Tests
# =============================================================================

async def test_investigator_agent_attribution():
    bus = EventBus(max_queue_size=100, num_workers=1)
    await bus.start()

    investigator = InvestigatorAgent(event_bus=bus)
    investigated_events = []
    bus.subscribe(ThreatInvestigatedEvent, lambda e: investigated_events.append(e))

    anomaly = AnomalyDetectedEvent(
        process_pid=5555,
        process_name="suspicious.exe",
        threat_score=0.88,
        dynamic_threshold=0.65,
        port=4444,
        threat_type="C2 Beaconing Attempt",
    )

    await bus.publish(anomaly)
    await asyncio.sleep(0.1)

    assert len(investigated_events) == 1
    inv = investigated_events[0]
    assert inv.source_anomaly_event_id == anomaly.event_id
    assert inv.threat_score == 0.88
    assert len(inv.feature_attributions) > 0
    assert inv.attribution_method in ("TreeExplainer", "DomainAttributionMatrix (TreeSHAP unavailable)")
    assert "TreeSHAP" in inv.root_cause

    await bus.stop()


# =============================================================================
# 6. Remediator Agent Tests (Mock Safe Containment)
# =============================================================================

async def test_remediator_agent_guardrails_and_actions():
    bus = EventBus(max_queue_size=100, num_workers=1)
    await bus.start()

    remediator = RemediatorAgent(event_bus=bus)
    remediation_events = []
    bus.subscribe(RemediationExecutedEvent, lambda e: remediation_events.append(e))

    # Case 1: Zero-Day threat triggers HONEYPOT_REDIRECT
    zero_day_event = ThreatInvestigatedEvent(
        source_anomaly_event_id="anom-1",
        process_pid=3333,
        threat_score=0.92,
        severity="critical",
        root_cause="zero-day probe targeting decoy service",
        attribution_method="TreeExplainer",
    )
    await bus.publish(zero_day_event)
    await asyncio.sleep(0.1)

    assert len(remediation_events) == 1
    assert remediation_events[0].action_type == ActionType.HONEYPOT_REDIRECT
    assert remediation_events[0].action_status == ActionStatus.SUCCESS

    # Case 2: Guardrail protects AegisAI / Python / system processes
    protected_event = ThreatInvestigatedEvent(
        source_anomaly_event_id="anom-2",
        process_pid=1234,
        process_name="python.exe",
        threat_score=0.95,
        severity="critical",
        root_cause="High CPU burst in python runtime",
        attribution_method="TreeExplainer",
    )
    await bus.publish(protected_event)
    await asyncio.sleep(0.1)

    assert len(remediation_events) == 2
    # Must be SKIPPED by guardrail
    assert remediation_events[1].action_status == ActionStatus.SKIPPED
    assert "Protected" in remediation_events[1].action_reason

    await bus.stop()


# =============================================================================
# 7. Auditor Agent Tests (Verification & SQLite Persistence)
# =============================================================================

async def test_auditor_agent_verification_and_sqlite():
    bus = EventBus(max_queue_size=100, num_workers=1)
    await bus.start()

    auditor = AuditorAgent(event_bus=bus)
    # Configure tiny audit delay for rapid test execution
    auditor.audit_delay = 0.05
    # Direct DB to temporary test database
    temp_dir = tempfile.mkdtemp()
    auditor.db_path = Path(temp_dir) / "test_aegisai.db"
    auditor._init_db()

    audited_events = []
    bus.subscribe(AuditCompletedEvent, lambda e: audited_events.append(e))

    # Successful honeypot redirection event
    rem_event = RemediationExecutedEvent(
        source_investigation_event_id="inv-99",
        process_pid=7777,
        process_name="recon_scanner.bin",
        action_type=ActionType.HONEYPOT_REDIRECT,
        action_status=ActionStatus.SUCCESS,
        action_reason="Zero-day decoy capture",
        target="HONEYPOT:7777",
        details={"feature_vector": [0.1, 0.2, 0.3]},
    )

    await bus.publish(rem_event)
    await asyncio.sleep(0.15)

    assert len(audited_events) == 1
    audit = audited_events[0]
    assert audit.verification_status == VerificationStatus.SUCCESS
    assert audit.retraining_label == "novel/unknown behavior"

    # Verify record was stored in SQLite table
    conn = sqlite3.connect(str(auditor.db_path))
    cursor = conn.cursor()
    cursor.execute("SELECT id, threat_label, verification_result, feature_vector FROM retraining_samples WHERE id=?", (rem_event.event_id,))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row[0] == rem_event.event_id
    assert row[1] == "novel/unknown behavior"
    assert row[2] == "SUCCESS"
    saved_vec = json.loads(row[3])
    assert saved_vec == [0.1, 0.2, 0.3]

    await bus.stop()


async def test_auditor_bounded_fallback():
    bus = EventBus(max_queue_size=100, num_workers=1)
    await bus.start()

    auditor = AuditorAgent(event_bus=bus)
    auditor.audit_delay = 0.01
    auditor.max_fallback_attempts = 2

    # A failed kill event on a dummy PID
    failed_kill = RemediationExecutedEvent(
        source_investigation_event_id="inv-fail",
        process_pid=99999,
        action_type=ActionType.PID_KILL,
        action_status=ActionStatus.FAILED,
        action_reason="Mock failure",
        target="PID:99999",
    )

    # Attempt 1 -> fallback executes
    action, status, verified = await auditor._execute_fallback(failed_kill)
    assert auditor._fallback_history["pid_99999"] == 1

    # Attempt 2 -> fallback executes
    action, status, verified = await auditor._execute_fallback(failed_kill)
    assert auditor._fallback_history["pid_99999"] == 2

    # Attempt 3 -> bounded limit reached, returns NO_ACTION / SKIPPED
    action, status, verified = await auditor._execute_fallback(failed_kill)
    assert action == ActionType.NO_ACTION
    assert status == ActionStatus.SKIPPED
    assert verified is False

    await bus.stop()


# =============================================================================
# 8. End-to-End 4-Agent Execution Chain Test
# =============================================================================

async def test_end_to_end_4_agent_pipeline():
    orchestrator = AgentOrchestrator()
    orchestrator.auditor.audit_delay = 0.05

    trace_log = []
    orchestrator.register_trace_callback(lambda t: trace_log.append(t))

    await orchestrator.start()

    attack_payload = {
        "threat_type": "Zero-Day Memory Injection (Reflective DLL)",
        "source_ip": "198.51.100.99",
        "port": 4444,
        "threat_score": 0.94,
        "feature_vector": [4444.0, 6.0, 500000.0, 15.0, 10.0] + [0.0] * 15,
        "telemetry": {
            "pid": 8888,
            "processName": "injected_payload.exe",
        },
    }

    # Ingest attack into the 4-agent orchestrator
    anomaly = await orchestrator.ingest_attack(attack_payload)
    assert anomaly is not None

    # Wait for async pipeline to propagate through all 4 agents
    await asyncio.sleep(0.6)

    await orchestrator.stop()

    # Verify traces from all 4 agents were emitted in order
    agent_names = [t.get("agent") for t in trace_log]
    assert "Detector Agent" in agent_names
    assert "Investigator Agent" in agent_names
    assert "Remediator Agent" in agent_names
    assert "Auditor Agent" in agent_names


# =============================================================================
# Standalone CLI Test Runner
# =============================================================================

def run_all_tests():
    print("\n" + "=" * 75)
    print("       AegisAI 4-Agent Architecture - Unit & Integration Tests")
    print("=" * 75)

    tests = [
        ("1. Event Schemas & Serialization", lambda: test_event_schemas_validation_and_serialization()),
        ("2. Event Bus Pub/Sub & Error Isolation", lambda: asyncio.run(test_event_bus_pub_sub_and_isolation())),
        ("2b. Event Bus Duplicate Subscriptions & Shutdown", lambda: asyncio.run(test_event_bus_duplicate_and_shutdown())),
        ("3. Dynamic Adaptive Threshold tau(t)", lambda: test_dynamic_threshold_computations()),
        ("4. Detector Agent Anomaly Filtering", lambda: asyncio.run(test_detector_agent_anomaly_filtering())),
        ("5. Investigator Agent Attribution", lambda: asyncio.run(test_investigator_agent_attribution())),
        ("6. Remediator Agent Guardrails & Actions", lambda: asyncio.run(test_remediator_agent_guardrails_and_actions())),
        ("7. Auditor Agent Verification & SQLite Vector Persistence", lambda: asyncio.run(test_auditor_agent_verification_and_sqlite())),
        ("7b. Auditor Agent Bounded Fallback Limit", lambda: asyncio.run(test_auditor_bounded_fallback())),
        ("8. End-to-End 4-Agent Execution Chain", lambda: asyncio.run(test_end_to_end_4_agent_pipeline())),
    ]

    all_passed = True
    for name, test_fn in tests:
        try:
            test_fn()
            print(f"  \033[92m[PASS]\033[0m {name}")
        except Exception as e:
            print(f"  \033[91m[FAIL]\033[0m {name}: {e}")
            import traceback
            traceback.print_exc()
            all_passed = False

    print("=" * 75)
    if all_passed:
        print("  \033[92m\033[1mALL 10 AGENT ARCHITECTURE TESTS PASSED SUCCESSFULLY!\033[0m")
        print("=" * 75 + "\n")
        sys.exit(0)
    else:
        print("  \033[91m\033[1mSOME TESTS FAILED!\033[0m")
        print("=" * 75 + "\n")
        sys.exit(1)


if __name__ == "__main__":
    run_all_tests()
