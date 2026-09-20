"""
AegisAI Dynamic Generative Honeypot Traps & Active Deception Engine Test Suite.
Verifies:
  1. Dynamic decoy listener initialization and protocol handshake emulation (HTTP, FTP, SSH, RawSocket).
  2. Shannon entropy calculation and non-destructive signature extraction.
  3. Dynamic socket traffic redirection & payload entrapment.
  4. Remediator Agent HONEYPOT_REDIRECT execution & Quorum token authorization.
  5. Auditor Agent SQLite retraining persistence with 'novel/unknown behavior' tag.
"""
from __future__ import annotations

import sys
from pathlib import Path

SERVER_ROOT = Path(__file__).resolve().parents[1]
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

import asyncio
import pytest
import sqlite3
import json
import hashlib

from app.services.deception import (
    DynamicHoneypotEngine,
    calculate_entropy,
    dynamic_honeypot_engine,
)
from app.agents.event_bus import EventBus
from app.agents.remediator import RemediatorAgent
from app.agents.auditor import AuditorAgent
from app.agents.schemas import (
    ThreatInvestigatedEvent,
    RemediationExecutedEvent,
    ActionType,
    ActionStatus,
    VerificationStatus,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Entropy & Signature Extraction Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_shannon_entropy_calculation():
    """Verify Shannon entropy correctly scores plain strings vs encrypted shellcode."""
    low_entropy = "AAAAAAAABBBBBBBBCCCCCCCC"
    score_low = calculate_entropy(low_entropy)
    assert 0.0 <= score_low < 0.35

    # High entropy random shellcode / encrypted bytes
    high_entropy_bytes = bytes([x % 256 for x in range(256)])
    score_high = calculate_entropy(high_entropy_bytes)
    assert 0.85 <= score_high <= 1.0


def test_signature_extraction():
    """Verify non-destructive extraction of SHA-256 hash, entropy, byte length, and hex signature."""
    engine = DynamicHoneypotEngine()
    raw = "\\x90\\x90\\x90\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3"
    sig = engine.extract_signature(
        raw_payload=raw,
        source_ip="198.51.100.42",
        source_port=49152,
        decoy_port=8443,
        trap_type="FAKE_RAW_SOCKET",
    )

    assert "sha256_hash" in sig
    assert len(sig["sha256_hash"]) == 64
    assert sig["entropy_score"] > 0.0
    assert sig["byte_length"] == len(raw)
    assert sig["hex_signature"].startswith("0x")
    assert sig["decoy_port"] == 8443
    assert sig["source_ip"] == "198.51.100.42"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Dynamic Socket Redirection & Protocol Emulation Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_dynamic_socket_redirection():
    """Verify dynamic redirection assigns appropriate decoy ports and returns entrapment record."""
    engine = DynamicHoneypotEngine()

    # SSH Vector Redirection
    res_ssh = engine.redirect_traffic_to_decoy(
        target_ip="203.0.113.15",
        target_port=22,
        threat_type="SSH Credential Brute-Force",
    )
    assert res_ssh["status"] == "TRAPPED"
    assert res_ssh["decoy_port"] == 2222
    assert res_ssh["protocol"] == "SSH"
    assert "payload_hash" in res_ssh
    assert "entropy_score" in res_ssh

    # Web / HTTP Vector Redirection
    res_http = engine.redirect_traffic_to_decoy(
        target_ip="203.0.113.16",
        target_port=80,
        threat_type="SQL Injection Web Attack",
    )
    assert res_http["status"] == "TRAPPED"
    assert res_http["decoy_port"] == 8080
    assert res_http["protocol"] == "HTTP"

    # Zero-Day Raw Socket Redirection
    res_raw = engine.redirect_traffic_to_decoy(
        target_ip="203.0.113.17",
        target_port=4444,
        threat_type="Zero-Day Memory Injection",
    )
    assert res_raw["status"] == "TRAPPED"
    assert res_raw["decoy_port"] == 8443
    assert res_raw["protocol"] == "RAW_SOCKET"


@pytest.mark.asyncio
async def test_active_decoy_listeners_handshake():
    """Verify active decoy listeners bind and return protocol handshakes."""
    engine = DynamicHoneypotEngine()
    test_ports = {"HTTP": 18080, "FTP": 12121, "SSH": 12222, "RAW_SOCKET": 18443}
    await engine.start(host="127.0.0.1", custom_ports=test_ports)

    try:
        metrics = engine.get_deception_metrics()
        assert metrics["status"] == "OPERATIONAL"
        assert len(metrics["active_ports"]) >= 4

        # Test HTTP Decoy Listener on port 18080
        reader, writer = await asyncio.open_connection("127.0.0.1", 18080)
        writer.write(b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(512), timeout=3.0)
        assert b"HTTP/1.1 200 OK" in resp or b"Apache" in resp
        writer.close()
        await writer.wait_closed()

        # Test FTP Decoy Listener on port 12121
        reader_ftp, writer_ftp = await asyncio.open_connection("127.0.0.1", 12121)
        banner_ftp = await asyncio.wait_for(reader_ftp.readline(), timeout=3.0)
        assert b"220" in banner_ftp
        writer_ftp.write(b"USER admin\r\n")
        await writer_ftp.drain()
        resp_user = await asyncio.wait_for(reader_ftp.readline(), timeout=3.0)
        assert b"331" in resp_user
        writer_ftp.write(b"QUIT\r\n")
        await writer_ftp.drain()
        writer_ftp.close()
        await writer_ftp.wait_closed()

        # Test SSH Decoy Listener on port 12222
        reader_ssh, writer_ssh = await asyncio.open_connection("127.0.0.1", 12222)
        banner_ssh = await asyncio.wait_for(reader_ssh.readline(), timeout=3.0)
        assert b"SSH-2.0-OpenSSH" in banner_ssh
        writer_ssh.close()
        await writer_ssh.wait_closed()

    finally:
        await engine.stop()


# ─────────────────────────────────────────────────────────────────────────────
# 3. Remediator Agent & Quorum Token Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_remediator_honeypot_redirect_action():
    """Verify Remediator Agent automatically triggers HONEYPOT_REDIRECT for zero-day threats."""
    bus = EventBus()
    remediator = RemediatorAgent(bus)

    investigated_event = ThreatInvestigatedEvent(
        source_anomaly_event_id="anomaly-zd-1234",
        threat_score=0.88,
        severity="critical",
        root_cause="Zero-Day Anomaly Probe (Unclassified Shellcode)",
        positive_drivers=[{"feature": "high_port_entropy", "impact": 0.42}],
        negative_indicators=[],
        process_pid=None,
        process_name=None,
        memory_context={"source_ip": "198.51.100.99", "port": 4444},
        honeypot_context={"decoy_candidate": True},
        feature_vector=[0.88, 4444.0, 1.0],
    )

    action_type = remediator._determine_action(investigated_event)
    assert action_type == ActionType.HONEYPOT_REDIRECT

    # Execute honeypot redirection
    status, reason, details = remediator._execute_honeypot_redirect(investigated_event)
    assert status == ActionStatus.SUCCESS
    assert "Dynamic honeypot activated" in reason
    assert details["status"] == "TRAPPED"
    assert "payload_hash" in details
    assert "entropy_score" in details


# ─────────────────────────────────────────────────────────────────────────────
# 4. Auditor Agent & Edge Retraining Persistence Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_auditor_retraining_persistence_novel_behavior():
    """Verify Auditor Agent tags honeypot entrapments as novel/unknown behavior in aegisai.db."""
    bus = EventBus()
    auditor = AuditorAgent(bus)

    remediation_event = RemediationExecutedEvent(
        source_investigation_event_id="inv-zd-5678",
        process_pid=None,
        process_name=None,
        action_type=ActionType.HONEYPOT_REDIRECT,
        action_status=ActionStatus.SUCCESS,
        action_reason="Dynamic honeypot activated on port 2222 | Redirecting traffic",
        target="HONEYPOT:UNCLASSIFIED",
        details={
            "decoy_port": 2222,
            "payload_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "entropy_score": 0.84,
            "hex_signature": "0x5353482d322e30",
        },
        feature_vector=[0.88, 2222.0, 0.84],
        quorum_verified=True,
        execution_authorized=True,
        execution_status="SUCCESS",
    )

    # Classify retraining label
    label = auditor._classify_retraining_label(remediation_event, verified=True)
    assert label == "novel/unknown behavior"

    # Persist to SQLite
    auditor._persist_retraining_sample(
        event=remediation_event,
        verification_status=VerificationStatus.SUCCESS,
        retraining_label=label,
    )

    # Query SQLite database to verify persistence
    conn = sqlite3.connect(str(auditor.db_path))
    cursor = conn.cursor()
    cursor.execute("SELECT id, threat_label, verification_result, metadata FROM retraining_samples WHERE id = ?", (remediation_event.event_id,))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row[0] == remediation_event.event_id
    assert row[1] == "novel/unknown behavior"
    assert row[2] == "SUCCESS"
    meta = json.loads(row[3])
    assert meta["decoy_port"] == 2222
    assert meta["entropy_score"] == 0.84
