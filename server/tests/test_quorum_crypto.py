"""
AegisAI Cryptographic Action Quorum & HMAC Authorization Test Suite
Verifies:
  1.  Valid token generation
  2.  Valid HMAC verification
  3.  Modified PID rejection (payload mismatch)
  4.  Modified action rejection (payload mismatch)
  5.  Modified threat hash rejection (payload mismatch)
  6.  Modified nonce rejection (unknown nonce)
  7.  Modified timestamp rejection (payload mismatch)
  8.  Invalid signature rejection (invalid HMAC)
  9.  Expiration after 30 seconds
  10. Nonce replay rejection
  11. Rejected token cannot execute
  12. Expired token cannot execute
  13. Unknown nonce cannot execute
  14. Missing token cannot execute
  15. Human approval allows valid high-risk action
  16. Human rejection blocks action
  17. Protected PID blocks action
  18. PID identity change blocks action
  19. AegisAI self-kill protection
  20. Concurrent duplicate authorization requests (race condition protection)
  21. Double-click authorization
  22. Automatic honeypot authorization
  23. HMAC secret never appears in logs or serialized payloads
"""
from __future__ import annotations

import asyncio
import copy
import os
import sys
import time
from pathlib import Path
import pytest

SERVER_ROOT = Path(__file__).resolve().parents[1]
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

from app.core.quorum import (
    PendingQuorumStore,
    PendingTokenRecord,
    QuorumTokenStatus,
    compute_threat_hash,
    generate_hmac_signature,
    generate_nonce,
    get_quorum_secret,
    serialize_canonical_payload,
    set_quorum_secret,
    verify_hmac_signature,
)
from app.core.security import (
    is_aegisai_self,
    is_protected_process,
    validate_process_identity,
)
from app.agents.schemas import (
    ActionStatus,
    ActionType,
    QuorumToken,
    ThreatInvestigatedEvent,
)
from app.agents.event_bus import EventBus
from app.agents.remediator import RemediatorAgent


@pytest.fixture
def fresh_quorum_store():
    """Provides a fresh isolated PendingQuorumStore instance."""
    return PendingQuorumStore(token_lifetime=30.0)


# =============================================================================
# 1. Valid Token Generation
# =============================================================================

@pytest.mark.asyncio
async def test_valid_token_generation(fresh_quorum_store):
    threat_hash = compute_threat_hash(
        source_event_id="evt-1001",
        threat_score=0.96,
        severity="critical",
        root_cause="Outbound socket entropy anomaly",
        target_pid=8104,
        process_name="svchost.exe",
    )
    record, abbrev = await fresh_quorum_store.create_pending_token(
        target_pid=8104,
        action_type="PID_KILL",
        threat_hash=threat_hash,
        threat_score=0.96,
        process_info={"name": "svchost.exe"},
    )

    assert record is not None
    assert len(record.nonce) == 32  # 16 bytes hex = 32 chars
    assert record.target_pid == 8104
    assert record.action_type == "PID_KILL"
    assert record.threat_hash == threat_hash
    assert record.status == QuorumTokenStatus.PENDING_AUTHORIZATION
    assert len(record.hmac_signature) == 64  # SHA-256 hex digest = 64 chars
    assert record.expires_at > record.timestamp
    assert "..." in abbrev


# =============================================================================
# 2. Valid HMAC Verification
# =============================================================================

@pytest.mark.asyncio
async def test_valid_hmac_verification(fresh_quorum_store):
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=4242,
        action_type="NET_ISOLATE",
        threat_hash="a" * 64,
        threat_score=0.88,
    )
    canonical_bytes = record.canonical_bytes()
    assert verify_hmac_signature(canonical_bytes, record.hmac_signature) is True


# =============================================================================
# 3. Modified PID Rejection (Payload Mismatch)
# =============================================================================

@pytest.mark.asyncio
async def test_modified_pid_rejection(fresh_quorum_store):
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=5000,
        action_type="PID_KILL",
        threat_hash="b" * 64,
        threat_score=0.90,
    )
    # Approve legitimately
    ok, status, r = await fresh_quorum_store.authorize_token(
        record.nonce, record.hmac_signature, "APPROVE"
    )
    assert ok is True

    # Tampered PID 9999 instead of 5000
    valid, reason, _ = await fresh_quorum_store.validate_for_execution(
        nonce=record.nonce,
        expected_pid=9999,
        expected_action="PID_KILL",
        expected_threat_hash="b" * 64,
    )
    assert valid is False
    assert reason == "PAYLOAD_MISMATCH"


# =============================================================================
# 4. Modified Action Rejection (Payload Mismatch)
# =============================================================================

@pytest.mark.asyncio
async def test_modified_action_rejection(fresh_quorum_store):
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=5000,
        action_type="PID_KILL",
        threat_hash="c" * 64,
        threat_score=0.90,
    )
    await fresh_quorum_store.authorize_token(record.nonce, record.hmac_signature, "APPROVE")

    valid, reason, _ = await fresh_quorum_store.validate_for_execution(
        nonce=record.nonce,
        expected_pid=5000,
        expected_action="NET_ISOLATE",  # Altered action
        expected_threat_hash="c" * 64,
    )
    assert valid is False
    assert reason == "PAYLOAD_MISMATCH"


# =============================================================================
# 5. Modified Threat Hash Rejection
# =============================================================================

@pytest.mark.asyncio
async def test_modified_threat_hash_rejection(fresh_quorum_store):
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=5000,
        action_type="PID_KILL",
        threat_hash="d" * 64,
        threat_score=0.90,
    )
    await fresh_quorum_store.authorize_token(record.nonce, record.hmac_signature, "APPROVE")

    valid, reason, _ = await fresh_quorum_store.validate_for_execution(
        nonce=record.nonce,
        expected_pid=5000,
        expected_action="PID_KILL",
        expected_threat_hash="f" * 64,  # Altered threat hash
    )
    assert valid is False
    assert reason == "PAYLOAD_MISMATCH"


# =============================================================================
# 6. Modified Nonce Rejection (Unknown Nonce)
# =============================================================================

@pytest.mark.asyncio
async def test_modified_nonce_rejection(fresh_quorum_store):
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=5000,
        action_type="PID_KILL",
        threat_hash="e" * 64,
        threat_score=0.90,
    )
    # Supplied unknown nonce
    ok, reason, _ = await fresh_quorum_store.authorize_token(
        "deadbeef" * 4, record.hmac_signature, "APPROVE"
    )
    assert ok is False
    assert reason == "UNKNOWN_NONCE"


# =============================================================================
# 7. Modified Timestamp Rejection (Payload Mismatch)
# =============================================================================

def test_modified_timestamp_rejection():
    payload = {
        "action_type": "PID_KILL",
        "nonce": "11" * 16,
        "target_pid": 1234,
        "threat_hash": "a" * 64,
        "timestamp": 1700000000.0,
    }
    canonical = serialize_canonical_payload(payload)
    sig = generate_hmac_signature(canonical)

    # Tamper with timestamp
    tampered = copy.deepcopy(payload)
    tampered["timestamp"] = 1700000001.0
    tampered_canonical = serialize_canonical_payload(tampered)

    assert verify_hmac_signature(tampered_canonical, sig) is False


# =============================================================================
# 8. Invalid Signature Rejection
# =============================================================================

@pytest.mark.asyncio
async def test_invalid_signature_rejection(fresh_quorum_store):
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=6000,
        action_type="PID_KILL",
        threat_hash="f" * 64,
        threat_score=0.95,
    )
    fake_signature = "bad" * 21 + "a"
    ok, reason, _ = await fresh_quorum_store.authorize_token(
        record.nonce, fake_signature, "APPROVE"
    )
    assert ok is False
    assert reason == "INVALID_HMAC_SIGNATURE"


# =============================================================================
# 9. Expiration After 30 Seconds
# =============================================================================

@pytest.mark.asyncio
async def test_expiration_after_30_seconds(fresh_quorum_store):
    # Set short TTL of 0.05 seconds for test speed
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=7000,
        action_type="PID_KILL",
        threat_hash="1" * 64,
        threat_score=0.92,
        lifetime=0.05,
    )
    # Wait for expiration
    await asyncio.sleep(0.08)

    ok, reason, _ = await fresh_quorum_store.authorize_token(
        record.nonce, record.hmac_signature, "APPROVE"
    )
    assert ok is False
    assert reason == "TOKEN_EXPIRED"
    assert record.status == QuorumTokenStatus.EXPIRED


# =============================================================================
# 10. Nonce Replay Rejection
# =============================================================================

@pytest.mark.asyncio
async def test_nonce_replay_rejection(fresh_quorum_store):
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=8000,
        action_type="PID_KILL",
        threat_hash="2" * 64,
        threat_score=0.91,
    )
    # First authorization succeeds
    ok1, reason1, _ = await fresh_quorum_store.authorize_token(
        record.nonce, record.hmac_signature, "APPROVE"
    )
    assert ok1 is True
    assert reason1 == "AUTHORIZED"

    # Replay identical request
    ok2, reason2, _ = await fresh_quorum_store.authorize_token(
        record.nonce, record.hmac_signature, "APPROVE"
    )
    assert ok2 is False
    assert reason2 == "NONCE_ALREADY_CONSUMED"


# =============================================================================
# 11. Rejected Token Cannot Execute
# =============================================================================

@pytest.mark.asyncio
async def test_rejected_token_cannot_execute(fresh_quorum_store):
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=9000,
        action_type="PID_KILL",
        threat_hash="3" * 64,
        threat_score=0.93,
    )
    # Reject token
    ok, reason, _ = await fresh_quorum_store.authorize_token(
        record.nonce, record.hmac_signature, "REJECT"
    )
    assert ok is True
    assert record.status == QuorumTokenStatus.REJECTED

    # Attempt to execute
    valid, v_reason, _ = await fresh_quorum_store.validate_for_execution(
        record.nonce, 9000, "PID_KILL", "3" * 64
    )
    assert valid is False
    assert "TOKEN_STATUS_REJECTED" in v_reason


# =============================================================================
# 12. Expired Token Cannot Execute
# =============================================================================

@pytest.mark.asyncio
async def test_expired_token_cannot_execute(fresh_quorum_store):
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=9001,
        action_type="PID_KILL",
        threat_hash="4" * 64,
        threat_score=0.93,
        lifetime=0.05,
    )
    await asyncio.sleep(0.08)

    valid, v_reason, _ = await fresh_quorum_store.validate_for_execution(
        record.nonce, 9001, "PID_KILL", "4" * 64
    )
    assert valid is False
    assert "TOKEN_STATUS_EXPIRED" in v_reason or "TOKEN_STATUS_PENDING_AUTHORIZATION" in v_reason


# =============================================================================
# 13. Unknown Nonce Cannot Execute
# =============================================================================

@pytest.mark.asyncio
async def test_unknown_nonce_cannot_execute(fresh_quorum_store):
    valid, reason, _ = await fresh_quorum_store.validate_for_execution(
        "unknown_nonce_123", 1000, "PID_KILL", "5" * 64
    )
    assert valid is False
    assert reason == "UNKNOWN_NONCE"


# =============================================================================
# 14. Missing Token Cannot Execute
# =============================================================================

@pytest.mark.asyncio
async def test_missing_token_cannot_execute(fresh_quorum_store):
    valid, reason, _ = await fresh_quorum_store.validate_for_execution(
        "", 1000, "PID_KILL", "5" * 64
    )
    assert valid is False


# =============================================================================
# 15. Human Approval Allows Valid High-Risk Action
# =============================================================================

@pytest.mark.asyncio
async def test_human_approval_allows_valid_high_risk_action(fresh_quorum_store):
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=7777,
        action_type="PID_KILL",
        threat_hash="6" * 64,
        threat_score=0.96,
        process_info={"name": "malicious_miner.exe"},
    )
    ok, reason, r = await fresh_quorum_store.authorize_token(
        record.nonce, record.hmac_signature, "APPROVE"
    )
    assert ok is True
    assert r.status == QuorumTokenStatus.AUTHORIZED
    assert r.human_authorized is True
    assert r.execution_authorized is True

    valid, v_reason, _ = await fresh_quorum_store.validate_for_execution(
        record.nonce, 7777, "PID_KILL", "6" * 64
    )
    assert valid is True
    assert v_reason == "VALID"


# =============================================================================
# 16. Human Rejection Blocks Action
# =============================================================================

@pytest.mark.asyncio
async def test_human_rejection_blocks_action(fresh_quorum_store):
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=7778,
        action_type="PID_KILL",
        threat_hash="7" * 64,
        threat_score=0.96,
    )
    ok, reason, r = await fresh_quorum_store.authorize_token(
        record.nonce, record.hmac_signature, "REJECT"
    )
    assert ok is True
    assert r.status == QuorumTokenStatus.REJECTED
    assert r.human_authorized is False
    assert r.execution_authorized is False


# =============================================================================
# 17. Protected PID Blocks Action
# =============================================================================

def test_protected_pid_blocks_action():
    # PID 0 or 4 (System)
    prot0, r0 = is_protected_process(0)
    assert prot0 is True
    prot4, r4 = is_protected_process(4)
    assert prot4 is True

    # Windows critical processes
    for name in ["csrss.exe", "smss.exe", "wininit.exe", "services.exe", "lsass.exe", "explorer.exe"]:
        prot, reason = is_protected_process(9999, name=name)
        assert prot is True, f"{name} must be protected"


# =============================================================================
# 18. PID Identity Change Blocks Action (Anti-PID Reuse Race Condition)
# =============================================================================

def test_pid_identity_change_blocks_action():
    current_pid = os.getpid()
    # Expecting notepad.exe, but current process is python.exe
    valid, reason = validate_process_identity(
        pid=current_pid,
        expected_name="notepad.exe",
    )
    assert valid is False
    assert "PID_IDENTITY_CHANGED" in reason or "AegisAI_SELF_KILL_PREVENTED" in reason or "PROTECTED_PROCESS" in reason


# =============================================================================
# 19. AegisAI Self-Kill Protection
# =============================================================================

def test_aegisai_self_kill_protection():
    current_pid = os.getpid()
    assert is_aegisai_self(current_pid) is True

    valid, reason = validate_process_identity(pid=current_pid)
    assert valid is False
    assert "AegisAI_SELF_KILL_PREVENTED" in reason


# =============================================================================
# 20. Concurrent Duplicate Authorization Requests (Critical Race Condition Test)
# =============================================================================

@pytest.mark.asyncio
async def test_concurrent_duplicate_authorization_requests(fresh_quorum_store):
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=3141,
        action_type="PID_KILL",
        threat_hash="8" * 64,
        threat_score=0.97,
    )

    # Launch two simultaneous authorization requests with identical nonce
    results = await asyncio.gather(
        fresh_quorum_store.authorize_token(record.nonce, record.hmac_signature, "APPROVE"),
        fresh_quorum_store.authorize_token(record.nonce, record.hmac_signature, "APPROVE"),
        return_exceptions=True,
    )

    success_count = sum(1 for r in results if isinstance(r, tuple) and r[0] is True)
    failure_count = sum(1 for r in results if isinstance(r, tuple) and r[0] is False)

    # Exactly ONE must succeed and exactly ONE must be rejected as already consumed
    assert success_count == 1, f"Expected exactly 1 success, got {success_count}"
    assert failure_count == 1, f"Expected exactly 1 rejection, got {failure_count}"

    failed_result = [r for r in results if isinstance(r, tuple) and r[0] is False][0]
    assert failed_result[1] == "NONCE_ALREADY_CONSUMED"


# =============================================================================
# 21. Double-Click Authorization Handling
# =============================================================================

@pytest.mark.asyncio
async def test_double_click_authorization_handling(fresh_quorum_store):
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=2718,
        action_type="PID_KILL",
        threat_hash="9" * 64,
        threat_score=0.92,
    )

    # First click
    click1_ok, click1_reason, _ = await fresh_quorum_store.authorize_token(
        record.nonce, record.hmac_signature, "APPROVE"
    )
    # Immediate second click
    click2_ok, click2_reason, _ = await fresh_quorum_store.authorize_token(
        record.nonce, record.hmac_signature, "APPROVE"
    )

    assert click1_ok is True
    assert click1_reason == "AUTHORIZED"
    assert click2_ok is False
    assert click2_reason == "NONCE_ALREADY_CONSUMED"


# =============================================================================
# 22. Automatic Honeypot Authorization
# =============================================================================

@pytest.mark.asyncio
async def test_automatic_honeypot_authorization(fresh_quorum_store):
    record, _ = await fresh_quorum_store.create_pending_token(
        target_pid=0,
        action_type="HONEYPOT_REDIRECT",
        threat_hash="0" * 64,
        threat_score=0.75,
    )

    ok, reason = await fresh_quorum_store.auto_authorize_low_risk(record)
    assert ok is True
    assert reason == "AUTHORIZED"
    assert record.status == QuorumTokenStatus.AUTHORIZED
    assert record.execution_authorized is True
    assert record.human_authorized is False  # Automated cryptographic trail


# =============================================================================
# 23. HMAC Secret Never Appears in Logs or Serialized Records
# =============================================================================

@pytest.mark.asyncio
async def test_hmac_secret_never_appears_in_logs(fresh_quorum_store):
    secret_bytes = get_quorum_secret()
    secret_str = secret_bytes.decode("utf-8", errors="ignore")

    record, abbrev = await fresh_quorum_store.create_pending_token(
        target_pid=1111,
        action_type="PID_KILL",
        threat_hash="e" * 64,
        threat_score=0.90,
    )

    trail = fresh_quorum_store.get_audit_trail()
    for entry in trail:
        serialized = str(entry)
        assert secret_str not in serialized, "Secret must NEVER appear in audit trail"

    pending_list = await fresh_quorum_store.get_pending_tokens()
    for item in pending_list:
        serialized = str(item)
        assert secret_str not in serialized, "Secret must NEVER appear in pending tokens list"
