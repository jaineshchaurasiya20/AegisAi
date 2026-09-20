"""
AegisAI Unit Test Suite — Step 3 (Ephemeral Memory Sandbox) & Step 6 (NIST/GDPR Audit Generator)
Verifies:
  1. Ephemeral memory manager RAM buffering & zero disk writes
  2. SHA-256 data anonymization under PCTA strict mode
  3. Memory zero-fill wipe & gc.collect() routine
  4. AuditorAgent NIST CSF 2.0 & GDPR Article 33 compliance mapping
  5. TreeSHAP mathematical proofs & HMAC cryptographic proofs
  6. Audit REST export endpoints (JSON & Markdown)
"""
import sys
from pathlib import Path

SERVER_ROOT = Path(__file__).resolve().parents[1]
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

import pytest
import hashlib
import json
from httpx import AsyncClient, ASGITransport

from app.core.sandbox import (
    EphemeralMemoryManager,
    anonymize_telemetry_dict,
    hash_identity,
    ephemeral_sandbox,
)
from app.agents.event_bus import EventBus
from app.agents.auditor import AuditorAgent
from app.agents.schemas import (
    RemediationExecutedEvent,
    ActionType,
    ActionStatus,
    VerificationStatus,
)
from app.main import app
from app.core.security import create_access_token


# ─────────────────────────────────────────────────────────────────────────────
# 1. Ephemeral Memory Sandbox Tests (PCTA Compliance)
# ─────────────────────────────────────────────────────────────────────────────

def test_hash_identity_sha256():
    """Verify SHA-256 pseudonymization format."""
    val = "powershell.exe"
    anon = hash_identity(val)
    assert anon.startswith("ANON_")
    expected_hex = hashlib.sha256(val.encode("utf-8")).hexdigest()[:16]
    assert anon == f"ANON_{expected_hex}"


def test_anonymize_telemetry_pcta_strict():
    """Verify sensitive process and network handles are hashed in PCTA strict mode."""
    raw_telemetry = {
        "pid": 5812,
        "processName": "malicious_script.exe",
        "commandLine": "malicious_script.exe -ex bypass",
        "source_ip": "198.51.100.75",
        "user": "DOMAIN\\SecAdmin",
        "openSockets": [
            {"protocol": "TCP", "remoteIp": "198.51.100.75", "localIp": "127.0.0.1", "remotePort": 4444}
        ],
        "cpuUsagePct": 42.1,
    }

    sanitized = anonymize_telemetry_dict(raw_telemetry, strict=True)

    # Sensitive fields must be anonymized
    assert sanitized["processName"].startswith("ANON_")
    assert "malicious_script.exe" not in sanitized["processName"]
    assert sanitized["commandLine"].startswith("ANON_")
    assert sanitized["source_ip"].startswith("ANON_")
    assert sanitized["user"].startswith("ANON_")
    assert sanitized["openSockets"][0]["remoteIp"].startswith("ANON_")
    assert sanitized["openSockets"][0]["localIp"].startswith("ANON_")

    # Non-sensitive metrics preserved
    assert sanitized["pid"] == 5812
    assert sanitized["cpuUsagePct"] == 42.1


def test_ephemeral_memory_buffering_and_zero_fill_wipe():
    """Verify RAM buffering in io.BytesIO and explicit zero-fill context wipe."""
    manager = EphemeralMemoryManager(wipe_interval=60, strict_mode=True)

    # Buffer traces and telemetry strictly in RAM
    t1 = {"processName": "curl.exe", "source_ip": "10.0.0.5", "action": "probe"}
    t2 = {"event": "agent_trace", "message": "Investigating beacon"}

    manager.buffer_telemetry(t1)
    manager.buffer_trace(t2)

    # Buffer must hold active bytes in memory
    active_bytes = manager.get_buffered_bytes_count()
    assert active_bytes > 0
    assert len(manager.get_recent_traces()) == 1

    # Execute zero-knowledge context wipe
    wipe_res = manager.wipe_ephemeral_context()

    assert wipe_res["status"] == "wiped"
    assert wipe_res["bytes_wiped"] == active_bytes
    assert wipe_res["total_wipes"] == 1
    assert "gc_objects_collected" in wipe_res

    # Buffers must be completely zeroed and truncated
    assert manager.get_buffered_bytes_count() == 0
    assert len(manager.get_recent_traces()) == 0

    stats = manager.get_sandbox_stats()
    assert stats["active_ram_bytes"] == 0
    assert stats["disk_spill_prevented"] is True
    assert stats["total_wipes_executed"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# 2. Auditor Agent NIST CSF & GDPR Compliance Generator Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_auditor_compliance_report_generation():
    """Verify compliance report aggregation with NIST CSF 2.0, GDPR Art 33, TreeSHAP, and HMAC proofs."""
    bus = EventBus()
    auditor = AuditorAgent(bus)

    threat_id = "test-threat-uuid-9999"
    report = auditor.generate_compliance_report(threat_id=threat_id, format="json")

    assert isinstance(report, dict)

    # 1. Report Metadata & Integrity Checksum
    meta = report["report_metadata"]
    assert meta["report_id"].startswith("RPT-")
    assert "sha256_integrity_checksum" in meta
    assert len(meta["sha256_integrity_checksum"]) == 64
    assert "NIST CSF 2.0" in meta["standards"]
    assert "GDPR Article 33" in meta["standards"]

    # 2. Incident Summary
    summary = report["incident_summary"]
    assert summary["threat_id"] == threat_id
    assert "attack_vector_synthesis" in summary
    assert len(summary["attack_vector_synthesis"]) > 20

    # 3. Mathematical Proof (TreeSHAP)
    math_proof = report["mathematical_proof"]
    assert "TreeSHAP" in math_proof["explainer_model"]
    assert isinstance(math_proof["top_risk_multipliers"], list)
    assert isinstance(math_proof["safety_indicators"], list)

    # 4. Cryptographic Proof (Quorum HMAC-SHA256)
    crypto_proof = report["cryptographic_proof"]
    assert crypto_proof["hmac_algorithm"] == "HMAC-SHA256"
    assert crypto_proof["token_verification_status"] == "VERIFIED_VALID"
    assert "nonce_hash" in crypto_proof
    assert len(crypto_proof["nonce_hash"]) == 64
    assert crypto_proof["operator_authorization"]["authorization_policy"] == "CRYPTOGRAPHIC_ACTION_QUORUM"

    # 5. Closed-Loop OS Kernel Verification
    kernel = report["closed_loop_verification"]
    assert kernel["verification_status"] in ("SUCCESS", "FAILED")
    assert "kernel_audit_delay_ms" in kernel
    assert kernel["process_state_post_action"] in ("TERMINATED", "RUNNING")

    # 6. Compliance Framework Mapping
    comp = report["compliance_mapping"]
    nist = comp["NIST_CSF_2_0"]
    assert "PR.DS-1" in nist
    assert nist["PR.DS-1"]["status"] == "COMPLIANT"
    assert "Zero-Knowledge Ephemeral RAM" in nist["PR.DS-1"]["title"]

    assert "DE.AE-1" in nist
    assert nist["DE.AE-1"]["status"] == "COMPLIANT"

    assert "RS.MI-1" in nist
    assert nist["RS.MI-1"]["status"] == "COMPLIANT"

    gdpr = comp["GDPR_Article_33"]
    assert gdpr["status"] == "COMPLIANT"
    assert "72_HOURS_MANDATE_SATISFIED" in gdpr["reporting_window"]


def test_auditor_markdown_report_formatting():
    """Verify court-admissible formatted Markdown compliance export."""
    bus = EventBus()
    auditor = AuditorAgent(bus)

    threat_id = "test-threat-uuid-8888"
    md_report = auditor.generate_compliance_report(threat_id=threat_id, format="markdown")

    assert isinstance(md_report, str)
    assert "# 🛡️ AegisAI Compliance Audit Report" in md_report
    assert "## 1. Incident Summary" in md_report
    assert "## 2. Mathematical Proof (TreeSHAP Feature Attributions)" in md_report
    assert "## 3. Cryptographic Quorum Proof" in md_report
    assert "## 4. Closed-Loop OS Kernel Verification" in md_report
    assert "## 5. Regulatory Compliance Mapping" in md_report
    assert "PR.DS-1" in md_report
    assert "DE.AE-1" in md_report
    assert "RS.MI-1" in md_report
    assert "GDPR Article 33" in md_report
    assert "SHA-256" in md_report


# ─────────────────────────────────────────────────────────────────────────────
# 3. REST Endpoint Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_export_json_endpoint():
    """Test GET /api/audit/export/{threat_id} returns court-admissible JSON report."""
    token = create_access_token({"sub": "admin", "role": "admin"})
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get(
            "/api/audit/export/threat-alpha-100?format=json",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200
        assert "application/json" in res.headers["content-type"]
        assert "attachment; filename=" in res.headers["content-disposition"]

        data = res.json()
        assert data["incident_summary"]["threat_id"] == "threat-alpha-100"
        assert "compliance_mapping" in data
        assert "PR.DS-1" in data["compliance_mapping"]["NIST_CSF_2_0"]
        assert "GDPR_Article_33" in data["compliance_mapping"]


@pytest.mark.asyncio
async def test_audit_export_markdown_endpoint():
    """Test GET /api/audit/export/{threat_id}?format=markdown returns formatted markdown."""
    token = create_access_token({"sub": "admin", "role": "admin"})
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get(
            "/api/audit/export/threat-alpha-200?format=markdown",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200
        assert "text/markdown" in res.headers["content-type"]
        assert "attachment; filename=" in res.headers["content-disposition"]
        assert "# 🛡️ AegisAI Compliance Audit Report" in res.text


@pytest.mark.asyncio
async def test_audit_report_post_endpoint():
    """Test POST /api/audit/report endpoint."""
    token = create_access_token({"sub": "admin", "role": "admin"})
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post(
            "/api/audit/report",
            json={"threat_id": "threat-post-300", "format": "json"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["threat_id"] == "threat-post-300"
        assert "sha256_integrity_checksum" in data["report"]["report_metadata"]


@pytest.mark.asyncio
async def test_sandbox_status_and_wipe_endpoints():
    """Test GET /api/audit/sandbox/status and POST /api/audit/sandbox/wipe."""
    token = create_access_token({"sub": "admin", "role": "admin"})
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Buffer test data
        ephemeral_sandbox.buffer_trace({"msg": "Live audit test trace", "source_ip": "1.2.3.4"})

        # Check status
        status_res = await ac.get(
            "/api/audit/sandbox/status",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert status_res.status_code == 200
        status_data = status_res.json()
        assert status_data["sandbox_mode"] == "Zero-Knowledge Ephemeral RAM"
        assert status_data["disk_spill_prevented"] is True

        # Trigger manual wipe
        wipe_res = await ac.post(
            "/api/audit/sandbox/wipe",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert wipe_res.status_code == 200
        wipe_data = wipe_res.json()
        assert wipe_data["details"]["status"] == "wiped"
        assert "gc_objects_collected" in wipe_data["details"]
