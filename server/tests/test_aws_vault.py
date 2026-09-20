"""
AegisAI Unit & Integration Tests — AWS KMS & Amazon S3 Object Lock (Immutable Legal Vault)
Tests:
  1. Canonical JSON serialization, checksum hashing, and metadata generation.
  2. Graceful fallback when AWS credentials or boto3 clients are unconfigured.
  3. Mock S3 client verification enforcing SSE-KMS, ObjectLockMode='COMPLIANCE', and retain-until dates.
  4. REST endpoint integration for GET /api/audit/export/{threat_id}?format=json & POST /api/audit/report.
"""
import sys
from pathlib import Path

SERVER_ROOT = Path(__file__).resolve().parents[1]
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

import json
import hashlib
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import pytest
from httpx import AsyncClient, ASGITransport

from app.services.aws_service import AWSS3AuditVault, aws_s3_vault
from app.core.config import Settings
from app.agents.event_bus import EventBus
from app.agents.auditor import AuditorAgent
from app.main import app
from app.core.security import create_access_token


def test_canonical_json_serialization_and_checksum_integrity():
    """Verify deterministic canonical serialization and SHA-256 hash calculation."""
    vault = AWSS3AuditVault()
    sample_report = {
        "report_metadata": {
            "report_id": "RPT-SAMPLE-001",
            "generation_timestamp": "2026-09-19T12:00:00Z",
            "standards": ["NIST CSF 2.0", "GDPR Article 33"],
        },
        "incident_summary": {
            "threat_id": "threat-test-abc-123",
            "threat_score": 0.95,
            "threat_type": "Reflective DLL Injection",
        },
    }

    # Canonical bytes calculation
    canonical_bytes = json.dumps(sample_report, sort_keys=True, default=str).encode("utf-8")
    expected_hash = hashlib.sha256(canonical_bytes).hexdigest()

    # Re-order keys to verify sort_keys invariance
    reordered_report = {
        "incident_summary": {
            "threat_type": "Reflective DLL Injection",
            "threat_score": 0.95,
            "threat_id": "threat-test-abc-123",
        },
        "report_metadata": {
            "standards": ["NIST CSF 2.0", "GDPR Article 33"],
            "generation_timestamp": "2026-09-19T12:00:00Z",
            "report_id": "RPT-SAMPLE-001",
        },
    }
    reordered_bytes = json.dumps(reordered_report, sort_keys=True, default=str).encode("utf-8")
    reordered_hash = hashlib.sha256(reordered_bytes).hexdigest()

    assert expected_hash == reordered_hash
    assert len(expected_hash) == 64


def test_graceful_fallback_when_credentials_absent():
    """Verify that unconfigured/missing AWS credentials return graceful fallback without raising exceptions."""
    custom_settings = Settings(
        AWS_S3_BUCKET_NAME="aegisai-immutable-audit-vault",
        AWS_VAULT_ENABLED=True,
    )
    vault = AWSS3AuditVault(settings=custom_settings)

    # Force S3 client to None (simulating absent credentials or connection failure)
    vault.set_s3_client(None)

    # Mock get_s3_client to return None
    vault.get_s3_client = lambda: None

    report = {
        "report_metadata": {"report_id": "RPT-FALLBACK-1"},
        "incident_summary": {"threat_id": "threat-fallback-99"},
    }

    result = vault.upload_immutable_audit("threat-fallback-99", report)

    assert result["success"] is False
    assert result["fallback_mode"] == "LOCAL_ONLY"
    assert result["kms_encrypted"] is False
    assert result["object_locked"] is False
    assert result["sha256_verified"] is True
    assert "unavailable" in result["error"].lower()


def test_s3_put_object_enforces_kms_and_object_lock_compliance():
    """Verify put_object params enforce SSE-KMS, COMPLIANCE mode, 7-day retention, and metadata."""
    custom_settings = Settings(
        AWS_REGION="us-east-1",
        AWS_S3_BUCKET_NAME="aegisai-compliance-vault",
        AWS_KMS_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/test-key-id",
        AWS_OBJECT_LOCK_RETENTION_DAYS=7,
        AWS_VAULT_ENABLED=True,
    )
    vault = AWSS3AuditVault(settings=custom_settings)

    mock_s3 = MagicMock()
    mock_s3.put_object.return_value = {
        "VersionId": "v1.0-immutable-token",
        "ETag": '"abcdef0123456789"',
    }
    vault.set_s3_client(mock_s3)

    threat_id = "threat-worm-7777"
    bus = EventBus()
    auditor = AuditorAgent(bus)
    report = auditor.generate_compliance_report(threat_id=threat_id, format="json")

    result = vault.upload_immutable_audit(threat_id, report)

    assert result["success"] is True
    assert result["s3_uri"] == f"s3://aegisai-compliance-vault/vault/AegisAI_Audit_Report_{threat_id}.json"
    assert result["kms_encrypted"] is True
    assert result["kms_key_id"] == "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
    assert result["object_locked"] is True
    assert result["object_lock_mode"] == "COMPLIANCE"
    assert result["sha256_verified"] is True
    assert result["version_id"] == "v1.0-immutable-token"

    # Verify mock call parameters
    mock_s3.put_object.assert_called_once()
    _, kwargs = mock_s3.put_object.call_args

    assert kwargs["Bucket"] == "aegisai-compliance-vault"
    assert kwargs["Key"] == f"vault/AegisAI_Audit_Report_{threat_id}.json"
    assert kwargs["ServerSideEncryption"] == "aws:kms"
    assert kwargs["SSEKMSKeyId"] == "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
    assert kwargs["ObjectLockMode"] == "COMPLIANCE"
    assert isinstance(kwargs["ObjectLockRetainUntilDate"], datetime)
    # Check retention date is approx 7 days in future
    future_diff = kwargs["ObjectLockRetainUntilDate"] - datetime.now(timezone.utc)
    assert 6 <= future_diff.days <= 7

    # Verify forensic metadata
    meta = kwargs["Metadata"]
    assert meta["threat-id"] == threat_id
    assert meta["compliance-standard"] == "NIST_CSF_2.0_GDPR_Art_33"
    assert len(meta["sha256-checksum"]) == 64


def test_s3_upload_handles_client_exception_gracefully():
    """Verify that when boto3 put_object raises ClientError, it falls back without crashing."""
    vault = AWSS3AuditVault()
    mock_s3 = MagicMock()
    mock_s3.put_object.side_effect = RuntimeError("S3 AccessDenied: Bucket Object Lock configuration required")
    vault.set_s3_client(mock_s3)

    report = {"report_metadata": {}, "incident_summary": {"threat_id": "threat-err-1"}}
    res = vault.upload_immutable_audit("threat-err-1", report)

    assert res["success"] is False
    assert res["fallback_mode"] == "LOCAL_ONLY"
    assert "AccessDenied" in res["error"]


@pytest.mark.asyncio
async def test_api_export_audit_json_with_aws_vault():
    """Verify GET /api/audit/export/{threat_id}?format=json synchronizes with AWS Vault and attaches aws_vault_status."""
    token = create_access_token({"sub": "admin", "role": "admin"})
    transport = ASGITransport(app=app)

    mock_s3 = MagicMock()
    mock_s3.put_object.return_value = {"VersionId": "v1.audit-test"}
    aws_s3_vault.set_s3_client(mock_s3)

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get(
            "/api/audit/export/threat-vault-sync-100?format=json",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200
        assert res.headers["content-type"].startswith("application/json")
        assert res.headers["x-aws-vault-status"] == "VERIFIED"

        data = res.json()
        assert "aws_vault_status" in data
        vault_status = data["aws_vault_status"]
        assert vault_status["success"] is True
        assert vault_status["kms_encrypted"] is True
        assert vault_status["object_locked"] is True
        assert vault_status["sha256_verified"] is True
        assert vault_status["s3_uri"] == "s3://aegisai-immutable-audit-vault/vault/AegisAI_Audit_Report_threat-vault-sync-100.json"


@pytest.mark.asyncio
async def test_api_report_post_with_aws_vault():
    """Verify POST /api/audit/report includes aws_vault_status in response payload."""
    token = create_access_token({"sub": "admin", "role": "admin"})
    transport = ASGITransport(app=app)

    mock_s3 = MagicMock()
    mock_s3.put_object.return_value = {"VersionId": "v1.post-test"}
    aws_s3_vault.set_s3_client(mock_s3)

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post(
            "/api/audit/report",
            json={"threat_id": "threat-vault-post-200", "format": "json"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert "aws_vault_status" in data
        assert data["aws_vault_status"]["success"] is True
        assert data["aws_vault_status"]["kms_encrypted"] is True
        assert data["aws_vault_status"]["object_locked"] is True
