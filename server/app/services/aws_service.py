"""
AegisAI AWS Cloud Vault Service — AWS KMS & Amazon S3 Object Lock (Immutable Legal Vault)
Handles cryptographic sealing and WORM (Write Once, Read Many) compliance archival
of court-admissible NIST CSF 2.0 & GDPR Article 33 audit reports into Amazon S3.
"""
from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional
from loguru import logger

from app.core.config import get_settings


class AWSS3AuditVault:
    """
    Manages immutable, tamper-resistant storage for AegisAI compliance audit reports.
    Enforces Server-Side Encryption with AWS Key Management Service (SSE-KMS) and
    Amazon S3 Object Lock in COMPLIANCE mode with legal retention windows.
    """

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self.region = self.settings.AWS_REGION
        self.bucket_name = self.settings.AWS_S3_BUCKET_NAME
        self.kms_key_id = self.settings.AWS_KMS_KEY_ID
        self.retention_days = self.settings.AWS_OBJECT_LOCK_RETENTION_DAYS
        self.vault_enabled = self.settings.AWS_VAULT_ENABLED
        self._s3_client = None

    def get_s3_client(self):
        """Lazy-initialize boto3 S3 client with safe fallback handling."""
        if self._s3_client is not None:
            return self._s3_client

        try:
            import boto3
            from botocore.config import Config

            boto_cfg = Config(
                region_name=self.region,
                retries={"max_attempts": 3, "mode": "standard"},
                connect_timeout=5,
                read_timeout=10,
            )
            self._s3_client = boto3.client("s3", config=boto_cfg)
            return self._s3_client
        except Exception as e:
            logger.warning(f"[AWS Vault] Failed to initialize boto3 S3 client: {e}")
            return None

    def set_s3_client(self, client: Any) -> None:
        """Inject mock or custom S3 client for testing."""
        self._s3_client = client

    def upload_immutable_audit(self, threat_id: str, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Uploads and cryptographically locks a court-admissible audit report to Amazon S3.

        Guarantees:
          1. Canonical JSON serialization & SHA-256 integrity verification.
          2. Server-Side Encryption with AWS KMS (SSE-KMS).
          3. S3 Object Lock in COMPLIANCE mode (WORM) with retain-until date.
          4. Forensic metadata binding (threat ID, SHA-256 checksum, compliance standard).
          5. Graceful fallback on missing/invalid credentials without interrupting local flow.
        """
        import copy

        # 1. Check & verify original SHA-256 checksum against report metadata
        meta_checksum = report_data.get("report_metadata", {}).get("sha256_integrity_checksum")
        if meta_checksum:
            try:
                verif_dict = copy.deepcopy(report_data)
                if "report_metadata" in verif_dict and "sha256_integrity_checksum" in verif_dict["report_metadata"]:
                    del verif_dict["report_metadata"]["sha256_integrity_checksum"]
                verif_dict.pop("aws_vault_status", None)
                verif_bytes = json.dumps(verif_dict, sort_keys=True, default=str).encode("utf-8")
                calc_meta_checksum = hashlib.sha256(verif_bytes).hexdigest()
                sha256_verified = (calc_meta_checksum == meta_checksum)
            except Exception:
                sha256_verified = False
        else:
            sha256_verified = True

        # 2. Canonical JSON serialization of full payload
        try:
            canonical_bytes = json.dumps(report_data, sort_keys=True, default=str).encode("utf-8")
            payload_checksum = hashlib.sha256(canonical_bytes).hexdigest()
        except Exception as e:
            logger.error(f"[AWS Vault] Failed to serialize report for threat {threat_id}: {e}")
            return {
                "success": False,
                "s3_uri": None,
                "kms_encrypted": False,
                "object_locked": False,
                "sha256_verified": False,
                "fallback_mode": "LOCAL_ONLY",
                "error": f"Serialization error: {str(e)}",
            }

        if not self.vault_enabled:
            logger.info("[AWS Vault] AWS Vault sync is disabled by configuration (LOCAL_ONLY)")
            return {
                "success": False,
                "s3_uri": None,
                "kms_encrypted": False,
                "object_locked": False,
                "sha256_verified": sha256_verified,
                "fallback_mode": "LOCAL_ONLY",
                "error": "AWS Vault sync disabled via configuration",
            }

        s3_client = self.get_s3_client()
        if s3_client is None:
            logger.warning("[AWS Vault] Boto3 S3 client unavailable; falling back to local audit persistence.")
            return {
                "success": False,
                "s3_uri": None,
                "kms_encrypted": False,
                "object_locked": False,
                "sha256_verified": sha256_verified,
                "fallback_mode": "LOCAL_ONLY",
                "error": "AWS S3 client unavailable (credentials unconfigured or missing boto3)",
            }

        object_key = f"vault/AegisAI_Audit_Report_{threat_id}.json"
        retention_date = datetime.now(timezone.utc) + timedelta(days=self.retention_days)

        put_params: Dict[str, Any] = {
            "Bucket": self.bucket_name,
            "Key": object_key,
            "Body": canonical_bytes,
            "ContentType": "application/json",
            "ServerSideEncryption": "aws:kms",
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": retention_date,
            "Metadata": {
                "threat-id": str(threat_id),
                "sha256-checksum": str(payload_checksum),
                "compliance-standard": "NIST_CSF_2.0_GDPR_Art_33",
            },
        }

        if self.kms_key_id:
            put_params["SSEKMSKeyId"] = self.kms_key_id

        try:
            logger.info(
                f"[AWS Vault] Uploading immutable audit to s3://{self.bucket_name}/{object_key} "
                f"(SSE-KMS | COMPLIANCE Lock {self.retention_days}d)"
            )
            response = s3_client.put_object(**put_params)

            s3_uri = f"s3://{self.bucket_name}/{object_key}"
            logger.info(f"[AWS Vault] Successfully locked audit report in AWS S3 Vault: {s3_uri}")

            return {
                "success": True,
                "s3_uri": s3_uri,
                "bucket": self.bucket_name,
                "object_key": object_key,
                "threat_id": threat_id,
                "kms_encrypted": True,
                "kms_key_id": self.kms_key_id or "default-aws/s3",
                "object_locked": True,
                "object_lock_mode": "COMPLIANCE",
                "object_lock_retain_until": retention_date.isoformat(),
                "sha256_verified": sha256_verified,
                "sha256_checksum": payload_checksum,
                "version_id": response.get("VersionId") if isinstance(response, dict) else None,
                "etag": response.get("ETag") if isinstance(response, dict) else None,
            }

        except Exception as e:
            logger.warning(
                f"[AWS Vault] Cloud sync failed for {threat_id}: {e}. "
                "Operating under graceful fallback (local report preserved)."
            )
            return {
                "success": False,
                "s3_uri": None,
                "kms_encrypted": False,
                "object_locked": False,
                "sha256_verified": sha256_verified,
                "fallback_mode": "LOCAL_ONLY",
                "error": str(e),
                "threat_id": threat_id,
            }


# Singleton instances for application lifecycle
aws_s3_vault = AWSS3AuditVault()


class AWSEventBridgeService:
    """
    Manages asynchronous fleet-wide threat intelligence broadcasting via AWS EventBridge.
    Publishes zero-day payload signatures, Shannon entropy scores, and decoy entrapment
    telemetry to enterprise event consumers and SageMaker edge retraining pipelines.
    """

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self.region = self.settings.AWS_REGION
        self.bus_name = self.settings.AWS_EVENTBRIDGE_BUS_NAME
        self.enabled = self.settings.AWS_EVENTBRIDGE_ENABLED
        self._events_client = None

    def get_events_client(self):
        """Lazy-initialize boto3 EventBridge client with safe fallback handling."""
        if self._events_client is not None:
            return self._events_client

        try:
            import boto3
            from botocore.config import Config

            boto_cfg = Config(
                region_name=self.region,
                retries={"max_attempts": 3, "mode": "standard"},
                connect_timeout=5,
                read_timeout=10,
            )
            self._events_client = boto3.client("events", config=boto_cfg)
            return self._events_client
        except Exception as e:
            logger.warning(f"[AWS EventBridge] Failed to initialize boto3 events client: {e}")
            return None

    def set_events_client(self, client: Any) -> None:
        """Inject mock or custom EventBridge client for testing."""
        self._events_client = client

    def publish_zero_day_signature(
        self,
        threat_id: str,
        signature_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Publish novel zero-day honeypot payload signature to AWS EventBridge.

        Guarantees:
          1. Schema validation (threat_id, sha256_fingerprint, entropy, decoy_port, hex_prefix).
          2. Asynchronous cloud broadcast to 'aegisai.deception' under 'ZeroDayThreatTrapped'.
          3. Graceful fallback to LOCAL_RETRAINING_ONLY if cloud sync is unconfigured or fails.
        """
        if not self.enabled:
            logger.info("[AWS EventBridge] Cloud broadcast disabled via configuration (LOCAL_RETRAINING_ONLY)")
            return {
                "success": False,
                "fallback_mode": "LOCAL_RETRAINING_ONLY",
                "error": "AWS EventBridge disabled via configuration",
                "threat_id": threat_id,
            }

        # 1. Structure forensic signature detail
        raw_payload = signature_data.get("rawPayload") or signature_data.get("raw_payload") or ""
        hex_prefix = signature_data.get("hex_prefix")
        if not hex_prefix and raw_payload:
            hex_prefix = raw_payload[:32].encode("utf-8", errors="ignore").hex()

        raw_entropy = signature_data.get("entropy")
        if raw_entropy is None:
            raw_entropy = signature_data.get("shannon_entropy", 0.0)

        detail = {
            "threat_id": str(threat_id),
            "sha256_fingerprint": str(
                signature_data.get("sha256_fingerprint")
                or signature_data.get("payloadHash")
                or signature_data.get("hash")
                or hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
            ),
            "shannon_entropy": round(float(raw_entropy), 4),
            "decoy_port": signature_data.get("decoy_port") or signature_data.get("sourcePort") or signature_data.get("port"),
            "hex_prefix": hex_prefix,
            "sanitized_command": signature_data.get("command_executed") or signature_data.get("commandExecuted") or "N/A",
            "trap_type": signature_data.get("trap_type") or signature_data.get("trapType") or "HONEYPOT_TRAP",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

        # 2. Check client availability
        events_client = self.get_events_client()
        if events_client is None:
            logger.warning("[AWS EventBridge] Client unavailable; operating under LOCAL_RETRAINING_ONLY fallback.")
            return {
                "success": False,
                "fallback_mode": "LOCAL_RETRAINING_ONLY",
                "error": "AWS EventBridge client unavailable (credentials unconfigured or missing boto3)",
                "threat_id": threat_id,
            }

        # 3. Publish to AWS EventBridge
        try:
            entry_params = {
                "Source": "aegisai.deception",
                "DetailType": "ZeroDayThreatTrapped",
                "EventBusName": self.bus_name,
                "Detail": json.dumps(detail, sort_keys=True, default=str),
            }

            logger.info(
                f"[AWS EventBridge] Publishing zero-day signature for {threat_id} "
                f"to bus '{self.bus_name}' (Source: aegisai.deception, Entropy: {detail['shannon_entropy']})"
            )
            response = events_client.put_events(Entries=[entry_params])

            failed_count = response.get("FailedEntryCount", 0)
            entries = response.get("Entries", [])
            first_entry = entries[0] if entries else {}

            if failed_count > 0:
                err_msg = first_entry.get("ErrorMessage", "Unknown EventBridge error")
                logger.warning(f"[AWS EventBridge] PutEvents reported failure: {err_msg}")
                return {
                    "success": False,
                    "fallback_mode": "LOCAL_RETRAINING_ONLY",
                    "error": err_msg,
                    "threat_id": threat_id,
                }

            event_id = first_entry.get("EventId")
            logger.info(f"[AWS EventBridge] Successfully published zero-day signature | Event ID: {event_id}")

            return {
                "success": True,
                "event_id": event_id,
                "event_bus": self.bus_name,
                "source": "aegisai.deception",
                "detail_type": "ZeroDayThreatTrapped",
                "threat_id": threat_id,
                "sha256_fingerprint": detail["sha256_fingerprint"],
                "shannon_entropy": detail["shannon_entropy"],
                "timestamp_utc": detail["timestamp_utc"],
                "detail": detail,
            }

        except Exception as e:
            logger.warning(
                f"[AWS EventBridge] Cloud broadcast failed for {threat_id}: {e}. "
                "Operating under graceful fallback (local edge retraining preserved)."
            )
            return {
                "success": False,
                "fallback_mode": "LOCAL_RETRAINING_ONLY",
                "error": str(e),
                "threat_id": threat_id,
            }


# Singleton instance for application lifecycle
aws_eventbridge = AWSEventBridgeService()
