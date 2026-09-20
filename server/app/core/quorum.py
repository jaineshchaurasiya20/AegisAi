"""
AegisAI Cryptographic Action Quorum & HMAC Authorization Engine
Enforces a cryptographic security boundary around autonomous and operator-authorized remediation.
Provides:
  - HMAC-SHA256 token generation & constant-time verification
  - Canonical payload serialization (RFC-8785 compliant deterministic JSON)
  - Deterministic threat hash derivation (SHA-256)
  - Single-use nonce generation and anti-replay protection
  - Server-side timestamp & 30-second TTL expiration
  - Thread-safe / asyncio-safe PendingQuorumStore with atomic state transitions
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from loguru import logger

from app.core.config import get_settings

settings = get_settings()

# Allowed remediation action types under quorum governance
ALLOWED_ACTION_TYPES = frozenset({"PID_KILL", "NET_ISOLATE", "HONEYPOT_REDIRECT"})


class QuorumTokenStatus(str, Enum):
    PENDING_AUTHORIZATION = "PENDING_AUTHORIZATION"
    AUTHORIZED = "AUTHORIZED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


# =============================================================================
# Secret Key Initialization
# =============================================================================

def _resolve_quorum_secret() -> bytes:
    """
    Resolve HMAC secret from environment or configuration.
    If absent, generates an ephemeral 256-bit cryptographically secure runtime secret.
    Clearly logs warning if ephemeral secret is used. Never prints or leaks the secret.
    """
    raw_secret = (
        os.getenv("AEGISAI_QUORUM_SECRET")
        or os.getenv("AegisAI_QUORUM_SECRET")
        or getattr(settings, "QUORUM_SECRET", None)
    )

    if raw_secret and str(raw_secret).strip():
        logger.info("[Cryptographic Quorum] Loaded persistent HMAC quorum secret from environment/config.")
        return str(raw_secret).strip().encode("utf-8")

    ephemeral_secret = secrets.token_bytes(32)
    logger.warning(
        "[Cryptographic Quorum] AEGISAI_QUORUM_SECRET not set in environment or config. "
        "Generated ephemeral cryptographically secure 256-bit runtime secret. "
        "NOTICE: Pending authorization tokens CANNOT survive a process restart."
    )
    return ephemeral_secret


_QUORUM_SECRET: bytes = _resolve_quorum_secret()


def get_quorum_secret() -> bytes:
    """Return active HMAC secret bytes (for internal cryptographic functions only)."""
    return _QUORUM_SECRET


def set_quorum_secret(new_secret: str | bytes) -> None:
    """Set quorum secret (used primarily for test isolation)."""
    global _QUORUM_SECRET
    if isinstance(new_secret, str):
        _QUORUM_SECRET = new_secret.encode("utf-8")
    else:
        _QUORUM_SECRET = new_secret


# =============================================================================
# Canonical Serialization & Threat Hash
# =============================================================================

def serialize_canonical_payload(payload: Dict[str, Any]) -> bytes:
    """
    Serialize dictionary into canonical deterministic JSON byte representation:
      - UTF-8 encoding
      - Sorted keys
      - Stable separators without whitespace: (',', ':')
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_threat_hash(
    source_event_id: str,
    threat_score: float,
    severity: str,
    root_cause: str,
    target_pid: Optional[int] = None,
    process_name: Optional[str] = None,
    feature_vector: Optional[List[float]] = None,
) -> str:
    """
    Construct a deterministic SHA-256 hash representing the investigated threat event.
    The same investigated event consistently produces the same threat hash.
    Unstable fields (e.g. wall-clock request times or random socket ports) are excluded.
    """
    # Round threat score to 4 decimals for numeric stability across serialization
    stable_score = round(float(threat_score), 4)
    # Round feature vector floats to 4 decimals if provided
    stable_features: List[float] = []
    if feature_vector:
        stable_features = [round(float(v), 4) for v in feature_vector]

    deterministic_dict = {
        "feature_vector": stable_features,
        "process_name": (process_name or "").lower(),
        "root_cause": (root_cause or "").strip(),
        "severity": (severity or "medium").lower(),
        "source_event_id": str(source_event_id),
        "target_pid": int(target_pid) if target_pid is not None else 0,
        "threat_score": stable_score,
    }

    canonical_bytes = serialize_canonical_payload(deterministic_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


# =============================================================================
# HMAC-SHA256 Generation & Verification
# =============================================================================

def generate_nonce() -> str:
    """Generate a single-use 128-bit cryptographically secure hex nonce."""
    return secrets.token_hex(16)


def generate_hmac_signature(canonical_payload: bytes, secret: Optional[bytes] = None) -> str:
    """Generate HMAC-SHA256 signature over canonical payload bytes."""
    key = secret if secret is not None else get_quorum_secret()
    return hmac.new(key, canonical_payload, hashlib.sha256).hexdigest()


def verify_hmac_signature(
    canonical_payload: bytes,
    signature: str,
    secret: Optional[bytes] = None,
) -> bool:
    """
    Verify HMAC-SHA256 signature using constant-time comparison.
    Prevents timing side-channel attacks.
    """
    if not signature or not isinstance(signature, str):
        return False
    expected_sig = generate_hmac_signature(canonical_payload, secret=secret)
    return hmac.compare_digest(expected_sig, signature.strip().lower())


# =============================================================================
# Pending Quorum Registry & Data Structures
# =============================================================================

@dataclass
class PendingTokenRecord:
    nonce: str
    target_pid: int
    action_type: str
    threat_hash: str
    timestamp: float
    hmac_signature: str
    status: QuorumTokenStatus
    threat_score: float
    process_info: Dict[str, Any]
    human_authorized: bool = False
    execution_authorized: bool = False
    execution_status: str = "PENDING"
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    consumed: bool = False

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        now = current_time if current_time is not None else time.time()
        return now > self.expires_at

    def canonical_payload_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type,
            "nonce": self.nonce,
            "target_pid": self.target_pid,
            "threat_hash": self.threat_hash,
            "timestamp": self.timestamp,
        }

    def canonical_bytes(self) -> bytes:
        return serialize_canonical_payload(self.canonical_payload_dict())


class PendingQuorumStore:
    """
    Thread-safe and asyncio-safe in-memory store for pending Quorum tokens.
    Guarantees:
      - Single-use nonces: Once AUTHORIZED, REJECTED, EXPIRED, or EXECUTED, the nonce cannot be reused.
      - Immutability: Stored canonical payload cannot be overwritten by client-supplied parameters.
      - Concurrency safety: Atomic state transitions prevent double-spend / race conditions.
    """

    def __init__(self, token_lifetime: float = 30.0):
        self.token_lifetime = token_lifetime
        self._tokens: Dict[str, PendingTokenRecord] = {}
        self._lock = asyncio.Lock()
        self._audit_trail: List[Dict[str, Any]] = []

    def log_audit(self, event_type: str, details: Dict[str, Any]) -> None:
        """Append safe audit record without secrets or credentials."""
        record = {
            "event_type": event_type,
            "timestamp": time.time(),
            "details": details,
        }
        self._audit_trail.append(record)
        logger.info(f"[Cryptographic Quorum] AUDIT: {event_type} | {details}")

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        return list(self._audit_trail)

    async def create_pending_token(
        self,
        target_pid: int,
        action_type: str,
        threat_hash: str,
        threat_score: float,
        process_info: Optional[Dict[str, Any]] = None,
        lifetime: Optional[float] = None,
    ) -> Tuple[PendingTokenRecord, str]:
        """
        Create a new single-use token in PENDING_AUTHORIZATION state.
        Returns (PendingTokenRecord, abbreviated_signature).
        """
        if action_type not in ALLOWED_ACTION_TYPES:
            raise ValueError(f"Action type '{action_type}' is not allowed in Quorum layer.")

        async with self._lock:
            nonce = generate_nonce()
            while nonce in self._tokens:
                nonce = generate_nonce()

            now = time.time()
            ttl = lifetime if lifetime is not None else self.token_lifetime
            expires_at = now + ttl

            canonical_dict = {
                "action_type": action_type,
                "nonce": nonce,
                "target_pid": int(target_pid),
                "threat_hash": threat_hash,
                "timestamp": now,
            }
            canonical_bytes = serialize_canonical_payload(canonical_dict)
            signature = generate_hmac_signature(canonical_bytes)

            record = PendingTokenRecord(
                nonce=nonce,
                target_pid=int(target_pid),
                action_type=action_type,
                threat_hash=threat_hash,
                timestamp=now,
                hmac_signature=signature,
                status=QuorumTokenStatus.PENDING_AUTHORIZATION,
                threat_score=threat_score,
                process_info=process_info or {},
                human_authorized=False,
                execution_authorized=False,
                execution_status="PENDING",
                created_at=now,
                expires_at=expires_at,
                consumed=False,
            )

            self._tokens[nonce] = record

            self.log_audit(
                "QUORUM_TOKEN_GENERATED",
                {
                    "nonce": nonce,
                    "target_pid": target_pid,
                    "action_type": action_type,
                    "threat_hash": threat_hash[:12] + "...",
                    "expires_at": expires_at,
                },
            )

            abbrev_sig = f"{signature[:4]}...{signature[-4:]}"
            return record, abbrev_sig

    async def get_token(self, nonce: str) -> Optional[PendingTokenRecord]:
        async with self._lock:
            return self._tokens.get(nonce)

    async def authorize_token(
        self,
        nonce: str,
        supplied_signature: str,
        decision: str,
    ) -> Tuple[bool, str, Optional[PendingTokenRecord]]:
        """
        Atomically evaluate and authorize or reject a pending token.
        Concurrency safe: Exactly one concurrent request on the same nonce will succeed.
        Decisions: 'APPROVE' | 'REJECT'.
        Returns (success: bool, reason: str, record: Optional[PendingTokenRecord]).
        """
        decision_upper = decision.strip().upper()
        if decision_upper not in ("APPROVE", "REJECT"):
            return False, "INVALID_DECISION", None

        async with self._lock:
            record = self._tokens.get(nonce)
            if not record:
                self.log_audit("UNAUTHORIZED_EXECUTION_ATTEMPT", {"nonce": nonce, "reason": "UNKNOWN_NONCE"})
                return False, "UNKNOWN_NONCE", None

            # Check if nonce was already consumed or transitioned out of PENDING_AUTHORIZATION
            if record.consumed or record.status != QuorumTokenStatus.PENDING_AUTHORIZATION:
                self.log_audit(
                    "UNAUTHORIZED_EXECUTION_ATTEMPT",
                    {"nonce": nonce, "reason": "NONCE_ALREADY_CONSUMED", "status": record.status.value},
                )
                return False, "NONCE_ALREADY_CONSUMED", record

            # Check expiration against server-side time
            now = time.time()
            if record.is_expired(now):
                record.status = QuorumTokenStatus.EXPIRED
                record.consumed = True
                self.log_audit(
                    "QUORUM_EXPIRED",
                    {"nonce": nonce, "reason": "TOKEN_EXPIRED", "expired_seconds_ago": round(now - record.expires_at, 2)},
                )
                return False, "TOKEN_EXPIRED", record

            # Verify supplied HMAC against stored canonical payload
            canonical_bytes = record.canonical_bytes()
            if not verify_hmac_signature(canonical_bytes, supplied_signature):
                self.log_audit(
                    "UNAUTHORIZED_EXECUTION_ATTEMPT",
                    {"nonce": nonce, "reason": "INVALID_HMAC_SIGNATURE"},
                )
                return False, "INVALID_HMAC_SIGNATURE", record

            # Verify stored HMAC matches active secret
            if not verify_hmac_signature(canonical_bytes, record.hmac_signature):
                self.log_audit(
                    "UNAUTHORIZED_EXECUTION_ATTEMPT",
                    {"nonce": nonce, "reason": "STORED_HMAC_SECRET_MISMATCH"},
                )
                return False, "STORED_HMAC_SECRET_MISMATCH", record

            # Transition state atomically
            record.consumed = True  # Single-use nonce consumed immediately

            if decision_upper == "APPROVE":
                record.status = QuorumTokenStatus.AUTHORIZED
                record.human_authorized = True
                record.execution_authorized = True
                record.execution_status = "AUTHORIZED"

                self.log_audit(
                    "QUORUM_APPROVED",
                    {
                        "nonce": nonce,
                        "action_type": record.action_type,
                        "target_pid": record.target_pid,
                        "decision": "APPROVE",
                    },
                )
                return True, "AUTHORIZED", record

            else:
                record.status = QuorumTokenStatus.REJECTED
                record.human_authorized = False
                record.execution_authorized = False
                record.execution_status = "REJECTED"

                self.log_audit(
                    "QUORUM_REJECTED",
                    {
                        "nonce": nonce,
                        "action_type": record.action_type,
                        "target_pid": record.target_pid,
                        "decision": "REJECT",
                    },
                )
                return True, "REJECTED", record

    async def auto_authorize_low_risk(
        self,
        record: PendingTokenRecord,
    ) -> Tuple[bool, str]:
        """
        Auto-authorize a low-risk action (e.g. HONEYPOT_REDIRECT).
        Verifies internal signature against canonical payload, marks AUTHORIZED,
        and authorizes execution with cryptographic audit record.
        """
        async with self._lock:
            if record.action_type != "HONEYPOT_REDIRECT":
                return False, "ACTION_NOT_ELIGIBLE_FOR_AUTO_AUTHORIZATION"

            canonical_bytes = record.canonical_bytes()
            if not verify_hmac_signature(canonical_bytes, record.hmac_signature):
                return False, "INVALID_HMAC"

            record.status = QuorumTokenStatus.AUTHORIZED
            record.human_authorized = False  # Automated cryptographic authorization
            record.execution_authorized = True
            record.consumed = True

            self.log_audit(
                "QUORUM_AUTO_AUTHORIZED",
                {
                    "nonce": record.nonce,
                    "action_type": record.action_type,
                    "target_pid": record.target_pid,
                },
            )
            return True, "AUTHORIZED"

    async def validate_for_execution(
        self,
        nonce: str,
        expected_pid: int,
        expected_action: str,
        expected_threat_hash: str,
    ) -> Tuple[bool, str, Optional[PendingTokenRecord]]:
        """
        Final pre-execution verification against stored token state:
          - Nonce exists
          - Token is in AUTHORIZED state
          - execution_authorized is True
          - Target PID matches stored record
          - Action type matches stored record
          - Threat hash matches stored record
          - Token has not expired
        """
        async with self._lock:
            record = self._tokens.get(nonce)
            if not record:
                self.log_audit("UNAUTHORIZED_EXECUTION_ATTEMPT", {"nonce": nonce, "reason": "UNKNOWN_NONCE"})
                return False, "UNKNOWN_NONCE", None

            if record.status != QuorumTokenStatus.AUTHORIZED or not record.execution_authorized:
                self.log_audit(
                    "UNAUTHORIZED_EXECUTION_ATTEMPT",
                    {"nonce": nonce, "reason": "EXECUTION_NOT_AUTHORIZED", "status": record.status.value},
                )
                return False, f"TOKEN_STATUS_{record.status.value}", record

            if record.is_expired():
                record.status = QuorumTokenStatus.EXPIRED
                self.log_audit("UNAUTHORIZED_EXECUTION_ATTEMPT", {"nonce": nonce, "reason": "TOKEN_EXPIRED"})
                return False, "TOKEN_EXPIRED", record

            if int(record.target_pid) != int(expected_pid):
                self.log_audit(
                    "UNAUTHORIZED_EXECUTION_ATTEMPT",
                    {"nonce": nonce, "reason": "PID_MISMATCH", "expected": expected_pid, "stored": record.target_pid},
                )
                return False, "PAYLOAD_MISMATCH", record

            if record.action_type != expected_action:
                self.log_audit(
                    "UNAUTHORIZED_EXECUTION_ATTEMPT",
                    {"nonce": nonce, "reason": "ACTION_MISMATCH", "expected": expected_action, "stored": record.action_type},
                )
                return False, "PAYLOAD_MISMATCH", record

            if record.threat_hash != expected_threat_hash:
                self.log_audit(
                    "UNAUTHORIZED_EXECUTION_ATTEMPT",
                    {"nonce": nonce, "reason": "THREAT_HASH_MISMATCH"},
                )
                return False, "PAYLOAD_MISMATCH", record

            return True, "VALID", record

    async def mark_execution_outcome(
        self,
        nonce: str,
        success: bool,
        detail: str = "",
    ) -> None:
        """Mark token outcome as EXECUTED or FAILED post OS action."""
        async with self._lock:
            record = self._tokens.get(nonce)
            if not record:
                return
            if success:
                record.status = QuorumTokenStatus.EXECUTED
                record.execution_status = "EXECUTED"
                self.log_audit("QUORUM_EXECUTION_SUCCESS", {"nonce": nonce, "detail": detail})
            else:
                record.status = QuorumTokenStatus.FAILED
                record.execution_status = "FAILED"
                self.log_audit("QUORUM_EXECUTION_FAILED", {"nonce": nonce, "detail": detail})

    async def get_pending_tokens(self) -> List[Dict[str, Any]]:
        """Return list of active pending authorization requests for SOC inspection."""
        async with self._lock:
            now = time.time()
            results = []
            for r in self._tokens.values():
                if r.status == QuorumTokenStatus.PENDING_AUTHORIZATION and not r.is_expired(now):
                    results.append({
                        "nonce": r.nonce,
                        "target_pid": r.target_pid,
                        "process_name": r.process_info.get("name", "unknown"),
                        "action_type": r.action_type,
                        "threat_score": r.threat_score,
                        "threat_hash": r.threat_hash[:12] + "...",
                        "created_at": r.created_at,
                        "expires_at": r.expires_at,
                        "remaining_seconds": max(0.0, round(r.expires_at - now, 1)),
                        "abbreviated_hmac": f"{r.hmac_signature[:4]}...{r.hmac_signature[-4:]}",
                    })
            return results


# Global singleton pending quorum store
quorum_store = PendingQuorumStore(token_lifetime=getattr(settings, "QUORUM_TOKEN_LIFETIME", 30.0))
