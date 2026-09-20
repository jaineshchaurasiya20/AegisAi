"""
AegisAI 4-Agent Architecture — Strongly Typed Event Contracts & Schemas
Defines Pydantic models for inter-agent asynchronous communication.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _gen_uuid() -> str:
    return str(uuid.uuid4())


# =============================================================================
# Action & Verification Enums
# =============================================================================

class ActionType(str, Enum):
    PID_KILL = "PID_KILL"
    NET_ISOLATE = "NET_ISOLATE"
    HONEYPOT_REDIRECT = "HONEYPOT_REDIRECT"
    NO_ACTION = "NO_ACTION"


class ActionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class VerificationStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


# =============================================================================
# Base Event
# =============================================================================

class BaseAgentEvent(BaseModel):
    event_id: str = Field(default_factory=_gen_uuid)
    timestamp: datetime = Field(default_factory=_utc_now)

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# =============================================================================
# 1. TelemetryEvent
# =============================================================================

class TelemetryEvent(BaseAgentEvent):
    """Point-in-time host and network telemetry snapshot collected by Detector."""
    hostname: str = "localhost"
    host_ip: str = "127.0.0.1"
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    processes: List[Dict[str, Any]] = Field(default_factory=list)
    network_sockets: List[Dict[str, Any]] = Field(default_factory=list)
    network_io: Dict[str, float] = Field(default_factory=dict)
    feature_vector: List[float] = Field(default_factory=list)
    raw_snapshot: Optional[Dict[str, Any]] = None


# =============================================================================
# 2. AnomalyDetectedEvent
# =============================================================================

class AnomalyDetectedEvent(BaseAgentEvent):
    """Emitted by Detector Agent when threat_score > dynamic_threshold."""
    process_pid: Optional[int] = None
    process_name: Optional[str] = None
    threat_score: float
    dynamic_threshold: float
    telemetry: Dict[str, Any] = Field(default_factory=dict)
    feature_vector: List[float] = Field(default_factory=list)
    severity: str = "medium"
    source_ip: Optional[str] = None
    port: Optional[int] = None
    threat_type: Optional[str] = "Suspicious Activity"


# =============================================================================
# 3. ThreatInvestigatedEvent
# =============================================================================

class ThreatInvestigatedEvent(BaseAgentEvent):
    """Emitted by Investigator Agent after XAI attribution and root-cause analysis."""
    source_anomaly_event_id: str
    process_pid: Optional[int] = None
    process_name: Optional[str] = None
    threat_score: float
    severity: str
    positive_risk_drivers: List[Dict[str, Any]] = Field(default_factory=list)
    negative_safety_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    feature_attributions: List[Dict[str, Any]] = Field(default_factory=list)
    feature_vector: List[float] = Field(default_factory=list)
    root_cause: str
    memory_context: Dict[str, Any] = Field(default_factory=dict)
    honeypot_context: Optional[Dict[str, Any]] = None
    confidence: float = 1.0
    attribution_method: str = "TreeExplainer"


# =============================================================================
# Quorum Token & Authorization Models
# =============================================================================

class QuorumTokenStatus(str, Enum):
    PENDING_AUTHORIZATION = "PENDING_AUTHORIZATION"
    AUTHORIZED = "AUTHORIZED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class QuorumToken(BaseModel):
    """Cryptographic authorization token guaranteeing action quorum."""
    nonce: str
    target_pid: int
    action_type: str
    threat_hash: str
    timestamp: float
    hmac_signature: str
    status: str = "PENDING_AUTHORIZATION"
    expires_at: Optional[float] = None
    threat_score: Optional[float] = None
    process_name: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True


# =============================================================================
# 4. RemediationExecutedEvent
# =============================================================================

class RemediationExecutedEvent(BaseAgentEvent):
    """Emitted by Remediator Agent after containment action is executed."""
    source_investigation_event_id: str
    process_pid: Optional[int] = None
    process_name: Optional[str] = None
    action_type: ActionType
    action_status: ActionStatus
    action_reason: str
    target: str
    details: Dict[str, Any] = Field(default_factory=dict)
    feature_vector: List[float] = Field(default_factory=list)
    # Cryptographic Quorum & Authorization metadata
    quorum_token: Optional[QuorumToken] = None
    quorum_verified: bool = False
    human_authorized: bool = False
    execution_authorized: bool = False
    execution_status: str = "SKIPPED"


# =============================================================================
# Quorum Inter-Agent & Broadcast Events
# =============================================================================

class QuorumAuthorizationRequiredEvent(BaseAgentEvent):
    """Emitted by Remediator when high-risk remediation requires operator confirmation."""
    event_type: str = "QuorumAuthorizationRequired"
    nonce: str
    target_pid: int
    process_name: str
    action_type: str
    threat_score: float
    root_cause_summary: str
    timestamp_val: float
    expires_at: float
    abbreviated_hmac_signature: str
    threat_hash: str


class QuorumApprovedEvent(BaseAgentEvent):
    """Emitted when cryptographic quorum is approved by operator."""
    event_type: str = "QuorumApproved"
    nonce: str
    action_type: str
    target_pid: int
    decision: str = "APPROVE"
    executed_by: str = "human_operator"


class QuorumRejectedEvent(BaseAgentEvent):
    """Emitted when cryptographic quorum is rejected by operator."""
    event_type: str = "QuorumRejected"
    nonce: str
    action_type: str
    target_pid: int
    decision: str = "REJECT"
    reason: str = "REJECTED_BY_OPERATOR"


# =============================================================================
# 5. AuditCompletedEvent
# =============================================================================

class AuditCompletedEvent(BaseAgentEvent):
    """Emitted by Auditor Agent after closed-loop verification & retraining storage."""
    source_remediation_event_id: str
    process_pid: Optional[int] = None
    verification_status: VerificationStatus
    process_alive: bool
    network_activity_detected: bool
    system_stable: bool
    fallback_action: Optional[ActionType] = None
    fallback_status: Optional[ActionStatus] = None
    retraining_required: bool = False
    retraining_payload: Optional[Dict[str, Any]] = None
    retraining_label: Optional[str] = None  # 'verified threat', 'verified false positive', 'novel/unknown behavior'
    feature_vector: List[float] = Field(default_factory=list)


# =============================================================================
# 6. ZeroDayThreatTrappedEvent (Honeypot Deception & EventBridge Fleet Broadcast)
# =============================================================================

class ZeroDayThreatTrappedEvent(BaseAgentEvent):
    """Emitted when Deception Engine or Auditor traps a novel zero-day payload in a honeypot."""
    threat_id: str
    sha256_fingerprint: str
    shannon_entropy: float = 0.0
    decoy_port: Optional[int] = None
    trap_type: str = "HONEYPOT_TRAP"
    hex_prefix: Optional[str] = None
    sanitized_command: Optional[str] = "N/A"
    raw_payload_sample: Optional[str] = None
    eventbridge_synced: bool = False
    eventbridge_event_id: Optional[str] = None


# =============================================================================
# Agent Trace Event (WebSocket & Console Broadcasting)
# =============================================================================

class AgentTraceEvent(BaseAgentEvent):
    """Structured trace for human-readable console logging and WebSocket SOC displays."""
    agent: str
    status: str
    message: str
    severity: Optional[str] = "info"
    payload: Optional[Dict[str, Any]] = None
