"""
AegisAI Agents Package
Provides the 4-Agent Event-Driven Architecture (Detector, Investigator, Remediator, Auditor, Orchestrator)
and preserves the incident remediation agent workflow.
"""
from app.agents.schemas import (
    BaseAgentEvent,
    TelemetryEvent,
    AnomalyDetectedEvent,
    ThreatInvestigatedEvent,
    RemediationExecutedEvent,
    AuditCompletedEvent,
    AgentTraceEvent,
    ActionType,
    ActionStatus,
    VerificationStatus,
)
from app.agents.event_bus import EventBus
from app.agents.detector import DetectorAgent, compute_dynamic_threshold
from app.agents.investigator import InvestigatorAgent
from app.agents.remediator import RemediatorAgent
from app.agents.auditor import AuditorAgent
from app.agents.orchestrator import AgentOrchestrator, orchestrator

__all__ = [
    "BaseAgentEvent",
    "TelemetryEvent",
    "AnomalyDetectedEvent",
    "ThreatInvestigatedEvent",
    "RemediationExecutedEvent",
    "AuditCompletedEvent",
    "AgentTraceEvent",
    "ActionType",
    "ActionStatus",
    "VerificationStatus",
    "EventBus",
    "DetectorAgent",
    "compute_dynamic_threshold",
    "InvestigatorAgent",
    "RemediatorAgent",
    "AuditorAgent",
    "AgentOrchestrator",
    "orchestrator",
]
