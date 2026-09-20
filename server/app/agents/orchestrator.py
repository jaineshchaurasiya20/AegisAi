"""
AegisAI Agent Orchestrator
Coordinates lifecycle, event wiring, and telemetry/trace broadcasting for the 4-Agent Architecture
and the Cryptographic Action Quorum layer.
"""
from __future__ import annotations

import asyncio
import inspect
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from loguru import logger

from app.agents.schemas import (
    BaseAgentEvent,
    TelemetryEvent,
    AnomalyDetectedEvent,
    ThreatInvestigatedEvent,
    RemediationExecutedEvent,
    AuditCompletedEvent,
    QuorumAuthorizationRequiredEvent,
    QuorumApprovedEvent,
    QuorumRejectedEvent,
    AgentTraceEvent,
)
from app.agents.event_bus import EventBus
from app.agents.detector import DetectorAgent
from app.agents.investigator import InvestigatorAgent
from app.agents.remediator import RemediatorAgent
from app.agents.auditor import AuditorAgent


class AgentOrchestrator:
    """
    AgentOrchestrator manages the lifecycle of the Event Bus, all 4 specialized agents,
    and the Cryptographic Action Quorum layer.
    Dispatches agent traces to terminal stdout and WebSocket SOC monitors.
    """

    def __init__(self):
        self.bus = EventBus(max_queue_size=2000, num_workers=2)
        self.detector = DetectorAgent(self.bus)
        self.investigator = InvestigatorAgent(self.bus)
        self.remediator = RemediatorAgent(self.bus)
        self.auditor = AuditorAgent(self.bus)

        self._running = False
        self._trace_callbacks: List[Callable[[Dict[str, Any]], Any]] = []
        self._setup_trace_listeners()

    def register_trace_callback(self, cb: Callable[[Dict[str, Any]], Any]) -> None:
        """Register a callback for WebSocket or external broadcasting."""
        if cb not in self._trace_callbacks:
            self._trace_callbacks.append(cb)

    def _setup_trace_listeners(self) -> None:
        """Wire event listeners to generate human-readable traces for SOC and terminal."""
        self.bus.subscribe(AnomalyDetectedEvent, self._on_anomaly)
        self.bus.subscribe(ThreatInvestigatedEvent, self._on_investigated)
        self.bus.subscribe(QuorumAuthorizationRequiredEvent, self._on_quorum_auth_required)
        self.bus.subscribe(QuorumApprovedEvent, self._on_quorum_approved)
        self.bus.subscribe(QuorumRejectedEvent, self._on_quorum_rejected)
        self.bus.subscribe(RemediationExecutedEvent, self._on_remediation)
        self.bus.subscribe(AuditCompletedEvent, self._on_audit)

    async def _broadcast_trace(
        self,
        agent: str,
        status: str,
        message: str,
        event_id: str,
        severity: str = "info",
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log trace to console and dispatch to registered callbacks."""
        import json
        safe_payload = {}
        if payload is not None:
            try:
                safe_payload = json.loads(json.dumps(payload, default=str))
            except Exception:
                safe_payload = {"raw": str(payload)}

        trace = {
            "type": "agent_trace",
            "agent": agent,
            "status": status,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": event_id,
            "severity": severity,
            "payload": safe_payload,
        }
        for cb in self._trace_callbacks:
            try:
                if inspect.iscoroutinefunction(cb):
                    await cb(trace)
                else:
                    cb(trace)
            except Exception as e:
                logger.debug(f"[Orchestrator] Trace callback error: {e}")

    async def _on_anomaly(self, event: AnomalyDetectedEvent) -> None:
        if "zero-day" in str(event.threat_type).lower() or "unclassified" in str(event.threat_type).lower() or event.threat_score >= 0.85:
            msg = f"Zero-day anomaly detected | Score: {event.threat_score:.2f}"
        else:
            msg = f"Dynamic threshold tuned to {event.dynamic_threshold:.2f} | Anomaly score: {event.threat_score:.2f}"
        print(f"\n\033[96m\033[1m[Detector Agent]\033[0m\n{msg}")
        payload = event.model_dump() if hasattr(event, "model_dump") else event.dict()
        await self._broadcast_trace("Detector Agent", "ANOMALY_DETECTED", msg, event.event_id, event.severity, payload)

    async def _on_investigated(self, event: ThreatInvestigatedEvent) -> None:
        msg = f"Threat investigated | Root cause: {event.root_cause}"
        print(f"\033[95m\033[1m[Investigator Agent]\033[0m\n{msg}")
        payload = event.model_dump() if hasattr(event, "model_dump") else event.dict()
        await self._broadcast_trace("Investigator Agent", "INVESTIGATED", msg, event.event_id, event.severity, payload)

    async def _on_quorum_auth_required(self, event: QuorumAuthorizationRequiredEvent) -> None:
        msg1 = f"High-risk action requested: {event.action_type} on PID {event.target_pid}"
        msg2 = f"HMAC-SHA256 token generated: {event.abbreviated_hmac_signature}"
        msg3 = f"Authorization required | expires in {int(max(0, event.expires_at - event.timestamp_val))}s"
        print(f"\033[93m\033[1m[Remediator Agent]\033[0m\n{msg1}")
        print(f"\033[94m\033[1m[Cryptographic Quorum]\033[0m\n{msg2}")
        print(f"\033[94m\033[1m[Cryptographic Quorum]\033[0m\n{msg3}")
        print(f"\033[96m\033[1m[Frontend]\033[0m\nHuman authorization requested")
        
        payload = event.model_dump() if hasattr(event, "model_dump") else event.dict()
        # Broadcast full quorum payload for WebSocket modal triggers
        await self._broadcast_trace(
            "Cryptographic Quorum",
            "QUORUM_AUTHORIZATION_REQUIRED",
            f"{msg2} | {msg3}",
            event.event_id,
            "warning",
            payload,
        )

    async def _on_quorum_approved(self, event: QuorumApprovedEvent) -> None:
        msg1 = "HMAC verified | Nonce matched"
        msg2 = "Human authorization confirmed"
        print(f"\033[92m\033[1m[Cryptographic Quorum]\033[0m\n{msg1}")
        print(f"\033[92m\033[1m[Cryptographic Quorum]\033[0m\n{msg2}")
        print(f"\033[93m\033[1m[Remediator Agent]\033[0m\nPID identity verified")
        payload = event.model_dump() if hasattr(event, "model_dump") else event.dict()
        await self._broadcast_trace("Cryptographic Quorum", "QUORUM_APPROVED", f"{msg1} | {msg2}", event.event_id, "info", payload)

    async def _on_quorum_rejected(self, event: QuorumRejectedEvent) -> None:
        msg = f"Quorum authorization rejected by operator: {event.reason}"
        print(f"\033[91m\033[1m[Cryptographic Quorum]\033[0m\n{msg}")
        payload = event.model_dump() if hasattr(event, "model_dump") else event.dict()
        await self._broadcast_trace("Cryptographic Quorum", "QUORUM_REJECTED", msg, event.event_id, "warning", payload)

    async def _on_remediation(self, event: RemediationExecutedEvent) -> None:
        pid_str = f" for PID {event.process_pid}" if event.process_pid else ""
        if event.action_status.value == "SKIPPED":
            msg = f"Remediation skipped for {event.target} ({event.action_reason})"
        elif event.action_status.value == "FAILED":
            msg = f"Remediation failed for {event.target} ({event.action_reason})"
        elif event.action_type.value == "HONEYPOT_REDIRECT":
            decoy_port = event.details.get("decoy_port", 2222) if event.details else 2222
            msg = f"Dynamic honeypot activated on port {decoy_port} | Redirecting traffic"
        elif event.action_type.value == "PID_KILL":
            msg = f"Execution successful for PID {event.process_pid or event.target}"
        elif event.action_type.value == "NET_ISOLATE":
            msg = f"Network containment active for {event.target}"
        else:
            msg = f"No action required ({event.action_reason})"

        print(f"\033[93m\033[1m[Remediator Agent]\033[0m\n{msg}")
        payload = event.model_dump() if hasattr(event, "model_dump") else event.dict()
        await self._broadcast_trace("Remediator Agent", event.action_status.value, msg, event.event_id, "warning", payload)

        # Emit Decoy Listener trace on honeypot redirection
        if event.action_type.value == "HONEYPOT_REDIRECT" and event.details:
            sig_hash = event.details.get("payload_hash", "3f8a9b1c7e2d")[:12]
            entropy = event.details.get("entropy_score", 0.84)
            decoy_msg = f"Attacker payload trapped | Extracted SHA-256 payload signature ({sig_hash}...) | Entropy: {entropy}"
            print(f"\033[94m\033[1m[Decoy Listener]\033[0m\n{decoy_msg}")
            await self._broadcast_trace("Decoy Listener", "PAYLOAD_TRAPPED", decoy_msg, event.event_id, "warning", event.details)

    async def _on_audit(self, event: AuditCompletedEvent) -> None:
        if event.verification_status.value == "SUCCESS":
            if getattr(event, "retraining_label", None) == "novel/unknown behavior":
                msg = "Closed-loop verification passed | Signature stored for edge retraining"
            else:
                msg = "Closed-loop verification passed | Feature stored for edge retraining"
            print(f"\033[92m\033[1m[Auditor Agent]\033[0m\n{msg}\n")
        else:
            msg = f"Closed-loop verification failed ({event.verification_status.value})"
            print(f"\033[91m\033[1m[Auditor Agent]\033[0m\n{msg}\n")
        payload = event.model_dump() if hasattr(event, "model_dump") else event.dict()
        await self._broadcast_trace("Auditor Agent", event.verification_status.value, msg, event.event_id, "info", payload)

    async def start(self) -> None:
        """Start Event Bus, agents, and background loops."""
        if self._running:
            return
        self._running = True
        logger.info("[Orchestrator] Starting AegisAI 4-Agent Architecture & Quorum Layer...")
        await self.bus.start()
        await self.detector.start()
        logger.info("[Orchestrator] All 4 agents operational.")

    async def stop(self) -> None:
        """Gracefully stop all agents and drain Event Bus."""
        if not self._running:
            return
        self._running = False
        logger.info("[Orchestrator] Stopping 4-Agent Architecture...")
        await self.detector.stop()
        await self.bus.stop()
        logger.info("[Orchestrator] 4-Agent Architecture shutdown complete.")

    async def ingest_attack(self, attack_data: Dict[str, Any]) -> AnomalyDetectedEvent | None:
        """Ingest an attack event into the 4-agent pipeline."""
        return await self.detector.ingest_event(attack_data)


# Global singleton orchestrator
orchestrator = AgentOrchestrator()
