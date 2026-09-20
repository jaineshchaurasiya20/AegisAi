"""
AegisAI Remediator Agent with Cryptographic Action Quorum
Responsible for executing targeted containment actions (PID_KILL, NET_ISOLATE, HONEYPOT_REDIRECT)
strictly bounded by HMAC-SHA256 quorum authorization, multi-factor process identity verification,
and anti-replay validation.
"""
from __future__ import annotations

import os
import signal
import platform
import subprocess
import psutil
from typing import Any, Dict, List, Optional
from loguru import logger

from app.core.config import get_settings
from app.core.quorum import (
    quorum_store,
    compute_threat_hash,
    QuorumTokenStatus,
)
from app.core.security import (
    is_protected_process,
    is_aegisai_self,
    validate_process_identity,
)
from app.deception.honeypot_emulator import honeypot_emulator
from app.services.deception import dynamic_honeypot_engine
from app.api.routes.actions import _isolate_host
from app.agents.schemas import (
    ThreatInvestigatedEvent,
    RemediationExecutedEvent,
    QuorumAuthorizationRequiredEvent,
    QuorumApprovedEvent,
    QuorumRejectedEvent,
    QuorumToken,
    ActionType,
    ActionStatus,
)
from app.agents.event_bus import EventBus

settings = get_settings()


class RemediatorAgent:
    """
    Remediator Agent coordinates surgical containment bounded by Cryptographic Action Quorum.
    Generates HMAC-SHA256 tokens, gates high-risk actions behind human authorization,
    and conducts pre-execution process identity validation.
    """

    def __init__(self, event_bus: EventBus):
        self.bus = event_bus
        self.protected_processes = set(p.lower() for p in settings.PROTECTED_PROCESSES)
        self.current_pid = os.getpid()
        self._pending_investigations: Dict[str, ThreatInvestigatedEvent] = {}
        self._setup_subscriptions()

    def _setup_subscriptions(self) -> None:
        self.bus.subscribe(ThreatInvestigatedEvent, self.handle_investigation)

    async def handle_investigation(self, event: ThreatInvestigatedEvent) -> None:
        """Handle investigated threat through the Cryptographic Action Quorum security boundary."""
        try:
            # STEP 1: Determine proposed action
            action_type = self._determine_action(event)

            if action_type == ActionType.NO_ACTION:
                remediation_event = RemediationExecutedEvent(
                    source_investigation_event_id=event.event_id,
                    process_pid=event.process_pid,
                    process_name=event.process_name,
                    action_type=ActionType.NO_ACTION,
                    action_status=ActionStatus.SKIPPED,
                    action_reason="Threat score or confidence below remediation threshold",
                    target=f"PID:{event.process_pid or 'N/A'}",
                    details={"threat_score": event.threat_score},
                    feature_vector=event.feature_vector,
                    quorum_verified=False,
                    human_authorized=False,
                    execution_authorized=False,
                    execution_status="SKIPPED",
                )
                await self.bus.publish(remediation_event)
                return

            # STEP 2: Pre-Quorum Guardrail: Check if target process is system protected or AegisAI itself
            if event.process_pid:
                is_prot, prot_reason = is_protected_process(event.process_pid, event.process_name)
                if is_prot:
                    logger.warning(
                        f"[Remediator Agent] Guard triggered: Refusing to remediate protected process "
                        f"'{event.process_name}' (PID: {event.process_pid}): {prot_reason}"
                    )
                    remediation_event = RemediationExecutedEvent(
                        source_investigation_event_id=event.event_id,
                        process_pid=event.process_pid,
                        process_name=event.process_name,
                        action_type=action_type,
                        action_status=ActionStatus.SKIPPED,
                        action_reason=f"Protected process {prot_reason}",
                        target=f"PID:{event.process_pid or 'N/A'}",
                        details={"pid": event.process_pid, "name": event.process_name, "reason": prot_reason},
                        feature_vector=event.feature_vector,
                        quorum_verified=False,
                        human_authorized=False,
                        execution_authorized=False,
                        execution_status="BLOCKED",
                    )
                    await self.bus.publish(remediation_event)
                    return

            # STEP 3: Construct canonical payload & compute deterministic threat hash
            threat_hash = compute_threat_hash(
                source_event_id=event.event_id,
                threat_score=event.threat_score,
                severity=event.severity,
                root_cause=event.root_cause,
                target_pid=event.process_pid,
                process_name=event.process_name,
                feature_vector=event.feature_vector,
            )

            # STEP 3 & 4: Generate HMAC token and store in pending quorum registry
            process_info = {
                "name": event.process_name or (event.memory_context.get("name") if event.memory_context else "unknown"),
                "create_time": event.memory_context.get("create_time") if event.memory_context else None,
                "cmdline": event.memory_context.get("cmdline") if event.memory_context else [],
                "source_ip": event.memory_context.get("source_ip") if event.memory_context else "127.0.0.1",
                "investigation_event_id": event.event_id,
            }

            token_record, abbrev_sig = await quorum_store.create_pending_token(
                target_pid=event.process_pid or 0,
                action_type=action_type.value,
                threat_hash=threat_hash,
                threat_score=event.threat_score,
                process_info=process_info,
            )

            self._pending_investigations[token_record.nonce] = event

            # STEP 5: Evaluate authorization policy
            if action_type == ActionType.HONEYPOT_REDIRECT:
                # LOW-RISK: Auto-authorize deception redirection with cryptographic audit trail
                auto_auth_ok, status_str = await quorum_store.auto_authorize_low_risk(token_record)
                if auto_auth_ok:
                    action_status, reason, details = self._execute_honeypot_redirect(event)
                    await quorum_store.mark_execution_outcome(
                        token_record.nonce,
                        success=(action_status == ActionStatus.SUCCESS),
                        detail=reason,
                    )

                    q_token = QuorumToken(
                        nonce=token_record.nonce,
                        target_pid=token_record.target_pid,
                        action_type=token_record.action_type,
                        threat_hash=token_record.threat_hash,
                        timestamp=token_record.timestamp,
                        hmac_signature=token_record.hmac_signature,
                        status=token_record.status.value,
                        expires_at=token_record.expires_at,
                        threat_score=token_record.threat_score,
                        process_name=process_info["name"],
                    )

                    remediation_event = RemediationExecutedEvent(
                        source_investigation_event_id=event.event_id,
                        process_pid=event.process_pid,
                        process_name=event.process_name,
                        action_type=action_type,
                        action_status=action_status,
                        action_reason=reason,
                        target=f"HONEYPOT:{event.process_pid or 'UNCLASSIFIED'}",
                        details=details,
                        feature_vector=event.feature_vector,
                        quorum_token=q_token,
                        quorum_verified=True,
                        human_authorized=False,
                        execution_authorized=True,
                        execution_status=action_status.value,
                    )
                    await self.bus.publish(remediation_event)
                return

            # HIGH-RISK: PID_KILL, NET_ISOLATE
            # Require authorization when:
            # - threat score > 0.85 OR
            # - target process is unknown OR
            # - process is classified critical/unknown OR
            # - action policy requires human confirmation
            requires_auth = (
                event.threat_score > 0.85
                or not event.process_pid
                or event.process_pid <= 4
                or not event.process_name
                or not settings.AUTO_KILL_ENABLED
            )

            if requires_auth:
                logger.warning(
                    f"[Cryptographic Quorum] High-risk action requested: {action_type.value} on PID {event.process_pid} "
                    f"(Score: {event.threat_score:.2f}) | Halting execution for operator quorum"
                )

                auth_req_event = QuorumAuthorizationRequiredEvent(
                    nonce=token_record.nonce,
                    target_pid=token_record.target_pid,
                    process_name=process_info["name"],
                    action_type=action_type.value,
                    threat_score=event.threat_score,
                    root_cause_summary=event.root_cause,
                    timestamp_val=token_record.timestamp,
                    expires_at=token_record.expires_at,
                    abbreviated_hmac_signature=abbrev_sig,
                    threat_hash=threat_hash,
                )
                await self.bus.publish(auth_req_event)
                return

            # If policy explicitly allows auto-execution for verified non-critical userland process:
            auto_ok, _ = await quorum_store.auto_authorize_low_risk(token_record)
            if auto_ok:
                await self.execute_authorized_remediation(token_record.nonce)

        except Exception as e:
            logger.error(f"[Remediator Agent] Remediation exception for {event.event_id}: {e}")
            remediation_event = RemediationExecutedEvent(
                source_investigation_event_id=event.event_id,
                process_pid=event.process_pid,
                process_name=event.process_name,
                action_type=ActionType.NO_ACTION,
                action_status=ActionStatus.FAILED,
                action_reason=f"Remediator exception: {e}",
                target="ERROR",
                details={"error": str(e)},
                feature_vector=getattr(event, "feature_vector", []),
                quorum_verified=False,
                human_authorized=False,
                execution_authorized=False,
                execution_status="FAILED",
            )
            await self.bus.publish(remediation_event)

    async def execute_authorized_remediation(
        self,
        nonce: str,
    ) -> tuple[ActionStatus, str, Dict[str, Any]]:
        """
        Execute remediation after human operator or policy authorization has been confirmed.
        Enforces multi-factor pre-execution validation:
          1. Cryptographic quorum validation
          2. Server-side token state & single-use verification
          3. PID existence check
          4. Process name match (anti-PID reuse race check)
          5. Process creation time match
          6. Protected process & AegisAI self-kill safety check
        """
        record = await quorum_store.get_token(nonce)
        if not record:
            quorum_store.log_audit("UNAUTHORIZED_EXECUTION_ATTEMPT", {"nonce": nonce, "reason": "UNKNOWN_NONCE"})
            return ActionStatus.FAILED, "UNKNOWN_NONCE", {}

        # 1. Cryptographic Quorum Validation
        valid, reason, _ = await quorum_store.validate_for_execution(
            nonce=nonce,
            expected_pid=record.target_pid,
            expected_action=record.action_type,
            expected_threat_hash=record.threat_hash,
        )
        if not valid:
            logger.warning(f"[Cryptographic Quorum] Execution blocked | {reason}")
            return ActionStatus.FAILED, reason, {}

        inv_event = self._pending_investigations.get(nonce)

        # 2. Process Identity & Safety Validation
        pid = record.target_pid
        expected_name = record.process_info.get("name")
        expected_create_time = record.process_info.get("create_time")

        if record.action_type == ActionType.PID_KILL.value:
            valid_id, id_reason = validate_process_identity(
                pid=pid,
                expected_name=expected_name,
                expected_create_time=expected_create_time,
            )
            if not valid_id:
                logger.warning(f"[Remediator Agent] Execution blocked | {id_reason}")
                quorum_store.log_audit(
                    "UNAUTHORIZED_EXECUTION_ATTEMPT",
                    {"nonce": nonce, "pid": pid, "action": record.action_type, "reason": id_reason},
                )
                await quorum_store.mark_execution_outcome(nonce, success=False, detail=id_reason)

                q_token = QuorumToken(
                    nonce=record.nonce,
                    target_pid=record.target_pid,
                    action_type=record.action_type,
                    threat_hash=record.threat_hash,
                    timestamp=record.timestamp,
                    hmac_signature=record.hmac_signature,
                    status=record.status.value,
                    expires_at=record.expires_at,
                    threat_score=record.threat_score,
                    process_name=expected_name,
                )

                remediation_event = RemediationExecutedEvent(
                    source_investigation_event_id=getattr(inv_event, "event_id", "manual"),
                    process_pid=pid,
                    process_name=expected_name,
                    action_type=ActionType.PID_KILL,
                    action_status=ActionStatus.SKIPPED,
                    action_reason=f"Identity check blocked execution: {id_reason}",
                    target=f"PID:{pid}",
                    details={"error": id_reason},
                    feature_vector=getattr(inv_event, "feature_vector", []),
                    quorum_token=q_token,
                    quorum_verified=True,
                    human_authorized=record.human_authorized,
                    execution_authorized=False,
                    execution_status="BLOCKED",
                )
                await self.bus.publish(remediation_event)
                return ActionStatus.SKIPPED, id_reason, {"error": id_reason}

        # 3. Perform OS Action
        action_status = ActionStatus.FAILED
        reason = "Execution error"
        details: Dict[str, Any] = {}

        if record.action_type == ActionType.PID_KILL.value:
            action_status, reason, details = self._execute_pid_kill(
                pid=pid,
                expected_name=expected_name,
                threat_score=record.threat_score,
            )
        elif record.action_type == ActionType.NET_ISOLATE.value:
            source_ip = record.process_info.get("source_ip", "127.0.0.1")
            action_status, reason, details = self._execute_net_isolate(source_ip)
        elif record.action_type == ActionType.HONEYPOT_REDIRECT.value:
            if inv_event:
                action_status, reason, details = self._execute_honeypot_redirect(inv_event)
            else:
                action_status = ActionStatus.SUCCESS
                reason = "Honeypot redirection executed"

        # 4. Mark Outcome in Quorum Store
        success = (action_status == ActionStatus.SUCCESS)
        await quorum_store.mark_execution_outcome(nonce, success=success, detail=reason)

        q_token = QuorumToken(
            nonce=record.nonce,
            target_pid=record.target_pid,
            action_type=record.action_type,
            threat_hash=record.threat_hash,
            timestamp=record.timestamp,
            hmac_signature=record.hmac_signature,
            status=record.status.value,
            expires_at=record.expires_at,
            threat_score=record.threat_score,
            process_name=expected_name,
        )

        # 5. Emit RemediationExecutedEvent onto EventBus for Auditor
        remediation_event = RemediationExecutedEvent(
            source_investigation_event_id=getattr(inv_event, "event_id", "manual"),
            process_pid=pid,
            process_name=expected_name,
            action_type=ActionType(record.action_type),
            action_status=action_status,
            action_reason=reason,
            target=f"PID:{pid}" if pid else "HOST",
            details=details,
            feature_vector=getattr(inv_event, "feature_vector", []),
            quorum_token=q_token,
            quorum_verified=True,
            human_authorized=record.human_authorized,
            execution_authorized=True,
            execution_status=action_status.value,
        )
        await self.bus.publish(remediation_event)

        return action_status, reason, details

    def _determine_action(self, event: ThreatInvestigatedEvent) -> ActionType:
        """Select containment action based on confidence, severity, and zero-day status."""
        score = event.threat_score
        pid = event.process_pid

        # Ambiguous / zero-day / honeypot eligible / probe
        is_zero_day = (
            "zero-day" in str(event.root_cause).lower()
            or "unclassified" in str(event.root_cause).lower()
            or "probe" in str(event.root_cause).lower()
            or "scan" in str(event.root_cause).lower()
            or (event.honeypot_context and event.honeypot_context.get("decoy_candidate"))
        )
        if is_zero_day and score >= 0.70:
            return ActionType.HONEYPOT_REDIRECT

        # Critical threat with valid userland process PID
        if score >= settings.CRITICAL_ACTION_THRESHOLD and pid and pid > 4:
            return ActionType.PID_KILL

        # High network threat or port scanning
        if score >= 0.75 and ("entropy" in str(event.root_cause).lower() or "burst" in str(event.root_cause).lower()):
            if pid and pid > 4:
                return ActionType.PID_KILL
            return ActionType.NET_ISOLATE

        if score >= settings.AGENT_BASE_THRESHOLD and pid and pid > 4:
            return ActionType.PID_KILL

        return ActionType.NO_ACTION

    def _execute_pid_kill(
        self,
        pid: Optional[int],
        expected_name: Optional[str],
        threat_score: float,
    ) -> tuple[ActionStatus, str, Dict[str, Any]]:
        """Surgically terminate process by PID after verifying identity and safety guards."""
        if not pid or pid <= 4:
            return ActionStatus.FAILED, "Invalid PID (< 4)", {"pid": pid}

        # Guard: Protect self and parent processes
        if is_aegisai_self(pid):
            logger.warning(f"[Remediator Agent] Guard triggered: Denied attempt to terminate self PID {pid}")
            return ActionStatus.SKIPPED, "Target is AegisAI itself", {"pid": pid}

        # Guard: Check process name against protected list
        try:
            if psutil.pid_exists(pid):
                proc = psutil.Process(pid)
                proc_name = proc.name().lower()
                if proc_name in self.protected_processes:
                    logger.warning(
                        f"[Remediator Agent] Guard triggered: Refusing kill on protected process '{proc_name}' (PID: {pid})"
                    )
                    return ActionStatus.SKIPPED, f"Protected process '{proc_name}'", {"pid": pid, "name": proc_name}
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Multi-factor identity validation: compare observed PID name with expected name
        is_valid, id_reason = validate_process_identity(pid, expected_name)
        if not is_valid:
            logger.error(
                f"[Remediator Agent] Process identity mismatch for PID {pid}: {id_reason}. Aborting kill."
            )
            return ActionStatus.FAILED, f"Identity mismatch: {id_reason}", {"pid": pid, "expected": expected_name}

        try:
            logger.info(f"[Remediator Agent] Executing kill on PID {pid} ({expected_name})")
            if psutil.pid_exists(pid):
                p = psutil.Process(pid)
                p.terminate()
                try:
                    p.wait(timeout=0.5)
                except psutil.TimeoutExpired:
                    p.kill()

            # Cross-platform fallback: Windows taskkill
            if platform.system() == "Windows" and psutil.pid_exists(pid):
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, timeout=5)

            alive = psutil.pid_exists(pid)
            if not alive:
                logger.info(f"[Remediator Agent] PID {pid} successfully terminated.")
                return ActionStatus.SUCCESS, f"Terminated PID {pid}", {"pid": pid, "name": expected_name}
            else:
                logger.error(f"[Remediator Agent] PID {pid} is still alive after termination.")
                return ActionStatus.FAILED, f"Process {pid} survived kill", {"pid": pid}
        except Exception as e:
            logger.error(f"[Remediator Agent] Kill failed for PID {pid}: {e}")
            return ActionStatus.FAILED, str(e), {"pid": pid, "error": str(e)}

    def _execute_net_isolate(self, source_ip: str) -> tuple[ActionStatus, str, Dict[str, Any]]:
        """Isolate malicious remote IP via OS firewall."""
        try:
            res = _isolate_host(source_ip)
            if res.get("success"):
                logger.info(f"[Remediator Agent] Host isolated: {source_ip}")
                return ActionStatus.SUCCESS, f"Isolated host {source_ip}", res
            else:
                return ActionStatus.FAILED, res.get("detail", "Firewall command failed"), res
        except Exception as e:
            return ActionStatus.FAILED, str(e), {"error": str(e)}

    def _execute_honeypot_redirect(self, event: ThreatInvestigatedEvent) -> tuple[ActionStatus, str, Dict[str, Any]]:
        """Redirect zero-day anomaly or probe traffic to active dynamic decoy honeypot trap."""
        try:
            target_ip = event.memory_context.get("source_ip") if event.memory_context else "198.51.100.88"
            target_port = int(event.memory_context.get("port", 4444)) if event.memory_context else 4444

            capture = dynamic_honeypot_engine.redirect_traffic_to_decoy(
                target_ip=target_ip,
                target_port=target_port,
                threat_type=event.root_cause,
                telemetry=event.memory_context,
                raw_payload=getattr(event, "raw_payload", None),
            )

            status = ActionStatus.SUCCESS
            decoy_port = capture.get("decoy_port", 2222)
            reason = f"Dynamic honeypot activated on port {decoy_port} | Redirecting traffic"

            print(f"\033[93m\033[1m[Remediator Agent]\033[0m\n{reason}")
            logger.warning(f"[Remediator Agent] Deception trap active on port {decoy_port} | Status: {status.value}")
            return status, reason, capture
        except Exception as e:
            logger.error(f"[Remediator Agent] Honeypot redirect failed: {e}")
            return ActionStatus.FAILED, f"Honeypot redirection failed: {e}", {"error": str(e)}
