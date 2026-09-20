"""
AegisAI Investigator Agent
Responsible for XAI feature attribution (TreeSHAP/TreeExplainer), read-only process
and socket context inspection, root-cause derivation, and threat classification.
"""
from __future__ import annotations

import psutil
from typing import Any, Dict, List, Optional
from loguru import logger

from app.ml.xai_explainer import xai_manager
from app.deception.trap_logger import trap_logger
from app.agents.schemas import AnomalyDetectedEvent, ThreatInvestigatedEvent
from app.agents.event_bus import EventBus


class InvestigatorAgent:
    """
    Investigator Agent subscribes to AnomalyDetectedEvent, performs XAI feature attribution,
    gathers read-only system and network context, formulates root-cause findings,
    and publishes ThreatInvestigatedEvent.
    """

    def __init__(self, event_bus: EventBus):
        self.bus = event_bus
        self._setup_subscriptions()

    def _setup_subscriptions(self) -> None:
        self.bus.subscribe(AnomalyDetectedEvent, self.handle_anomaly)

    async def handle_anomaly(self, event: AnomalyDetectedEvent) -> None:
        """Handle incoming anomaly event from Detector Agent."""
        try:
            logger.info(
                f"[Investigator Agent] Investigating anomaly {event.event_id[:8]} "
                f"(PID: {event.process_pid}, Score: {event.threat_score:.2f})"
            )

            # 1. Feature Attribution via XAI Explainer
            threat_dict = {
                "id": event.event_id,
                "threat_score": event.threat_score,
                "port": event.port or 4444,
                "threat_type": event.threat_type or "Suspicious Activity",
                "telemetry": event.telemetry or {},
            }
            xai_result = xai_manager.explain_threat(threat_dict)
            attributions: List[Dict[str, Any]] = xai_result.get("feature_attributions", [])

            # Separate into positive risk drivers and negative safety indicators
            positive_drivers = [a for a in attributions if a.get("impact", 0) > 0]
            negative_indicators = [a for a in attributions if a.get("impact", 0) <= 0]

            # Sort positive drivers descending by impact
            positive_drivers.sort(key=lambda x: x.get("impact", 0), reverse=True)
            negative_indicators.sort(key=lambda x: x.get("impact", 0))

            # Determine attribution method
            shap_explainer = getattr(xai_manager, "_shap_explainer", None)
            is_shap_available = shap_explainer is not None
            attribution_method = (
                "TreeExplainer"
                if is_shap_available
                else "DomainAttributionMatrix (TreeSHAP unavailable)"
            )

            # 2. Read-Only Context Investigation
            memory_context = self._inspect_process_context(event.process_pid)
            honeypot_context = self._inspect_honeypot_context(event.source_ip, event.port)

            # 3. Formulate Root Cause
            root_cause = self._synthesize_root_cause(
                positive_drivers, event, is_shap_available=is_shap_available
            )
            logger.info(f"[Investigator Agent] {root_cause}")

            # 4. Construct & Publish ThreatInvestigatedEvent
            investigated_event = ThreatInvestigatedEvent(
                source_anomaly_event_id=event.event_id,
                process_pid=event.process_pid,
                process_name=event.process_name or memory_context.get("name"),
                threat_score=event.threat_score,
                severity=event.severity,
                positive_risk_drivers=positive_drivers,
                negative_safety_indicators=negative_indicators,
                feature_attributions=attributions,
                feature_vector=event.feature_vector,
                root_cause=root_cause,
                memory_context=memory_context,
                honeypot_context=honeypot_context,
                confidence=round(min(1.0, max(0.5, event.threat_score)), 2),
                attribution_method=attribution_method,
            )

            await self.bus.publish(investigated_event)

        except Exception as e:
            logger.error(
                f"[Investigator Agent] Error investigating anomaly {getattr(event, 'event_id', 'unknown')}: {e}"
            )

    def _inspect_process_context(self, pid: Optional[int]) -> Dict[str, Any]:
        """Safely inspect live process metadata via psutil (read-only)."""
        if not pid or pid <= 4:
            return {"status": "NO_PID_SPECIFIED"}

        try:
            if not psutil.pid_exists(pid):
                return {"status": "PROCESS_NOT_FOUND", "pid": pid}

            proc = psutil.Process(pid)
            with proc.oneshot():
                return {
                    "status": "ACTIVE",
                    "pid": pid,
                    "name": proc.name(),
                    "status_code": proc.status(),
                    "cpu_percent": proc.cpu_percent(),
                    "memory_mb": round(proc.memory_info().rss / (1024 * 1024), 2),
                    "create_time": proc.create_time(),
                    "username": proc.username() if hasattr(proc, "username") else "UNKNOWN",
                    "cmdline": proc.cmdline()[:5] if hasattr(proc, "cmdline") else [],
                    "parent_pid": proc.ppid() if hasattr(proc, "ppid") else None,
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {"status": "INSPECT_RESTRICTED", "pid": pid, "error": str(e)}
        except Exception as e:
            return {"status": "ERROR", "pid": pid, "error": str(e)}

    def _inspect_honeypot_context(self, source_ip: Optional[str], port: Optional[int]) -> Optional[Dict[str, Any]]:
        """Query existing deception log captures for historical interaction with source IP."""
        if not source_ip:
            return None

        try:
            recent_traps = trap_logger.get_recent_captures(limit=20)
            matching = [t for t in recent_traps if t.get("source_ip") == source_ip]
            return {
                "source_ip": source_ip,
                "historical_trap_hits": len(matching),
                "last_trap_type": matching[0].get("trap_type") if matching else None,
                "decoy_candidate": True if ("zero-day" in str(source_ip) or (port and port in [2121, 2222, 4444])) else False,
            }
        except Exception:
            return None

    def _synthesize_root_cause(
        self,
        positive_drivers: List[Dict[str, Any]],
        event: AnomalyDetectedEvent,
        is_shap_available: bool = False,
    ) -> str:
        """Derive an evidence-backed root cause sentence from positive attribution drivers."""
        prefix = "TreeSHAP identified" if is_shap_available else "TreeSHAP unavailable for current model | Fallback attribution used:"
        if positive_drivers:
            top = positive_drivers[0]
            feature_name = top.get("feature", "unknown_metric")
            impact = top.get("impact", 0.0)

            # Contextual human-readable explanations
            if "port_entropy" in feature_name:
                driver_desc = f"high socket entropy on port {event.port or 'dynamic'}"
            elif "outbound_bytes" in feature_name:
                driver_desc = "outbound data burst anomaly"
            elif "cpu_anomaly" in feature_name:
                driver_desc = "process CPU spike consistent with unauthorized activity"
            elif "parent_process" in feature_name:
                driver_desc = "suspicious process lineage"
            else:
                driver_desc = f"primary risk driver '{feature_name}'"

            return f"{prefix} {driver_desc} ({impact:+.2f} impact)"

        return f"Anomaly score ({event.threat_score:.2f}) exceeded dynamic threshold ({event.dynamic_threshold:.2f})"
