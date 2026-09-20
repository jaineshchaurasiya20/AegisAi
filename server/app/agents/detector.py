
"""
AegisAI Detector Agent
Responsible for continuous telemetry sampling, dynamic adaptive thresholding,
and anomaly detection using dual-model ONNX inference.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from loguru import logger

from app.core.config import get_settings
from app.collector.host_monitor import get_host_snapshot
from app.ml.inference import run_inference
from app.agents.schemas import TelemetryEvent, AnomalyDetectedEvent, BaseAgentEvent
from app.agents.event_bus import EventBus

settings = get_settings()


def compute_dynamic_threshold(
    base_threshold: float,
    cpu_percent: float,
    memory_percent: float,
    bytes_sent_per_s: float = 0.0,
    bytes_recv_per_s: float = 0.0,
    load_factor: float = 0.20,
    min_threshold: float = 0.50,
    max_threshold: float = 0.88,
) -> float:
    """
    Compute bounded dynamic adaptive threshold:
        τ(t) = clamp(τ_base + Δ_load, τ_min, τ_max)

    Reduces false positives during compilation, model training, or heavy I/O workloads.
    Deterministic, bounded, and unit-testable.
    """
    # Excess workload factors beyond baseline host activity
    cpu_excess = max(0.0, (float(cpu_percent) - 20.0) / 80.0)
    mem_excess = max(0.0, (float(memory_percent) - 50.0) / 50.0)
    io_throughput = (float(bytes_sent_per_s) + float(bytes_recv_per_s)) / 10_000_000.0  # 10 MB/s ref
    io_excess = min(1.0, max(0.0, io_throughput))

    composite_load = (0.50 * cpu_excess) + (0.30 * mem_excess) + (0.20 * io_excess)
    delta_load = load_factor * composite_load

    tau = base_threshold + delta_load
    clamped_tau = round(min(max_threshold, max(min_threshold, tau)), 4)
    return clamped_tau


class DetectorAgent:
    """
    Detector Agent runs a 1.0s telemetry sampling loop, evaluates dynamic adaptive thresholds,
    and publishes TelemetryEvent and AnomalyDetectedEvent onto the Event Bus.
    """

    def __init__(
        self,
        event_bus: EventBus,
        base_threshold: Optional[float] = None,
        min_threshold: Optional[float] = None,
        max_threshold: Optional[float] = None,
        load_factor: Optional[float] = None,
        sampling_interval: Optional[float] = None,
    ):
        self.bus = event_bus
        self.base_threshold = base_threshold if base_threshold is not None else settings.AGENT_BASE_THRESHOLD
        self.min_threshold = min_threshold if min_threshold is not None else settings.AGENT_MIN_THRESHOLD
        self.max_threshold = max_threshold if max_threshold is not None else settings.AGENT_MAX_THRESHOLD
        self.load_factor = load_factor if load_factor is not None else settings.AGENT_LOAD_FACTOR
        self.sampling_interval = sampling_interval if sampling_interval is not None else settings.AGENT_SAMPLING_INTERVAL

        self._running = False
        self._sampling_task: Optional[asyncio.Task] = None
        self._last_threshold: float = self.base_threshold
        self._last_snapshot: Optional[Dict[str, Any]] = None

    @property
    def dynamic_threshold(self) -> float:
        return self._last_threshold

    async def start(self) -> None:
        """Start the continuous telemetry sampling background loop."""
        if self._running:
            return
        self._running = True
        self._sampling_task = asyncio.create_task(self._sampling_loop(), name="DetectorAgent-SamplingLoop")
        logger.info(
            f"[Detector Agent] Started (interval={self.sampling_interval}s, "
            f"base_threshold={self.base_threshold}, min={self.min_threshold}, max={self.max_threshold})"
        )

    async def stop(self) -> None:
        """Stop the sampling loop cleanly."""
        if not self._running:
            return
        self._running = False
        if self._sampling_task:
            self._sampling_task.cancel()
            try:
                await self._sampling_task
            except asyncio.CancelledError:
                pass
            self._sampling_task = None
        logger.info("[Detector Agent] Stopped.")

    async def _sampling_loop(self) -> None:
        """Continuous 1.0-second host telemetry sampling coroutine."""
        while self._running:
            try:
                snapshot = await get_host_snapshot()
                self._last_snapshot = snapshot
                await self._process_snapshot(snapshot)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[Detector Agent] Error in sampling loop: {e}")

            await asyncio.sleep(self.sampling_interval)

    async def _process_snapshot(self, snapshot: Dict[str, Any]) -> None:
        """Process one host snapshot: calculate dynamic threshold, run inference, emit events."""
        cpu = snapshot.get("cpu_percent", 0.0)
        mem = snapshot.get("memory_percent", 0.0)
        sent = snapshot.get("bytes_sent_per_s", 0.0)
        recv = snapshot.get("bytes_recv_per_s", 0.0)

        tau = compute_dynamic_threshold(
            base_threshold=self.base_threshold,
            cpu_percent=cpu,
            memory_percent=mem,
            bytes_sent_per_s=sent,
            bytes_recv_per_s=recv,
            load_factor=self.load_factor,
            min_threshold=self.min_threshold,
            max_threshold=self.max_threshold,
        )
        self._last_threshold = tau

        # Dual-model ONNX ML inference
        inference_result = await run_inference(snapshot)
        threat_score = float(inference_result.get("threat_score", 0.0))
        feature_vector = inference_result.get("feature_vector", [])
        severity = inference_result.get("severity", "low")

        # Publish standard TelemetryEvent
        telemetry_event = TelemetryEvent(
            hostname=snapshot.get("host_ip", "localhost"),
            host_ip=snapshot.get("host_ip", "127.0.0.1"),
            cpu_usage=cpu,
            memory_usage=mem,
            disk_usage=snapshot.get("disk_percent", 0.0),
            processes=snapshot.get("top_processes", []),
            network_sockets=snapshot.get("active_sockets", []),
            network_io={
                "bytes_sent_per_s": sent,
                "bytes_recv_per_s": recv,
                "packets_sent_per_s": snapshot.get("packets_sent_per_s", 0.0),
                "packets_recv_per_s": snapshot.get("packets_recv_per_s", 0.0),
            },
            feature_vector=feature_vector,
            raw_snapshot=snapshot,
        )
        await self.bus.publish(telemetry_event)

        # Anomaly detection decision rule: threat_score > dynamic_threshold
        if threat_score > tau:
            logger.warning(
                f"[Detector Agent] Dynamic threshold tuned to {tau:.2f} | Anomaly score: {threat_score:.2f}"
            )
            # Identify candidate target process from top processes or telemetry
            top_procs = snapshot.get("top_processes", [])
            target_pid = top_procs[0].get("pid") if top_procs else None
            target_name = top_procs[0].get("name") if top_procs else None

            anomaly_event = AnomalyDetectedEvent(
                process_pid=target_pid,
                process_name=target_name,
                threat_score=threat_score,
                dynamic_threshold=tau,
                telemetry={
                    "snapshot": snapshot,
                    "inference": inference_result,
                    "pid": target_pid,
                    "processName": target_name,
                },
                feature_vector=feature_vector,
                severity=severity,
                source_ip=snapshot.get("host_ip", "127.0.0.1"),
                port=top_procs[0].get("port") if top_procs and "port" in top_procs[0] else None,
                threat_type="Host Anomaly Detection",
            )
            await self.bus.publish(anomaly_event)

    async def ingest_event(self, event_data: Dict[str, Any]) -> AnomalyDetectedEvent | None:
        """
        Ingest external threat event (e.g. from /api/threats/scan or replay attacks script).
        Evaluates dynamic threshold and publishes AnomalyDetectedEvent if threshold is exceeded.
        """
        # Calculate current dynamic threshold from last snapshot or defaults
        snapshot = self._last_snapshot or {}
        cpu = snapshot.get("cpu_percent", 15.0)
        mem = snapshot.get("memory_percent", 35.0)
        sent = snapshot.get("bytes_sent_per_s", 0.0)
        recv = snapshot.get("bytes_recv_per_s", 0.0)

        tau = compute_dynamic_threshold(
            base_threshold=self.base_threshold,
            cpu_percent=cpu,
            memory_percent=mem,
            bytes_sent_per_s=sent,
            bytes_recv_per_s=recv,
            load_factor=self.load_factor,
            min_threshold=self.min_threshold,
            max_threshold=self.max_threshold,
        )
        self._last_threshold = tau

        telemetry = event_data.get("telemetry") or {}
        target_pid = telemetry.get("pid")
        target_name = telemetry.get("processName") or event_data.get("process_name")

        score = float(event_data.get("threat_score", 0.0))
        severity = event_data.get("severity") or (
            "critical" if score > 0.88 else "high" if score > 0.70 else "medium" if score > 0.45 else "low"
        )

        logger.info(
            f"[Detector Agent] Dynamic threshold tuned to {tau:.2f} | Anomaly score: {score:.2f}"
        )

        if score > tau:
            feature_vector = event_data.get("feature_vector")
            if not feature_vector:
                try:
                    from app.ml.preprocessor import extract_features_from_host
                    feat_input = {**snapshot, **telemetry} if isinstance(telemetry, dict) else snapshot
                    feature_vector = extract_features_from_host(feat_input).flatten().tolist()
                except Exception as _fe_err:
                    logger.debug(f"[Detector Agent] Feature extraction fallback: {_fe_err}")
                    feature_vector = []

            anomaly_event = AnomalyDetectedEvent(
                process_pid=target_pid,
                process_name=target_name,
                threat_score=score,
                dynamic_threshold=tau,
                telemetry=telemetry,
                feature_vector=feature_vector,
                severity=severity,
                source_ip=event_data.get("source_ip"),
                port=event_data.get("port"),
                threat_type=event_data.get("threat_type", "Suspicious Activity"),
            )
            await self.bus.publish(anomaly_event)
            return anomaly_event
        else:
            logger.debug(
                f"[Detector Agent] Ingested event score {score:.2f} <= dynamic threshold {tau:.2f}. "
                "Anomaly event suppressed."
            )
            return None
