"""
AegisAI Ephemeral Memory Sandbox
Zero-Knowledge Ephemeral Memory Pipeline for PCTA Compliance.

Buffers runtime telemetry and agent execution traces strictly in memory
(io.BytesIO and in-memory queues) without writing unencrypted cleartext
telemetry to disk. Performs periodic garbage collection and context-wiping
every 60 seconds with explicit zero-fill memory overwrites and gc.collect().
"""
from __future__ import annotations

import asyncio
import gc
import hashlib
import io
import json
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from loguru import logger

from app.core.config import get_settings

settings = get_settings()


def hash_identity(val: str) -> str:
    """Generate SHA-256 hashed identity token for PCTA compliance."""
    if not val:
        return "ANON_UNKNOWN"
    digest = hashlib.sha256(val.strip().encode("utf-8")).hexdigest()
    return f"ANON_{digest[:16]}"


def anonymize_telemetry_dict(data: Dict[str, Any], strict: bool = True) -> Dict[str, Any]:
    """
    Anonymize sensitive process, network, and host attributes into SHA-256 hashes
    before ephemeral buffering or external display.
    """
    if not strict or not isinstance(data, dict):
        return data

    sanitized = {}
    sensitive_keys = {
        "processname", "process_name", "proc_name", "commandline", "command_line",
        "parentprocess", "parent_process", "user", "username", "source_ip", "sourceip",
        "destination_ip", "dest_ip", "targetip", "target_ip", "remoteip", "remote_ip"
    }

    for k, v in data.items():
        k_lower = k.lower().replace("-", "_")
        if k_lower in sensitive_keys and isinstance(v, str):
            sanitized[k] = hash_identity(v)
        elif k_lower == "opensockets" and isinstance(v, list):
            sanitized_sockets = []
            for sock in v:
                if isinstance(sock, dict):
                    s_copy = dict(sock)
                    if "remoteIp" in s_copy and isinstance(s_copy["remoteIp"], str):
                        s_copy["remoteIp"] = hash_identity(s_copy["remoteIp"])
                    if "localIp" in s_copy and isinstance(s_copy["localIp"], str):
                        s_copy["localIp"] = hash_identity(s_copy["localIp"])
                    sanitized_sockets.append(s_copy)
                else:
                    sanitized_sockets.append(sock)
            sanitized[k] = sanitized_sockets
        elif isinstance(v, dict):
            sanitized[k] = anonymize_telemetry_dict(v, strict=strict)
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            sanitized[k] = [anonymize_telemetry_dict(item, strict=strict) for item in v]
        else:
            sanitized[k] = v

    return sanitized


class EphemeralMemoryManager:
    """
    Zero-Knowledge Ephemeral RAM Sandbox.
    Maintains runtime telemetry and agent execution traces strictly in memory buffers.
    Zero unencrypted disk writes occur. Wipes memory every 60 seconds with explicit zero-fill.
    """

    def __init__(self, wipe_interval: Optional[int] = None, strict_mode: Optional[bool] = None):
        self.wipe_interval = wipe_interval or settings.EPHEMERAL_WIPE_INTERVAL
        self.strict_mode = settings.PCTA_STRICT_MODE if strict_mode is None else strict_mode
        self._lock = threading.Lock()

        # In-memory buffer stream strictly in RAM
        self._byte_buffer = io.BytesIO()
        self._trace_queue: List[Dict[str, Any]] = []
        self._telemetry_queue: List[Dict[str, Any]] = []

        # Audit & wipe metrics
        self._wipe_count = 0
        self._last_wipe_timestamp: Optional[str] = None
        self._total_bytes_wiped = 0
        self._active_wipe_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    def buffer_telemetry(self, telemetry: Dict[str, Any]) -> str:
        """
        Buffer telemetry strictly in RAM. Anonymizes sensitive attributes
        if PCTA strict mode is enabled.
        """
        data = anonymize_telemetry_dict(telemetry, strict=self.strict_mode)
        serialized = json.dumps(data, default=str).encode("utf-8") + b"\n"

        with self._lock:
            self._telemetry_queue.append(data)
            self._byte_buffer.write(serialized)
            # Keep trace queues bounded in RAM
            if len(self._telemetry_queue) > 500:
                self._telemetry_queue.pop(0)

        return hashlib.sha256(serialized).hexdigest()

    def buffer_trace(self, trace: Dict[str, Any]) -> None:
        """Buffer agent execution trace strictly in memory."""
        data = anonymize_telemetry_dict(trace, strict=self.strict_mode)
        serialized = json.dumps(data, default=str).encode("utf-8") + b"\n"

        with self._lock:
            self._trace_queue.append(data)
            self._byte_buffer.write(serialized)
            if len(self._trace_queue) > 1000:
                self._trace_queue.pop(0)

    def get_recent_traces(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent ephemeral traces without persisting to disk."""
        with self._lock:
            return list(self._trace_queue[-limit:])

    def get_buffered_bytes_count(self) -> int:
        """Return the current active byte size of in-memory telemetry buffers."""
        with self._lock:
            return self._byte_buffer.tell()

    def wipe_ephemeral_context(self) -> Dict[str, Any]:
        """
        Zero-knowledge memory wipe routine:
        1. Overwrites RAM byte buffers with null bytes.
        2. Clears in-memory queues and truncates buffers.
        3. Invokes Python's gc.collect() to reclaim unreferenced memory frames.
        """
        with self._lock:
            buffer_size = self._byte_buffer.tell()

            if buffer_size > 0:
                # Explicit zero-fill memory overwrite before deallocation
                self._byte_buffer.seek(0)
                self._byte_buffer.write(b"\x00" * buffer_size)
                self._byte_buffer.seek(0)
                self._byte_buffer.truncate(0)

            queue_items_cleared = len(self._trace_queue) + len(self._telemetry_queue)
            self._trace_queue.clear()
            self._telemetry_queue.clear()

            self._wipe_count += 1
            self._total_bytes_wiped += buffer_size
            now_iso = datetime.now(timezone.utc).isoformat()
            self._last_wipe_timestamp = now_iso

        # Explicit garbage collection pass
        collected = gc.collect()

        logger.info(
            f"[Ephemeral Sandbox] Memory wipe executed | Wiped {buffer_size} bytes, "
            f"{queue_items_cleared} queued items | gc.collect() reclaimed {collected} objects"
        )

        return {
            "status": "wiped",
            "timestamp": now_iso,
            "bytes_wiped": buffer_size,
            "items_cleared": queue_items_cleared,
            "gc_objects_collected": collected,
            "total_wipes": self._wipe_count,
            "pcta_strict_mode": self.strict_mode,
        }

    async def start_wipe_loop(self) -> None:
        """Periodic context-wiping background loop running every wipe_interval seconds."""
        self._stop_event.clear()
        logger.info(
            f"[Ephemeral Sandbox] Periodic wipe loop initialized (interval: {self.wipe_interval}s, PCTA: {self.strict_mode})"
        )

        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(self.wipe_interval)
                if self._stop_event.is_set():
                    break
                self.wipe_ephemeral_context()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[Ephemeral Sandbox] Error during scheduled context wipe: {e}")

    def stop_wipe_loop(self) -> None:
        """Signal background wipe loop to terminate."""
        self._stop_event.set()
        if self._active_wipe_task and not self._active_wipe_task.done():
            self._active_wipe_task.cancel()

    def get_sandbox_stats(self) -> Dict[str, Any]:
        """Return health and compliance statistics for the ephemeral memory sandbox."""
        with self._lock:
            active_bytes = self._byte_buffer.tell()
            queued_traces = len(self._trace_queue)
            queued_telemetry = len(self._telemetry_queue)

        return {
            "sandbox_mode": "Zero-Knowledge Ephemeral RAM",
            "pcta_strict_mode": self.strict_mode,
            "wipe_interval_seconds": self.wipe_interval,
            "active_ram_bytes": active_bytes,
            "queued_traces": queued_traces,
            "queued_telemetry": queued_telemetry,
            "total_wipes_executed": self._wipe_count,
            "total_bytes_scrubbed": self._total_bytes_wiped,
            "last_wipe_timestamp": self._last_wipe_timestamp,
            "disk_spill_prevented": True,
        }


# Global singleton instance
ephemeral_sandbox = EphemeralMemoryManager()
