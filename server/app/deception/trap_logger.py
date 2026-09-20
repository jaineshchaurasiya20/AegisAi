"""
AegisAI Trap Logger — Segregated Payload & Telemetry Audit Logging.
Saves honeypot interaction records into /honeypot/captures/ as immutable JSON artifacts.
"""
import os
import json
import hashlib
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from loguru import logger

# Standardized capture directory anchored at project server root
SERVER_ROOT = Path(os.getenv("AEGIS_SERVER_ROOT", Path(__file__).resolve().parents[2]))
CAPTURES_DIR = SERVER_ROOT / "honeypot" / "captures"
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)

class TrapLogger:
    """
    Manages structured capture persistence and querying for honeypot deception telemetry.
    """

    def __init__(self, output_dir: Path = CAPTURES_DIR):
        self.output_dir = output_dir
        self._lock = threading.Lock()
        self._memory_captures: List[Dict[str, Any]] = []
        self._ensure_dir()

    def _ensure_dir(self):

        """Ensuring segregated captures directory exists."""

        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"Could not create honeypot captures directory: {e}")

    def log_trap_capture(
        self,
        source_ip: str,
        source_port: int,
        trap_type: str,
        decoy_target: str,
        raw_payload: str,
        command_executed: Optional[str] = None,
        isolation_status: str = "TRAPPED",
        capture_id: Optional[str] = None,
        custom_timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Record a honeypot interaction event, compute SHA-256 payload hash, and write to disk.
        """
        ts = custom_timestamp or datetime.now(timezone.utc).isoformat()
        clean_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        
        # Calculate SHA-256 hash of payload
        payload_bytes = (raw_payload or "").encode("utf-8")
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()

        cid = capture_id or f"trap_{hashlib.md5(f'{source_ip}:{source_port}:{ts}'.encode()).hexdigest()[:10]}"

        record = {
            "captureId": cid,
            "timestamp": ts,
            "sourceIp": source_ip,
            "sourcePort": int(source_port),
            "trapType": trap_type,
            "decoyTarget": decoy_target,
            "rawPayload": raw_payload,
            "commandExecuted": command_executed or "N/A",
            "payloadHash": payload_hash,
            "isolationStatus": isolation_status,
        }

        # Write to disk
        filename = f"trap_capture_{clean_ts}_{cid}.json"
        filepath = self.output_dir / filename

        with self._lock:
            try:
                self._ensure_dir()
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(record, f, indent=2)
                logger.info(f"[HONEYPOT-LOGGER] Logged trap capture to {filename} (Target: {decoy_target})")
            except Exception as e:
                logger.error(f"[HONEYPOT-LOGGER] Failed writing trap capture to disk: {e}")

            # Keeping in memory cache for instant API queries
            self._memory_captures.insert(0, record)
            if len(self._memory_captures) > 200:
                self._memory_captures.pop()

        return record

    def get_recent_captures(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent trap captures from memory or disk."""
        with self._lock:
            if self._memory_captures:
                return self._memory_captures[:limit]

        # Disk fallback if memory is empty
        captures = []
        try:
            if self.output_dir.exists():
                files = sorted(self.output_dir.glob("trap_capture_*.json"), reverse=True)
                for f in files[:limit]:
                    try:
                        with open(f, "r", encoding="utf-8") as fp:
                            captures.append(json.load(fp))
                    except Exception:
                        continue
        except Exception as e:
            logger.warning(f"Failed to read captures from disk: {e}")

        with self._lock:
            if captures and not self._memory_captures:
                self._memory_captures = captures.copy()

        return captures[:limit]

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate honeypot deception trap statistics."""
        captures = self.get_recent_captures(limit=500)
        by_type = {"FAKE_FTP": 0, "FAKE_REGISTRY": 0, "FAKE_SSH": 0, "DECOY_FILE": 0}
        for c in captures:
            t = c.get("trapType")
            if t in by_type:
                by_type[t] += 1
            else:
                by_type[t] = 1

        return {
            "totalTrapped": len(captures),
            "byTrapType": by_type,
            "capturesDirectory": str(self.output_dir),
            "activeDecoys": [
                {"type": "FAKE_FTP", "target": "port:2121 (Aegis-FTP-Synthetic)"},
                {"type": "FAKE_SSH", "target": "port:2222 (OpenSSH-Decoy-Banner)"},
                {"type": "FAKE_REGISTRY", "target": "HKLM\\SOFTWARE\\AegisDecoy\\AdminCreds"},
                {"type": "DECOY_FILE", "target": "C:\\AegisDecoy\\shadow_backup"},
            ],
        }


# Global singleton logger
trap_logger = TrapLogger()
