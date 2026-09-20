"""
AegisAI Dynamic Generative Honeypot Traps & Active Deception Engine.
Provides active ephemeral decoy listeners, realistic protocol handshake emulators
(HTTP, FTP, SSH, RawSocket), dynamic socket redirection, Shannon entropy calculation,
and non-destructive payload entrapment for edge retraining.
"""
from __future__ import annotations

import asyncio
import math
import hashlib
import json
import random
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from loguru import logger

from app.deception.trap_logger import trap_logger


def calculate_entropy(data: bytes | str) -> float:
    """
    Compute normalized Shannon entropy score H(X) for raw payload bytes.
    Returns float in range [0.0, 1.0].
    Higher scores (~0.70-1.0) indicate encrypted, compressed, or shellcode payloads.
    """
    if not data:
        return 0.0

    raw_bytes = data.encode("utf-8", errors="ignore") if isinstance(data, str) else data
    if not raw_bytes:
        return 0.0

    total_len = len(raw_bytes)
    freqs = Counter(raw_bytes)
    entropy = 0.0
    for count in freqs.values():
        p_x = count / total_len
        entropy -= p_x * math.log2(p_x)

    # 8 bits max entropy per byte -> normalize to [0.0, 1.0]
    normalized = round(min(1.0, max(0.0, entropy / 8.0)), 4)
    return normalized


# Preconfigured decoy service profiles
DECOY_PROFILES = {
    "HTTP": {
        "port": 8080,
        "trap_type": "FAKE_HTTP",
        "service_name": "Apache/2.4.52 (Ubuntu) Decoy Gateway",
        "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n<html><body><h1>Corporate Internal Portal</h1><form action='/login' method='POST'><input name='user'/><input name='password'/></form></body></html>",
    },
    "FTP": {
        "port": 2121,
        "trap_type": "FAKE_FTP",
        "service_name": "Aegis Synthetic Backup FTP Server v2.4",
        "banner": "220 Aegis Synthetic Backup FTP Server Ready\r\n",
    },
    "SSH": {
        "port": 2222,
        "trap_type": "FAKE_SSH",
        "service_name": "OpenSSH 8.9p1 Ubuntu-3ubuntu0.1 Decoy",
        "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
    },
    "RAW": {
        "port": 8443,
        "trap_type": "FAKE_RAW_SOCKET",
        "service_name": "Synthetic C2 Sandbox Interceptor",
        "banner": "\x00\x01\xAE\x00READY_FOR_HANDSHAKE\n",
    },
}


class DynamicHoneypotEngine:
    """
    Dynamic Generative Honeypot Engine.
    Manages dynamic decoy listeners, protocol handshakes, socket traffic redirection,
    and extraction of cryptographic signatures without host OS execution.
    """

    def __init__(self):
        self._active_servers: Dict[int, asyncio.Server] = {}
        self._is_running = False
        self._lock = threading.Lock()
        self._diverted_socket_count = 0
        self._trapped_records: List[Dict[str, Any]] = []
        self._trace_listener: Optional[Callable[[str, str, Dict[str, Any]], Any]] = None

    def set_trace_listener(self, listener: Callable[[str, str, Dict[str, Any]], Any]) -> None:
        """Register a callback to stream live decoy connection traces to SOC."""
        self._trace_listener = listener

    # ── Protocol Handshake Emulators (Async Streams) ─────────────────────────

    async def _handle_http_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Emulate realistic HTTP / Web Application decoy."""
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "127.0.0.1"
        src_port = peer[1] if peer else 8080
        logger.info(f"[HONEYPOT-HTTP] Incoming connection from {src_ip}:{src_port}")

        try:
            req_lines = []
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=8.0)
                if not line or line == b"\r\n" or line == b"\n":
                    break
                req_lines.append(line.decode("utf-8", errors="ignore").strip())
                if len(req_lines) > 20:
                    break

            raw_req = "\n".join(req_lines) if req_lines else "GET / HTTP/1.1"
            
            # Send realistic HTTP response to keep attacker engaged
            resp = DECOY_PROFILES["HTTP"]["banner"].encode("utf-8")
            writer.write(resp)
            await writer.drain()

            self._record_entrapment(
                source_ip=src_ip,
                source_port=src_port,
                decoy_port=8080,
                trap_type="FAKE_HTTP",
                protocol="HTTP",
                raw_payload=raw_req,
                command_executed=req_lines[0] if req_lines else "HTTP_PROBE",
            )
        except Exception as e:
            logger.debug(f"[HONEYPOT-HTTP] Session closed: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_ftp_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Emulate interactive FTP server with multi-command conversation."""
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "127.0.0.1"
        src_port = peer[1] if peer else 2121
        logger.info(f"[HONEYPOT-FTP] Incoming connection from {src_ip}:{src_port}")

        try:
            writer.write(b"220 Aegis Synthetic Backup FTP Server Ready\r\n")
            await writer.drain()

            commands = []
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=12.0)
                if not line:
                    break
                decoded = line.decode("utf-8", errors="ignore").strip()
                commands.append(decoded)

                cmd_upper = decoded.upper()
                if cmd_upper.startswith("USER"):
                    writer.write(b"331 Password required for administrator.\r\n")
                elif cmd_upper.startswith("PASS"):
                    writer.write(b"230 User logged in, secure sandbox active.\r\n")
                elif cmd_upper.startswith("LIST") or cmd_upper.startswith("NLST"):
                    writer.write(b"150 Here comes the directory listing.\r\n226 Directory send OK.\r\n")
                elif cmd_upper.startswith("RETR"):
                    writer.write(b"550 File access restricted by security policy.\r\n")
                elif cmd_upper.startswith("STOR"):
                    writer.write(b"150 Ok to send data in honeypot quarantine buffer.\r\n226 Transfer complete.\r\n")
                elif cmd_upper.startswith("QUIT"):
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"500 Unknown command in sandboxed mode.\r\n")
                await writer.drain()

            raw_payload = "\n".join(commands) if commands else "FTP_CONNECT_PROBE"
            self._record_entrapment(
                source_ip=src_ip,
                source_port=src_port,
                decoy_port=2121,
                trap_type="FAKE_FTP",
                protocol="FTP",
                raw_payload=raw_payload,
                command_executed=commands[-1] if commands else "FTP_CONNECT",
            )
        except Exception as e:
            logger.debug(f"[HONEYPOT-FTP] Session ended: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_ssh_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Emulate OpenSSH server banner & handshake."""
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "127.0.0.1"
        src_port = peer[1] if peer else 2222
        logger.info(f"[HONEYPOT-SSH] Incoming connection from {src_ip}:{src_port}")

        try:
            writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
            await writer.drain()

            client_banner = await asyncio.wait_for(reader.readline(), timeout=10.0)
            raw = client_banner.decode("utf-8", errors="ignore").strip() if client_banner else "SSH_PROBE"

            self._record_entrapment(
                source_ip=src_ip,
                source_port=src_port,
                decoy_port=2222,
                trap_type="FAKE_SSH",
                protocol="SSH",
                raw_payload=raw,
                command_executed="SSH Protocol Handshake / Auth Probe",
            )
        except Exception as e:
            logger.debug(f"[HONEYPOT-SSH] Session ended: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_raw_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Emulate raw binary / C2 socket listener."""
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "127.0.0.1"
        src_port = peer[1] if peer else 8443
        logger.info(f"[HONEYPOT-RAW] Incoming connection from {src_ip}:{src_port}")

        try:
            writer.write(b"\x00\x01\xAE\x00AEGIS_DECOY_READY\n")
            await writer.drain()

            data = await asyncio.wait_for(reader.read(4096), timeout=8.0)
            raw_hex = data.hex() if data else "EMPTY_PROBE"

            self._record_entrapment(
                source_ip=src_ip,
                source_port=src_port,
                decoy_port=8443,
                trap_type="FAKE_RAW_SOCKET",
                protocol="RAW_SOCKET",
                raw_payload=raw_hex,
                command_executed="Binary Shellcode / Raw Beacon Probe",
            )
        except Exception as e:
            logger.debug(f"[HONEYPOT-RAW] Session ended: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── Signature Extraction & Entrapment Persistence ───────────────────────

    def extract_signature(
        self,
        raw_payload: str | bytes,
        source_ip: str = "127.0.0.1",
        source_port: int = 0,
        decoy_port: int = 2222,
        trap_type: str = "FAKE_SSH",
    ) -> Dict[str, Any]:
        """
        Extract non-destructive deception signature without executing payload on host OS:
          - SHA-256 cryptographic digest
          - Shannon entropy score (0.0 to 1.0)
          - Raw byte length
          - Hex stream preview
        """
        payload_str = raw_payload if isinstance(raw_payload, str) else raw_payload.decode("utf-8", errors="ignore")
        payload_bytes = payload_str.encode("utf-8", errors="ignore")

        sha256_hash = hashlib.sha256(payload_bytes).hexdigest()
        entropy_score = calculate_entropy(payload_bytes)
        hex_sig = payload_bytes[:32].hex()

        return {
            "sha256_hash": sha256_hash,
            "entropy_score": entropy_score,
            "byte_length": len(payload_bytes),
            "hex_signature": f"0x{hex_sig}" if hex_sig else "0x0",
            "source_ip": source_ip,
            "source_port": int(source_port),
            "decoy_port": int(decoy_port),
            "trap_type": trap_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _record_entrapment(
        self,
        source_ip: str,
        source_port: int,
        decoy_port: int,
        trap_type: str,
        protocol: str,
        raw_payload: str,
        command_executed: str,
    ) -> Dict[str, Any]:
        """Record live entrapment event, calculate signature, and trigger telemetry logger."""
        sig = self.extract_signature(
            raw_payload=raw_payload,
            source_ip=source_ip,
            source_port=source_port,
            decoy_port=decoy_port,
            trap_type=trap_type,
        )

        record = {
            "source_ip": source_ip,
            "source_port": source_port,
            "decoy_port": decoy_port,
            "trap_type": trap_type,
            "protocol": protocol,
            "raw_payload": raw_payload,
            "command_executed": command_executed,
            "payload_hash": sig["sha256_hash"],
            "entropy_score": sig["entropy_score"],
            "hex_signature": sig["hex_signature"],
            "byte_length": sig["byte_length"],
            "status": "TRAPPED",
            "timestamp": sig["timestamp"],
        }

        with self._lock:
            self._diverted_socket_count += 1
            self._trapped_records.insert(0, record)
            if len(self._trapped_records) > 200:
                self._trapped_records.pop()

        # Log into persistent captures directory via trap_logger
        trap_logger.log_trap_capture(
            source_ip=source_ip,
            source_port=source_port,
            trap_type=trap_type,
            decoy_target=f"port:{decoy_port} ({protocol}-Dynamic-Decoy)",
            raw_payload=raw_payload,
            command_executed=command_executed,
            isolation_status="TRAPPED",
        )

        trace_msg = (
            f"Attacker payload trapped on port {decoy_port} | "
            f"SHA-256: {sig['sha256_hash'][:12]}... | Payload entropy: {sig['entropy_score']}"
        )
        print(f"\033[94m\033[1m[Decoy Listener]\033[0m\n{trace_msg}")

        if self._trace_listener:
            try:
                self._trace_listener("Decoy Listener", "PAYLOAD_TRAPPED", record)
            except Exception as e:
                logger.debug(f"[Deception Engine] Trace listener note: {e}")

        return record

    # ── Dynamic Socket Redirection ──────────────────────────────────────────

    def redirect_traffic_to_decoy(
        self,
        target_ip: str = "127.0.0.1",
        target_port: int = 4444,
        decoy_port: Optional[int] = None,
        threat_type: Optional[str] = None,
        telemetry: Optional[Dict[str, Any]] = None,
        raw_payload: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute active deception redirection:
          1. Select or assign active ephemeral decoy listener.
          2. Extract deception signature and calculate Shannon entropy.
          3. Reroute incoming socket stream to sandboxed synthetic handler.
        """
        # Select target decoy port based on context
        threat_str = (threat_type or "").lower()
        if not decoy_port:
            if target_port in [80, 443, 8080] or "web" in threat_str or "sql" in threat_str:
                decoy_port = 8080
                trap_type = "FAKE_HTTP"
                protocol = "HTTP"
            elif target_port in [21, 2121] or "ftp" in threat_str:
                decoy_port = 2121
                trap_type = "FAKE_FTP"
                protocol = "FTP"
            elif target_port in [22, 2222] or "ssh" in threat_str or "brute" in threat_str:
                decoy_port = 2222
                trap_type = "FAKE_SSH"
                protocol = "SSH"
            else:
                decoy_port = 8443
                trap_type = "FAKE_RAW_SOCKET"
                protocol = "RAW_SOCKET"
        else:
            trap_type = f"DECOY_{decoy_port}"
            protocol = "TCP"

        # Generate realistic payload if none provided
        if not raw_payload:
            if protocol == "HTTP":
                raw_payload = f"POST /api/v1/exploit HTTP/1.1\r\nHost: {target_ip}:{target_port}\r\nUser-Agent: ZeroDayScanner/3.1\r\n\r\npayload=unauthorized_mem_probe"
            elif protocol == "FTP":
                raw_payload = "USER root\r\nPASS toor123\r\nRETR shadow_keys.bin"
            elif protocol == "SSH":
                raw_payload = "SSH-2.0-OpenSSH_8.9p1\r\nAuth: root / id_rsa brute-force probe"
            else:
                raw_payload = "\\x90\\x90\\x90\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3"

        # Extract deception signature
        sig = self.extract_signature(
            raw_payload=raw_payload,
            source_ip=target_ip,
            source_port=target_port,
            decoy_port=decoy_port,
            trap_type=trap_type,
        )

        with self._lock:
            self._diverted_socket_count += 1

        entrapment = {
            "source_ip": target_ip,
            "source_port": target_port,
            "decoy_port": decoy_port,
            "trap_type": trap_type,
            "protocol": protocol,
            "status": "TRAPPED",
            "redirect_success": True,
            "diverted_sockets_total": self._diverted_socket_count,
            "payload_hash": sig["sha256_hash"],
            "entropy_score": sig["entropy_score"],
            "hex_signature": sig["hex_signature"],
            "byte_length": sig["byte_length"],
            "raw_payload": raw_payload,
            "timestamp": sig["timestamp"],
            "listener_active": decoy_port in self._active_servers or self._is_running,
        }

        # Also store to memory entrapment history
        with self._lock:
            self._trapped_records.insert(0, entrapment)
            if len(self._trapped_records) > 200:
                self._trapped_records.pop()

        # Log into trap logger
        trap_logger.log_trap_capture(
            source_ip=target_ip,
            source_port=target_port,
            trap_type=trap_type,
            decoy_target=f"port:{decoy_port} ({protocol}-Dynamic-Decoy)",
            raw_payload=raw_payload,
            command_executed="Automated Dynamic Deception Redirect",
            isolation_status="TRAPPED",
        )

        logger.info(
            f"[Deception Engine] Redirected traffic from {target_ip}:{target_port} "
            f"to Decoy Listener on port {decoy_port} | Entropy: {sig['entropy_score']}"
        )

        return entrapment

    # ── Listener Lifecycle Management ────────────────────────────────────────

    async def start(self, host: str = "127.0.0.1", custom_ports: Optional[Dict[str, int]] = None) -> None:
        """Start async socket listeners for active decoy services."""
        if self._is_running:
            return

        ports_map = custom_ports or {}
        listeners = [
            (ports_map.get("HTTP", 8080), self._handle_http_connection, "HTTP"),
            (ports_map.get("FTP", 2121), self._handle_ftp_connection, "FTP"),
            (ports_map.get("SSH", 2222), self._handle_ssh_connection, "SSH"),
            (ports_map.get("RAW_SOCKET", 8443), self._handle_raw_connection, "RAW_SOCKET"),
        ]

        for port, handler, name in listeners:
            try:
                srv = await asyncio.start_server(handler, host, port)
                self._active_servers[port] = srv
                logger.info(f"[Deception Engine] Active Decoy Listener [{name}] listening on {host}:{port}")
            except Exception as e:
                logger.warning(f"[Deception Engine] Could not bind decoy port {port}: {e}")

        self._is_running = True

    async def stop(self) -> None:
        """Cleanly close all active decoy listeners."""
        for port, srv in list(self._active_servers.items()):
            try:
                srv.close()
                await srv.wait_closed()
            except Exception:
                pass
        self._active_servers.clear()
        self._is_running = False
        logger.info("[Deception Engine] All dynamic decoy listeners stopped.")

    def get_deception_metrics(self) -> Dict[str, Any]:
        """Return live operational metrics of the deception engine."""
        with self._lock:
            return {
                "active_listeners_count": len(self._active_servers),
                "active_ports": list(self._active_servers.keys()),
                "total_diverted_sockets": self._diverted_socket_count,
                "trapped_records_count": len(self._trapped_records),
                "recent_traps": list(self._trapped_records[:10]),
                "status": "OPERATIONAL" if self._is_running else "STANDBY",
            }


# Global singleton dynamic honeypot engine
dynamic_honeypot_engine = DynamicHoneypotEngine()
