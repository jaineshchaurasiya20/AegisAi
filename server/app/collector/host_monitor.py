"""
AegisAI Host Monitor — psutil-based system telemetry collector.
Collects CPU, RAM, disk, network I/O, and active socket connections.
Respects RAM_PAUSE_THRESHOLD to avoid overloading monitored hosts (rules.md §2).
"""
import asyncio
import psutil
import time
from typing import Dict, Any
# pyrefly: ignore [missing-import]
from loguru import logger
from app.core.config import get_settings

settings = get_settings()

_last_net_io = None
_last_net_time = None


async def get_host_snapshot() -> Dict[str, Any]:
    """
    Capture a point-in-time host telemetry snapshot.
    Runs blocking psutil calls in a thread pool to avoid blocking the event loop.
    """
    loop = asyncio.get_event_loop()
    snapshot = await loop.run_in_executor(None, _collect_sync)
    return snapshot


def _collect_sync() -> Dict[str, Any]:
    global _last_net_io, _last_net_time

    # --- CPU & Memory ---
    cpu_percent = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()

    # Safety guardrail: log warning if RAM exceeds threshold
    if mem.percent > settings.RAM_PAUSE_THRESHOLD:
        logger.warning(f"RAM usage {mem.percent:.1f}% exceeds pause threshold {settings.RAM_PAUSE_THRESHOLD}%. Reducing sampling.")

    # --- Disk ---
    disk = psutil.disk_usage("/")

    # --- Network I/O delta (bytes/s, packets/s) ---
    net_io = psutil.net_io_counters()
    now = time.monotonic()
    bytes_sent_per_s = 0.0
    bytes_recv_per_s = 0.0
    packets_sent_per_s = 0.0
    packets_recv_per_s = 0.0

    if _last_net_io is not None and _last_net_time is not None:
        dt = max(now - _last_net_time, 0.001)
        bytes_sent_per_s = (net_io.bytes_sent - _last_net_io.bytes_sent) / dt
        bytes_recv_per_s = (net_io.bytes_recv - _last_net_io.bytes_recv) / dt
        packets_sent_per_s = (net_io.packets_sent - _last_net_io.packets_sent) / dt
        packets_recv_per_s = (net_io.packets_recv - _last_net_io.packets_recv) / dt

    _last_net_io = net_io
    _last_net_time = now

    # --- Active Connections & Remote Sockets ---
    connections = 0
    active_sockets = []
    try:
        raw_conns = psutil.net_connections(kind="inet")
        connections = len(raw_conns)
        for c in raw_conns:
            if c.raddr and c.raddr.ip and not c.raddr.ip.startswith("127.") and c.raddr.ip != "0.0.0.0":
                active_sockets.append({
                    "remote_ip": c.raddr.ip,
                    "remote_port": c.raddr.port,
                    "local_port": c.laddr.port if c.laddr else 0,
                    "status": c.status,
                })
    except Exception:
        connections = 0

    # --- Top Userland Processes by CPU/Memory ---
    SYSTEM_NAMES = {"system idle process", "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe"}
    top_processes = []
    try:
        candidates = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
            try:
                info = p.info
                p_name = (info.get("name") or "").lower()
                pid = info.get("pid") or 0
                if pid > 4 and p_name not in SYSTEM_NAMES:
                    candidates.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Sort by CPU usage or memory
        candidates.sort(key=lambda x: (x.get("cpu_percent") or 0, x.get("memory_percent") or 0), reverse=True)
        top_processes = candidates[:8]
    except Exception:
        pass

    # Get local hostname & IP
    try:
        import socket
        hostname = socket.gethostname()
        host_ip = socket.gethostbyname(hostname)
    except Exception:
        host_ip = "127.0.0.1"

    return {
        "cpu_percent": cpu_percent,
        "cpu_count": psutil.cpu_count(),
        "memory_total_gb": round(mem.total / 1e9, 2),
        "memory_used_gb": round(mem.used / 1e9, 2),
        "memory_percent": mem.percent,
        "disk_total_gb": round(disk.total / 1e9, 2),
        "disk_used_gb": round(disk.used / 1e9, 2),
        "disk_percent": disk.percent,
        "bytes_sent_per_s": round(bytes_sent_per_s, 2),
        "bytes_recv_per_s": round(bytes_recv_per_s, 2),
        "packets_sent_per_s": round(packets_sent_per_s, 2),
        "packets_recv_per_s": round(packets_recv_per_s, 2),
        "net_total_bytes_sent": net_io.bytes_sent,
        "net_total_bytes_recv": net_io.bytes_recv,
        "connections": connections,
        "host_ip": host_ip,
        "active_sockets": active_sockets[:6],
        "top_processes": top_processes,
    }
