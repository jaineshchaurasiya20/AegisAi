"""
AegisAI Automated Containment Engine — process termination & network isolation.

SAFETY GUARDRAILS (rules.md §3):
- Automated kills are DISABLED by default (config.yaml: auto_kill_enabled: false)
- Admin must explicitly enable containment in config.yaml
- All containment actions are logged with full audit trail
- Network isolation scripts warn about required Administrator/sudo privileges
"""
import os
import signal
import platform
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List
from loguru import logger
from app.core.config import get_settings

settings = get_settings()

_containment_audit_log: List[Dict[str, Any]] = []


def _log_action(action: str, target: Any, reason: str, success: bool):
    """Append to in-memory audit log (persist to DB in production)."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "target": str(target),
        "reason": reason,
        "success": success,
        "operator": "aegisai-auto",
    }
    _containment_audit_log.append(entry)
    level = "SUCCESS" if success else "ERROR"
    logger.log(level, f"CONTAINMENT [{action}] target={target} reason={reason}")


def kill_process(pid: int, threat_score: float, reason: str = "ml_detection") -> Dict[str, Any]:
    """
    Terminate a process by PID.
    Requires auto_kill_enabled=true in config.yaml to execute.
    """
    if not settings.AUTO_KILL_ENABLED:
        msg = (
            f"BLOCKED: Attempted to kill PID {pid} (score={threat_score:.3f}). "
            "Auto-kill is disabled. Set containment.auto_kill_enabled=true in config.yaml to enable."
        )
        logger.warning(msg)
        _log_action("KILL_BLOCKED", pid, reason, success=False)
        return {"action": "blocked", "pid": pid, "reason": "auto_kill_disabled"}

    if threat_score < settings.CRITICAL_ACTION_THRESHOLD:
        logger.info(f"PID {pid} score {threat_score:.3f} below kill threshold {settings.CRITICAL_ACTION_THRESHOLD}. Skipping.")
        return {"action": "skipped", "pid": pid, "reason": "below_threshold"}

    try:
        if platform.system() == "Windows":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], check=True, capture_output=True)
        else:
            os.kill(pid, signal.SIGKILL)
        _log_action("KILL_PROCESS", pid, reason, success=True)
        return {"action": "killed", "pid": pid, "threat_score": threat_score}
    except ProcessLookupError:
        _log_action("KILL_PROCESS", pid, "process_not_found", success=False)
        return {"action": "failed", "pid": pid, "reason": "process_not_found"}
    except PermissionError:
        logger.error(f"Permission denied killing PID {pid}. Run with Administrator/root privileges.")
        _log_action("KILL_PROCESS", pid, "permission_denied", success=False)
        return {"action": "failed", "pid": pid, "reason": "permission_denied"}


def isolate_network_interface(interface: str = "eth0") -> Dict[str, Any]:
    """
    Isolate a network interface by disabling it.
    IMPORTANT: Requires Administrator/sudo privileges.
    Requires auto_isolate_network=true in config.yaml.
    """
    if not settings.AUTO_ISOLATE_NETWORK:
        logger.warning(
            f"BLOCKED: Network isolation requested for {interface}. "
            "Set containment.auto_isolate_network=true in config.yaml to enable. "
            "NOTE: This action requires Administrator/sudo privileges."
        )
        _log_action("ISOLATE_BLOCKED", interface, "auto_isolate_disabled", success=False)
        return {"action": "blocked", "interface": interface, "reason": "auto_isolate_disabled"}

    try:
        if platform.system() == "Windows":
            cmd = ["netsh", "interface", "set", "interface", interface, "admin=disable"]
        else:
            cmd = ["ip", "link", "set", interface, "down"]
        subprocess.run(cmd, check=True, capture_output=True)
        _log_action("ISOLATE_NETWORK", interface, "threat_detected", success=True)
        return {"action": "isolated", "interface": interface}
    except subprocess.CalledProcessError as e:
        logger.error(f"Network isolation failed: {e}")
        _log_action("ISOLATE_NETWORK", interface, "command_failed", success=False)
        return {"action": "failed", "interface": interface, "reason": str(e)}


def get_audit_log() -> List[Dict[str, Any]]:
    """Return the in-memory containment audit log."""
    return list(reversed(_containment_audit_log))
