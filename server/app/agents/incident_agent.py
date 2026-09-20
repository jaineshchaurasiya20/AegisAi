import os
import json
import subprocess
import ipaddress
import re
from datetime import datetime
from typing import AsyncGenerator, Dict, Any, List, Optional, Tuple
from loguru import logger

from .state import IncidentState, IncidentStatus

# Environment flag – default to dry‑run mode
ENABLE_REAL_CONTAINMENT = os.getenv("ENABLE_REAL_CONTAINMENT", "False").lower() == "true"


def _first_present(*values: Any) -> Any:
    """Return the first non-empty value from a set of threat metadata fields."""
    return next((value for value in values if value not in (None, "")), None)


def _resolve_threat_target(state: IncidentState) -> Tuple[Optional[str], Optional[int]]:
    """Resolve source IP and destination port from state, metadata, then sockets."""
    metadata = state.metadata or {}
    target = metadata.get("target") if isinstance(metadata.get("target"), dict) else {}
    telemetry = metadata.get("telemetry") if isinstance(metadata.get("telemetry"), dict) else {}

    source_ip = _first_present(
        state.source_ip,
        metadata.get("source_ip"),
        metadata.get("target_ip"),
        target.get("source_ip"),
        target.get("ip"),
        telemetry.get("source_ip"),
        telemetry.get("remoteIp"),
    )
    destination_port = _first_present(
        state.destination_port,
        metadata.get("destination_port"),
        metadata.get("target_port"),
        metadata.get("port"),
        target.get("destination_port"),
        target.get("port"),
        telemetry.get("destination_port"),
        telemetry.get("remotePort"),
    )

    matching_socket = next(
        (socket for socket in state.open_sockets if source_ip and socket.get("remoteIp") == source_ip),
        None,
    )
    fallback_socket = matching_socket or (state.open_sockets[0] if state.open_sockets else None)
    if fallback_socket:
        source_ip = _first_present(source_ip, fallback_socket.get("remoteIp"))
        destination_port = _first_present(
            destination_port,
            fallback_socket.get("remotePort"),
            fallback_socket.get("localPort"),
        )

    try:
        source_ip = str(ipaddress.ip_address(source_ip)) if source_ip else None
    except ValueError:
        logger.warning(f"Ignoring invalid source IP for threat {state.threat_id}: {source_ip!r}")
        source_ip = None

    try:
        destination_port = int(destination_port) if destination_port is not None else None
        if not 1 <= destination_port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        logger.warning(
            f"Ignoring invalid destination port for threat {state.threat_id}: {destination_port!r}"
        )
        destination_port = None

    return source_ip, destination_port


def _safe_threat_filename(threat_id: str) -> str:
    """Keep generated filenames platform-safe without losing threat identity."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", threat_id).strip("_") or "unknown-threat"

async def _state_analyzer_node(state: IncidentState) -> IncidentState:
    """Inspect host snapshot and populate process_tree / open_sockets.
    Uses the existing host_monitor collector.
    """
    try:
        from app.collector.host_monitor import get_host_snapshot
        snapshot = await get_host_snapshot()
        # host_monitor returns 'top_processes' and 'active_sockets'
        raw_procs   = snapshot.get("top_processes", [])
        raw_sockets = snapshot.get("active_sockets", [])

        # Normalize socket keys to localPort for the planner heuristic
        normalized_sockets = []
        for s in raw_sockets:
            normalized_sockets.append({
                "localPort":  s.get("local_port", 0),
                "remoteIp":   s.get("remote_ip", ""),
                "remotePort": s.get("remote_port", 0),
                "status":     s.get("status", ""),
            })

        state.process_tree = raw_procs
        state.open_sockets = normalized_sockets
        state.metadata = {
            **state.metadata,
            "host_snapshot_time": snapshot.get("timestamp", ""),
            "cpu_percent":        snapshot.get("cpu_percent"),
            "memory_percent":     snapshot.get("memory_percent"),
        }
        state.add_log(
            step="StateAnalyzer",
            message="Collected host snapshot — {} processes, {} sockets".format(
                len(state.process_tree), len(state.open_sockets)
            ),
        )
    except Exception as e:
        logger.error(f"StateAnalyzerNode failed: {e}")
        # Provide a safe fallback so the pipeline can still continue
        state.process_tree = []
        state.open_sockets = []
        state.add_log(step="StateAnalyzer", message=f"Snapshot error (fallback): {e}", status="WARN")
    return state

async def _containment_planner_node(state: IncidentState) -> IncidentState:
    """Create a dynamic mitigation plan based on collected telemetry."""
    plan: List[Dict[str, Any]] = []

    source_ip, destination_port = _resolve_threat_target(state)
    if destination_port is not None:
        plan.append({
            "action": "block_port",
            "port": destination_port,
            "source_ip": source_ip,
            "reason": f"Threat-scoped block for {source_ip or 'unknown source'}:{destination_port}",
        })
    else:
        state.add_log(
            step="ContainmentPlanner",
            message="No valid destination port available; skipped firewall patch generation.",
            status="WARN",
        )

    # Heuristic 2: terminate suspicious processes (ssh/ftp related)
    for proc in state.process_tree:
        name = proc.get("name", "").lower()
        if "ssh" in name or "ftp" in name:
            plan.append({"action": "terminate_pid", "pid": proc.get("pid"), "reason": f"Suspicious process: {name}"})

    # Always capture memory for forensics
    plan.append({"action": "snapshot_memory", "reason": "Capture memory state for forensic analysis"})

    state.mitigation_plan = plan
    state.add_log(step="ContainmentPlanner", message=f"Generated {len(plan)} mitigation steps.")
    return state

async def _execution_node(state: IncidentState) -> IncidentState:
    """Execute or dry‑run each mitigation step.
    Commands are logged; real execution occurs only when ENABLE_REAL_CONTAINMENT=True.
    """
    for idx, step in enumerate(state.mitigation_plan, start=1):
        action = step.get("action")
        msg_prefix = f"Step {idx}/{len(state.mitigation_plan)}"
        try:
            if action == "block_port":
                port = step["port"]
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name=BlockPort{port}", "dir=in", "action=block", f"protocol=TCP", f"localport={port}"]
                description = f"Blocking port {port}"
            elif action == "terminate_pid":
                pid = step["pid"]
                cmd = ["taskkill", "/F", "/PID", str(pid)]
                description = f"Terminating PID {pid}"
            elif action == "snapshot_memory":
                # Dummy placeholder – in real world you'd invoke a memory dumper
                cmd = []
                description = "Snapshotting process memory (dry‑run placeholder)"
            else:
                cmd = []
                description = f"Unknown action {action}"

            if not ENABLE_REAL_CONTAINMENT or not cmd:
                logger.info(f"[DRY‑RUN] {description}")
                state.add_log(step="Execution", message=f"[DRY‑RUN] {description}")
            else:
                logger.info(f"Executing: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    state.add_log(step="Execution", message=f"Executed: {description}")
                else:
                    raise RuntimeError(f"Command failed: {result.stderr}")
        except Exception as e:
            logger.error(f"ExecutionNode error on step {idx}: {e}")
            state.add_log(step="Execution", message=f"Error on step {idx}: {e}", status="ERROR")
            state.status = IncidentStatus.FAILED
            break
    return state

async def _patch_generator_node(state: IncidentState, mode: str) -> IncidentState:
    """Generate firewall / registry patch files for audit.
    Files are stored under the 'patches' directory next to this module.
    """
    patches_dir = os.path.join(os.path.dirname(__file__), "patches")
    os.makedirs(patches_dir, exist_ok=True)
    generated_paths: List[str] = []
    resolved_source_ip, _ = _resolve_threat_target(state)
    created_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    safe_threat_id = _safe_threat_filename(state.threat_id)
    for step in state.mitigation_plan:
        if step.get("action") == "block_port":
            port = step["port"]
            source_ip = step.get("source_ip") or resolved_source_ip
            filename = f"firewall_block_{safe_threat_id}_{timestamp}.rules"
            filepath = os.path.join(patches_dir, filename)
            content = f"# Auto‑generated firewall rule to block port {port}\nnetsh advfirewall firewall add rule name=BlockPort{port} dir=in action=block protocol=TCP localport={port}\n"
            remote_ip_clause = f" remoteip={source_ip}" if source_ip else ""
            content = (
                "# AegisAI Dynamic Remediation Patch\n"
                f"# Threat ID: {state.threat_id} | Created: {created_at}\n"
                f"# Target IP: {source_ip or 'unspecified'} | Destination Port: {port}\n"
                f"# Mode: {mode} (ENABLE_REAL_CONTAINMENT={ENABLE_REAL_CONTAINMENT})\n"
                f'netsh advfirewall firewall add rule name="AegisAI_Block_{safe_threat_id}" '
                f"dir=in action=block protocol=TCP localport={port}{remote_ip_clause}\n"
            )
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            generated_paths.append(filepath)
            state.add_log(step="PatchGenerator", message=f"Created firewall patch {filename}")
        elif step.get("action") == "terminate_pid":
            pid = step["pid"]
            filename = f"terminate_pid_{pid}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
            filepath = os.path.join(patches_dir, filename)
            content = {"action": "terminate_pid", "pid": pid, "reason": step.get("reason")}
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(content, f, indent=2)
            generated_paths.append(filepath)
            state.add_log(step="PatchGenerator", message=f"Created termination patch {filename}")
    if generated_paths:
        # Store the first generated path for easy access (could be extended later)
        state.generated_patch_path = generated_paths[0]
    else:
        state.add_log(step="PatchGenerator", message="No patches generated.")
    return state

async def run_agent(state: IncidentState, mode: str = "AUTONOMOUS") -> AsyncGenerator[Dict[str, Any], None]:
    """Async state‑graph runner.
    Yields a dict after each node for SSE streaming.
    """
    state.status = IncidentStatus.RUNNING
    # 1 – State Analyzer
    state = await _state_analyzer_node(state)
    yield {"step": "StateAnalyzer", "message": "Host snapshot collected", "status": "INFO", "state": state.model_dump(mode="json")}
    if state.status == IncidentStatus.FAILED:
        return

    # 2 – Containment Planner
    state = await _containment_planner_node(state)
    yield {"step": "ContainmentPlanner", "message": f"Generated {len(state.mitigation_plan)} steps", "status": "INFO", "state": state.model_dump(mode="json")}
    if state.status == IncidentStatus.FAILED:
        return

    # 3 – Execution (dry-run unless real flag enabled)
    state = await _execution_node(state)
    exec_status = "COMPLETED" if state.status != IncidentStatus.FAILED else "FAILED"
    yield {"step": "Execution", "message": f"Execution {exec_status.lower()}", "status": exec_status, "state": state.model_dump(mode="json")}
    if state.status == IncidentStatus.FAILED:
        return

    # 4 – Patch Generator
    state = await _patch_generator_node(state, mode)
    state.status = IncidentStatus.COMPLETED
    yield {"step": "PatchGenerator", "message": "Patch generation complete", "status": "COMPLETED", "state": state.model_dump(mode="json")}

    # Final summary
    yield {"step": "Summary", "message": "Remediation workflow finished", "status": "COMPLETED", "state": state.model_dump(mode="json")}
