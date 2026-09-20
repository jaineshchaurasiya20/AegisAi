"""
AegisAI Threats Routes — Retrieve threat logs, trigger manual scans.
"""
import asyncio
import uuid
import random
import time
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from app.core.security import get_current_user
from app.ml.inference import run_inference
from app.ml.xai_explainer import xai_manager
from app.deception.honeypot_emulator import honeypot_emulator
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/threats", tags=["threats"])

# In-memory threat log store (replace with SQLite in production)
_threat_log: List[dict] = []


class FeatureAttribution(BaseModel):
    feature: str
    feature_name: Optional[str] = None
    value: float
    value_formatted: Optional[str] = None
    impact: float
    impact_pct: Optional[int] = 0
    direction: Optional[str] = "INCREASED_RISK"
    description: str
    reason: Optional[str] = None


class ThreatExplanationResponse(BaseModel):
    threat_id: str
    threat_score: float
    predicted_class: Optional[str] = "Suspicious Activity"
    predicted_severity: Optional[str] = "HIGH"
    confidence_score: Optional[float] = 0.0
    confidence_disclaimer: Optional[str] = None
    execution_time_ms: float
    cached: bool
    explainer_method: Optional[str] = "SHAP (TreeExplainer)"
    model_name: Optional[str] = "XGBoost + IsolationForest (Hybrid ONNX Runtime)"
    top_features: Optional[List[FeatureAttribution]] = []
    feature_attributions: List[FeatureAttribution]
    plain_english_explanation: Optional[str] = None
    technical_explanation: Optional[str] = None


import psutil


_proc_candidates = []
_last_proc_scan = 0


def _get_process_candidates():
    global _proc_candidates, _last_proc_scan
    now = time.time()
    if _proc_candidates and (now - _last_proc_scan) < 60:
        return _proc_candidates

    system_names = {"system idle process", "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe"}
    candidates = []
    try:
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
            try:
                info = p.info
                p_name = (info.get("name") or "").lower()
                pid = info.get("pid") or 0
                if pid > 4 and p_name not in system_names:
                    candidates.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                continue
    except Exception:
        pass
    if not candidates:
        candidates = [{"pid": 4820, "name": "powershell.exe"}, {"pid": 6124, "name": "cmd.exe"}, {"pid": 9812, "name": "curl.exe"}]
    _proc_candidates = candidates
    _last_proc_scan = now
    return _proc_candidates


def _generate_demo_threat() -> dict:
    """Generate a realistic threat entry backed by real system process telemetry."""
    severities = ["critical", "high", "medium", "low"]
    weights = [0.15, 0.25, 0.30, 0.30]
    severity = random.choices(severities, weights)[0]
    score_map = {"critical": (0.88, 1.0), "high": (0.70, 0.88), "medium": (0.45, 0.70), "low": (0.1, 0.45)}
    lo, hi = score_map[severity]
    score = round(random.uniform(lo, hi), 4)

    threat_types = [
        "Zero-Day Anomaly Probe", "Zero-Day Memory Injection", "High-Frequency Port Scan",
        "SSH Brute Force Signature", "C2 Beaconing Pattern", "DNS Exfiltration Tunnel",
        "Lateral Movement Attempt", "Anomalous Child Process", "Outbound Byte Spike"
    ]
    threat_type = random.choice(threat_types)

    candidates = _get_process_candidates()
    chosen = random.choice(candidates)
    target_pid = chosen.get("pid") or random.randint(2000, 28000)
    target_proc_name = chosen.get("name") or "powershell.exe"

    source_ip = f"{random.randint(45,198)}.{random.randint(10,250)}.{random.randint(1,254)}.{random.randint(2,250)}"

    threat_id = str(uuid.uuid4())
    port = random.choice([2121, 2222, 80, 443, 3306, 4444, 8080, 53, 6667, 49152])

    telemetry = {
        "pid": target_pid,
        "processName": target_proc_name,
        "parentProcess": "explorer.exe",
        "parentPid": 1024,
        "cpuUsagePct": round(random.uniform(2.5, 48.0), 1),
        "memoryUsageMb": round(random.uniform(45.0, 320.0), 1),
        "commandLine": f"{target_proc_name} --remote-target={source_ip}:{port}",
        "openSockets": [
            {"protocol": "TCP", "localPort": random.randint(49000, 65000), "remoteIp": source_ip, "remotePort": port, "state": "ESTABLISHED"},
            {"protocol": "TCP", "localPort": 443, "remoteIp": "8.8.8.8", "remotePort": 443, "state": "ESTABLISHED"},
        ],
    }

    # Decide default action vs Deception Honeypot trap routing
    is_zero_day = "zero-day" in threat_type.lower() or "anomalous" in threat_type.lower()
    is_trapped = is_zero_day or (score >= 0.70 and random.random() < 0.35)

    honeypot_capture = None
    if is_trapped:
        action_taken = "trapped_in_honeypot"
        deception_status = "TRAPPED"
        try:
            honeypot_capture = honeypot_emulator.redirect_threat({
                "source_ip": source_ip,
                "port": port,
                "threat_type": threat_type,
                "telemetry": telemetry,
            })
        except Exception as e:
            logger.warning(f"Honeypot routing failed: {e}")
    else:
        action_taken = "logged" if score < 0.88 else "process_isolated"
        deception_status = "NORMAL"

    entry = {
        "id": threat_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "threat_type": threat_type,
        "source_ip": source_ip,
        "destination_ip": "127.0.0.1",
        "port": port,
        "threat_score": score,
        "action_taken": action_taken,
        "deception_status": deception_status,
        "honeypot_capture": honeypot_capture,
        "telemetry": telemetry,
    }

    # Asynchronously pre-warm cache for high-confidence threats (score >= 0.85)
    if score >= 0.85:
        xai_manager.precompute_high_risk(entry)

    return entry


# Initialize default threat log entries immediately
try:
    _threat_log = [_generate_demo_threat() for _ in range(25)]
except Exception as _e:
    _threat_log = []


@router.get("/", response_model=List[dict])
async def get_threats(
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """Retrieve threat log entries with optional severity filter."""
    global _threat_log
    # Seed with demo data on first call
    if not _threat_log:
        _threat_log = [_generate_demo_threat() for _ in range(25)]

    results = _threat_log
    if severity:
        results = [t for t in results if t["severity"] == severity]
    return results[-limit:][::-1]


@router.get("/{threat_id}/explain", response_model=ThreatExplanationResponse)
async def explain_threat(
    threat_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    On-Demand XAI Endpoint — Generates or fetches cached SHAP feature attributions for a threat.
    Returns 404 if the threat ID does not exist in the log store.
    """
    global _threat_log
    # Find threat by ID
    threat = next((t for t in _threat_log if t.get("id") == threat_id), None)
    if not threat:
        raise HTTPException(status_code=404, detail=f"Threat '{threat_id}' not found")

    return xai_manager.explain_threat(threat)


from typing import Dict, Any
from app.api.websockets import manager


class ThreatScanRequest(BaseModel):
    threat_type: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = "127.0.0.1"
    port: Optional[int] = None
    threat_score: Optional[float] = None
    raw_payload: Optional[str] = None
    features: Optional[Dict[str, float]] = None
    telemetry: Optional[Dict[str, Any]] = None
    auto_remediate: Optional[bool] = False


@router.post("/scan")
async def trigger_scan(
    payload: Optional[ThreatScanRequest] = None,
    current_user: dict = Depends(get_current_user),
):
    """
    Trigger an ML inference scan on current telemetry or stream a live attack replay record.
    Evaluates ONNX model inference, triggers honeypot traps for zero-days, and broadcasts to live SOC dashboards.
    """
    global _threat_log
    inference_result = await run_inference(payload.telemetry if payload and payload.telemetry else None)

    # Base demo threat or custom replay record
    entry = _generate_demo_threat()

    if payload:
        if payload.threat_type:
            entry["threat_type"] = payload.threat_type
        if payload.source_ip:
            entry["source_ip"] = payload.source_ip
        if payload.destination_ip:
            entry["destination_ip"] = payload.destination_ip
        if payload.port:
            entry["port"] = payload.port
        if payload.telemetry:
            entry["telemetry"] = payload.telemetry

        # Calculate threat score via ONNX or provided override
        if payload.threat_score is not None:
            entry["threat_score"] = float(payload.threat_score)
        else:
            entry["threat_score"] = float(inference_result.get("threat_score", entry["threat_score"]))
    else:
        entry["threat_score"] = float(inference_result.get("threat_score", entry["threat_score"]))

    score = entry["threat_score"]
    entry["severity"] = (
        "critical" if score > 0.88
        else "high" if score > 0.70
        else "medium" if score > 0.45
        else "low"
    )

    # Check zero-day deception honeypot routing
    is_zero_day = "zero-day" in entry["threat_type"].lower() or "anomalous" in entry["threat_type"].lower()
    is_trapped = is_zero_day or (score >= 0.70 and ("scan" in entry["threat_type"].lower() or "probe" in entry["threat_type"].lower()))

    if is_trapped:
        entry["action_taken"] = "trapped_in_honeypot"
        entry["deception_status"] = "TRAPPED"
        try:
            entry["honeypot_capture"] = honeypot_emulator.redirect_threat({
                "source_ip": entry["source_ip"],
                "port": entry["port"],
                "threat_type": entry["threat_type"],
                "raw_payload": payload.raw_payload if payload and payload.raw_payload else "REPLAYED_ATTACK_VECTOR",
                "telemetry": entry["telemetry"],
            })
        except Exception as e:
            logger.warning(f"Honeypot routing failed during scan: {e}")
    else:
        entry["action_taken"] = "logged" if score < 0.88 else "process_isolated"
        entry["deception_status"] = "NORMAL"

    entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    _threat_log.append(entry)

    # Trigger OS desktop notification for critical and high severity threats
    if entry.get("severity") in ("critical", "high") or score >= 0.70:
        try:
            from app.core.notifications import notify_threat_alert
            notify_threat_alert(
                threat_type=entry.get("threat_type", "Cyber Threat"),
                severity=entry.get("severity", "high"),
                source_ip=entry.get("source_ip", "Unknown"),
                port=entry.get("port"),
                action_taken=entry.get("action_taken", "logged"),
            )
        except Exception as _notify_err:
            logger.debug(f"Desktop notification error: {_notify_err}")

    # Pre-compute XAI attributions for high-risk threats
    if score >= 0.85:
        try:
            xai_manager.precompute_high_risk(entry)
        except Exception:
            pass

    # Real-time WebSocket broadcast to all connected SOC clients
    try:
        await manager.broadcast({
            "type": "THREAT_DETECTED",
            "payload": entry,
            "threat": entry,
            "timestamp": entry["timestamp"],
        })
    except Exception as e:
        logger.warning(f"WebSocket broadcast error: {e}")

    # Check Autonomous Containment Policy
    try:
        from app.api.routes.actions import _policy, _audit_log, _isolate_host, _kill_process
        if _policy.get("containmentMode") == "AUTONOMOUS" and score >= _policy.get("autoContainThreshold", 0.85):
            auto_action = "ISOLATE_HOST" if _policy.get("enableAutoHostIsolation") else ("KILL_PROCESS" if _policy.get("enableAutoProcessKill") else None)
            if auto_action == "ISOLATE_HOST":
                act_res = _isolate_host(entry["source_ip"])
            elif auto_action == "KILL_PROCESS" and entry.get("telemetry", {}).get("pid"):
                act_res = _kill_process(entry["telemetry"]["pid"])
            else:
                act_res = {"success": True, "detail": "Autonomous containment policy applied."}

            audit_entry = {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "threatId": entry["id"],
                "actionType": auto_action or "ISOLATE_HOST",
                "mode": "AUTONOMOUS",
                "pid": entry.get("telemetry", {}).get("pid"),
                "processName": entry.get("telemetry", {}).get("processName"),
                "targetIp": entry["source_ip"],
                "executedBy": "AegisAI-Autonomous-Engine",
                "success": act_res.get("success", True),
                "detail": act_res.get("detail", "Self-healing auto-containment executed."),
            }
            _audit_log.append(audit_entry)
            entry["auto_containment"] = audit_entry
    except Exception as e:
        logger.warning(f"Autonomous containment dispatch failed: {e}")

    # Dispatch through 4-Agent Architecture Pipeline
    try:
        from app.agents.orchestrator import orchestrator
        await orchestrator.ingest_attack(entry)
    except Exception as _agent_err:
        logger.warning(f"4-Agent pipeline dispatch note: {_agent_err}")

    return {
        "message": "Scan and threat ingestion complete",
        "result": entry,
        "onnx_inference": inference_result,
    }


@router.get("/stats")
async def threat_stats(current_user: dict = Depends(get_current_user)):
    """Aggregate threat statistics for dashboard counters."""
    global _threat_log
    if not _threat_log:
        _threat_log = [_generate_demo_threat() for _ in range(25)]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for t in _threat_log:
        counts[t["severity"]] += 1
    return {
        "total": len(_threat_log),
        "by_severity": counts,
        "avg_score": round(sum(t["threat_score"] for t in _threat_log) / len(_threat_log), 4),
    }


class ReplayRequest(BaseModel):
    count: int = Field(default=4, ge=1, le=20)
    delay: float = Field(default=1.0, ge=0.2, le=5.0)


REPLAY_SCENARIOS = [
    {
        "threat_type": "SQL Injection & Schema Exfiltration",
        "port": 3000,
        "threat_score": 0.89,
        "raw_payload": "SELECT * FROM users WHERE user_id='' UNION SELECT 1,username,password_hash FROM admin--",
    },
    {
        "threat_type": "DDoS LOIC HTTP Flood (Volumetric)",
        "port": 443,
        "threat_score": 0.97,
        "raw_payload": "GET /api/v1/resource HTTP/1.1\r\nHost: victim.internal\r\nUser-Agent: LOIC/2.0.0.4",
    },
    {
        "threat_type": "SSH Credential Brute-Force Spray",
        "port": 2222,
        "threat_score": 0.76,
        "raw_payload": "SSH-2.0-OpenSSH_8.2p1 auth request password attempt user='root'",
    },
    {
        "threat_type": "Zero-Day Memory Injection (Reflective DLL)",
        "port": 4444,
        "threat_score": 0.96,
        "raw_payload": "\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3",
    },
    {
        "threat_type": "High-Frequency SYN Stealth Port Scan",
        "port": 8080,
        "threat_score": 0.84,
        "raw_payload": "TCP SYN probe sequence seq=39281729 win=1024",
    },
    {
        "threat_type": "Cobalt Strike C2 Beaconing Loop",
        "port": 443,
        "threat_score": 0.92,
        "raw_payload": "POST /submit.php?id=a9f4c8 HTTP/1.1\r\nCookie: SESSIONID=Y29iYWx0c3RyaWtl",
    },
]


async def _stream_replay_attacks(count: int, delay: float):
    """Background task streaming attack scenarios into the 4-agent pipeline."""
    for i in range(count):
        scenario = REPLAY_SCENARIOS[i % len(REPLAY_SCENARIOS)]
        req = ThreatScanRequest(
            threat_type=scenario["threat_type"],
            port=scenario["port"],
            threat_score=scenario["threat_score"],
            raw_payload=scenario["raw_payload"],
        )
        try:
            await trigger_scan(payload=req, current_user={"username": "system-replay", "role": "admin"})
        except Exception as e:
            logger.warning(f"[Replay Streamer] Error ingesting replay scenario {i+1}: {e}")

        if i < count - 1:
            await asyncio.sleep(delay)


@router.post("/replay")
async def trigger_replay(
    payload: Optional[ReplayRequest] = None,
    current_user: dict = Depends(get_current_user),
):
    """
    Trigger live attack replay stream for interactive demo / judging.
    Asynchronously streams attack events through ONNX inference, detection, and 4-Agent pipeline.
    """
    count = payload.count if payload else 4
    delay = payload.delay if payload else 1.0

    asyncio.create_task(_stream_replay_attacks(count, delay))

    return {
        "status": "streaming",
        "message": f"Live attack replay stream initiated ({count} scenarios, interval={delay}s)",
        "count": count,
        "delay": delay,
    }
