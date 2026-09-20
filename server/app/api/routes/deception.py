"""
AegisAI Deception & Honeypot API Routes.
Provides endpoints to query trapped attacker telemetry, inspect active decoy configurations,
and simulate zero-day honeypot redirections.
"""
import random
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from app.core.security import get_current_user
from app.deception.trap_logger import trap_logger
from app.deception.honeypot_emulator import honeypot_emulator, DECOY_CONFIG

router = APIRouter(prefix="/api/deception", tags=["deception"])


class HoneypotTrapCapture(BaseModel):
    captureId: str
    timestamp: str
    sourceIp: str
    sourcePort: int
    trapType: str  # 'FAKE_FTP' | 'FAKE_REGISTRY' | 'FAKE_SSH' | 'DECOY_FILE'
    decoyTarget: str
    rawPayload: str
    commandExecuted: Optional[str] = "N/A"
    payloadHash: Optional[str] = None
    isolationStatus: str = "TRAPPED"


class SimulateTrapRequest(BaseModel):
    trapType: Optional[str] = Field(None, description="Optional trap type: FAKE_FTP, FAKE_SSH, FAKE_REGISTRY, DECOY_FILE")
    sourceIp: Optional[str] = Field(None, description="Attacker source IP to simulate")
    rawPayload: Optional[str] = Field(None, description="Custom payload string to trap")


@router.get("/traps", response_model=List[HoneypotTrapCapture])
async def get_trap_captures(
    limit: int = Query(50, ge=1, le=500),
    trap_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieve segregated honeypot payload and telemetry captures.
    """
    captures = trap_logger.get_recent_captures(limit=limit)
    if trap_type:
        captures = [c for c in captures if c.get("trapType") == trap_type]
    return captures


@router.get("/stats")
async def get_deception_stats(current_user: dict = Depends(get_current_user)):
    """
    Get honeypot deception stats, active decoy assets, and capture storage path.
    """
    return trap_logger.get_stats()

@router.get("/config", response_model=Dict[str, Any])
async def get_deception_config(current_user: dict = Depends(get_current_user)):
    """Return the decoy configuration dictionary for front‑end visibility."""
    return DECOY_CONFIG


@router.post("/simulate", response_model=HoneypotTrapCapture)
async def simulate_honeypot_trap(
    payload: SimulateTrapRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Simulate a zero-day probe trigger that redirects attacker traffic into a synthetic trap.
    """
    trap_type = payload.trapType or random.choice(["FAKE_FTP", "FAKE_SSH", "FAKE_REGISTRY", "DECOY_FILE"])
    source_ip = payload.sourceIp or f"{random.randint(45, 198)}.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(2, 250)}"
    default_ports = {
        "FAKE_FTP": 2121,
        "FAKE_SSH": 2222,
        "FAKE_REGISTRY": 3389,
        "DECOY_FILE": 445,
    }
    source_port = default_ports.get(trap_type, random.choice([2121, 2222, 4444, 8080]))

    event = {
        "trap_type": trap_type,
        "source_ip": source_ip,
        "port": source_port,
        "threat_type": f"Zero-Day Probe ({trap_type})",
        "raw_payload": payload.rawPayload,
    }

    # Execute redirection into honeypot
    capture = honeypot_emulator.redirect_threat(event)
    return capture
