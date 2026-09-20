"""
AegisAI Telemetry Routes — Host metrics and network telemetry endpoints.
"""
from fastapi import APIRouter, Depends
from app.core.security import get_current_user
from app.collector.host_monitor import get_host_snapshot

router = APIRouter(prefix="/api/telemetry", tags=["telemetry"])


@router.get("/host")
async def host_metrics(current_user: dict = Depends(get_current_user)):
    """Return a real-time snapshot of host system metrics."""
    return await get_host_snapshot()


@router.get("/status")
async def system_status():
    """Health-check endpoint — no auth required."""
    return {"status": "operational", "engine": "AegisAI v1.0"}
