import json
from datetime import datetime
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Any, AsyncGenerator, Dict, Optional

from app.agents.incident_agent import run_agent
from app.agents.state import IncidentState, IncidentStatus

router = APIRouter(prefix="/api/agent", tags=["Agent"])


def _json_default(obj):
    """Custom JSON serializer for types not handled by default."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


class RemediateRequest(BaseModel):
    threat_id: str
    mode: str = "AUTONOMOUS"  # or "MANUAL"
    source_ip: Optional[str] = None
    destination_port: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


@router.post("/remediate")
async def remediate(request: RemediateRequest):
    """
    Stream agentic incident response steps as Server-Sent Events (text/event-stream).
    Each SSE event carries a JSON payload with step, status, message, and a compact
    state summary (avoiding large or non-serializable objects).
    """
    if request.mode not in {"AUTONOMOUS", "MANUAL"}:
        raise HTTPException(status_code=400, detail="Invalid mode — must be AUTONOMOUS or MANUAL")

    state = IncidentState(
        threat_id=request.threat_id,
        source_ip=request.source_ip,
        destination_port=request.destination_port,
        metadata=request.metadata,
        status=IncidentStatus.PENDING,
    )

    async def event_stream() -> AsyncGenerator[str, None]:
        async for payload in run_agent(state, mode=request.mode):
            # Strip full 'state' dict to avoid datetime serialization issues;
            # keep only the lightweight summary fields.
            safe_payload = {
                "step":               payload.get("step"),
                "message":            payload.get("message"),
                "status":             payload.get("status"),
                "threat_id":          request.threat_id,
                "mitigation_plan":    payload.get("state", {}).get("mitigation_plan", []),
                "generated_patch":    payload.get("state", {}).get("generated_patch_path"),
                "step_logs": [
                    {
                        "step":      log.get("step"),
                        "message":   log.get("message"),
                        "status":    log.get("status"),
                        "timestamp": log.get("timestamp").isoformat()
                        if isinstance(log.get("timestamp"), datetime)
                        else str(log.get("timestamp", "")),
                    }
                    for log in payload.get("state", {}).get("step_logs", [])
                ],
            }
            yield f"data: {json.dumps(safe_payload)}\n\n"

        # Signal stream end
        yield 'data: {"step": "END", "status": "DONE", "message": "Stream closed"}\n\n'

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
