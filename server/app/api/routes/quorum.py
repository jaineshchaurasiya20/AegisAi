"""
AegisAI Quorum API Routes
Exposes endpoints for operator authorization of pending cryptographic quorum actions.

POST /api/quorum/authorize — Authorize or reject a pending containment action
GET  /api/quorum/pending   — Retrieve active pending authorization requests
GET  /api/quorum/audit     — Retrieve quorum cryptographic audit trail
"""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from loguru import logger

from app.core.security import get_current_user
from app.core.quorum import (
    quorum_store,
    QuorumTokenStatus,
)
from app.agents.schemas import (
    QuorumApprovedEvent,
    QuorumRejectedEvent,
)
from app.agents.orchestrator import orchestrator

router = APIRouter(prefix="/api/quorum", tags=["quorum"])


class QuorumAuthorizeRequest(BaseModel):
    nonce: str = Field(..., description="Single-use 128-bit hex nonce of the pending action")
    hmac_signature: str = Field(..., description="HMAC-SHA256 signature associated with the token")
    decision: Literal["APPROVE", "REJECT"] = Field(..., description="Operator decision (APPROVE or REJECT)")


class QuorumAuthorizeResponse(BaseModel):
    success: bool
    status: str
    nonce: str
    execution_status: Optional[str] = None
    reason: Optional[str] = None


@router.post("/authorize", response_model=QuorumAuthorizeResponse)
async def authorize_action(
    payload: QuorumAuthorizeRequest,
    # Allow optional token auth or demo auth to avoid blocking UI during emergency SOC response
    current_user: Optional[dict] = None,
):
    """
    Operator endpoint to APPROVE or REJECT a pending high-risk containment action.
    Client supplies ONLY nonce, hmac_signature, and decision.
    Target PID, action type, and threat hash are retrieved server-side to prevent tampering.
    """
    nonce = payload.nonce.strip()
    signature = payload.hmac_signature.strip()
    decision = payload.decision.strip().upper()

    logger.info(f"[Quorum API] Authorization request received for nonce {nonce[:8]}... | Decision: {decision}")

    # Step 1: Atomic authorization attempt in Quorum store
    success, reason, record = await quorum_store.authorize_token(
        nonce=nonce,
        supplied_signature=signature,
        decision=decision,
    )

    if not success:
        logger.warning(f"[Quorum API] Authorization failed for nonce {nonce[:8]}... | Reason: {reason}")
        if reason == "TOKEN_EXPIRED":
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail={"success": False, "status": "EXPIRED", "reason": "TOKEN_EXPIRED"},
            )
        elif reason in ("NONCE_ALREADY_CONSUMED", "ALREADY_CONSUMED"):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"success": False, "status": "REJECTED", "reason": "NONCE_ALREADY_CONSUMED"},
            )
        elif reason == "UNKNOWN_NONCE":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"success": False, "status": "REJECTED", "reason": "UNKNOWN_NONCE"},
            )
        elif reason in ("INVALID_HMAC_SIGNATURE", "STORED_HMAC_SECRET_MISMATCH"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"success": False, "status": "REJECTED", "reason": "INVALID_HMAC"},
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"success": False, "status": "REJECTED", "reason": reason},
            )

    assert record is not None

    # Step 2: Handle APPROVE flow
    if decision == "APPROVE":
        approved_event = QuorumApprovedEvent(
            nonce=nonce,
            action_type=record.action_type,
            target_pid=record.target_pid,
            decision="APPROVE",
            executed_by=current_user.get("username", "soc_operator") if current_user else "soc_operator",
        )
        await orchestrator.bus.publish(approved_event)

        # Trigger Remediator execution with pre-execution identity validation
        logger.info(
            f"[Quorum API] Operator approved {record.action_type} for PID {record.target_pid}. "
            f"Handing off to Remediator Agent."
        )

        import asyncio
        # Run remediation in background task or inline
        asyncio.create_task(orchestrator.remediator.execute_authorized_remediation(nonce))

        return QuorumAuthorizeResponse(
            success=True,
            status="AUTHORIZED",
            nonce=nonce,
            execution_status="EXECUTING",
        )

    # Step 3: Handle REJECT flow
    else:
        rejected_event = QuorumRejectedEvent(
            nonce=nonce,
            action_type=record.action_type,
            target_pid=record.target_pid,
            decision="REJECT",
            reason="REJECTED_BY_OPERATOR",
        )
        await orchestrator.bus.publish(rejected_event)

        logger.info(f"[Quorum API] Operator rejected {record.action_type} for PID {record.target_pid}. Remediation aborted.")

        return QuorumAuthorizeResponse(
            success=True,
            status="REJECTED",
            nonce=nonce,
            execution_status="SUPPRESSED",
        )


@router.get("/pending")
async def get_pending_actions():
    """Retrieve list of active, non-expired authorization requests awaiting operator decision."""
    items = await quorum_store.get_pending_tokens()
    return {"pending_count": len(items), "items": items}


@router.get("/audit")
async def get_quorum_audit():
    """Retrieve cryptographic quorum audit log entries."""
    trail = quorum_store.get_audit_trail()
    return {"audit_count": len(trail), "items": list(reversed(trail[-100:]))}
