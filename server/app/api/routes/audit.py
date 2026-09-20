"""
AegisAI Audit Routes — NIST CSF 2.0 & GDPR Article 33 Automated Report Export & Ephemeral Sandbox Control.
"""
import json
from typing import Literal, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from loguru import logger

from app.core.security import get_current_user
from app.agents.orchestrator import orchestrator
from app.core.sandbox import ephemeral_sandbox
from app.services.aws_service import aws_s3_vault

router = APIRouter(prefix="/api/audit", tags=["audit"])


class ReportRequest(BaseModel):
    threat_id: str
    format: Optional[Literal["json", "markdown"]] = "json"


@router.get("/export/{threat_id}")
async def export_audit_report(
    threat_id: str,
    format: Literal["json", "markdown"] = Query("json"),
    download: bool = Query(True),
    current_user: dict = Depends(get_current_user),
):
    """
    Generate and export a court-admissible NIST CSF 2.0 & GDPR Article 33 compliance audit report.
    Includes full incident lifecycle aggregation, TreeSHAP mathematical proofs, Quorum HMAC proof,
    closed-loop OS kernel verification state, SHA-256 integrity checksum, and automated AWS S3
    Object Lock (WORM compliance mode) + AWS KMS encryption synchronization.
    """
    try:
        report = orchestrator.auditor.generate_compliance_report(threat_id=threat_id, format=format)
        
        if format == "markdown":
            filename = f"aegisai_audit_{threat_id[:8]}.md"
            headers = {}
            if download:
                headers["Content-Disposition"] = f'attachment; filename="{filename}"'
            return Response(content=str(report), media_type="text/markdown; charset=utf-8", headers=headers)
        else:
            # Upload to AWS S3 Immutable Vault (SSE-KMS & WORM Object Lock)
            vault_status = aws_s3_vault.upload_immutable_audit(threat_id=threat_id, report_data=report)
            report["aws_vault_status"] = vault_status

            filename = f"aegisai_audit_{threat_id[:8]}.json"
            content_str = json.dumps(report, indent=2, default=str)
            headers = {
                "X-AWS-Vault-Status": "VERIFIED" if vault_status.get("success") else "FALLBACK_LOCAL",
            }
            if vault_status.get("s3_uri"):
                headers["X-AWS-Vault-URI"] = vault_status["s3_uri"]
            if download:
                headers["Content-Disposition"] = f'attachment; filename="{filename}"'
            return Response(content=content_str, media_type="application/json; charset=utf-8", headers=headers)

    except Exception as e:
        logger.error(f"[Audit API] Error exporting audit report for {threat_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate audit report: {str(e)}")


@router.post("/report")
async def generate_report_json(
    payload: ReportRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    API endpoint to generate structured audit report JSON or Markdown payload directly in response.
    Automatically synchronizes with AWS S3 Immutable Vault when format='json'.
    """
    try:
        report = orchestrator.auditor.generate_compliance_report(
            threat_id=payload.threat_id,
            format=payload.format or "json",
        )
        vault_status = None
        if (payload.format or "json") == "json" and isinstance(report, dict):
            vault_status = aws_s3_vault.upload_immutable_audit(threat_id=payload.threat_id, report_data=report)
            report["aws_vault_status"] = vault_status

        return {
            "success": True,
            "threat_id": payload.threat_id,
            "format": payload.format,
            "report": report,
            "aws_vault_status": vault_status,
        }
    except Exception as e:
        logger.error(f"[Audit API] Error generating report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")


@router.get("/sandbox/status")
async def get_sandbox_status(
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieve Zero-Knowledge Ephemeral RAM Sandbox metrics and PCTA compliance status.
    """
    return ephemeral_sandbox.get_sandbox_stats()


@router.post("/sandbox/wipe")
async def trigger_sandbox_wipe(
    current_user: dict = Depends(get_current_user),
):
    """
    Execute manual zero-fill context wipe on in-memory buffers and trigger gc.collect().
    """
    result = ephemeral_sandbox.wipe_ephemeral_context()
    return {
        "message": "Zero-Knowledge Ephemeral RAM buffer wiped successfully",
        "details": result,
    }
