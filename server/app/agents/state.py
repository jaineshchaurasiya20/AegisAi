import os
import json
from enum import Enum
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class IncidentStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class StepLog(BaseModel):
    step: str
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    status: str = "INFO"

class IncidentState(BaseModel):
    threat_id: str
    source_ip: Optional[str] = None
    destination_port: Optional[int] = Field(default=None, ge=1, le=65535)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    process_tree: List[Dict[str, Any]] = Field(default_factory=list)
    open_sockets: List[Dict[str, Any]] = Field(default_factory=list)
    mitigation_plan: List[Dict[str, Any]] = Field(default_factory=list)
    step_logs: List[StepLog] = Field(default_factory=list)
    status: IncidentStatus = IncidentStatus.PENDING
    generated_patch_path: Optional[str] = None

    def add_log(self, step: str, message: str, status: str = "INFO"):
        self.step_logs.append(StepLog(step=step, message=message, status=status))
