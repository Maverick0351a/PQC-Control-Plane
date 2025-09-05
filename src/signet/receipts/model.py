from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime, timezone

class EnforcementReceipt(BaseModel):
    id: str
    type: str = "pqc.enforcement"
    time: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace('+00:00','Z'))
    decision: str
    reason: str
    pch: Optional[Dict[str, Any]] = None
    prev_receipt_hash_b64: Optional[str] = None
    request_ref: Optional[Dict[str, Any]] = None
    controller: Optional[Dict[str, Any]] = None
