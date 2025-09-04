from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any

class EnforcementReceipt(BaseModel):
    id: str
    decision: str
    reason: str
    pch: Dict[str, Any]
    prev_receipt_hash_b64: Optional[str]
    leaf_hash_b64: Optional[str] = None
    request_ref: Dict[str, Any]
    time: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
