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
    # Handshake / path passport enrichment (optional; DPR extension)
    clienthello_bytes: Optional[int] = None
    hrr_seen: Optional[bool] = None
    passport_id: Optional[str] = None
    # Public non-repudiation signature (Ed25519) over canonical receipt minus these two fields.
    public_sig_b64: Optional[str] = None
    # Session binding tag (HMAC over same canonical bytes using HKDF-expanded exporter key)
    session_tag_b64: Optional[str] = None
    # Strength indicator for session binding (e.g., 'ekm', 'none')
    session_binding_strength: Optional[str] = None
