from pydantic import BaseModel
from typing import Optional, Literal

class PCHEvidenceRef(BaseModel):
    type: Literal["pch.sth"] = "pch.sth"
    merkle_root_b64: Optional[str] = None
    cbom_hash_b64: Optional[str] = None

class PCHResult(BaseModel):
    present: bool
    verified: bool
    channel_binding: Optional[str] = None
    evidence_ref: Optional[PCHEvidenceRef] = None
    failure_reason: Optional[str] = None
    evidence_sha256_hex: Optional[str] = None
    sig_alg: Optional[str] = None
