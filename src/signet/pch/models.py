from pydantic import BaseModel, Field
from datetime import datetime

class PCHReceiptFragment(BaseModel):
    present: bool
    verified: bool
    failure_reason: str | None = None
    channel_binding: str | None = None
    evidence_sha256_hex: str | None = None
    sig_alg: str | None = None
    time: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
