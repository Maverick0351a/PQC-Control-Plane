from pydantic import BaseModel, Field
from typing import Literal, List, Dict, Any
from datetime import datetime

# Minimal VKC envelope carried inside a VDC payload
class VKC(BaseModel):
    schema: Literal["vkc.v1"]
    vkc_type: Literal["knowledge.fact","knowledge.skill","memory.note","intent.plan",
                      "evidence.use","hypothesis.attack","change.proposal"]
    title: str
    created: str = Field(default_factory=lambda: datetime.utcnow().isoformat()+"Z")
    producer: str  # DID or key-id
    labels: Dict[str, Any] = {}
    claims: List[Dict[str, Any]] = []     # facts, assumptions, or steps
    citations: List[str] = []             # VKC ids supporting this VKC
    body: Dict[str, Any] = {}             # free-form data by type
