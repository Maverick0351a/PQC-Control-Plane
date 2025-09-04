import base64
import hashlib
from ..crypto.jcs import jcs_canonicalize

def evidence_sha256_hex_from_header(evidence_b64: str) -> str:
    val = evidence_b64.strip()
    if val.startswith(":") and val.endswith(":"):
        val = val[1:-1]
    raw = base64.b64decode(val.encode())
    return hashlib.sha256(raw).hexdigest()

def make_evidence_jcs(evidence_obj: dict) -> str:
    raw = jcs_canonicalize(evidence_obj)
    return ":" + base64.b64encode(raw).decode() + ":"
