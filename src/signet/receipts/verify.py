import base64
import hmac
import hashlib
from typing import Dict, Any
from ..crypto.jcs import jcs_canonicalize
from ..utils.ct import ct_eq

HKDF_INFO = b"DPR-MAC-Key/v1"

def _hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]

def canonical_bytes_for_session_tag(rec: Dict[str, Any]) -> bytes:
    # Shallow copy then drop proof fields only. The envelope.session_binding
    # is now inserted before canonicalization by the emitter and MUST be part
    # of the tag base. Do not strip it here.
    temp = dict(rec)
    temp.pop("public_sig_b64", None)
    temp.pop("session_tag_b64", None)
    return jcs_canonicalize(temp)

def verify_session_tag(rec: Dict[str, Any], exporter_bytes: bytes) -> bool:
    tag_b64 = rec.get("session_tag_b64")
    if not tag_b64:
        return False
    try:
        tag = base64.b64decode(tag_b64)
        mac_key = _hkdf_expand(exporter_bytes, HKDF_INFO, 32)
        can = canonical_bytes_for_session_tag(rec)
        exp = hmac.new(mac_key, can, hashlib.sha256).digest()
        return ct_eq(tag, exp)
    except Exception:
        return False