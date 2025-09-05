"""Receipt Envelope v1 implementation.

Canonical, JCS-signed envelope for enforcement + telemetry decisions.
Signature covers the object minus the signature_b64 field itself.

Structure:
{
  "envelope": { version, id, time, actor, binding?, sth_ref? },
  "claims": { ... domain specific claims ... },
  "signature_b64": "..."  # Ed25519 over JCS(envelope+claims)
}

Binding (optional) is an exporter-derived HKDF tag HMACed with claims body to
prevent cross-channel grafting when exporter is present.
"""
from __future__ import annotations

from typing import Optional, Dict, Any
import uuid
import datetime
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from ..crypto.jcs import jcs_canonicalize
from ..config import SERVER_SIGNING_KEY


HKDF_INFO = b"Signet-Receipt-Bind/v1"


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _load_privkey(pem_path: str) -> Ed25519PrivateKey:
    with open(pem_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _hkdf_expand_from_exporter(exporter: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive mac_key directly using exporter as PRK (HKDF-Expand only).

    Spec simplification: mac_key = HKDF-Expand(exporter, info, 32)
    (Exporter treated as already a pseudorandom key per TLS exporter properties.)
    """
    # For length 32 (<= one SHA256 block) a single HMAC invocation suffices.
    t1 = hmac.new(exporter, info + b"\x01", hashlib.sha256).digest()
    return t1[:length]


def _binding_tag(exporter: Optional[bytes], claims_obj: Dict[str, Any]) -> Optional[str]:
    if not exporter:
        return None
    mac_key = _hkdf_expand_from_exporter(exporter, HKDF_INFO, 32)
    claims_bytes = jcs_canonicalize(claims_obj)
    tag = hmac.new(mac_key, claims_bytes, hashlib.sha256).digest()
    return base64.b64encode(tag).decode()


def build_envelope(
    actor: Dict[str, str],
    claims: Dict[str, Any],
    exporter: Optional[bytes] = None,
    exporter_type: Optional[str] = None,
    sth_ref: Optional[Dict[str, str]] = None,
    binding_availability: Optional[str] = None,
) -> Dict[str, Any]:
    env = {
        "envelope": {
            "version": "sig.v1",
            "id": f"urn:signet:rec:{uuid.uuid4()}",
            "time": _utc_now_iso(),
            "actor": actor,
        },
        "claims": claims,
    }
    if exporter and exporter_type:
        availability = binding_availability or ("present" if exporter else "unavailable")
        tag_b64 = _binding_tag(exporter, claims)
        env["envelope"]["binding"] = {
            "type": exporter_type,
            "tag_b64": tag_b64,
            "availability": availability,
        }
    if sth_ref:
        env["envelope"]["sth_ref"] = sth_ref
    # Sign (JCS canonicalization) excluding signature field
    priv = _load_privkey(SERVER_SIGNING_KEY)
    to_sign = jcs_canonicalize({k: env[k] for k in ("envelope", "claims")})
    sig_b64 = base64.b64encode(priv.sign(to_sign)).decode()
    env["signature_b64"] = sig_b64
    return env
