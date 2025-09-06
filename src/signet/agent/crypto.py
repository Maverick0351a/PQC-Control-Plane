from __future__ import annotations

"""Thin crypto wrappers the Agent SHOULD provide (no bespoke algorithms).

- COSE_Sign1 Ed25519 sign/verify for VDC SigBase
- Optional PQC (ml-dsa-65) hook (flag-gated; requires liboqs bindings elsewhere)
- Digests: SHA-384 (VDC), SHA-256 (RFC 9530)
- HTTP Message Signatures base construction (RFC 9421) for PCH-Lite
- RFC 3161 timestamp attachment (accept DER tokens; no TSA client here)
- Transparency anchoring helper: submit VDC to EVG sink

Agent SHOULD NOT implement primitives; we rely on pyca/cryptography and existing modules.
"""

from typing import Any, Dict, Optional, Tuple
import base64
import hashlib
import os

from ..vdc.cose_sign import sign1_ed25519
from ..vdc.verify import verify_vdc_cose_sign1
from ..pch.base_string import build_canonical_base
from .signer import Signer
import cbor2


# Digests
def sha384(data: bytes) -> bytes:
    return hashlib.sha384(data).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# COSE Sign/Verify (Ed25519)
def cose_sign1_ed25519(sig_base: bytes, *, sk_raw: bytes, kid: bytes, ekm: bytes | None = None) -> bytes:
    return sign1_ed25519(sig_base, sk_raw, kid, vdc_sb_hash="sha-384", vdc_ekm=ekm)


def cose_verify_sign1_ed25519(cose_bytes: bytes, *, pub_raw: bytes, ekm: bytes | None = None) -> bool:
    ok, _ = verify_vdc_cose_sign1(cose_bytes, pub_raw, ekm)
    return ok


def cose_sign1_with_signer(sig_base: bytes, *, signer: Signer, key_ref: str, kid: bytes, alg: str = "ed25519", ekm: bytes | None = None) -> bytes:
    """Sign the SigBase using a Signer and wrap as COSE_Sign1.

    For ed25519, we need to produce the same COSE protected header values used by VDC.
    """
    if alg.lower() != "ed25519":
        raise ValueError("Only ed25519 is supported for COSE wrapper here")
    # Build protected header matching VDC conventions
    protected_map: Dict[Any, Any] = {1: -8, 4: kid, "vdc-sb-hash": "sha-384"}
    crit: list = ["vdc-sb-hash"]
    if ekm is not None:
        protected_map["vdc-ekm"] = ekm
        crit.append("vdc-ekm")
    protected_map[2] = crit  # COSE 'crit'
    protected_bstr = cbor2.dumps(protected_map, canonical=True)
    # Sig_structure = ["Signature1", protected, external_aad=b"", payload=sig_base]
    to_sign = cbor2.dumps(["Signature1", protected_bstr, b"", sig_base], canonical=True)
    sig = signer.sign(key_ref, to_sign, alg)
    cose_obj = [protected_bstr, {}, sig_base, sig]
    return cbor2.dumps(cose_obj, canonical=True)


# HTTP Message Signatures (RFC 9421) base construction
def build_http_sig_base(request_like: Any, components: list[str], params: Dict[str, str], evidence_sha256_hex: str) -> str:
    """Use existing PCH base-string builder for RFC 9421-compatible base.

    request_like must expose .headers, .method, .url.path, .url.query, .url.netloc.
    """
    return build_canonical_base(request_like, components, params, evidence_sha256_hex)


# RFC 3161 timestamp (accept DER tokens and pair with hash alg identifier)
def format_timestamps(pairs: list[tuple[bytes, str]]) -> list[Dict[int, Any]]:
    """Return VDC-compatible timestamp list: [{1: der, 2: alg}, ...]."""
    out: list[Dict[int, Any]] = []
    for der, alg in pairs:
        out.append({1: der, 2: alg})
    return out


# EVG anchoring helper (submit VDC; server hashes SigBase internally)
def anchor_vdc_to_evg(vdc_bytes: bytes, *, sink_url: Optional[str] = None, timeout_s: float = 5.0) -> Dict[str, Any]:
    import httpx
    url = sink_url or os.getenv("RECEIPTS_SINK_URL", "http://evg-sink:8080/ingest")
    data_b64 = base64.b64encode(vdc_bytes).decode()
    resp = httpx.post(url, json={"type": "vdc", "data": data_b64}, timeout=timeout_s)
    resp.raise_for_status()
    return resp.json()
