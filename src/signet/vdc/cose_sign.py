from __future__ import annotations

from typing import Optional, Tuple, Dict, Any

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


ALG_EDDSA = -8  # COSE algorithm ID for EdDSA
HDR_CRIT = 2    # COSE header label for "crit"


def _sig_structure(protected_bstr: bytes, payload: bytes) -> bytes:
    # Sig_structure = ["Signature1", protected, external_aad:bstr, payload]
    arr = ["Signature1", protected_bstr, b"", payload]
    return cbor2.dumps(arr, canonical=True)


def sign1_ed25519(payload: bytes, privkey_bytes: bytes, kid: bytes, *, vdc_sb_hash: str = "sha-384", vdc_ekm: Optional[bytes] = None) -> bytes:
    """Create COSE_Sign1 with protected headers including VDC profile params.

    Protected header includes:
    - alg (1): EdDSA
    - kid (4)
    - crit (2): list of critical header parameter labels (tstr) we use
    - "vdc-sb-hash": tstr MUST be "sha-384"
    - optional "vdc-ekm": bstr if channel-bound
    """
    protected_map: Dict[Any, Any] = {1: ALG_EDDSA, 4: kid, "vdc-sb-hash": vdc_sb_hash}
    crit: list = ["vdc-sb-hash"]
    if vdc_ekm is not None:
        protected_map["vdc-ekm"] = vdc_ekm
        crit.append("vdc-ekm")
    protected_map[HDR_CRIT] = crit
    protected_bstr = cbor2.dumps(protected_map, canonical=True)
    to_sign = _sig_structure(protected_bstr, payload)
    sk = Ed25519PrivateKey.from_private_bytes(privkey_bytes)
    sig = sk.sign(to_sign)
    cose_obj = [protected_bstr, {}, payload, sig]
    return cbor2.dumps(cose_obj, canonical=True)


def verify1_ed25519(cose_bytes: bytes, pubkey_bytes: bytes, expected_kid: Optional[bytes] = None) -> Tuple[bytes, Dict[Any, Any]]:
    obj = cbor2.loads(cose_bytes)
    if not (isinstance(obj, list) and len(obj) == 4):
        raise ValueError("bad COSE_Sign1 structure")
    protected_bstr, unprot, payload, sig = obj
    if not isinstance(protected_bstr, (bytes, bytearray)):
        raise ValueError("protected header must be bstr")
    prot = cbor2.loads(protected_bstr)
    if prot.get(1) != ALG_EDDSA:
        raise ValueError("unexpected alg")
    if expected_kid is not None and prot.get(4) != expected_kid:
        raise ValueError("unexpected kid")
    to_verify = _sig_structure(protected_bstr, payload)
    pk = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
    try:
        pk.verify(sig, to_verify)
    except Exception as e:  # pragma: no cover - cryptography throws InvalidSignature
        raise ValueError("bad signature") from e
    return payload, prot
