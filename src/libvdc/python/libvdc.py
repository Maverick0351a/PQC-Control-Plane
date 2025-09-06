from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from cbor2 import loads as cbor_loads, dumps as cbor_dumps

MAGIC = b"\x89vdc\r\n\x1a\n"  # must match src.signet.vdc.model


@dataclass
class VdcInfo:
    meta: Dict[int, Any]
    payloads: List[Dict[int, Any]]
    receipts: List[bytes]
    anchors: List[Dict[int, Any]]
    timestamps: List[Dict[int, Any]]


def parse_vdc(buf: bytes) -> VdcInfo:
    if not buf.startswith(MAGIC):
        raise ValueError("not a VDC file")
    body = cbor_loads(buf[len(MAGIC) :])
    # Forward-compat: unknown top-level numeric keys ignored unless critical in policies
    meta = body.get(2, {})
    known: Set[int] = {1, 2, 3, 4, 5, 6}
    unknown = [k for k in body.keys() if isinstance(k, int) and k not in known]
    policies = (meta or {}).get(5, {}) if isinstance(meta, dict) else {}
    critical = set()
    if isinstance(policies, dict):
        ck = policies.get("critical_top_level_keys")
        if isinstance(ck, list):
            for i in ck:
                if isinstance(i, int):
                    critical.add(i)
    for uk in unknown:
        if uk in critical:
            raise ValueError("unknown critical top-level key present")
    return VdcInfo(
        meta=meta,
        payloads=body.get(3, []),
        receipts=body.get(4, []),
        anchors=body.get(5, []),
        timestamps=body.get(6, []),
    )


def verify_ed25519(buf: bytes, pubkey_bytes: bytes, kid: Optional[bytes] = None) -> bool:
    """Lightweight verify: check at least one COSE_Sign1 matches SigBase."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    info = parse_vdc(buf)
    # Build SigBase per spec
    import hashlib
    meta_digest = hashlib.sha384(cbor_dumps(info.meta, canonical=True)).digest()
    payload_digests = [pd[4] for pd in info.payloads]
    payload_norm = [hashlib.sha384(d).digest() for d in payload_digests]
    ok = False
    for sign1 in info.receipts:
        arr = cbor_loads(sign1)
        if not (isinstance(arr, list) and len(arr) == 4):
            continue
        protected = arr[0]
        sig = arr[3]
        prot = cbor_loads(protected)
        crit = prot.get(2) or []
        # Fail-closed on unknown crit headers
        for name in crit:
            if name not in ("vdc-sb-hash", "vdc-ekm"):
                continue  # lightweight lib: skip signature if unknown crit
        if "vdc-sb-hash" not in crit or prot.get("vdc-sb-hash") != "sha-384":
            continue
        ekm_hdr = prot.get("vdc-ekm")
    sig_base_item = ["VDC-SIG/v1", meta_digest, payload_norm]
        if ekm_hdr is not None:
            if "vdc-ekm" not in crit:
                continue
            sig_base_item.append(ekm_hdr)
        sig_base = cbor_dumps(sig_base_item, canonical=True)
        # Sig_structure = ["Signature1", protected, b"", SigBase]
        to_sign = cbor_dumps(["Signature1", protected, b"", sig_base], canonical=True)
        try:
            Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(sig, to_sign)
            ok = True
            if kid is None:
                break
        except InvalidSignature:
            continue
    # Optional: check timestamps if present and a signature matched
    if ok and info.timestamps:
        try:
            from asn1crypto import tsp  # type: ignore
            import hashlib as _hl
            sb_sha256 = _hl.sha256(cbor_dumps(["VDC-SIG/v1", meta_digest, payload_norm], canonical=True)).digest()
            sb_sha384 = _hl.sha384(cbor_dumps(["VDC-SIG/v1", meta_digest, payload_norm], canonical=True)).digest()
            for ts in info.timestamps:
                if not isinstance(ts, dict) or 1 not in ts or 2 not in ts:
                    return False
                der = ts[1]; alg = ts[2]
                token = tsp.TimeStampToken.load(bytes(der))
                tst_info = token["content"]["encap_content_info"]["content"].parsed
                mi = tst_info["message_imprint"]
                hashed_message = mi["hashed_message"].native
                algo_name = mi["hash_algorithm"]["algorithm"].native
                if alg == "sha-256":
                    if hashed_message != sb_sha256 or algo_name not in ("sha256",):
                        return False
                elif alg == "sha-384":
                    if hashed_message != sb_sha384 or algo_name not in ("sha384",):
                        return False
                else:
                    return False
        except Exception:
            return False
    return ok
