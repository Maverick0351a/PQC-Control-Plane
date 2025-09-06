from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .model import (
    build_payload_descriptor,
    build_vdc,
    compute_digest,
    det_cbor_dumps,
    file_write_vdc,
    anchor_ct_v2_trivial,
)
from .cose_sign import sign1_ed25519


def pack_vdc(
    meta: Dict[int, Any],
    payloads: List[Tuple[str, str, bytes, Optional[str]]],
    # tuples of (id, cty, data, role)
    ed25519_priv: bytes,
    kid: bytes,
    attach_evg_anchor: bool = False,
    ekm: Optional[bytes] = None,
    timestamps: Optional[List[Tuple[bytes, str]]] = None,
    profile: Optional[str] = None,
) -> bytes:
    # Build payload descriptors with digests
    pd_list: List[Dict[int, Any]] = []
    for pid, cty, data, role in payloads:
        d = compute_digest(data, "sha-384")
        pd = build_payload_descriptor(pid, cty, "sha-384", d, data_embedded=data, role=role)
        pd_list.append(pd)

    # Optionally set interop profile in meta.policies.profile BEFORE signing
    if profile:
        pol = dict(meta.get(5, {}))
        pol["profile"] = profile
        meta = dict(meta)
        meta[5] = pol

    # SigBase (v0.1): ["VDC-SIG/v1", meta_digest, [payload_digests...], ?ekm]
    meta_digest = compute_digest(det_cbor_dumps(meta), "sha-384")
    # Normalize payload entries: bind SHA-384 of each payload digest
    payload_norm = [compute_digest(pd[4], "sha-384") for pd in pd_list]
    sig_base_item = ["VDC-SIG/v1", meta_digest, payload_norm]
    if ekm is not None:
        sig_base_item.append(ekm)
    sig_base = det_cbor_dumps(sig_base_item)
    cose = sign1_ed25519(sig_base, ed25519_priv, kid, vdc_sb_hash="sha-384", vdc_ekm=ekm)
    receipts = [cose]
    anchors: List[Dict[int, Any]] = []
    if attach_evg_anchor:
        anchors.append(anchor_ct_v2_trivial(sig_base))
    # Encode timestamps as list of maps {1: tst_der, 2: hash_alg}
    ts_list: List[Dict[int, Any]] = []
    if timestamps:
        for der, alg in timestamps:
            ts_list.append({1: der, 2: alg})
    vdc2 = build_vdc(meta, pd_list, receipts=receipts, anchors=anchors, timestamps=ts_list)
    return file_write_vdc(vdc2)
