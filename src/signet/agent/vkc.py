from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple, List

from ..vdc.pack import pack_vdc
from ..vdc.model import (
    compute_digest,
    build_payload_descriptor,
    det_cbor_dumps,
    build_vdc,
    file_write_vdc,
)
from ..cbom.export import build_cbom
from ..vdc.model import anchor_ct_v2_trivial
from .signer import Signer
from .crypto import cose_sign1_with_signer


def _producer() -> str:
    return os.getenv("VDC_PRODUCER_DID") or os.getenv("SIGNET_SERVICE", "signet-agent")


def build_vkc(plan: Dict[str, Any], *, kid: Optional[bytes] = None, sk: Optional[bytes] = None) -> Tuple[bytes, Dict[str, Any]]:
    """Build a minimal VKC as a VDC pack with one embedded JSON payload.

    Returns (vdc_bytes, summary_dict)
    """
    # Meta
    import datetime
    created = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    meta = {
        1: "advisory-plan",  # purpose
        2: _producer(),       # producer DID or service name
        3: plan.get("created") or plan.get("ts") or plan.get("time") or created,
        4: {1: "offline", 2: "n/a"},  # crypto context
        5: {"cbom": build_cbom(), "profile": "vdc-core"},
    }
    # Payloads: use canonical JSON bytes with SHA-384 digest-as-payload
    import json
    plan_bytes = json.dumps(plan, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payloads: List[Tuple[str, str, bytes, Optional[str]]] = [
        ("vkc-advisory-plan", "application/vnd.vkc+json-sha384", compute_digest(plan_bytes, "sha-384"), "advisory"),
    ]
    # Key material from env if not provided
    if sk is None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        pem_path = os.getenv("VDC_SIGNING_KEY", os.getenv("SERVER_SIGNING_KEY", "keys/sth_ed25519_sk.pem"))
        with open(pem_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
            assert isinstance(key, Ed25519PrivateKey)
            sk = key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
    if kid is None:
        kid = os.getenv("VDC_KID", "vdc-sth-ed25519").encode()
    buf = pack_vdc(meta, payloads, sk, kid, attach_evg_anchor=True, ekm=None, timestamps=None, profile="vdc-core")
    return buf, {"bytes": len(buf)}


def build_vkc_with_signer(plan: Dict[str, Any], *, signer: Signer, key_ref: str, kid: bytes, ekm: Optional[bytes] = None) -> Tuple[bytes, Dict[str, Any]]:
    """Build a VKC (VDC) using an external Signer (KMS/HSM or pyca dev).

    This path never loads/export private keys; the signer produces the raw signature.
    """
    import datetime, json
    created = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    meta = {
        1: "advisory-plan",
        2: _producer(),
        3: plan.get("created") or plan.get("ts") or plan.get("time") or created,
        4: {1: "offline", 2: "n/a"},
        5: {"cbom": build_cbom(), "profile": "vdc-core"},
    }
    plan_bytes = json.dumps(plan, separators=(",", ":"), sort_keys=True).encode("utf-8")
    # Descriptor for digest-as-payload
    pd_list: List[Dict[int, Any]] = []
    d = compute_digest(plan_bytes, "sha-384")
    pd_list.append(build_payload_descriptor("vkc-advisory-plan", "application/vnd.vkc+json-sha384", "sha-384", d, data_embedded=None, role="advisory"))
    # Build SigBase
    meta_digest = compute_digest(det_cbor_dumps(meta), "sha-384")
    payload_norm = [compute_digest(pd[4], "sha-384") for pd in pd_list]
    sig_base_item = ["VDC-SIG/v1", meta_digest, payload_norm]
    sig_base = det_cbor_dumps(sig_base_item)
    # COSE via signer
    cose = cose_sign1_with_signer(sig_base, signer=signer, key_ref=key_ref, kid=kid, alg="ed25519", ekm=ekm)
    anchors = [anchor_ct_v2_trivial(sig_base)]
    vdc2 = build_vdc(meta, pd_list, receipts=[cose], anchors=anchors, timestamps=[])
    buf = file_write_vdc(vdc2)
    return buf, {"bytes": len(buf)}
