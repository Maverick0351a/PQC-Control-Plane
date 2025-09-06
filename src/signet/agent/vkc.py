from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple, List

from ..vdc.pack import pack_vdc
from ..vdc.model import compute_digest
from ..cbom.export import build_cbom


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
