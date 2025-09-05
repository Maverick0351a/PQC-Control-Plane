import base64
import re
from typing import Dict, Tuple, List
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from .alg_registry import verify_alg
from ..config import CLIENT_KEYS
from ..pch.base_string import build_canonical_base
import json
import os

COMPONENT_RE = re.compile(r'\s*([@a-zA-Z0-9\-]+)\s*')

def parse_signature_input(header: str) -> Tuple[str, List[str], Dict[str, str]]:
    # Example: pch=("@method" "@path" "content-digest");created=...;keyid="caller-1";alg="ed25519"
    # Return label ('pch'), components list, params dict
    label, rest = header.split("=", 1)
    if not rest.startswith("("):
        raise ValueError("invalid Signature-Input")
    items, params = rest.split(")", 1)
    items = items[1:].strip()
    # Extract components between quotes – items looks like: "@method" "@path" "content-digest"
    raw_parts = [p.strip() for p in items.split('"')]
    comps = [p for p in raw_parts if p and not p.isspace()]
    # parse params
    params = params.strip().lstrip(";")
    p = {}
    for part in params.split(";"):
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            p[k.strip()] = v.strip().strip('"')
        else:
            p[part.strip()] = True
    return label, comps, p

def build_signature_base(request, components: List[str], params: Dict[str, str], evidence_sha256_hex: str) -> str:
    """Backward compatible wrapper that now delegates to canonical builder.

    Centralization happens in pch.base_string.build_canonical_base.
    """
    return build_canonical_base(request, components, params, evidence_sha256_hex)

def load_client_keys() -> Dict[str, Dict[str, str]]:
    if not os.path.exists(CLIENT_KEYS):
        return {}
    with open(CLIENT_KEYS, "r", encoding="utf-8") as f:
        return json.load(f)

def verify_signature(alg: str, keyid: str, signature_b64: str, message: str) -> bool:
    """Backward-compatible verification entrypoint.

    Delegates to alg_registry for all algorithms (including legacy ed25519).
    """
    keys = load_client_keys()
    entry = keys.get(keyid)
    if not entry:
        return False
    # Allow hybrid client entries to advertise 'ecdsa-p256+ml-dsa-65'
    if entry.get("alg") != alg:
        return False
    try:
        return verify_alg(alg, entry, signature_b64, message)
    except Exception:  # pragma: no cover - defensive
        return False

def sign_ed25519(private_pem: str, message: str) -> str:
    priv = serialization.load_pem_private_key(private_pem.encode(), password=None)
    assert isinstance(priv, Ed25519PrivateKey)
    sig = priv.sign(message.encode())
    return base64.b64encode(sig).decode()
