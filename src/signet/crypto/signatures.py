import base64
import time
import re
from typing import Dict, Tuple, List
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from ..config import CLIENT_KEYS
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
    # Minimal base: each line 'component: value' followed by '@signature-params'
    lines = []
    headers = {k.lower(): v for k, v in request.headers.items()}
    for comp in components:
        lc = comp.lower()
        if lc == "@method":
            val = request.method.upper()
        elif lc == "@path":
            path = request.url.path or "/"
            query = request.url.query
            val = path if not query else f"{path}?{query}"
        elif lc == "@authority":
            # Use exact Host header (includes port) for signature authority alignment
            val = request.headers.get("host") or request.url.netloc or ""
        elif lc == "content-digest":
            val = headers.get("content-digest", "")
        elif lc == "content-type":
            val = headers.get("content-type", "")
        elif lc == "pch-challenge":
            val = headers.get("pch-challenge", "")
        elif lc == "pch-channel-binding":
            val = headers.get("pch-channel-binding", "")
        elif lc == "evidence-sha-256":
            val = evidence_sha256_hex
        else:
            # Generic header
            val = headers.get(lc, "")
        lines.append(f"{lc}: {val}")
    # @signature-params (simplified)
    comp_list = " ".join([f'"{c}"' for c in components])
    params_copy = {**params}
    # normalize
    created = params_copy.get("created") or str(int(time.time()))
    keyid = params_copy.get("keyid", "")
    alg = params_copy.get("alg", "ed25519")
    # Use single quotes around the f-string so we can embed double quotes safely
    sig_params = (
        f"@signature-params: ({comp_list});created={created};keyid=\"{keyid}\";alg=\"{alg}\""
    )
    lines.append(sig_params)
    return "\n".join(lines)

def load_client_keys() -> Dict[str, Dict[str, str]]:
    if not os.path.exists(CLIENT_KEYS):
        return {}
    with open(CLIENT_KEYS, "r", encoding="utf-8") as f:
        return json.load(f)

def verify_signature(alg: str, keyid: str, signature_b64: str, message: str) -> bool:
    keys = load_client_keys()
    entry = keys.get(keyid)
    if not entry:
        return False
    if entry.get("alg") != alg:
        return False
    if alg.lower() == "ed25519":
        pub_pem = entry.get("public_key_pem")
        pub_b64 = entry.get("public_key_b64")
        if pub_pem:
            pub = Ed25519PublicKey.from_public_bytes(
                serialization.load_pem_public_key(pub_pem.encode()).public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            )
        elif pub_b64:
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        else:
            return False
        try:
            pub.verify(base64.b64decode(signature_b64), message.encode())
            return True
        except Exception:
            return False
    # Future: ml-dsa via OQS
    return False

def sign_ed25519(private_pem: str, message: str) -> str:
    priv = serialization.load_pem_private_key(private_pem.encode(), password=None)
    assert isinstance(priv, Ed25519PrivateKey)
    sig = priv.sign(message.encode())
    return base64.b64encode(sig).decode()
