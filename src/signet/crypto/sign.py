"""Signing helpers for PCH message base supporting multiple algorithms.

These helpers are client-side oriented but may be reused in tests.
"""
from __future__ import annotations

import base64
import json
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec

try:  # optional
    import oqs  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    oqs = None  # type: ignore


def sign_message(alg: str, private_key_pem: str, message: str, extra: Dict[str, Any] | None = None) -> str:
    alg_l = alg.lower()
    msg_bytes = message.encode()
    if alg_l == "ed25519":
        sk = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        assert isinstance(sk, ed25519.Ed25519PrivateKey)
        return base64.b64encode(sk.sign(msg_bytes)).decode()
    if alg_l == "ml-dsa-65":
        if oqs is None:
            raise RuntimeError("pyoqs not installed; cannot sign with ml-dsa-65")
        # Expect extra["ml_dsa_65_sk_b64"] if direct key provided else PEM path
        if not extra or "ml_dsa_65_sk_b64" not in extra:
            raise RuntimeError("ml-dsa-65 requires extra['ml_dsa_65_sk_b64'] base64 secret key")
        sk_bytes = base64.b64decode(extra["ml_dsa_65_sk_b64"])  # Dilithium3 secret key bytes
        with oqs.Signature("Dilithium3") as signer:  # pragma: no cover
            sig = signer.sign(msg_bytes, sk_bytes)
        return base64.b64encode(sig).decode()
    if alg_l == "ecdsa-p256+ml-dsa-65":
        if oqs is None:
            raise RuntimeError("pyoqs not installed; cannot sign hybrid without pqc lib")
        if not extra or "ecdsa_p256_private_pem" not in extra or "ml_dsa_65_sk_b64" not in extra:
            raise RuntimeError("hybrid requires extra keys: ecdsa_p256_private_pem & ml_dsa_65_sk_b64")
        # ECDSA
        ecdsa_sk = serialization.load_pem_private_key(extra["ecdsa_p256_private_pem"].encode(), password=None)
        assert isinstance(ecdsa_sk, ec.EllipticCurvePrivateKey)
        sig1 = ecdsa_sk.sign(msg_bytes, ec.ECDSA(hashes.SHA256()))
        # ML-DSA
        sk_bytes = base64.b64decode(extra["ml_dsa_65_sk_b64"])
        with oqs.Signature("Dilithium3") as signer:  # pragma: no cover
            sig2 = signer.sign(msg_bytes, sk_bytes)
        container = {
            "alg": "ecdsa-p256+ml-dsa-65",
            "sigs": {
                "ecdsa-p256": base64.b64encode(sig1).decode(),
                "ml-dsa-65": base64.b64encode(sig2).decode(),
            },
        }
        return base64.b64encode(json.dumps(container).encode()).decode()
    raise ValueError(f"Unsupported alg: {alg}")


__all__ = ["sign_message"]
