"""Algorithm registry for PCH message signing.

Supported algorithms:
  - ed25519
  - ml-dsa-65 (Dilithium3 via pyoqs / liboqs)
  - ecdsa-p256+ml-dsa-65 (hybrid: both must verify)

The registry exposes two primary helpers:
  get_public_material(key_entry) -> structure with usable public keys
  verify_alg(alg, key_entry, signature_b64, message) -> bool

Hybrid signature encoding:
  The Signature header still carries a base64 value. For the hybrid alg the
  decoded UTF-8 bytes MUST be a JSON document of the form:
      {"alg":"ecdsa-p256+ml-dsa-65","sigs":{"ecdsa-p256":"<b64>","ml-dsa-65":"<b64>"}}
  Each inner value is the base64 of the raw signature for that sub‑algorithm.

Client key entry expectations (config/clients.json):
  ed25519: { "alg":"ed25519", "public_key_b64" | "public_key_pem": "..." }
  ml-dsa-65: { "alg":"ml-dsa-65", "public_key_b64": "..." }
  hybrid: { "alg":"ecdsa-p256+ml-dsa-65", "ecdsa_p256_pem": "-----BEGIN PUBLIC KEY-----...",
            "ml_dsa_65_pk_b64": "..." }

If pyoqs (import oqs) is not installed, ml-dsa algorithms raise a clear error.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.exceptions import InvalidSignature


class PQCUnavailable(Exception):
    """Raised when a PQC algorithm is requested but pyoqs/oqs is missing."""


def _require_pqc():
    try:  # pragma: no cover - import side effect
        import oqs  # type: ignore
        return oqs
    except Exception as e:  # pragma: no cover
        raise PQCUnavailable(
            "pyoqs (oqs) package not available. Install with 'pip install pyoqs' to use ml-dsa-65"
        ) from e


@dataclass
class PublicMaterial:
    alg: str
    ed25519_pk: ed25519.Ed25519PublicKey | None = None
    ml_dsa_65_pk: bytes | None = None
    ecdsa_p256_pk: ec.EllipticCurvePublicKey | None = None


def get_public_material(entry: Dict[str, Any]) -> PublicMaterial:
    alg = entry.get("alg", "").lower()
    pm = PublicMaterial(alg=alg)
    if alg == "ed25519":
        pem = entry.get("public_key_pem")
        b64k = entry.get("public_key_b64")
        if pem:
            pk_obj = serialization.load_pem_public_key(pem.encode())
            pm.ed25519_pk = ed25519.Ed25519PublicKey.from_public_bytes(
                pk_obj.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )
        elif b64k:
            pm.ed25519_pk = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(b64k))
    elif alg == "ml-dsa-65":
        pm.ml_dsa_65_pk = base64.b64decode(entry.get("public_key_b64", "")) if entry.get("public_key_b64") else None
    elif alg == "ecdsa-p256+ml-dsa-65":
        ecdsa_pem = entry.get("ecdsa_p256_pem")
        if ecdsa_pem:
            pm.ecdsa_p256_pk = serialization.load_pem_public_key(ecdsa_pem.encode())  # type: ignore
        pm.ml_dsa_65_pk = base64.b64decode(entry.get("ml_dsa_65_pk_b64", "")) if entry.get("ml_dsa_65_pk_b64") else None
    return pm


def verify_alg(alg: str, entry: Dict[str, Any], signature_b64: str, message: str) -> bool:
    alg_l = alg.lower()
    pm = get_public_material(entry)
    msg_bytes = message.encode()
    if alg_l == "ed25519":
        if not pm.ed25519_pk:
            return False
        try:
            pm.ed25519_pk.verify(base64.b64decode(signature_b64), msg_bytes)
            return True
        except Exception:
            return False
    if alg_l == "ml-dsa-65":
        if not pm.ml_dsa_65_pk:
            return False
        oqs = _require_pqc()
        try:  # pragma: no cover - depends on optional lib
            with oqs.Signature("Dilithium3") as verifier:
                return verifier.verify(msg_bytes, base64.b64decode(signature_b64), pm.ml_dsa_65_pk)
        except Exception:
            return False
    if alg_l == "ecdsa-p256+ml-dsa-65":
        # Hybrid JSON container
        try:
            json_bytes = base64.b64decode(signature_b64)
            container = json.loads(json_bytes.decode())
            sigs = container.get("sigs", {})
            sig_ecdsa_b64 = sigs.get("ecdsa-p256")
            sig_mldsa_b64 = sigs.get("ml-dsa-65")
        except Exception:
            return False
        # Verify ECDSA part
        if not (pm.ecdsa_p256_pk and sig_ecdsa_b64):
            return False
        ecdsa_ok = False
        try:
            pm.ecdsa_p256_pk.verify(
                base64.b64decode(sig_ecdsa_b64),
                msg_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
            ecdsa_ok = True
        except InvalidSignature:
            ecdsa_ok = False
        except Exception:
            return False
        if not ecdsa_ok:
            return False
        # Verify ML-DSA part
        if not (pm.ml_dsa_65_pk and sig_mldsa_b64):
            return False
        oqs = _require_pqc()
        try:  # pragma: no cover
            with oqs.Signature("Dilithium3") as verifier:
                return verifier.verify(msg_bytes, base64.b64decode(sig_mldsa_b64), pm.ml_dsa_65_pk)
        except Exception:
            return False
    return False


__all__ = ["verify_alg", "get_public_material", "PQCUnavailable"]
