from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable, Optional


@runtime_checkable
class Signer(Protocol):
    def sign(self, key_ref: str, msg: bytes, alg: str) -> bytes: ...
    def pubkey(self, key_ref: str) -> bytes: ...


@dataclass
class PycaSigner:
    """Local dev signer (DEV-ONLY). key_ref is a PEM file path.

    Alg: 'ed25519' only.
    """

    def sign(self, key_ref: str, msg: bytes, alg: str) -> bytes:
        if alg.lower() != "ed25519":
            raise ValueError("PycaSigner supports ed25519 only")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with open(key_ref, "rb") as f:
            sk = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(sk, Ed25519PrivateKey):
            raise ValueError("expected Ed25519 private key")
        return sk.sign(msg)

    def pubkey(self, key_ref: str) -> bytes:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with open(key_ref, "rb") as f:
            sk = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(sk, Ed25519PrivateKey):
            raise ValueError("expected Ed25519 private key")
        pk = sk.public_key()
        return pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


@dataclass
class OqsSigner:
    """Optional PQC signer (ml-dsa-65). Requires liboqs python bindings.

    key_ref may be a file path to a secret key blob or a logical ref. This is a stub
    to illustrate interface; wiring/load is environment-specific.
    """

    def __post_init__(self):
        try:
            import oqs  # noqa: F401
        except Exception as e:  # pragma: no cover
            raise RuntimeError("liboqs not available") from e

    def sign(self, key_ref: str, msg: bytes, alg: str) -> bytes:  # pragma: no cover
        if alg.lower() not in ("ml-dsa-65", "dilithium3"):
            raise ValueError("OqsSigner supports ml-dsa-65 (Dilithium3) only")
        import oqs
        # For demonstration: this assumes a serialized secret key exists at key_ref
        with open(key_ref, "rb") as f:
            sk = f.read()
        with oqs.Signature("Dilithium3") as sig:
            sig.set_secret_key(sk)
            return sig.sign(msg)

    def pubkey(self, key_ref: str) -> bytes:  # pragma: no cover
        import oqs
        with open(key_ref + ".pub", "rb") as f:
            return f.read()


@dataclass
class KmsSigner:
    """Production signer placeholder. Integrate with PKCS#11 or cloud KMS.

    key_ref is a logical key id/arn/uri. This class should call out to KMS/HSM to
    produce raw signatures without ever exporting private keys.
    """
    endpoint: Optional[str] = None

    def sign(self, key_ref: str, msg: bytes, alg: str) -> bytes:  # pragma: no cover
        raise NotImplementedError("Integrate with your KMS/HSM client here")

    def pubkey(self, key_ref: str) -> bytes:  # pragma: no cover
        raise NotImplementedError("Return raw public key bytes from KMS/HSM")
