# Tiny COSE_Sign1 (Ed25519) for CBOR payloads
import cbor2, hashlib, nacl.signing, nacl.encoding
from dataclasses import dataclass

@dataclass
class Sign1:
    protected: dict
    payload: bytes
    signature: bytes

def ed25519_sign(payload: bytes, protected: dict, sk_pem_path: str) -> Sign1:
    with open(sk_pem_path, "rb") as f:
        raw = f.read()
    # Expect raw 32-byte seed in PEM-like file; adapt as needed
    seed = raw[-32:] if len(raw) >= 32 else raw
    signer = nacl.signing.SigningKey(seed)
    to_be_signed = cbor2.dumps(["Signature1", cbor2.dumps(protected), b"", payload])
    sig = signer.sign(to_be_signed).signature
    return Sign1(protected=protected, payload=payload, signature=sig)

def ed25519_verify(sign1: Sign1, pk_bytes: bytes) -> bool:
    verify_key = nacl.signing.VerifyKey(pk_bytes)
    to_be_signed = cbor2.dumps(["Signature1", cbor2.dumps(sign1.protected), b"", sign1.payload])
    try:
        verify_key.verify(to_be_signed, sign1.signature)
        return True
    except Exception:
        return False
