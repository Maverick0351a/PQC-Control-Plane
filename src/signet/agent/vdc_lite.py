import cbor2, hashlib, os, glob
from .cose_lite import ed25519_sign, ed25519_verify, Sign1

# VDC = CBOR map { 2: meta, 3: payloads[], 4: receipts[], 5: anchors?, 6: timestamps? }
# Minimal deterministic CBOR: sort keys, canonical integers. cbor2 supports canonical enc.

def sha384(b: bytes) -> bytes:
    return hashlib.sha384(b).digest()

def det_cbor(obj) -> bytes:
    return cbor2.dumps(obj, canonical=True)

def make_vdc(meta: dict, payloads: list[dict], sk_path: str) -> bytes:
    meta_cbor = det_cbor(meta)
    meta_digest = sha384(meta_cbor)

    # compute payload digests
    digests = []
    for p in payloads:
        if "data_b64" in p:
            # In practice you may store bytes; here assume pre-hashed in p["sha384"]
            digests.append(bytes.fromhex(p["sha384"]))
        else:
            digests.append(bytes.fromhex(p["sha384"]))

    sig_base = det_cbor({
        "type":"VDC-SIG/v1",
        "meta_sha384": meta_digest,
        "payload_sha384_list": digests
    })

    sign1 = ed25519_sign(sig_base, {"alg":"Ed25519","v":"1"}, sk_path)
    vdc_map = {2: meta, 3: payloads, 4: [{"sign1": {
        "protected": sign1.protected, "payload": sign1.payload, "sig": sign1.signature
    }}]}
    return det_cbor(vdc_map)

def verify_vdc(vdc_bytes: bytes, trust_dir: str) -> bool:
    m = cbor2.loads(vdc_bytes)
    meta = m.get(2); payloads = m.get(3); receipts = m.get(4, [])
    meta_digest = sha384(det_cbor(meta))
    digests = [bytes.fromhex(p["sha384"]) for p in payloads]
    sig_base = det_cbor({"type":"VDC-SIG/v1","meta_sha384":meta_digest,"payload_sha384_list":digests})

    # Take first receipt (Ed25519 Sign1)
    s = receipts[0]["sign1"]
    sign1 = Sign1(protected=s["protected"], payload=sig_base, signature=s["sig"])
    for key_path in glob.glob(os.path.join(trust_dir, "*.pub")):
        with open(key_path, "rb") as f:
            pk = f.read()
        if ed25519_verify(sign1, pk):
            return True
    return False
