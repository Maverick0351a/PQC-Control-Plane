import httpx
from src.signet.config import BINDING_HEADER

URL = "http://localhost:8080/protected"

def _sign(chall, sid):
    body = b"{}"
    from tools.pch_client_demo import content_digest, b64, build_signature_base
    headers = {
        "content-digest": content_digest(body),
        "content-type": "application/json",
        "pch-challenge": chall,
        "pch-channel-binding": f"tls-session-id=:{b64(sid.encode())}:",
        BINDING_HEADER: sid
    }
    comps = ["@method","@path","@authority","content-digest","pch-challenge","pch-channel-binding"]
    params = {"created": "1700000000", "keyid":"caller-1", "alg":"ed25519"}
    base = build_signature_base("POST", URL, headers, comps, params, evidence_sha256_hex="")
    import base64 as _b
    from cryptography.hazmat.primitives import serialization
    with open("keys/client_demo_sk.pem","rb") as f:
        sk = serialization.load_pem_private_key(f.read(), password=None)
    sig = _b.b64encode(sk.sign(base.encode())).decode()
    headers["signature-input"] = 'pch=("@method" "@path" "@authority" "content-digest" "pch-challenge" "pch-channel-binding");created=1700000000;keyid="caller-1";alg="ed25519"'
    headers["signature"] = f"pch=:{sig}:"
    return headers

def test_pch_replay():
    sid = "devsession"
    with httpx.Client() as c:
        r1 = c.get(URL, headers={BINDING_HEADER: sid})
        chall = r1.headers["PCH-Challenge"]
        h = _sign(chall, sid)
        r2 = c.post(URL, headers=h, content=b"{}")
        assert r2.json()["pch"]["verified"] is True
        r3 = c.post(URL, headers=h, content=b"{}")
        assert r3.json()["pch"]["verified"] is False
        assert r3.json()["pch"]["failure_reason"] == "nonce_replay"
