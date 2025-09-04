import base64
import time
from starlette.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from src.signet.app import app

def test_pch_ok(tmp_path, monkeypatch):
    # Using generated keys from tools/gen_ed25519 (import side effects)
    client = TestClient(app)
    tls_id = "devsession"
    r1 = client.get("/protected", headers={"X-TLS-Session-ID": tls_id})
    assert r1.status_code == 401
    chal = r1.headers["PCH-Challenge"]
    body = b'{"demo":true}'
    def b64(b): return base64.b64encode(b).decode()
    headers = {
        "content-digest": f"sha-256=:{b64(__import__('hashlib').sha256(body).digest())}:",
        "content-type": "application/json",
        "pch-challenge": chal,
        "pch-channel-binding": f"tls-session-id=:{b64(tls_id.encode())}:",
        "x-tls-session-id": tls_id
    }
    comps = ["@method","@path","@authority","content-digest","pch-challenge","pch-channel-binding"]
    params = {"created": str(int(time.time())), "keyid":"caller-1","alg":"ed25519"}
    from src.signet.crypto.signatures import build_signature_base
    base = build_signature_base(request=client.build_request("POST","/protected",headers=headers), components=comps, params=params, evidence_sha256_hex="")
    sk = serialization.load_pem_private_key(open("keys/client_demo_sk.pem","rb").read(), password=None)
    sig = b64(sk.sign(base.encode()))
    # Properly format the Signature-Input listing each component separately
    components_str = " ".join([f'"{c}"' for c in comps])
    headers["signature-input"] = (
        f"pch=({components_str});created={params['created']};keyid=\"caller-1\";alg=\"ed25519\""
    )
    headers["signature"] = f"pch=:{sig}:"
    r2 = client.post("/protected", headers=headers, content=body)
    assert r2.status_code == 200
    assert r2.json()["pch"]["verified"] is True
