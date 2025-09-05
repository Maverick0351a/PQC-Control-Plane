import base64
import time
from starlette.testclient import TestClient
from src.signet.app import app

def test_pch_bad_signature():
    client = TestClient(app)
    r1 = client.get("/protected")
    chal = r1.headers["PCH-Challenge"]
    tls_id = "devsession"
    body = b'{}'
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
    build_signature_base(
        request=client.build_request("POST", "/protected", headers=headers),
        components=comps,
        params=params,
        evidence_sha256_hex="",
    )
    # Corrupt signature
    headers["signature-input"] = (
        "pch=(" + " ".join(f'\"{c}\"' for c in comps) + f");created={params['created']};keyid=\"caller-1\";alg=\"ed25519\""
    )
    headers["signature"] = "pch=:AAAAAAA:"
    r2 = client.post("/protected", headers=headers, content=body)
    assert r2.status_code == 200
    assert r2.json()["pch"]["verified"] is False
    assert r2.json()["pch"]["failure_reason"] == "bad_signature"
