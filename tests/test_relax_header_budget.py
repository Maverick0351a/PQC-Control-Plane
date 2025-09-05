import base64
import time
import json
from starlette.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from src.signet.app import app
from src.signet.controller.plan import set_utility_context, clear_utility_context


def build_signed(client, chal, body_bytes, evidence_b64, oversize_headers=False):
    def b64f(b: bytes) -> str:
        return base64.b64encode(b).decode()
    tls_id = "devsession"
    headers = {
        "content-digest": f"sha-256=:{b64f(__import__('hashlib').sha256(body_bytes).digest())}:",
        "content-type": "application/json",
        "pch-challenge": chal,
        "pch-channel-binding": f"tls-session-id=:{b64f(tls_id.encode())}:",
        "x-tls-session-id": tls_id,
        "evidence": f":{evidence_b64}:",
    }
    if oversize_headers:
        # Add dummy padding headers to exceed limit
        pad_val = "X" * 5000
        headers["x-pad-a"] = pad_val
    comps = ["@method","@path","@authority","content-digest","pch-challenge","pch-channel-binding"]
    params = {"created": str(int(time.time())), "keyid": "caller-1", "alg": "ed25519"}
    from src.signet.crypto.signatures import build_signature_base
    base = build_signature_base(
        request=client.build_request("POST","/protected",headers=headers),
        components=comps,
        params=params,
        evidence_sha256_hex="",
    )
    sk = serialization.load_pem_private_key(open("keys/client_demo_sk.pem","rb").read(), password=None)
    sig = b64f(sk.sign(base.encode()))
    headers["signature-input"] = "pch=(\"@method\" \"@path\" \"@authority\" \"content-digest\" \"pch-challenge\" \"pch-channel-binding\");created=" + params['created'] + ";keyid=\"caller-1\";alg=\"ed25519\""
    headers["signature"] = f"pch=:{sig}:"
    return headers


def test_relax_header_budget_flow():
    client = TestClient(app)
    # Step 1 challenge
    r1 = client.get("/protected", headers={"X-TLS-Session-ID":"devsession"})
    assert r1.status_code == 401
    assert "relax-header-budget" in r1.headers.get("WWW-Authenticate","")
    chal = r1.headers["PCH-Challenge"]
    # Oversize evidence header triggers 431 (Closed breaker, no relax)
    big_evidence = json.dumps({"blob": "Y"*6000})
    headers = build_signed(client, chal, b'{"demo":true}', base64.b64encode(big_evidence.encode()).decode(), oversize_headers=True)
    r2 = client.post("/protected", headers=headers, content=b'{"demo":true}')
    assert r2.status_code in (428,431)
    # Simulate utility context forcing relax
    set_utility_context({"header_budget_total": 4096, "header_total_bytes": 5000})
    # Re-challenge (nonce) then send relaxed mode: evidence removed from headers; supply body evidence
    r3 = client.get("/protected", headers={"X-TLS-Session-ID":"devsession"})
    chal2 = r3.headers["PCH-Challenge"]
    relaxed_body = json.dumps({"demo":True, "evidence": json.loads(big_evidence)})
    # Build digest etc without evidence header now
    def b64f(b: bytes) -> str:
        return base64.b64encode(b).decode()
    headers2 = {
        "content-digest": f"sha-256=:{b64f(__import__('hashlib').sha256(relaxed_body.encode()).digest())}:",
        "content-type": "application/json",
        "pch-challenge": chal2,
        "pch-channel-binding": f"tls-session-id=:{b64f('devsession'.encode())}:",
        "x-tls-session-id": "devsession",
        "evidence-sha-256": __import__('hashlib').sha256(json.dumps(json.loads(big_evidence),separators=(",",":")).encode()).hexdigest(),
    }
    comps = ["@method","@path","@authority","content-digest","pch-challenge","pch-channel-binding"]
    params = {"created": str(int(time.time())), "keyid": "caller-1", "alg": "ed25519"}
    from src.signet.crypto.signatures import build_signature_base
    base2 = build_signature_base(
        request=client.build_request("POST","/protected",headers=headers2),
        components=comps,
        params=params,
        evidence_sha256_hex=headers2["evidence-sha-256"],
    )
    sk = serialization.load_pem_private_key(open("keys/client_demo_sk.pem","rb").read(), password=None)
    sig2 = b64f(sk.sign(base2.encode()))
    headers2["signature-input"] = "pch=(\"@method\" \"@path\" \"@authority\" \"content-digest\" \"pch-challenge\" \"pch-channel-binding\");created=" + params['created'] + ";keyid=\"caller-1\";alg=\"ed25519\""
    headers2["signature"] = f"pch=:{sig2}:"
    r4 = client.post("/protected", headers=headers2, content=relaxed_body.encode())
    assert r4.status_code == 200
    pch_res = r4.json()["pch"]
    assert pch_res["relax_mode"] is True
    assert pch_res["evidence_ref"] == headers2["evidence-sha-256"]
    clear_utility_context()
