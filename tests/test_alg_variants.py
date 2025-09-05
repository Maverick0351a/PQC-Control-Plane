import base64
import json
import os
import time
import pytest
from starlette.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from src.signet.app import app
from src.signet.crypto.signatures import build_signature_base

try:
    import oqs  # type: ignore
    HAS_PQC = True
except Exception:
    HAS_PQC = False


def _issue_challenge(client):
    r1 = client.get("/protected", headers={"X-TLS-Session-ID": "devsession"})
    assert r1.status_code == 401
    return r1.headers["PCH-Challenge"]


def _post_signed(client, alg: str, keyid: str, sig_b64: str, created: str, body: bytes, chal: str):
    b64 = lambda b: base64.b64encode(b).decode()
    headers = {
        "content-digest": f"sha-256=:{b64(__import__('hashlib').sha256(body).digest())}:",
        "content-type": "application/json",
        "pch-challenge": chal,
        "pch-channel-binding": f"tls-session-id=:{b64('devsession'.encode())}:",
        "x-tls-session-id": "devsession",
    }
    comps = ["@method","@path","@authority","content-digest","pch-challenge","pch-channel-binding"]
    params = {"created": created, "keyid": keyid, "alg": alg}
    base = build_signature_base(
        request=client.build_request("POST","/protected",headers=headers),
        components=comps,
        params=params,
        evidence_sha256_hex="",
    )
    components_str = " ".join([f'"{c}"' for c in comps])
    headers["signature-input"] = f"pch=({components_str});created={created};keyid=\"{keyid}\";alg=\"{alg}\""
    headers["signature"] = f"pch=:{sig_b64}:"
    return client.post("/protected", headers=headers, content=body)


def test_alg_ed25519_ok():
    client = TestClient(app)
    chal = _issue_challenge(client)
    body = b'{"demo":true}'
    created = str(int(time.time()))
    # Build base to sign
    b64f = lambda b: base64.b64encode(b).decode()
    headers_tmp = {
        "content-digest": f"sha-256=:{b64f(__import__('hashlib').sha256(body).digest())}:",
        "content-type": "application/json",
        "pch-challenge": chal,
        "pch-channel-binding": f"tls-session-id=:{b64f('devsession'.encode())}:",
        "x-tls-session-id": "devsession",
    }
    comps = ["@method","@path","@authority","content-digest","pch-challenge","pch-channel-binding"]
    params = {"created": created, "keyid": "caller-1", "alg": "ed25519"}
    base = build_signature_base(
        request=client.build_request("POST","/protected",headers=headers_tmp),
        components=comps,
        params=params,
        evidence_sha256_hex="",
    )
    sk = serialization.load_pem_private_key(open("keys/client_demo_sk.pem","rb").read(), password=None)
    sig_b64 = b64f(sk.sign(base.encode()))
    r2 = _post_signed(client, "ed25519", "caller-1", sig_b64, created, body, chal)
    assert r2.status_code == 200
    assert r2.json()["pch"]["verified"] is True


def test_alg_ed25519_bad_sig():
    client = TestClient(app)
    chal = _issue_challenge(client)
    body = b'{"demo":true}'
    created = str(int(time.time()))
    # Intentionally bogus signature
    bad_sig = base64.b64encode(b"not-a-real-sig").decode()
    r2 = _post_signed(client, "ed25519", "caller-1", bad_sig, created, body, chal)
    assert r2.status_code == 200
    assert r2.json()["pch"]["verified"] is False


@pytest.mark.skipif(not HAS_PQC, reason="pyoqs not installed")
def test_alg_mldsa_placeholder():  # pragma: no cover - optional path
    # Placeholder: real signing requires secret key bytes; focus on verify API presence.
    # We expect verification False because config has empty public key.
    client = TestClient(app)
    chal = _issue_challenge(client)
    body = b'{}'
    created = str(int(time.time()))
    fake_sig = base64.b64encode(b"zeros").decode()
    r = _post_signed(client, "ml-dsa-65", "caller-ml", fake_sig, created, body, chal)
    assert r.status_code == 200
    assert r.json()["pch"]["sig_alg"] == "ml-dsa-65"


@pytest.mark.skipif(not HAS_PQC, reason="pyoqs not installed")
def test_alg_hybrid_placeholder():  # pragma: no cover - optional path
    client = TestClient(app)
    chal = _issue_challenge(client)
    body = b'{}'
    created = str(int(time.time()))
    container = {"alg": "ecdsa-p256+ml-dsa-65", "sigs": {"ecdsa-p256": "AAAA", "ml-dsa-65": "BBBB"}}
    fake_sig = base64.b64encode(json.dumps(container).encode()).decode()
    r = _post_signed(client, "ecdsa-p256+ml-dsa-65", "caller-hybrid", fake_sig, created, body, chal)
    assert r.status_code == 200
    assert r.json()["pch"]["sig_alg"] == "ecdsa-p256+ml-dsa-65"
