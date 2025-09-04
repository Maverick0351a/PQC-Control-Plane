import httpx
from src.signet.config import BINDING_HEADER

URL = "http://localhost:8080/protected"

def test_pch_bad_signature():
    sid = "devsession"
    with httpx.Client() as c:
        r1 = c.get(URL, headers={BINDING_HEADER: sid})
        chall = r1.headers["PCH-Challenge"]
        body = b"{}"
        from tools.pch_client_demo import content_digest, b64
        headers = {
            "content-digest": content_digest(body),
            "content-type": "application/json",
            "pch-challenge": chall,
            "pch-channel-binding": f"tls-session-id=:{b64(sid.encode())}:",
            BINDING_HEADER: sid,
            "signature-input": 'pch=("@method" "@path" "@authority" "content-digest" "pch-challenge" "pch-channel-binding");created=1700000000;keyid="caller-1";alg="ed25519"',
            "signature": 'pch=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"
        }
        r2 = c.post(URL, headers=headers, content=body)
        data = r2.json()["pch"]
        assert data["verified"] is False
        assert data["failure_reason"] == "bad_signature"
