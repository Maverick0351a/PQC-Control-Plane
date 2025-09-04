import argparse
import base64
import time
import httpx
import hashlib
from cryptography.hazmat.primitives import serialization

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()

def content_digest(data: bytes) -> str:
    return f"sha-256=:{b64(hashlib.sha256(data).digest())}:"

def build_signature_base(method, url, headers, components, params, evidence_sha256_hex):
    from urllib.parse import urlparse
    u = urlparse(url)
    path = u.path or "/"
    if u.query:
        path = f"{path}?{u.query}"
    lines = []
    for comp in components:
        lc = comp.lower()
        if lc == "@method":
            val = method.upper()
        elif lc == "@path":
            val = path
        elif lc == "@authority":
            val = headers.get("host", u.netloc)
        elif lc == "content-digest":
            val = headers.get("content-digest", "")
        elif lc == "pch-challenge":
            val = headers.get("pch-challenge", "")
        elif lc == "pch-channel-binding":
            val = headers.get("pch-channel-binding", "")
        elif lc == "evidence-sha-256":
            val = evidence_sha256_hex
        else:
            val = headers.get(lc, "")
        lines.append(f"{lc}: {val}")
    comp_list = " ".join([f'\"{c}\"' for c in components])
    created = params.get("created") or str(int(time.time()))
    keyid = params.get("keyid", "caller-1")
    alg = params.get("alg", "ed25519")
    lines.append(
        f"@signature-params: ({comp_list});created={created};keyid=\"{keyid}\";alg=\"{alg}\""
    )
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--body", default='{"demo":true}')
    ap.add_argument("--key", default="keys/client_demo_sk.pem")
    args = ap.parse_args()

    tls_session_id = "devsession"
    with httpx.Client() as s:
        r1 = s.get(args.url, headers={"X-TLS-Session-ID": tls_session_id})
        if r1.status_code != 401:
            print("Unexpected status", r1.status_code, r1.text)
            return
        pch_challenge = r1.headers.get("PCH-Challenge")
        print("Challenge header received:", pch_challenge)
        print("TLS session id used:", tls_session_id)

        body = args.body.encode()
        headers = {
            "content-digest": content_digest(body),
            "content-type": "application/json",
            "pch-challenge": pch_challenge,
            "pch-channel-binding": f"tls-session-id=:{b64(tls_session_id.encode())}:",
            "X-TLS-Session-ID": tls_session_id,
        }
        components = ["@method","@path","@authority","content-digest","pch-challenge","pch-channel-binding"]
        params = {"created": str(int(time.time())), "keyid":"caller-1", "alg":"ed25519"}
        base = build_signature_base("POST", args.url, headers, components, params, evidence_sha256_hex="")
        with open(args.key, "rb") as f:
            sk = serialization.load_pem_private_key(f.read(), password=None)
        sig = base64.b64encode(sk.sign(base.encode())).decode()
        components_str = " ".join([f'\"{c}\"' for c in components])
        headers["signature-input"] = f"pch=({components_str});created={params['created']};keyid=\"caller-1\";alg=\"ed25519\""
        headers["signature"] = f"pch=:{sig}:"
        r2 = s.post(args.url, headers=headers, content=body)
        print("POST status:", r2.status_code, r2.text)
        if r2.status_code == 200:
            try:
                resp = r2.json()
                print("Server PCH result:", resp.get("pch"))
            except Exception:
                pass

if __name__ == "__main__":
    main()
