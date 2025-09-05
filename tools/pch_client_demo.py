import argparse
import base64
import time
import httpx
import hashlib
from cryptography.hazmat.primitives import serialization
from urllib.parse import urlparse

try:  # optional
    import oqs  # type: ignore
except Exception:  # pragma: no cover
    oqs = None  # type: ignore

from src.signet.crypto.sign import sign_message

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()

def content_digest(data: bytes) -> str:
    return f"sha-256=:{b64(hashlib.sha256(data).digest())}:"

def build_signature_base(method, url, headers, components, params, evidence_sha256_hex, override_authority=None):
    # Minimal base builder matching server's logic
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
            # Allow explicit override; else prefer Host header (includes port), else netloc/hostname
            val = override_authority or headers.get("host") or u.netloc or u.hostname
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
    comp_list = " ".join([f'"{c}"' for c in components])
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
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification (dev only)")
    ap.add_argument("--authority", help="override @authority in signature base (does NOT change actual Host header)")
    ap.add_argument("--binding", choices=["tls-session-id","tls-exporter"], default="tls-session-id")
    ap.add_argument("--alg", choices=["ed25519","ml-dsa-65","ecdsa-p256+ml-dsa-65"], default="ed25519")
    ap.add_argument("--ecdsa-key", help="Path to ECDSA P-256 PEM (for hybrid)")
    ap.add_argument("--mldsa-sk-b64", help="Base64 Dilithium3 secret key (for ml-dsa or hybrid)")
    ap.add_argument("--evidence-mode", choices=["header","body"], default="header", help="Where to place evidence JSON")
    ap.add_argument("--evidence", help="Raw evidence JSON (defaults to small demo)")
    args = ap.parse_args()

    # Step 1: Obtain challenge (always send stable synthetic binding id for dev)
    binding_id = "devsession"
    with httpx.Client(verify=not args.insecure) as s:
        initial_headers = {"X-TLS-Session-ID": binding_id}
        if args.binding == "tls-exporter":
            # First hop through envoy; exporter header added by proxy. We may need /echo/headers to read it.
            pass
        r1 = s.get(args.url, headers=initial_headers)
        if r1.status_code != 401:
            print("Unexpected status", r1.status_code, r1.text)
            return
        pch_challenge = r1.headers.get("PCH-Challenge")
        debug_tls = r1.headers.get("X-Debug-TLS-Session-ID")
        print("Challenge header received:", pch_challenge)
        print("TLS session id (server debug):", debug_tls or "n/a")
        print("Binding id used (X-TLS-Session-ID & channel-binding):", binding_id)

        # Step 2: Signed POST with same binding id (nonce key matches)
        # Build evidence
        import json as _json
        evidence_obj = _json.loads(args.evidence) if args.evidence else {"demo": True, "ts": int(time.time())}
        evidence_json = _json.dumps(evidence_obj, separators=(",", ":"))
        body_payload = args.body
        if args.evidence_mode == "body":
            # Embed evidence inside body json envelope
            try:
                base_obj = _json.loads(body_payload)
            except Exception:
                base_obj = {"demo": True}
            base_obj["evidence"] = evidence_obj
            body_payload = _json.dumps(base_obj, separators=(",", ":"))
        body = body_payload.encode()
        if args.binding == "tls-exporter":
            # Attempt to fetch exporter via /echo/headers diagnostic (same host)
            echo_url = args.url.rsplit('/',1)[0] + "/echo/headers"
            try:
                echo = s.get(echo_url, headers={"X-TLS-Session-ID": binding_id})
                exporter = echo.json().get("headers",{}).get("x-tls-exporter")
            except Exception:
                exporter = None
            if not exporter:
                print("Could not obtain tls-exporter header via echo endpoint; aborting")
                return
            binding_line = f"tls-exporter=:{exporter}:"
            base_headers = {
                "content-digest": content_digest(body),
                "content-type": "application/json",
                "pch-challenge": pch_challenge,
                "pch-channel-binding": binding_line,
                "X-TLS-Exporter": exporter,
            }
        else:
            base_headers = {
                "content-digest": content_digest(body),
                "content-type": "application/json",
                "pch-challenge": pch_challenge,
                "pch-channel-binding": f"tls-session-id=:{b64(binding_id.encode())}:",
                "X-TLS-Session-ID": binding_id,
            }
        # Evidence placement
        if args.evidence_mode == "header":
            # Provide evidence header base64 (sha-256 already covered in digest lines)
            ev_b64 = base64.b64encode(evidence_json.encode()).decode()
            base_headers["evidence"] = f":{ev_b64}:"
        else:
            # Include only evidence-sha-256 header for relaxed mode
            import hashlib as _hashlib
            ev_hex = _hashlib.sha256(evidence_json.encode()).hexdigest()
            base_headers["evidence-sha-256"] = ev_hex
        req = s.build_request("POST", args.url, headers=base_headers, content=body)
        base_headers["host"] = req.headers.get("host")
        components = ["@method","@path","@authority","content-digest","pch-challenge","pch-channel-binding"]
        params = {"created": str(int(time.time())), "keyid": "caller-1", "alg": args.alg}
        base = build_signature_base(
            "POST",
            str(req.url),
            base_headers,
            components,
            params,
            evidence_sha256_hex="",
            override_authority=args.authority,
        )
        print("Client signature-base:\n" + base)
        extra = {}
        if args.alg == "ed25519":
            with open(args.key, "rb") as f:
                sk = serialization.load_pem_private_key(f.read(), password=None)
            sig = base64.b64encode(sk.sign(base.encode())).decode()
        elif args.alg == "ml-dsa-65":
            if not args.mldsa_sk_b64:
                print("--mldsa-sk-b64 required for ml-dsa-65")
                return
            extra["ml_dsa_65_sk_b64"] = args.mldsa_sk_b64
            sig = sign_message("ml-dsa-65", "", base, extra)
        elif args.alg == "ecdsa-p256+ml-dsa-65":
            if not args.ecdsa_key or not args.mldsa_sk_b64:
                print("--ecdsa-key and --mldsa-sk-b64 required for hybrid")
                return
            extra["ecdsa_p256_private_pem"] = open(args.ecdsa_key,"r",encoding="utf-8").read()
            extra["ml_dsa_65_sk_b64"] = args.mldsa_sk_b64
            sig = sign_message("ecdsa-p256+ml-dsa-65", "", base, extra)
        else:
            print("Unsupported alg")
            return
        components_str = " ".join([f'"{c}"' for c in components])
        req.headers["signature-input"] = (
            f"pch=({components_str});created={params['created']};keyid=\"caller-1\";alg=\"{args.alg}\""
        )
        req.headers["signature"] = f"pch=:{sig}:"
        r2 = s.send(req)
        if r2.status_code in (428,431) and args.evidence_mode == "header":
            print(f"Server responded {r2.status_code}; retrying in relax header budget mode (evidence body)")
            # Switch to body mode automatically
            args.evidence_mode = "body"
            return main()  # recursive simple restart
        print("POST status:", r2.status_code, r2.text)
        if r2.status_code == 200:
            try:
                print("Server PCH result:", r2.json().get("pch"))
            except Exception:
                pass

if __name__ == "__main__":
    main()
