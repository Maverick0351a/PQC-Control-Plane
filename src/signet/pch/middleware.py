from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp
import base64

from ..config import FEATURE_PCH, PCH_ADVISORY, BINDING_HEADER, BINDING_TYPE
from ..crypto.digest import parse_content_digest
from ..crypto.signatures import parse_signature_input, build_signature_base, verify_signature
from ..pch.nonce_store import NonceStore
from ..pch.evidence import evidence_sha256_hex_from_header
from ..utils.logging import get_logger

log = get_logger()
nonce_store = NonceStore()

def feature_enabled() -> bool:
    return FEATURE_PCH

class PCHMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request, call_next):
        # Enforce Content-Digest on write methods (advisory errors recorded in receipt)
        content_ok = True
        if request.method.upper() in ("POST", "PUT", "PATCH"):
            cd = request.headers.get("content-digest")
            body = await request.body()
            try:
                parsed = parse_content_digest(cd) if cd else None
                if not cd or parsed != __import__("hashlib").sha256(body).digest():
                    content_ok = False
            except Exception:
                content_ok = False

        # PCH-Lite process
        headers = {k.lower(): v for k, v in request.headers.items()}
        sig_input = headers.get("signature-input")
        signature = headers.get("signature")
        # pch_challenge_hdr not needed after issuing nonce; retained for potential future debug
        pch_challenge_hdr = headers.get("pch-challenge")  # noqa: F841
        pch_binding_hdr = headers.get("pch-channel-binding")

        client_ip = request.client.host if request.client else "unknown"
        route = request.url.path
        tls_id = headers.get(BINDING_HEADER.lower(), "")
    log.info(f"PCH middleware observed {BINDING_HEADER}={tls_id if tls_id else '(none)'}")

        if not sig_input or not signature:
            # issue challenge
            nonce = nonce_store.issue(route=route, client_ip=client_ip, tls_id=tls_id or "dev")
            challenge_val = f":{nonce}:"
            log.info(f"Issuing PCH challenge nonce for {client_ip} route={route} tls_id={(tls_id or 'dev')}")
            headers = {
                "WWW-Authenticate": f'PCH realm="pqc", algs="ed25519", challenge=":{nonce}:"',
                "PCH-Challenge": challenge_val,
                "Cache-Control": "no-store",
            }
            if PCH_ADVISORY:
                # Record advisory failure and continue to app with 401 on GET /protected
                request.state.pch_result = {
                    "present": False, "verified": False, "failure_reason": "missing_signature", "channel_binding": BINDING_TYPE
                }
                # If client explicitly asked /protected without signature, return 401 challenge immediately
                if request.url.path.startswith("/protected"):
                    return JSONResponse({"error":"PCH required","hint":"sign request and retry"}, status_code=401, headers=headers)
                response = await call_next(request)
                for k,v in headers.items():
                    response.headers[k] = v
                return response
            else:
                return JSONResponse({"error": "PCH required"}, status_code=401, headers=headers)

        # Parse signature-input
        try:
            label, components, params = parse_signature_input(sig_input)
        except Exception:
            request.state.pch_result = {"present": True, "verified": False, "failure_reason": "bad_signature_input", "channel_binding": BINDING_TYPE}
            if not PCH_ADVISORY:
                return JSONResponse({"error":"bad signature-input"}, status_code=401)
            return await call_next(request)

        # Extract signature for label
        sig_map = {}
        try:
            # "pch=:<b64>:" style or 'pch=:....:'; allow raw base64 too
            parts = [p.strip() for p in signature.split(",")]
            for part in parts:
                if "=" not in part:
                    continue
                k, v = part.split("=", 1)
                k = k.strip()
                v = v.strip()
                if v.startswith(":") and v.endswith(":"):
                    v = v[1:-1]
                if k == label:
                    sig_map[label] = v
        except Exception:
            pass
        sig_b64 = sig_map.get(label)

        # Evidence hash (derived component)
        evidence_b64 = headers.get("evidence")  # optional
        evidence_sha256_hex = ""
        if evidence_b64:
            try:
                evidence_sha256_hex = evidence_sha256_hex_from_header(evidence_b64)
            except Exception:
                evidence_sha256_hex = ""

        base = build_signature_base(request=request, components=components, params=params, evidence_sha256_hex=evidence_sha256_hex)
    log.info("Server signature-base:\n" + base)

        # Verify nonce
        challenge = headers.get("pch-challenge", "")
        challenge_val = challenge[1:-1] if challenge.startswith(":") and challenge.endswith(":") else challenge
        nonce_ok = nonce_store.consume(route=route, client_ip=client_ip, tls_id=tls_id or "dev", nonce=challenge_val)

        # Verify binding
        observed_binding = f"{BINDING_TYPE}=:{base64.b64encode((tls_id or 'dev').encode()).decode()}:" if BINDING_TYPE=="tls-session-id" else pch_binding_hdr
        binding_ok = (pch_binding_hdr == observed_binding)

        # Verify signature
        alg = params.get("alg","ed25519")
        keyid = params.get("keyid","")
        sig_ok = False
        if sig_b64:
            sig_ok = verify_signature(alg=alg, keyid=keyid, signature_b64=sig_b64, message=base)

        verified = bool(sig_ok and nonce_ok and binding_ok and content_ok)

        # Failure precedence: signature -> binding -> nonce -> content-digest so that an
        # incorrect channel binding is surfaced even if the nonce key (different binding value
        # used at issuance) would also fail. This matches test expectations.
        request.state.pch_result = {
            "present": True,
            "verified": verified,
            "failure_reason": None if verified else (
                "bad_signature" if not sig_ok else
                "bad_binding" if not binding_ok else
                "nonce_replay" if not nonce_ok else
                "bad_content_digest" if not content_ok else "unknown"
            ),
            "channel_binding": BINDING_TYPE,
            "evidence_sha256_hex": evidence_sha256_hex,
            "sig_alg": alg
        }

        if not verified and not PCH_ADVISORY:
            return JSONResponse({"error": "PCH verification failed", "reason": request.state.pch_result["failure_reason"]}, status_code=401)

        response = await call_next(request)
        return response
