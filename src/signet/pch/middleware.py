"""PCH verification & enforcement middleware."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp
import base64
import os
from ..config import (
    FEATURE_PCH,
    PCH_ADVISORY,
    BINDING_HEADER,
    BINDING_TYPE,
    REQUIRE_TLS_EXPORTER,
)
from ..receipts.store import ReceiptStore
from ..controller.monitor import monitor
from ..crypto.digest import parse_content_digest
from .binding import extract_binding
from ..crypto.signatures import (
    parse_signature_input,
    build_signature_base,
    verify_signature,
)
from ..pch.nonce_store import NonceStore
from ..pch.evidence import evidence_sha256_hex_from_header
from ..utils.logging import get_logger
from ..controller.shield import shield, shield_outcome

log = get_logger()
nonce_store = NonceStore()
_receipt_store = ReceiptStore()


def feature_enabled() -> bool:  # pragma: no cover simple accessor
    return FEATURE_PCH


class PCHMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request, call_next):  # noqa: C901 complexity acceptable for now
        start_time = __import__("time").time()

        # 1. Content-Digest (advisory)
        content_ok = True
        if request.method.upper() in {"POST", "PUT", "PATCH"}:
            body = await request.body()
            cd_header = request.headers.get("content-digest")
            try:
                parsed = parse_content_digest(cd_header) if cd_header else None
                if not cd_header or parsed != __import__("hashlib").sha256(body).digest():
                    content_ok = False
            except Exception:  # pragma: no cover
                content_ok = False

        # 2. Basic context
        headers_lower = {k.lower(): v for k, v in request.headers.items()}
        sig_input = headers_lower.get("signature-input")
        signature = headers_lower.get("signature")
        pch_binding_hdr = headers_lower.get("pch-channel-binding")
        client_ip = request.client.host if request.client else "unknown"
        route = request.url.path
        binding_type, tls_id = extract_binding(headers_lower)
        log.info(
            f"PCH middleware observed {('X-TLS-Exporter' if binding_type=='tls-exporter' else BINDING_HEADER)}="
            f"{tls_id if tls_id else '(none)'}"
        )
        # Early breaker evaluation; allow challenge path even if open (dynamic flag)
    # breaker_plan placeholder removed (unused)
        dynamic_breaker_enabled = os.getenv("BREAKER_ENABLED", "false").lower() == "true"
        if dynamic_breaker_enabled:
            sh_early = shield(route)
            if isinstance(sh_early, JSONResponse):
                if sig_input or signature:
                    return sh_early
                # breaker open on challenge path; continuing without using plan structure
            else:
                pass  # sh_early is a plan dict (unused here)

        # 3. Challenge path (missing signature artifacts)
        if not sig_input or not signature:
            nonce = nonce_store.issue(route=route, client_ip=client_ip, tls_id=tls_id or "dev")
            challenge_val = f":{nonce}:"
            challenge_headers = {
                "WWW-Authenticate": f'PCH realm="pqc", algs="ed25519", challenge=":{nonce}:"',
                "PCH-Challenge": challenge_val,
                "Cache-Control": "no-store",
            }
            if PCH_ADVISORY:
                request.state.pch_result = {
                    "present": False,
                    "verified": False,
                    "failure_reason": "missing_signature",
                    "channel_binding": binding_type,
                }
                if route.startswith("/protected"):
                    # Emit monitoring event for challenge so route stats appear even without signature
                    try:  # pragma: no cover
                        hdr_total = sum(len(k) + len(v) + 4 for k, v in request.headers.items())
                        largest_hdr = max((len(k) + len(v) + 4 for k, v in request.headers.items()), default=0)
                        monitor.emit(
                            {
                                "pch_present": False,
                                "pch_verified": False,
                                "failure_reason": "missing_signature",
                                "header_total_bytes": hdr_total,
                                "largest_header_bytes": largest_hdr,
                                "signature_bytes": 0,
                                "latency_ms": (__import__("time").time() - start_time) * 1000.0,
                                "http_status": 401,
                                "is_guarded_route": True,
                                "tls_binding_header_present": bool(request.headers.get(BINDING_HEADER)),
                                "route": route,
                            }
                        )
                    except Exception as e:  # pragma: no cover
                        log.warning(f"monitor emit (challenge protected) failed: {e}")
                    # Emit a denial receipt for challenge so transparency log captures enforcement rationale
                    try:  # pragma: no cover
                        _receipt_store.emit_enforcement_receipt(
                            request=request,
                            decision="deny",
                            reason="missing_signature_challenge",
                            pch=request.state.pch_result,
                        )
                    except Exception as e:  # pragma: no cover
                        log.warning(f"receipt emit (challenge protected) failed: {e}")
                    return JSONResponse(
                        {"error": "PCH required", "hint": "sign request and retry"},
                        status_code=401,
                        headers=challenge_headers,
                    )
                response = await call_next(request)
                for k, v in challenge_headers.items():
                    response.headers[k] = v
                # Emit monitoring event for unprotected/advisory challenge path
                try:  # pragma: no cover
                    hdr_total = sum(len(k) + len(v) + 4 for k, v in request.headers.items())
                    largest_hdr = max((len(k) + len(v) + 4 for k, v in request.headers.items()), default=0)
                    monitor.emit(
                        {
                            "pch_present": False,
                            "pch_verified": False,
                            "failure_reason": "missing_signature",
                            "header_total_bytes": hdr_total,
                            "largest_header_bytes": largest_hdr,
                            "signature_bytes": 0,
                            "latency_ms": (__import__("time").time() - start_time) * 1000.0,
                            "http_status": response.status_code,
                            "is_guarded_route": route.startswith("/protected"),
                            "tls_binding_header_present": bool(request.headers.get(BINDING_HEADER)),
                            "route": route,
                        }
                    )
                except Exception as e:  # pragma: no cover
                    log.warning(f"monitor emit (challenge advisory) failed: {e}")
                return response
            # Non-advisory: still emit a monitoring event so route stats populate
            try:  # pragma: no cover
                hdr_total = sum(len(k) + len(v) + 4 for k, v in request.headers.items())
                largest_hdr = max((len(k) + len(v) + 4 for k, v in request.headers.items()), default=0)
                monitor.emit(
                    {
                        "pch_present": False,
                        "pch_verified": False,
                        "failure_reason": "missing_signature",
                        "header_total_bytes": hdr_total,
                        "largest_header_bytes": largest_hdr,
                        "signature_bytes": 0,
                        "latency_ms": (__import__("time").time() - start_time) * 1000.0,
                        "http_status": 401,
                        "is_guarded_route": route.startswith("/protected"),
                        "tls_binding_header_present": bool(request.headers.get(BINDING_HEADER)),
                        "route": route,
                    }
                )
            except Exception as e:  # pragma: no cover
                log.warning(f"monitor emit (challenge non-advisory) failed: {e}")
            return JSONResponse({"error": "PCH required"}, status_code=401, headers=challenge_headers)

        # 4. Parse signature-input
        try:
            label, components, params = parse_signature_input(sig_input)
        except Exception:  # pragma: no cover
            request.state.pch_result = {
                "present": True,
                "verified": False,
                "failure_reason": "bad_signature_input",
                "channel_binding": binding_type,
            }
            if not PCH_ADVISORY:
                return JSONResponse({"error": "bad signature-input"}, status_code=401)
            return await call_next(request)

        # 5. Extract signature bytes
        sig_b64 = None
        try:
            for part in [p.strip() for p in signature.split(",")]:
                if "=" not in part:
                    continue
                k, v = part.split("=", 1)
                if v.startswith(":") and v.endswith(":"):
                    v = v[1:-1]
                if k.strip() == label:
                    sig_b64 = v.strip()
                    break
        except Exception:  # pragma: no cover
            pass

        # 6. Evidence (optional)
        evidence_sha256_hex = ""
        evidence_b64 = headers_lower.get("evidence")
        if evidence_b64:
            try:
                evidence_sha256_hex = evidence_sha256_hex_from_header(evidence_b64)
            except Exception:  # pragma: no cover
                evidence_sha256_hex = ""

        # 7. Build signature base
        base = build_signature_base(
            request=request,
            components=components,
            params=params,
            evidence_sha256_hex=evidence_sha256_hex,
        )
        log.info("Server signature-base:\n" + base)

        # 8. Nonce check
        challenge_hdr = headers_lower.get("pch-challenge", "")
        presented_nonce = (
            challenge_hdr[1:-1]
            if challenge_hdr.startswith(":") and challenge_hdr.endswith(":")
            else challenge_hdr
        )
        nonce_ok = nonce_store.consume(
            route=route,
            client_ip=client_ip,
            tls_id=tls_id or "dev",
            nonce=presented_nonce,
        )

        # 9. Channel binding check
        if binding_type == "tls-session-id":
            expected_binding = f"tls-session-id=:{base64.b64encode((tls_id or 'dev').encode()).decode()}:"
        else:  # tls-exporter
            expected_binding = f"tls-exporter=:{tls_id}:" if tls_id else ""
        binding_ok = pch_binding_hdr == expected_binding
        if not binding_ok:
            log.info(f"Binding mismatch type={binding_type} expected='{expected_binding}' got='{pch_binding_hdr}' tls_id='{tls_id}'")

        # 10. Signature verify
        alg = params.get("alg", "ed25519")
        keyid = params.get("keyid", "")
        sig_ok = bool(
            sig_b64
            and verify_signature(
                alg=alg, keyid=keyid, signature_b64=sig_b64, message=base
            )
        )

        verified = bool(sig_ok and nonce_ok and binding_ok and content_ok)

        # 11. Record result
        request.state.pch_result = {
            "present": True,
            "verified": verified,
            "failure_reason": None
            if verified
            else (
                "bad_signature"
                if not sig_ok
                else (
                    "bad_binding"
                    if not binding_ok
                    else (
                        "nonce_replay"
                        if not nonce_ok
                        else (
                            "bad_content_digest" if not content_ok else "unknown"
                        )
                    )
                )
            ),
            "channel_binding": binding_type,
            "evidence_sha256_hex": evidence_sha256_hex,
            "sig_alg": alg,
        }

        if not verified and not PCH_ADVISORY:
            return JSONResponse(
                {"error": "PCH verification failed", "reason": request.state.pch_result["failure_reason"]},
                status_code=401,
            )

        # 12. Enforcement (guarded routes)
        dyn_routes = [p.strip() for p in os.getenv("ENFORCE_PCH_ROUTES", "").split(",") if p.strip()]
        if dynamic_breaker_enabled:
            sh = shield(route)
            if isinstance(sh, JSONResponse):
                return sh
            # sh is a plan dict (unused)
        if any(route.startswith(p) for p in dyn_routes):
            pch_res = request.state.pch_result
            must_have = pch_res.get("present") and pch_res.get("verified")
            shield_skip = REQUIRE_TLS_EXPORTER and BINDING_TYPE != "tls-exporter"
            if not shield_skip and not must_have:
                rec = _receipt_store.emit_enforcement_receipt(
                    request=request,
                    decision="deny",
                    reason="pch_enforce",
                    pch=pch_res,
                )
                return JSONResponse({"error": "PCH required", "hint": "sign request and retry", "receipt_id": rec["id"]}, status_code=401)

        response = await call_next(request)

        # 13. Monitoring emit
        try:  # pragma: no cover
            pch_res = getattr(request.state, "pch_result", {})
            if dynamic_breaker_enabled:
                shield_outcome(route, bool(pch_res.get("verified")))
            hdr_total = sum(len(k) + len(v) + 4 for k, v in request.headers.items())
            largest_hdr = max((len(k) + len(v) + 4 for k, v in request.headers.items()), default=0)
            sig_header = request.headers.get("signature", "")
            sig_bytes = len(sig_header.encode()) if sig_header else 0
            latency_ms = (__import__("time").time() - start_time) * 1000.0
            monitor.emit(
                {
                    "pch_present": bool(pch_res.get("present")),
                    "pch_verified": pch_res.get("verified"),
                    "failure_reason": pch_res.get("failure_reason") or "none",
                    "header_total_bytes": hdr_total,
                    "largest_header_bytes": largest_hdr,
                    "signature_bytes": sig_bytes,
                    "latency_ms": latency_ms,
                    "http_status": response.status_code,
                    "is_guarded_route": route.startswith("/protected"),
                    "tls_binding_header_present": bool(request.headers.get(BINDING_HEADER)),
                    "route": route,
                }
            )
        except Exception as e:  # pragma: no cover
            log.warning(f"monitor emit failed: {e}")
        return response
