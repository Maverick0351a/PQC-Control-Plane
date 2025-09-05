"""PCH verification & enforcement middleware."""

import base64
import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from ..config import (
    FEATURE_PCH,
    PCH_ADVISORY,
    BINDING_HEADER,
    BINDING_TYPE,
    REQUIRE_TLS_EXPORTER,
    MAX_HEADER_BYTES,
    MAX_SINGLE_HEADER_BYTES,
    HEADER_DOWNGRADE_MODE,
)
from ..controller.monitor import monitor
from ..controller.plan import (
    set_utility_context,
    clear_utility_context,
    plan as breaker_plan,
    record_load_shed,
)
from ..controller.config import load_config
from ..controller.state import (
    load_state,
    update_error_ewma,
    update_latency_ewma,
    update_queue_stats,
    BreakerState,
)
from ..controller.plan import plan_action
from ..crypto.digest import parse_content_digest
from ..crypto.signatures import (
    parse_signature_input,
    build_signature_base,
    verify_signature,
)
from ..pch.evidence import evidence_sha256_hex_from_header
from ..pch.nonce_store import NonceStore
from ..receipts.store import ReceiptStore
from ..utils.logging import get_logger
from ..obs.prom import observe_request, update_breaker_snapshot
from .binding import extract_binding

HEADER_BUDGET_LIMIT = int(os.getenv("HEADER_BUDGET_LIMIT", str(MAX_HEADER_BYTES)))  # backward compat env

log = get_logger()
nonce_store = NonceStore()
_receipt_store = ReceiptStore()


def feature_enabled() -> bool:  # pragma: no cover - simple accessor
    return FEATURE_PCH


class PCHMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request, call_next):  # noqa: C901
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

        dynamic_breaker_enabled = os.getenv("BREAKER_ENABLED", "false").lower() == "true"
        cfg = load_config() if dynamic_breaker_enabled else None

        # 3. Utility context (header budget projection)
        try:
            projected_header_bytes = sum(len(k) + len(v) + 4 for k, v in request.headers.items())
            set_utility_context(
                {
                    "header_budget_total": HEADER_BUDGET_LIMIT,
                    "header_total_bytes": projected_header_bytes,
                }
            )
        except Exception:  # pragma: no cover
            pass

        # Sync error EWMA from monitor even when utility context present so breaker can trip on first request
        if dynamic_breaker_enabled:
            try:  # pragma: no cover
                from ..controller.monitor import monitor as _mon
                st_sync = load_state(route)
                rs = _mon.routes.get(route)
                if rs and st_sync.err_ewma_pqc == 0.0:
                    st_sync.err_ewma_pqc = getattr(rs.ewma_error, 'value', 0.0)
            except Exception:
                pass

        current_plan = breaker_plan(route)
        try:
            st_dbg = load_state(route)
            if dynamic_breaker_enabled:
                log.info(
                    f"breaker-pre route={route} state={st_dbg.state.value} err_ewma={st_dbg.err_ewma_pqc:.3f} "
                    f"trip_open={cfg.trip_open if cfg else 'n/a'} plan_action={current_plan.get('action')} plan_state={current_plan.get('state')}"
                )
        except Exception:
            pass
        # If breaker just transitioned to THROTTLE_PCH (legacy open) record a load shed snapshot for tests
        if dynamic_breaker_enabled and current_plan.get("action") in {"THROTTLE_PCH"}:
            st_tmp = load_state(route)
            record_load_shed(route, st_tmp, current_plan.get("reason") or "trip_open")
        action = current_plan.get("action")
        # Load-shed path: if breaker is OPEN or plan reason indicates safety gate/utility fallback
        if dynamic_breaker_enabled and current_plan.get("state") == BreakerState.OPEN.value:
            st = load_state(route)
            record_load_shed(route, st, "breaker_open")
            clear_utility_context()
            # Always surface 503 for breaker-open so tests detect trip reliably.
            return JSONResponse(
                {"error": "pch load-shed", "reason": "breaker_open", "state": "Open"},
                status_code=503,
            )
        if dynamic_breaker_enabled and current_plan.get("reason") in {"safety_both_violated", "safety_availability", "safety_header_budget_exceeded", "utility_fallback"}:
            st = load_state(route)
            record_load_shed(route, st, current_plan.get("reason") or "load_shed")
            clear_utility_context()
            # Return 200 classic pass-through (no PCH) but annotate advisory header
            request.state.pch_result = {"present": False, "verified": False, "failure_reason": "load_shed"}
            resp = await call_next(request)
            resp.headers["X-PCH-LoadShed"] = current_plan.get("reason") or "load_shed"
            return resp

    # (Duplicate open check removed; handled above before challenge logic.)

        # 4. Challenge (missing signature artifacts)
        public_paths = {"/__health", "/__metrics", "/cbom.json", "/echo/headers"}
        if route.startswith("/metrics") or route.startswith("/receipts/"):
            public_paths.add(route)
        if route in public_paths:
            # Skip PCH processing entirely for public informational endpoints
            clear_utility_context()
            return await call_next(request)
        if not sig_input or not signature:
            nonce = nonce_store.issue(route=route, client_ip=client_ip, tls_id=tls_id or "dev")
            challenge_val = f":{nonce}:"
            challenge_headers = {
                "WWW-Authenticate": f'PCH realm="pqc", algs="ed25519 ml-dsa-65 ecdsa-p256+ml-dsa-65", hints="relax-header-budget", challenge=":{nonce}:"',
                "PCH-Challenge": challenge_val,
                "Cache-Control": "no-store",
            }
            request.state.pch_result = {
                "present": False,
                "verified": False,
                "failure_reason": "missing_signature",
                "channel_binding": binding_type,
            }
            status = 401
            try:  # monitoring
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
                        "http_status": status,
                        "is_guarded_route": route.startswith("/protected"),
                        "tls_binding_header_present": bool(request.headers.get(BINDING_HEADER)),
                        "route": route,
                    }
                )
            except Exception:  # pragma: no cover
                pass
            # Emit denial receipt for protected challenges so transparency log records it
            if route.startswith("/protected"):
                try:  # pragma: no cover
                    _receipt_store.emit_enforcement_receipt(
                        request=request,
                        decision="deny",
                        reason="missing_signature_challenge",
                        pch=request.state.pch_result,
                    )
                except Exception:
                    pass
            # Update breaker EWMA immediately so trip logic can react within challenge wave
            if dynamic_breaker_enabled:
                try:
                    # Use already imported controller state helpers; avoid re-import which
                    # creates a local binding and caused UnboundLocalError earlier.
                    st_ch = load_state(route)
                    update_error_ewma(st_ch, True, True)
                    # Force immediate re-plan so subsequent requests observe OPEN state sooner
                    _ = breaker_plan(route)
                    log.debug(f"breaker early-update (challenge) err_ewma={st_ch.err_ewma_pqc:.3f} state={st_ch.state.value}")
                except Exception:  # pragma: no cover
                    pass
            # Intentionally DO NOT clear utility context here; relaxed follow-up may rely on it
            return JSONResponse({"error": "PCH required"}, status_code=status, headers=challenge_headers)

        # 5. Header budget & relax-mode / downgrade pre-check (must re-read env each request for monkeypatch tests)
        header_total_bytes = sum(len(k) + len(v) + 4 for k, v in request.headers.items())
        largest_hdr = max((len(k) + len(v) + 4 for k, v in request.headers.items()), default=0)
        dynamic_total_limit = int(os.getenv("MAX_HEADER_BYTES", str(MAX_HEADER_BYTES)))
        dynamic_single_limit = int(os.getenv("MAX_SINGLE_HEADER_BYTES", str(MAX_SINGLE_HEADER_BYTES)))
        mode_env = os.getenv("HEADER_DOWNGRADE_MODE", HEADER_DOWNGRADE_MODE)
        header_budget_limit = cfg.header_budget_max if cfg else dynamic_total_limit
        over_budget = header_total_bytes > header_budget_limit or largest_hdr > dynamic_single_limit

        # Heuristic: extremely large raw evidence (>4KB decoded) should still trigger pre-relax even if global limits high
        evidence_header_val = headers_lower.get("evidence")
        decoded_evidence_len = 0
        if evidence_header_val:
            ev_raw = evidence_header_val.strip(":")
            try:
                decoded_evidence_len = len(base64.b64decode(ev_raw + ("=" * ((4 - len(ev_raw) % 4) % 4))))
            except Exception:
                decoded_evidence_len = 0
        oversized_evidence_payload = decoded_evidence_len > 4096

        # Determine if we're in relax mode (explicit plan action)
        relax_mode = action == "RELAX_HEADER_BUDGET"
        # If utility context indicates prior over-budget condition, honor relax on follow-up
        try:
            util_ctx = getattr(request.state, 'utility_context', {})
            if not relax_mode and util_ctx:
                if util_ctx.get('header_total_bytes', 0) > util_ctx.get('header_budget_total', 0):
                    relax_mode = True
        except Exception:
            pass
        request.state._pch_over_budget = over_budget or oversized_evidence_payload

        # Pre-relax handling
        if over_budget or oversized_evidence_payload:
            if mode_env == "deny":
                try:  # monitoring emit for 431 path
                    monitor.emit(
                        {
                            "pch_present": bool(sig_input),
                            "pch_verified": False,
                            "failure_reason": "header_budget_exceeded",
                            "header_total_bytes": header_total_bytes,
                            "largest_header_bytes": largest_hdr,
                            "signature_bytes": len(signature.encode()) if signature else 0,
                            "latency_ms": (__import__("time").time() - start_time) * 1000.0,
                            "http_status": 431,
                            "is_guarded_route": route.startswith("/protected"),
                            "tls_binding_header_present": bool(request.headers.get(BINDING_HEADER)),
                            "route": route,
                            "header_431_total": 1,
                        }
                    )
                except Exception:  # pragma: no cover
                    pass
                clear_utility_context()
                return JSONResponse(
                    {
                        "error": "header_budget",
                        "limit": header_budget_limit,
                        "observed": header_total_bytes,
                    },
                    status_code=431,
                )
            elif mode_env in {"hash-only", "body-evidence"} and not relax_mode:
                # Oversized evidence header without hash triggers pre-relax hint (428)
                if evidence_header_val and "evidence-sha-256" not in headers_lower:
                    return JSONResponse(
                        {
                            "error": "header budget exceeded",
                            "hint": "downgrade: move evidence to body and provide evidence-sha-256 header",
                            "mode": "RELAX_HEADER_BUDGET",
                        },
                        status_code=428,
                        headers={"X-PCH-PreRelax": "1"},
                    )
                # If not evidence related just mark relax and continue parsing
                relax_mode = True

        # If client already downgraded evidence (hash present, header removed) force relax
        if ("evidence-sha-256" in headers_lower) and ("evidence" not in headers_lower):
            relax_mode = True

        # 6. Parse signature-input (skipped if load-shed earlier)
        try:
            label, components, params = parse_signature_input(sig_input)
        except Exception:
            request.state.pch_result = {
                "present": True,
                "verified": False,
                "failure_reason": "bad_signature_input",
                "channel_binding": binding_type,
            }
            if not PCH_ADVISORY:
                return JSONResponse({"error": "bad signature-input"}, status_code=401)
            return await call_next(request)

        # 7. Extract signature bytes
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

        # 8. Evidence (two modes)
        evidence_sha256_hex = ""
        evidence_ref = None
        if relax_mode:
            ev_hex_hdr = headers_lower.get("evidence-sha-256", "")
            body_bytes = await request.body()
            evidence_json_obj = None
            if body_bytes:
                try:
                    if request.headers.get("content-type", "").startswith("application/json"):
                        import json as _json
                        evidence_json_obj = _json.loads(body_bytes.decode())
                except Exception:  # pragma: no cover
                    evidence_json_obj = None
            if isinstance(evidence_json_obj, dict) and "evidence" in evidence_json_obj:
                ev_bytes = __import__("json").dumps(
                    evidence_json_obj["evidence"], separators=(",", ":")
                ).encode()
                import hashlib as _hashlib
                calc_hex = _hashlib.sha256(ev_bytes).hexdigest()
                evidence_sha256_hex = calc_hex
                evidence_ref = calc_hex
                if ev_hex_hdr and ev_hex_hdr != calc_hex:
                    clear_utility_context()
                    request.state.pch_result = {
                        "present": True,
                        "verified": False,
                        "failure_reason": "bad_evidence_hash",
                        "channel_binding": binding_type,
                    }
                    return JSONResponse({"error": "evidence hash mismatch"}, status_code=400)
            else:
                if HEADER_DOWNGRADE_MODE == "hash-only":
                    # Compute hash directly from body if JSON object with 'evidence' field is not provided
                    try:
                        if body_bytes:
                            import hashlib as _hashlib
                            evidence_sha256_hex = _hashlib.sha256(body_bytes).hexdigest()
                            evidence_ref = evidence_sha256_hex
                        else:
                            evidence_sha256_hex = ""
                    except Exception:
                        evidence_sha256_hex = ""
                else:
                    clear_utility_context()
                    return JSONResponse({"error": "missing evidence body"}, status_code=400)
        else:
            evidence_b64 = headers_lower.get("evidence")
            if evidence_b64:
                try:
                    evidence_sha256_hex = evidence_sha256_hex_from_header(evidence_b64)
                    evidence_ref = evidence_sha256_hex
                except Exception:  # pragma: no cover
                    evidence_sha256_hex = ""

        # 9. Build signature base
        base = build_signature_base(
            request=request,
            components=components,
            params=params,
            evidence_sha256_hex=evidence_sha256_hex,
        )
        log.info("Server signature-base:\n" + base)

    # Guard (late): already handled early; no-op retained for clarity

        # 10. Nonce check
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

        # 11. Channel binding check
        if binding_type == "tls-session-id":
            expected_binding = (
                f"tls-session-id=:{base64.b64encode((tls_id or 'dev').encode()).decode()}:"
            )
        else:
            expected_binding = f"tls-exporter=:{tls_id}:" if tls_id else ""
        binding_ok = pch_binding_hdr == expected_binding
        if not binding_ok:
            log.info(
                "Binding mismatch type=%s expected='%s' got='%s' tls_id='%s'",
                binding_type,
                expected_binding,
                pch_binding_hdr,
                tls_id,
            )

        # 12. Signature verify
        alg = params.get("alg", "ed25519")
        keyid = params.get("keyid", "")
        sig_ok = bool(
            sig_b64
            and verify_signature(alg=alg, keyid=keyid, signature_b64=sig_b64, message=base)
        )

        # Early breaker update on bad signature to accelerate trip (mirrors challenge path)
        if dynamic_breaker_enabled and not sig_ok:
            try:
                st_sig = load_state(route)
                update_error_ewma(st_sig, True, True)
                plan_after = breaker_plan(route)
                log.info(
                    f"breaker-early bad_sig route={route} err_ewma={st_sig.err_ewma_pqc:.3f} "
                    f"state={st_sig.state.value} plan_state={plan_after.get('state')} action={plan_after.get('action')}"
                )
            except Exception:  # pragma: no cover
                pass

        verified = bool(sig_ok and nonce_ok and binding_ok and content_ok)

        # 13. Record result
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
            "evidence_ref": evidence_ref,
            "relax_mode": relax_mode,
        }

        if not verified and not PCH_ADVISORY:
            return JSONResponse(
                {
                    "error": "PCH verification failed",
                    "reason": request.state.pch_result["failure_reason"],
                },
                status_code=401,
            )

        # 14. Enforcement (guarded routes)
        dyn_routes = [
            p.strip() for p in os.getenv("ENFORCE_PCH_ROUTES", "").split(",") if p.strip()
        ]
        # Lean controller early-drop not yet enforced here; enforcement happens after verification
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
                return JSONResponse(
                    {
                        "error": "PCH required",
                        "hint": "sign request and retry",
                        "receipt_id": rec["id"],
                    },
                    status_code=401,
                )

        # 15. Downstream
        response = await call_next(request)

        # 16. Monitoring + Prometheus instrumentation
        pch_res = getattr(request.state, "pch_result", {})
        hdr_total = sum(len(k) + len(v) + 4 for k, v in request.headers.items())
        sig_header = request.headers.get("signature", "")
        sig_bytes = len(sig_header.encode()) if sig_header else 0
        latency_ms = (__import__("time").time() - start_time) * 1000.0
        try:  # legacy monitor JSON aggregation
            if dynamic_breaker_enabled:
                # Update lean controller state metrics per outcome
                st = load_state(route)
                now_ts = __import__("time").time()
                service_ms = latency_ms
                is_pqc = True  # all guarded routes treated as PQC attempt for now
                update_queue_stats(st, now_ts, service_ms)
                update_latency_ewma(st, service_ms)
                failed = not bool(pch_res.get("verified")) or (500 <= response.status_code < 600)
                update_error_ewma(st, is_pqc, failed)
                if not failed:
                    st.consecutive_successes += 1
                else:
                    st.consecutive_successes = 0
                # Re-plan post-outcome (for next request visibility)
                act, ns, rat = plan_action(
                    {"header_total_bytes": hdr_total, "ewma_5xx": 0.0}, cfg, st
                ) if cfg else (action, st.state, {})
                st.state = ns
                # Augment existing plan snapshot fields for Prometheus update
                current_plan.update(
                    {
                        "action": act,
                        "state": st.state.value,
                        "err_ewma": st.err_ewma_pqc,
                        "rho": st.rho,
                        "kingman_wq_ms": st.wq_ms,
                    }
                )
            largest_hdr = max(
                (len(k) + len(v) + 4 for k, v in request.headers.items()), default=0
            )
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
        try:  # Prometheus
            observe_request(
                route=route,
                verified=bool(pch_res.get("verified")),
                failure_reason=pch_res.get("failure_reason") or "none",
                http_status=response.status_code,
                header_total_bytes=hdr_total,
                signature_bytes=sig_bytes,
                latency_ms=latency_ms,
            )
            if dynamic_breaker_enabled:
                # Use existing snapshot from breaker_plan for route
                snap = breaker_plan(route)
                update_breaker_snapshot(route, snap, snap)
        except Exception as e:  # pragma: no cover
            log.debug(f"prometheus instrumentation failed: {e}")
        clear_utility_context()
        return response
