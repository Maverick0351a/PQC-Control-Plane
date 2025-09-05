import os
import json
import base64
import hashlib
import uuid
import datetime
import hmac
import hashlib as _hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from .model import EnforcementReceipt
from .envelope import build_envelope
from ..controller.state import load_state
from ..controller.plan import plan
from ..crypto.jcs import jcs_canonicalize
from ..config import DATA_DIR, SERVER_SIGNING_KEY
from ..store.db import persist_receipt
from .emit import submit_to_evg
from ..dpcp.advisory import compute_dpcp_record
from ..controller.monitor import monitor

class ReceiptStore:
    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)

    def _date_path(self, date=None):
        date = date or datetime.date.today().isoformat()
        base_dir = os.getenv("DATA_DIR", DATA_DIR)
        day_dir = os.path.join(base_dir, date)
        os.makedirs(day_dir, exist_ok=True)
        return os.path.join(day_dir, "receipts.jsonl")

    def _last_hash_b64(self, path):
        if not os.path.exists(path):
            return None
        h = None
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                obj = json.loads(line)
                h = obj.get("leaf_hash_b64")
        return h

    def emit_enforcement_receipt(self, request, decision: str, reason: str, pch: dict):
        reqref = {
            "method": request.method,
            "path": request.url.path,
            "digest": request.headers.get("content-digest"),
            "keyid": (request.headers.get("signature-input") or "").split("keyid=")[-1].strip('"') if request.headers.get("signature-input") else None
        }
        # Opportunistic handshake metadata extraction (will be None if not present). For future
        # integration the TLS terminator / sidecar can propagate these via internal headers.
        try:
            ch_bytes = request.headers.get("X-TLS-ClientHello-Bytes")
            clienthello_bytes = int(ch_bytes) if ch_bytes and ch_bytes.isdigit() else None
        except Exception:
            clienthello_bytes = None
        hrr_seen = None
        try:
            hrr_hdr = request.headers.get("X-TLS-HRR-Seen")
            if hrr_hdr is not None:
                hrr_seen = hrr_hdr.lower() in {"1","true","yes"}
        except Exception:
            hrr_seen = None
        passport_id = None
        try:
            passport_id = request.headers.get("X-Path-Passport-ID")
        except Exception:
            passport_id = None
        # Load controller breaker snapshot for route
        try:
            brk = load_state(request.url.path)
            pl = plan(request.url.path)
            controller_state = None
            try:
                # Derive structured reason detail (gate vs utility) while preserving legacy flat reason
                reason = pl.get("reason")
                gate_reasons = {"safety_both_violated", "safety_header_budget_exceeded", "safety_availability"}
                util_reasons = {"utility_fallback", "utility_attempt"}
                reason_detail = {}
                if reason in gate_reasons:
                    reason_detail["gate"] = reason
                if reason in util_reasons:
                    reason_detail["util"] = reason
                controller_state = {
                    # Legacy keys (tests rely on these)
                    "breaker_state": brk.name,
                    "err_ewma": getattr(brk, 'err_ewma', getattr(brk, 'err_ewma_pqc', 0.0)),
                    "kingman_wq_ms": getattr(brk, 'kingman_wq_ms', 0.0),
                    "rho": getattr(brk, 'rho_est', getattr(brk, 'rho', 0.0)),
                    "consecutive_successes": getattr(brk, 'consecutive_successes', 0),
                    "action": pl.get("action"),
                    "reason": reason,
                    "deadband": pl.get("deadband"),
                    "utility": pl.get("utility"),
                    # Enriched fields (v2 evidence)
                    "lat_ewma_ms_pqc": getattr(brk, 'lat_ewma_ms_pqc', getattr(brk, 'lat_ewma', 0.0)),
                    # (removed alias Wq_ms; use kingman_wq_ms consistently)
                    "reason_detail": reason_detail or None,
                }
            except Exception:
                controller_state = None
        except Exception:
            controller_state = None

        rec = EnforcementReceipt(
            id=str(uuid.uuid4()),
            decision=decision,
            reason=reason or "",
            pch=pch,
            prev_receipt_hash_b64=None,
            request_ref=reqref,
            controller=controller_state,
            clienthello_bytes=clienthello_bytes,
            hrr_seen=hrr_seen,
            passport_id=passport_id,
        ).model_dump()

    # Build new envelope v1 alongside legacy record (drop-in path)
        try:
            actor = {"service": os.getenv("SIGNET_SERVICE", "signet-api"), "cluster": os.getenv("SIGNET_CLUSTER", "dev-local")}
            claims = {}
            if controller_state:
                claims["sndt"] = {
                    "state": controller_state.get("breaker_state"),
                    "ρ": round(controller_state.get("rho", 0.0), 4),
                    "err_ewma": round(controller_state.get("err_ewma", 0.0), 6),
                    "decision": controller_state.get("action"),
                    "reason": controller_state.get("reason"),
                }
            if pch:
                claims["cab"] = {
                    "prov": "openssl",  # placeholder provider metadata
                    "provider_ver": os.getenv("OPENSSL_VERSION", "unknown"),
                    "fips_mode": False,
                }
            env_obj = build_envelope(actor=actor, claims=claims, exporter=None, exporter_type=None, sth_ref=None)
            rec["envelope_v1"] = env_obj
        except Exception:
            pass

    # ------------------------------------------------------------------
        # Dual-binding proof (public Ed25519 signature + session HMAC tag)
        # Must occur AFTER envelope insertion so signature covers envelope.
        # Also include advisory DPCP block in canonical form for integrity.
        # Canonical form excludes the proof fields themselves.
        # ------------------------------------------------------------------
        def _hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
            return hmac.new(prk, info + b"\x01", _hashlib.sha256).digest()[:length]
        try:
            exporter_b64 = request.headers.get("X-TLS-Exporter-B64")
            exporter_bytes = base64.b64decode(exporter_b64) if exporter_b64 else None
        except Exception:
            exporter_bytes = None
        # DPCP advisory (mock provenance checksum + EKM binding) — include in canonical form
        try:
            # compute asynchronously-safe part synchronously by awaiting if coroutine
            dpcp_obj = None
            try:
                # In FastAPI sync path, request is async; use anyio to run coroutine
                import anyio
                async def _compute():
                    return await compute_dpcp_record(request, exporter_b64)
                dpcp_obj = anyio.run(_compute)
            except Exception:
                # Best-effort: ignore failures silently (advisory)
                dpcp_obj = None
            if dpcp_obj:
                rec["dpcp_v1"] = dpcp_obj
                try:
                    monitor.record_dpcp(profile=dpcp_obj.get("profile","unknown"), ekm_bound=(dpcp_obj.get("ekm_binding")=="ekm"))
                except Exception:
                    pass
        except Exception:
            pass

    # Pre-compute binding strength so it is included in signed content
        rec["session_binding_strength"] = "ekm" if exporter_bytes else "none"
        # Ensure envelope captures binding metadata BEFORE canonicalization so tag covers it
        try:
            env = rec.get("envelope_v1", {}).get("envelope")
            if env is not None:
                env["session_binding"] = {
                    "strength": rec.get("session_binding_strength", "none"),
                    # Predict has_tag: True iff exporter provided (tag will be computed)
                    "has_tag": bool(exporter_bytes),
                }
        except Exception:
            pass

        # Include prev and leaf hash BEFORE signature/tag so tag covers them too
        path = self._date_path()
        prev = self._last_hash_b64(path)
        rec["prev_receipt_hash_b64"] = prev
        leaf_bytes_pre = jcs_canonicalize(rec)
        leaf_hash_pre = hashlib.sha256(leaf_bytes_pre).digest()
        rec["leaf_hash_b64"] = base64.b64encode(leaf_hash_pre).decode()
        temp = dict(rec)
        temp.pop("public_sig_b64", None)
        temp.pop("session_tag_b64", None)
        # session_binding_strength intentionally retained in canonical form
        canonical_bytes = jcs_canonicalize(temp)
        try:
            with open(SERVER_SIGNING_KEY, "rb") as _f:
                sk: Ed25519PrivateKey = serialization.load_pem_private_key(_f.read(), password=None)
            rec["public_sig_b64"] = base64.b64encode(sk.sign(canonical_bytes)).decode()
        except Exception:
            rec["public_sig_b64"] = None
        if exporter_bytes:
            try:
                mac_key = _hkdf_expand(exporter_bytes, b"DPR-MAC-Key/v1", 32)
                tag = hmac.new(mac_key, canonical_bytes, _hashlib.sha256).digest()
                rec["session_tag_b64"] = base64.b64encode(tag).decode()
            except Exception:
                rec["session_tag_b64"] = None
                rec["session_binding_strength"] = "none"  # downgrade on failure
        else:
            rec["session_tag_b64"] = None

    # Envelope already includes session_binding; no mutation here to preserve tag integrity

        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        try:
            persist_receipt(rec)
        except Exception:
            pass
        # Best-effort forward to EVG sink for Merkle anchoring
        try:
            submit_to_evg(rec)
        except Exception:
            pass
        return rec
