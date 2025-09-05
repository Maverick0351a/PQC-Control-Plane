import os
import json
import base64
import hashlib
import uuid
import datetime
from .model import EnforcementReceipt
from ..controller.state import load_state
from ..controller.plan import plan
from ..crypto.jcs import jcs_canonicalize
from ..config import DATA_DIR
from ..store.db import persist_receipt

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
        ).model_dump()

        path = self._date_path()
        prev = self._last_hash_b64(path)
        rec["prev_receipt_hash_b64"] = prev
        # Canonical leaf
        leaf_bytes = jcs_canonicalize(rec)
        leaf_hash = hashlib.sha256(leaf_bytes).digest()
        rec["leaf_hash_b64"] = base64.b64encode(leaf_hash).decode()

        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        try:
            persist_receipt(rec)
        except Exception:
            pass
        return rec
