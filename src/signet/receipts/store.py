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
            controller_state = {
                "breaker_state": brk.name,
                "err_ewma": brk.err_ewma,
                "kingman_wq_ms": brk.kingman_wq_ms,
                "rho": brk.rho_est,
                "consecutive_successes": brk.consecutive_successes,
                "action": pl.get("action"),
                "reason": pl.get("reason"),
                "deadband": pl.get("deadband"),
                "utility": pl.get("utility"),
            }
        except Exception:
            controller_state = None

        rec = EnforcementReceipt(
            id=str(uuid.uuid4()),
            decision=decision,
            reason=reason,
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
