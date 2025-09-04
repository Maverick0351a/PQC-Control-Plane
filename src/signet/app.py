from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from .pch.middleware import PCHMiddleware, feature_enabled
from .receipts.store import ReceiptStore
from .receipts.compliance_pack import build_compliance_pack
from .utils.logging import get_logger
from .utils.breaker_metrics import breaker_metrics
import time

load_dotenv()

app = FastAPI(title="Signet PQC Control Plane — MVP")
log = get_logger()

# CORS (dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# PCH middleware (advisory by default)
if feature_enabled():
    app.add_middleware(PCHMiddleware)

store = ReceiptStore()

@app.get("/__health")
async def health():
    return {"status": "ok"}

@app.get("/protected")
async def protected(request: Request):
    # Decision: allow for MVP; PCH middleware annotates request.state.pch_result
    start = time.time()
    result = getattr(request.state, "pch_result", {"present": False, "verified": False, "failure_reason": "no_pch"})
    rec = store.emit_enforcement_receipt(request=request, decision="allow", reason="policy_ok", pch=result)
    latency = time.time() - start
    breaker_metrics.observe(latency_s=latency, error=not result.get("verified", False))
    return JSONResponse({"ok": True, "receipt_id": rec["id"], "pch": result})

@app.post("/protected")
async def protected_post(request: Request):
    # Same as GET but validates Content-Digest inside middleware
    start = time.time()
    result = getattr(request.state, "pch_result", {"present": False, "verified": False, "failure_reason": "no_pch"})
    rec = store.emit_enforcement_receipt(request=request, decision="allow", reason="policy_ok", pch=result)
    latency = time.time() - start
    breaker_metrics.observe(latency_s=latency, error=not result.get("verified", False))
    return JSONResponse({"ok": True, "receipt_id": rec["id"], "pch": result})

@app.post("/compliance/pack")
async def compliance_pack(body: dict):
    date = body.get("date")
    if not date:
        return JSONResponse({"error": "missing 'date' (YYYY-MM-DD)"}, status_code=400)
    path = build_compliance_pack(date_str=date)
    return JSONResponse({"pack": path})

@app.get("/__metrics")
async def metrics():
    return JSONResponse({"breaker": breaker_metrics.snapshot()})
