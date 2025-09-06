from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from .pch.middleware import PCHMiddleware, feature_enabled
from .receipts.store import ReceiptStore
from .receipts.compliance_pack import build_compliance_pack
from .utils.logging import get_logger
from .utils.breaker_metrics import breaker_metrics
from .controller.monitor import monitor
from .controller.state import load_state
from .controller.plan import last_decisions, plan as controller_plan
from .controller.config import load_config
from .cbom.export import build_cbom
from .obs.prom import prometheus_latest
from .vdc.emitter import list_index as vdc_list_index
from .store.db import fetch_receipt
from .agent.routes import include_agent_routes, router as agent_router
from .agent.metrics import metrics_router
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
include_agent_routes(app)
app.include_router(agent_router, prefix="/agent", tags=["agent"])
app.include_router(metrics_router, prefix="", tags=["metrics"])

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

    # metrics endpoints now provided by metrics_router

@app.get("/receipts/{receipt_id}")
async def get_receipt(receipt_id: str):
    r = fetch_receipt(receipt_id)
    if not r:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="receipt not found")
    return r

@app.get("/echo/headers")
async def echo_headers(request: Request):
    wanted = [
        "host",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-tls-session-id",
    "x-tls-exporter",
        "pch-challenge",
        "pch-channel-binding",
        "user-agent",
    ]
    hdrs = {k: v for k, v in request.headers.items() if k.lower() in wanted}
    return JSONResponse({"headers": hdrs})

@app.get("/cbom.json")
async def cbom():
    return JSONResponse(build_cbom())

@app.get("/compliance/vdc/index.json")
async def vdc_index():
    try:
        return JSONResponse(vdc_list_index())
    except Exception:
        return JSONResponse({})
