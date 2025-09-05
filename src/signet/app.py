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
from .controller.plan import _UTILITY_CONTEXT, TRIP_ERR, CLOSE_SUCCESSES
from .cbom.export import build_cbom
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
    mon = monitor.snapshot()
    routes_data = []
    for r, stats in mon.get("routes", {}).items():
        snap = load_state(r)
        util = _UTILITY_CONTEXT or {}
        # Derive utility if context present
        pqc_rate = util.get("pqc_rate")
        failure_rate = util.get("failure_rate")
        slo_headroom = util.get("slo_headroom")
        u_val = None
        if pqc_rate is not None and failure_rate is not None and slo_headroom is not None:
            alpha = util.get("alpha", 0.5)
            beta = util.get("beta", 0.5)
            gamma = util.get("gamma", 0.5)
            try:
                u_val = (pqc_rate ** alpha) * ((1 - failure_rate) ** beta) * (slo_headroom ** gamma)
            except Exception:
                u_val = None
        routes_data.append({
            "route": r,
            "state": snap.name,
            "err_ewma": round(snap.err_ewma,6),
            "rho": round(snap.rho_est,6),
            "kingman_wq_ms": round(snap.kingman_wq_ms,3),
            "consecutive_successes": snap.consecutive_successes,
            "pqc_rate": pqc_rate,
            "failure_rate": failure_rate,
            "slo_headroom": slo_headroom,
            "U": round(u_val,6) if u_val is not None else None,
            "deadband": {"open": TRIP_ERR, "close_successes": CLOSE_SUCCESSES},
        })
    return JSONResponse({
        "breaker": breaker_metrics.snapshot(),
        "monitor": mon,
        "routes": routes_data,
        "anomalies": mon.get("anomalies"),
        "header_total_bytes_hist": mon.get("header_total_bytes_hist"),
    })

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
