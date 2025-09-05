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
from .controller.plan import last_decisions
from .controller.config import load_config
from .cbom.export import build_cbom
from .obs.prom import prometheus_latest
from .store.db import fetch_receipt
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
    cfg = load_config()
    for r, stats in mon.get("routes", {}).items():
        snap = load_state(r)
        ia = snap.interarrival_stats
        sv = snap.service_stats
        mean_inter = ia.mean if ia.count else 0.0
        mean_service = sv.mean if sv.count else 0.0
        Ca2 = ia.variance / (mean_inter ** 2) if mean_inter > 0 else 0.0
        Cs2 = sv.variance / (mean_service ** 2) if mean_service > 0 else 0.0
        routes_data.append({
            "route": r,
            "state": snap.name,
            "rho": round(getattr(snap, 'rho', 0.0), 6),
            "Ca2": round(Ca2, 6),
            "Cs2": round(Cs2, 6),
            "kingman_wq_ms": round(getattr(snap, 'kingman_wq_ms', 0.0), 3),
            "err_ewma_pqc": round(getattr(snap, 'err_ewma', 0.0), 6),
            "lat_ewma_ms_pqc": round(getattr(snap, 'lat_ewma', 0.0), 3),
            "ewma_5xx": 0.0,  # placeholder (no global 5xx EWMA yet)
            "consecutive_successes": snap.consecutive_successes,
            "deadband": {"open": cfg.trip_open, "close_successes": cfg.close_successes},
        })
    return JSONResponse({
        "routes": routes_data,
        "decisions": last_decisions(),
        "monitor": mon,  # include raw monitor snapshot for tests expecting this key
        "header_431_total": sum(1 for r, st in mon.get("routes", {}).items() for ev in [st] if isinstance(st, dict)),  # placeholder aggregate
    })

@app.get("/metrics")
async def metrics_prom():  # Prometheus exposition
    data, ctype = prometheus_latest()
    from fastapi.responses import Response
    return Response(content=data, media_type=ctype)

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
