from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import Response
from ..obs.prom import prometheus_latest
from ..controller.monitor import monitor
from ..controller.state import load_state
from ..controller.plan import plan as controller_plan, last_decisions
from ..controller.config import load_config
from fastapi.responses import JSONResponse

metrics_router = APIRouter()

@metrics_router.get("/__metrics")
async def metrics_json():
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
        plan_snapshot = controller_plan(r)
        utility = plan_snapshot.get("utility") or {}
        routes_data.append({
            "route": r,
            "state": plan_snapshot.get("state", snap.name),
            "rho": round(getattr(snap, 'rho', 0.0), 6),
            "Ca2": round(Ca2, 6),
            "Cs2": round(Cs2, 6),
            "kingman_wq_ms": round(getattr(snap, 'kingman_wq_ms', 0.0), 3),
            "err_ewma_pqc": round(getattr(snap, 'err_ewma', 0.0), 6),
            "lat_ewma_ms_pqc": round(getattr(snap, 'lat_ewma', 0.0), 3),
            "ewma_5xx": 0.0,
            "consecutive_successes": snap.consecutive_successes,
            "deadband": {"open": cfg.trip_open, "close_successes": cfg.close_successes},
            "U": utility,
        })
    attempts = max(1, int(mon.get("pqc_attempts_total", 0)))
    verified = int(mon.get("pqc_verified_total", 0))
    pqc_success_rate = verified / attempts
    header_431_total = int(mon.get("http_431_total", 0))
    dpcp_total = int(mon.get("dpcp_total", 0))
    dpcp_ekm_bound_total = int(mon.get("dpcp_ekm_bound_total", 0))
    dpcp_profile_counts = mon.get("dpcp_profile_counts", {})
    return JSONResponse({
        "routes": routes_data,
        "decisions": last_decisions(),
        "monitor": mon,
        "pqc_success_rate": pqc_success_rate,
        "header_431_total": header_431_total,
        "header_total_bytes_hist": mon.get("header_total_bytes_hist", {}),
        "dpcp_total": dpcp_total,
        "dpcp_ekm_bound_total": dpcp_ekm_bound_total,
        "dpcp_profile_counts": dpcp_profile_counts,
    })

@metrics_router.get("/metrics")
async def metrics_prom():
    data, ctype = prometheus_latest()
    return Response(content=data, media_type=ctype)
