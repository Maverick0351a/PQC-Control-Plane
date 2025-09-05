"""Prometheus instrumentation for Signet PQC Control Plane.

Exports a registry and helper functions the middleware can call after each request.
Keeps labels minimal to avoid cardinality explosion (route only; reasons collapsed where needed).
"""
from __future__ import annotations
from typing import Optional, Dict, Any
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

# Registry must be created before metric objects reference it.
REGISTRY = CollectorRegistry()

REQUEST_COUNTER = Counter(
    "signet_pqc_requests_total",
    "Total requests through PCH middleware (protected + public).",
    ["route", "result", "reason", "http_status"],
    registry=REGISTRY,
)
HTTP_RESPONSES = Counter(
    "signet_http_responses_total",
    "HTTP responses by status code.",
    ["route", "code"],
    registry=REGISTRY,
)
BREAKER_STATE = Gauge(
    "signet_pqc_breaker_state",
    "Breaker state numeric (Closed=0, HalfOpen=1, Open=2).",
    ["route"],
    registry=REGISTRY,
)
ERR_EWMA = Gauge(
    "signet_pqc_err_ewma",
    "EWMA error rate per route.",
    ["route"],
    registry=REGISTRY,
)
RHO = Gauge(
    "signet_pqc_rho",
    "Utilization (rho) estimate per route.",
    ["route"],
    registry=REGISTRY,
)
KINGMAN_WQ = Gauge(
    "signet_pqc_kingman_wq_ms",
    "Kingman queue wait (ms) estimate per route.",
    ["route"],
    registry=REGISTRY,
)
UTILITY_U = Gauge(
    "signet_pqc_utility_u",
    "Utility U (if computed) per route.",
    ["route"],
    registry=REGISTRY,
)
HEADER_HIST = Histogram(
    "signet_pqc_header_total_bytes",
    "Histogram of total request header bytes (approx).",
    ["route"],
    buckets=(128,256,512,768,1024,2048,3072,4096,6144,8192,16384),
    registry=REGISTRY,
)
SIG_HIST = Histogram(
    "signet_pqc_signature_bytes",
    "Histogram of signature header size (bytes).",
    ["route"],
    buckets=(32,64,96,128,192,256,384,512,768,1024,2048),
    registry=REGISTRY,
)
LAT_HIST = Histogram(
    "signet_pqc_latency_ms",
    "End-to-end middleware observed latency (ms).",
    ["route"],
    buckets=(1,2,5,10,25,50,75,100,150,250,500,1000,2000),
    registry=REGISTRY,
)

# Relax mode correlation counter (added after main metrics to avoid ordering issues)
RELAX_COUNTER = Counter(
    "signet_pqc_relax_mode_total",
    "Count of requests observed in relax header budget mode (heuristic).",
    ["route", "reason"],
    registry=REGISTRY,
)

BREAKER_STATE_ENUM = {"Closed": 0, "HalfOpen": 1, "Open": 2}

def observe_request(
    *,
    route: str,
    verified: bool,
    failure_reason: str,
    http_status: int,
    header_total_bytes: int,
    signature_bytes: int,
    latency_ms: float,
):
    result = "ok" if verified else "fail"
    REQUEST_COUNTER.labels(route=route, result=result, reason=failure_reason, http_status=str(http_status)).inc()
    HTTP_RESPONSES.labels(route=route, code=str(http_status)).inc()
    HEADER_HIST.labels(route=route).observe(header_total_bytes)
    SIG_HIST.labels(route=route).observe(signature_bytes)
    LAT_HIST.labels(route=route).observe(latency_ms)
    if failure_reason in ("missing_signature", "bad_signature") and header_total_bytes > 4096:
        # heuristic relax trigger correlation metric
        RELAX_COUNTER.labels(route=route, reason="over_budget_retry").inc()


def update_breaker_snapshot(route: str, snapshot: Dict[str, Any], plan: Dict[str, Any]):
    state = snapshot.get("name") or snapshot.get("state") or "Closed"
    BREAKER_STATE.labels(route=route).set(BREAKER_STATE_ENUM.get(state, 0))
    ERR_EWMA.labels(route=route).set(snapshot.get("err_ewma", 0.0))
    RHO.labels(route=route).set(snapshot.get("rho_est", 0.0))
    KINGMAN_WQ.labels(route=route).set(snapshot.get("kingman_wq_ms", 0.0))
    util = plan.get("utility") if plan else None
    if util and isinstance(util, dict):
        # Prefer computed U if present (u_attempt vs fallback chosen); fall back None
        u_attempt = util.get("u_attempt")
        u_fallback = util.get("u_fallback")
        chosen = None
        if u_attempt is not None and u_fallback is not None:
            # If fallback chosen (plan['action'] == FALLBACK_CLASSIC) reflect whichever bigger? Use attempt else fallback
            chosen = u_attempt if plan.get("action") != "FALLBACK_CLASSIC" else u_fallback
        elif u_attempt is not None:
            chosen = u_attempt
        if chosen is not None:
            UTILITY_U.labels(route=route).set(chosen)


def prometheus_latest() -> tuple[bytes, str]:
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
