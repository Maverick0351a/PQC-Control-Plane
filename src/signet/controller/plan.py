"""Planning logic for circuit breaker actions."""
from __future__ import annotations
import time
from typing import Dict, Any
from .state import (
    load_state,
    save_state,
    transition,
    mark_success,
    mark_failure,
    set_probe,
)
from .monitor import monitor

TRIP_ERR = 0.2  # err_ewma threshold (lower for tests)
TRIP_WQ_MS = 50.0  # queueing delay
COOLDOWN_SEC = 5.0
CLOSE_SUCCESSES = 3

# Utility planning context (test / dynamic injection). Tests can set via set_utility_context.
_UTILITY_CONTEXT: Dict[str, Any] | None = None

def set_utility_context(cfg: Dict[str, Any]):  # pragma: no cover simple setter
    global _UTILITY_CONTEXT
    _UTILITY_CONTEXT = dict(cfg) if cfg is not None else None

def clear_utility_context():  # pragma: no cover
    global _UTILITY_CONTEXT
    _UTILITY_CONTEXT = None

def plan(route: str) -> Dict[str, Any]:
    snap = load_state(route)
    rs = monitor.routes.get(route)
    if rs:
        s = rs.snapshot()
        snap.err_ewma = s["ewma_error_rate"]
        snap.lat_ewma = s["ewma_latency_ms"]
        snap.rho_est = s["rho_estimate"]
        snap.kingman_wq_ms = s["kingman_wq_ms"]
        save_state(route, snap)
    # Anomaly-driven fast open: if global 431 header spike detected treat as immediate trip
    anomalies = monitor.anomalies
    header_spike = anomalies.get("header_431_spike") if anomalies else False

    now = time.time()
    action = "ATTEMPT_PQC"
    reason = "normal"
    # State machine
    if snap.name == "Closed":
        # If utility context present we allow utility evaluation first; only trip if no context
        if not _UTILITY_CONTEXT and (header_spike or snap.err_ewma > TRIP_ERR or snap.kingman_wq_ms > TRIP_WQ_MS):
            transition(route, snap, "Open")
            action = "THROTTLE_PCH"
            reason = "trip_open_header_spike" if header_spike else "trip_open"
    elif snap.name == "Open":
        if now - snap.last_transition_ts >= COOLDOWN_SEC:
            transition(route, snap, "HalfOpen")
            action = "PROBE_HALF_OPEN"
            reason = "enter_half_open"
        else:
            action = "THROTTLE_PCH"
            reason = "open_cooldown"
    elif snap.name == "HalfOpen":
        if snap.in_flight_probe:
            action = "THROTTLE_PCH"
            reason = "probe_in_flight"
        else:
            action = "PROBE_HALF_OPEN"
            reason = "allow_probe"

    # If state machine left us in Closed normal mode attempt PQC, apply safety gate + utility
    utility_meta: Dict[str, Any] = {}
    if snap.name == "Closed" and action == "ATTEMPT_PQC" and _UTILITY_CONTEXT:
        ctx = _UTILITY_CONTEXT
        # Safety (Leontief) gate: both headrooms must be positive
        availability_floor = ctx.get("availability_floor_5xx_ewma", 0.99)  # e.g., 99% availability => floor 0.99 success, so 5xx floor means max allowed?
        ewma_5xx = ctx.get("ewma_5xx", 0.0)
        # Interpret availability_floor_5xx_ewma as maximum tolerated 5xx rate; headroom positive if current < floor
        availability_headroom = availability_floor - ewma_5xx
        header_budget_total = ctx.get("header_budget_total", 8192)
        header_total_bytes = ctx.get("header_total_bytes", 0)
        header_budget_headroom = header_budget_total - header_total_bytes
        utility_meta.update({
            "availability_headroom": availability_headroom,
            "header_budget_headroom": header_budget_headroom,
        })
        if availability_headroom <= 0 and header_budget_headroom <= 0:
            # Pick the more critical (choose header relax to reduce overhead first)
            action = "RELAX_HEADER_BUDGET"
            reason = "safety_both_violated"
        elif availability_headroom <= 0:
            action = "FALLBACK_CLASSIC"
            reason = "safety_availability"
        elif header_budget_headroom <= 0:
            action = "RELAX_HEADER_BUDGET"
            reason = "safety_header_budget"
        else:
            # Within safe envelope -> Cobb-Douglas utilities
            alpha = ctx.get("alpha", 0.5)
            beta = ctx.get("beta", 0.5)
            gamma = ctx.get("gamma", 0.5)
            pqc_rate = max(ctx.get("pqc_rate", 0.0), 0.0)
            failure_rate = min(max(ctx.get("failure_rate", 0.0), 0.0), 1.0)
            slo_headroom = max(ctx.get("slo_headroom", 0.0), 0.0)
            fallback_pqc_rate = max(ctx.get("fallback_pqc_rate", pqc_rate * 0.5), 0.0)
            fallback_failure_rate = min(max(ctx.get("fallback_failure_rate", failure_rate * 0.5), 0.0), 1.0)
            fallback_slo_headroom = max(ctx.get("fallback_slo_headroom", slo_headroom), 0.0)
            def cd(pqc_r, fail_r, slo_h):
                # (PQC_rate)^alpha * (1 - failure_rate)^beta * (SLO_headroom)^gamma
                if pqc_r <= 0 or slo_h <= 0 or fail_r >= 1.0:
                    return 0.0
                return (pqc_r ** alpha) * ((1 - fail_r) ** beta) * (slo_h ** gamma)
            u_attempt = cd(pqc_rate, failure_rate, slo_headroom)
            u_fallback = cd(fallback_pqc_rate, fallback_failure_rate, fallback_slo_headroom)
            utility_meta.update({
                "u_attempt": round(u_attempt, 6),
                "u_fallback": round(u_fallback, 6),
                "pqc_rate": pqc_rate,
                "failure_rate": failure_rate,
                "slo_headroom": slo_headroom,
                "fallback_pqc_rate": fallback_pqc_rate,
                "fallback_failure_rate": fallback_failure_rate,
            })
            if u_fallback > u_attempt:
                action = "FALLBACK_CLASSIC"
                reason = "utility_fallback"
            else:
                reason = "utility_attempt"

    return {
        "state": snap.name,
        "err_ewma": snap.err_ewma,
        "rho": snap.rho_est,
        "kingman_wq_ms": snap.kingman_wq_ms,
        "action": action,
        "reason": reason,
        "deadband": {"open": TRIP_ERR, "close_successes": CLOSE_SUCCESSES},
        "utility": utility_meta or None,
    }

def outcome(route: str, success: bool):
    snap = load_state(route)
    if snap.name == "HalfOpen":
        # Release probe flag
        snap.in_flight_probe = False
        if success:
            snap.consecutive_successes += 1
            if snap.consecutive_successes >= CLOSE_SUCCESSES:
                transition(route, snap, "Closed")
            else:
                save_state(route, snap)
        else:
            transition(route, snap, "Open")
    elif snap.name == "Closed":
        if success:
            mark_success(route, snap)
        else:
            mark_failure(route, snap)
    elif snap.name == "Open":
        # ignore until half-open
        pass

def register_probe(route: str):
    snap = load_state(route)
    if snap.name == "HalfOpen" and not snap.in_flight_probe:
        set_probe(route, snap, True)
