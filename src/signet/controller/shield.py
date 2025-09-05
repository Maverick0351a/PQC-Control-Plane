"""Execution layer enforcing breaker actions & correctness safety invariants.

New invariant interface: check(plan_action, obs, cfg) -> (allowed, override_action, reason)
This gate evaluates correctness / safety before executing an action.
"""
from __future__ import annotations
from fastapi.responses import JSONResponse
from .plan import plan, outcome, register_probe

# Default thresholds (can be overridden via cfg passed to check)
DEFAULT_THRESHOLDS = {"trip_open": 0.2}

def check(plan_action: str, obs: dict, cfg: dict | None = None):
    """Evaluate safety invariants.

    Parameters:
      plan_action: proposed action (e.g. ATTEMPT_PQC, FALLBACK_CLASSIC, THROTTLE_PCH)
      obs: runtime observations; expected keys:
          binding_type (str)
          ewma_5xx (float)   - 1m EWMA of 5xx rate
      cfg: configuration; expected keys:
          require_tls_exporter (bool)
          thresholds: { trip_open: float }

    Returns:
      (allowed_original: bool, override_action_or_None: str|None, reason: str|None)
    """
    if cfg is None:
        cfg = {}
    thresholds = {**DEFAULT_THRESHOLDS, **cfg.get("thresholds", {})}
    require_tls_exporter = bool(cfg.get("require_tls_exporter", False))
    binding_type = obs.get("binding_type")
    ewma_5xx = float(obs.get("ewma_5xx", 0.0))

    # 1. Exporter requirement invariant
    if require_tls_exporter and binding_type != "tls-exporter":
        # Block original plan (cannot enforce PQC strictly when binding weaker than required)
        return (False, "THROTTLE_PCH", "require_tls_exporter_binding_mismatch")

    # 2. High 5xx EWMA invariant: disallow strict PQC-only attempt; force fallback
    if ewma_5xx > thresholds.get("trip_open", 0.2):
        if plan_action not in ("FALLBACK_CLASSIC", "RELAX_HEADER_BUDGET", "THROTTLE_PCH"):
            return (False, "FALLBACK_CLASSIC", "high_5xx_rate")

    # 3. Receipt invariant - always require receipts; represented by not overriding
    return (True, None, None)

def shield(route: str):
    pl = plan(route)
    action = pl["action"]
    if action == "THROTTLE_PCH":
        return JSONResponse({"error": "pqc_breaker_open", "controller": pl}, status_code=503, headers={"Retry-After":"5"})
    if action == "PROBE_HALF_OPEN":
        register_probe(route)
    return pl

def shield_outcome(route: str, success: bool):
    outcome(route, success)
