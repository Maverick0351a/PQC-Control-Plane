"""Invariant checks for lean controller.

Exports:
  check_invariants(obs, cfg) -> list[str]
  receipts_monotonicity(last_sth_ts, new_sth_ts, last_prev_hash, new_prev_hash) -> list[str]
"""
from __future__ import annotations
from typing import List

def check_invariants(obs: dict, cfg) -> List[str]:
    violations: List[str] = []
    if obs.get("binding_type") != "tls-exporter":
        violations.append("binding_advisory_only")
    if obs.get("ewma_5xx", 0.0) > cfg.availability_floor:
        violations.append("availability_floor")
    if obs.get("header_total_bytes", 0) > cfg.header_budget_max:
        violations.append("header_budget_exceeded")
    return violations

def receipts_monotonicity(last_sth_ts: float | None, new_sth_ts: float | None, last_prev_hash: str | None, new_prev_hash: str | None):
    v: List[str] = []
    if last_sth_ts is not None and new_sth_ts is not None and new_sth_ts < last_sth_ts:
        v.append("sth_timestamp_regression")
    if last_prev_hash is not None and new_prev_hash is not None and last_prev_hash == new_prev_hash:
        v.append("prev_hash_not_advancing")
    return v

# Legacy API expected by tests: check(plan_action, obs, cfg) -> (allowed, override, reason)
def check(plan_action: str, obs: dict, cfg: dict | None = None):  # pragma: no cover - adapter
    class DummyCfg:
        availability_floor = (cfg or {}).get("thresholds", {}).get("trip_open", 0.2)
        header_budget_max = 999999
    dc = DummyCfg()
    if (cfg or {}).get("require_tls_exporter") and obs.get("binding_type") != "tls-exporter":
        return (False, "THROTTLE_PCH", "require_tls_exporter_binding_mismatch")
    if obs.get("ewma_5xx", 0.0) > dc.availability_floor:
        if plan_action not in ("FALLBACK_CLASSIC", "THROTTLE_PCH"):
            return (False, "FALLBACK_CLASSIC", "high_5xx_rate")
    return (True, None, None)

# Backwards compatibility wrappers expected by middleware
def shield(route: str):  # pragma: no cover - legacy path not used in new tests
    from .plan import plan_action
    from .state import load_state
    st = load_state(route)
    cfg = __import__(".config", fromlist=["load_config"]).config.load_config()  # type: ignore
    pl = plan_action({}, cfg, st)
    return {"action": pl[0], "state": st.state.value}

def shield_outcome(route: str, success: bool):  # pragma: no cover - no-op for lean controller
    pass
