"""Execution layer enforcing breaker actions & correctness safety invariants.

Rego / OPA integration:
If `policy/shield.rego` exists and `opa` binary is available on PATH, we evaluate policy
to externalize safety decisions. Fallback to legacy inline rules if OPA absent.

Rego expected input structure:
{
    "obs": {"binding_type": str, "ewma_5xx": float},
    "cfg": {"safety": {"require_tls_exporter": bool, "availability_floor_5xx_ewma": float}}
}

Policy returns:
 - allow (boolean)
 - fallback (boolean)
 - enforce_allowed (boolean)

Mapping to breaker overrides:
    if require exporter & not allow => THROTTLE_PCH
    elif fallback => FALLBACK_CLASSIC
    else keep plan action
"""
from __future__ import annotations
from fastapi.responses import JSONResponse
from .plan import plan, outcome, register_probe
import json, os, subprocess, shutil

# Default thresholds (can be overridden via cfg passed to check)
DEFAULT_THRESHOLDS = {"trip_open": 0.2}

_REGO_POLICY_PATH = os.path.join(os.getcwd(), "policy", "shield.rego")
_OPA_BIN = shutil.which("opa")

def _eval_rego(obs: dict, cfg: dict) -> dict | None:
    if not (_OPA_BIN and os.path.exists(_REGO_POLICY_PATH)):
        return None
    try:
        # opa eval -f json -d policy/shield.rego 'data.signet.shield'
        input_doc = json.dumps({"obs": obs, "cfg": cfg})
        cmd = [_OPA_BIN, "eval", "-f", "json", "-d", _REGO_POLICY_PATH, "data.signet.shield"]
        proc = subprocess.run(cmd, input=input_doc.encode(), capture_output=True, timeout=1.0)
        if proc.returncode != 0:
            return None
        out = json.loads(proc.stdout.decode())
        # Extract first expression value object
        rs = out.get("result") or []
        if not rs:
            return None
        bindings = rs[0].get("expressions", [{}])[0].get("value")
        if isinstance(bindings, dict):
            # Normalize booleans
            return {
                "allow": bool(bindings.get("allow")),
                "fallback": bool(bindings.get("fallback")),
                "enforce_allowed": bool(bindings.get("enforce_allowed")),
            }
    except Exception:
        return None
    return None

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

    # Attempt Rego evaluation first
    rego_cfg = {"safety": {"require_tls_exporter": require_tls_exporter, "availability_floor_5xx_ewma": thresholds.get("trip_open", 0.2)}}
    rego_obs = {"binding_type": binding_type, "ewma_5xx": ewma_5xx}
    rego_res = _eval_rego(rego_obs, {"safety": rego_cfg["safety"]})
    if rego_res:
        if not rego_res.get("allow") and require_tls_exporter and binding_type != "tls-exporter":
            return (False, "THROTTLE_PCH", "require_tls_exporter_binding_mismatch")
        if rego_res.get("fallback") and plan_action not in ("FALLBACK_CLASSIC", "RELAX_HEADER_BUDGET", "THROTTLE_PCH"):
            return (False, "FALLBACK_CLASSIC", "high_5xx_rate_rego")
        return (True, None, None)

    # Legacy inline fallback if Rego not available
    if require_tls_exporter and binding_type != "tls-exporter":
        return (False, "THROTTLE_PCH", "require_tls_exporter_binding_mismatch")
    if ewma_5xx > thresholds.get("trip_open", 0.2):
        if plan_action not in ("FALLBACK_CLASSIC", "RELAX_HEADER_BUDGET", "THROTTLE_PCH"):
            return (False, "FALLBACK_CLASSIC", "high_5xx_rate")
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
