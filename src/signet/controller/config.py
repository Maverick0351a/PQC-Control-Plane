"""Controller configuration loader.

Loads from environment first, then optional config/controller.yml if present.
"""
from __future__ import annotations
import os
from dataclasses import dataclass
from typing import Dict, Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

_DEFAULT = {
    # Legacy test expectations
    "trip_open": 0.20,
    "close_successes": 3,
    "cooldown_sec": 5,
    "c_servers": 8,
    "weights": {"alpha": 0.5, "beta": 0.35, "gamma": 0.15},
    "availability_floor": 0.08,  # max 5xx EWMA allowed before safety gate
    "header_budget_max": 12000,
    "slo_latency_ms": 300,
}

@dataclass
class ControllerConfig:
    trip_open: float = _DEFAULT["trip_open"]
    close_successes: int = _DEFAULT["close_successes"]
    cooldown_sec: int = _DEFAULT["cooldown_sec"]
    c_servers: int = _DEFAULT["c_servers"]
    weights: Dict[str, float] = None  # type: ignore
    availability_floor: float = _DEFAULT["availability_floor"]
    header_budget_max: int = _DEFAULT["header_budget_max"]
    slo_latency_ms: int = _DEFAULT["slo_latency_ms"]

    def __post_init__(self):
        if self.weights is None:
            self.weights = dict(_DEFAULT["weights"])  # copy

_CONFIG: ControllerConfig | None = None

_DEF_PATH = os.path.join(os.getcwd(), "config", "controller.yml")

_ENV_MAP = {
    "trip_open": ("CONTROLLER_TRIP_OPEN", float),
    "close_successes": ("CONTROLLER_CLOSE_SUCCESSES", int),
    "cooldown_sec": ("CONTROLLER_COOLDOWN_SEC", int),
    "c_servers": ("CONTROLLER_C_SERVERS", int),
    "availability_floor": ("CONTROLLER_AVAILABILITY_FLOOR", float),
    "header_budget_max": ("CONTROLLER_HEADER_BUDGET_MAX", int),
    "slo_latency_ms": ("CONTROLLER_SLO_LATENCY_MS", int),
}

_WEIGHT_ENV = {
    "alpha": ("CONTROLLER_WEIGHT_ALPHA", float),
    "beta": ("CONTROLLER_WEIGHT_BETA", float),
    "gamma": ("CONTROLLER_WEIGHT_GAMMA", float),
}

def load_config() -> ControllerConfig:
    global _CONFIG
    if _CONFIG is not None:
        # Detect if any environment override has changed since last load; if so, rebuild config.
        try:
            for k, (env, cast) in _ENV_MAP.items():
                if env in os.environ:
                    current_val = getattr(_CONFIG, k)  # type: ignore[attr-defined]
                    try:
                        env_val = cast(os.environ[env])
                    except Exception:  # pragma: no cover
                        continue
                    if env_val != current_val:
                        _CONFIG = None
                        break
            if _CONFIG is not None:
                return _CONFIG
        except Exception:  # pragma: no cover - defensive
            return _CONFIG
    data: Dict[str, Any] = {}
    # File first
    if os.path.exists(_DEF_PATH) and yaml:
        try:
            with open(_DEF_PATH, "r", encoding="utf-8") as f:
                file_cfg = yaml.safe_load(f) or {}
            if isinstance(file_cfg, dict):
                data.update(file_cfg)
        except Exception:  # pragma: no cover
            pass
    # Env overrides
    for k, (env, cast) in _ENV_MAP.items():
        if env in os.environ:
            try:
                data[k] = cast(os.environ[env])
            except Exception:  # pragma: no cover
                pass
    weights = dict(_DEFAULT["weights"])
    if "weights" in data and isinstance(data["weights"], dict):
        weights.update({k: float(v) for k, v in data["weights"].items() if k in weights})
    # Env overrides for weights
    for k, (env, cast) in _WEIGHT_ENV.items():
        if env in os.environ:
            try:
                weights[k] = cast(os.environ[env])
            except Exception:
                pass
    cfg = ControllerConfig(
        trip_open=float(data.get("trip_open", _DEFAULT["trip_open"])),
        close_successes=int(data.get("close_successes", _DEFAULT["close_successes"])),
        cooldown_sec=int(data.get("cooldown_sec", _DEFAULT["cooldown_sec"])),
        c_servers=int(data.get("c_servers", _DEFAULT["c_servers"])),
        weights=weights,
        availability_floor=float(data.get("availability_floor", _DEFAULT["availability_floor"])),
        header_budget_max=int(data.get("header_budget_max", _DEFAULT["header_budget_max"])),
        slo_latency_ms=int(data.get("slo_latency_ms", _DEFAULT["slo_latency_ms"])),
    )
    _CONFIG = cfg
    return cfg
