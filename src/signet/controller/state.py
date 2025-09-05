"""Lean in-memory controller state & rolling statistics.

Implements:
 - BreakerState enum (CLOSED, HALF_OPEN, OPEN)
 - ControllerState dataclass holding EWMAs & queueing stats
 - RollingStats with Welford variance updates for inter-arrival & service times
 - Accessors to load/update per-route state (kept in-process; intentionally simple)

The previous Redis-backed state has been replaced to satisfy the lean controller
requirements. We keep a thin compatibility layer for older code expecting
`load_state` to return an object with attributes similar to the former
BreakerSnapshot (err_ewma, lat_ewma, rho_est, kingman_wq_ms, consecutive_successes).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Dict

__all__ = [
    "BreakerState",
    "ControllerState",
    "RollingStats",
    "load_state",
    "save_state",
    "update_error_ewma",
    "update_latency_ewma",
    "update_queue_stats",
]


class BreakerState(str, Enum):
    CLOSED = "Closed"
    HALF_OPEN = "HalfOpen"
    OPEN = "Open"


@dataclass
class RollingStats:
    """Welford rolling mean/variance (population) for a metric.

    For inter-arrival we also track last_ts to derive inter-arrival deltas.
    """

    mean: float = 0.0
    m2: float = 0.0  # sum of squares of diffs
    count: int = 0
    last_ts: float = 0.0  # only used for inter-arrival process

    def update(self, value: float):
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    def update_interarrival(self, now_ts: float):
        if self.last_ts > 0.0:
            ia = now_ts - self.last_ts
            if ia < 0:
                ia = 0.0
            self.update(ia)
        self.last_ts = now_ts

    def update_service(self, service_ms: float):
        # store in seconds for queueing theory (service time)
        self.update(max(service_ms, 0.0) / 1000.0)


@dataclass
class ControllerState:
    state: BreakerState = BreakerState.CLOSED
    err_ewma_pqc: float = 0.0
    err_ewma_classic: float = 0.0
    succ_ewma_pqc: float = 0.0
    lat_ewma_ms_pqc: float = 0.0
    consecutive_successes: int = 0
    cooldown_until_monotonic: float = 0.0
    interarrival_stats: RollingStats = field(default_factory=RollingStats)
    service_stats: RollingStats = field(default_factory=RollingStats)
    rho: float = 0.0
    # Queueing extras (cached) so that external plan() calls don't need to recalc each time
    wq_ms: float = 0.0

    # Back-compat shim properties (expected by receipt/tests)
    @property
    def name(self):  # pragma: no cover - simple alias
        return self.state.value

    @name.setter
    def name(self, val):  # pragma: no cover - legacy setter support
        try:
            self.state = BreakerState(val)
        except Exception:
            self.state = BreakerState.CLOSED
        # Mark manual reset time for downstream trip dampening
        try:  # pragma: no cover - simple timestamp
            import time as _t
            self._manual_reset_ts = _t.time()
        except Exception:
            pass

    @property
    def err_ewma(self):  # legacy field name
        return self.err_ewma_pqc

    @property
    def lat_ewma(self):  # legacy field name
        return self.lat_ewma_ms_pqc

    @property
    def kingman_wq_ms(self):
        return self.wq_ms

    @property
    def rho_est(self):  # legacy alias
        return self.rho


_ROUTE_STATES: Dict[str, ControllerState] = {}


def load_state(route: str) -> ControllerState:
    st = _ROUTE_STATES.setdefault(route, ControllerState())
    # attach route for probe lookup
    if not hasattr(st, 'route'):
        setattr(st, 'route', route)
    return st


def save_state(route: str, st: ControllerState):  # pragma: no cover - no-op (in-memory)
    _ROUTE_STATES[route] = st


def update_error_ewma(st: ControllerState, is_pqc: bool, failed: bool, alpha: float = 0.2):
    sample = 1.0 if failed else 0.0
    if is_pqc:
        st.err_ewma_pqc = alpha * sample + (1 - alpha) * st.err_ewma_pqc
        if not failed:
            st.succ_ewma_pqc = alpha * 1.0 + (1 - alpha) * st.succ_ewma_pqc
    else:
        st.err_ewma_classic = alpha * sample + (1 - alpha) * st.err_ewma_classic


def update_latency_ewma(st: ControllerState, service_ms: float, alpha: float = 0.2):
    st.lat_ewma_ms_pqc = alpha * service_ms + (1 - alpha) * st.lat_ewma_ms_pqc


def update_queue_stats(st: ControllerState, now_ts: float, service_ms: float):
    st.interarrival_stats.update_interarrival(now_ts)
    st.service_stats.update_service(service_ms)


def reset_for_new_state(st: ControllerState, new_state: BreakerState, cooldown_sec: int):
    st.state = new_state
    st.consecutive_successes = 0
    if new_state == BreakerState.OPEN:
        st.cooldown_until_monotonic = time.time() + cooldown_sec
    save_state("_dummy", st)  # no-op path but keeps parity

