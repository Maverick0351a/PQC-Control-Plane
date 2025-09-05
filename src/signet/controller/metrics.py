"""Controller metrics & queueing utility helpers.

Formulas:
  rho = min(lambda_hat / (c * mu_hat), 0.999)
    - lambda_hat = 1 / mean_interarrival
    - mu_hat = 1 / mean_service_time
  Kingman's formula (Wq seconds):
    Wq = (rho / (1 - rho)) * ((Ca^2 + Cs^2)/2) * (1 / mu_hat)

Where Ca^2, Cs^2 are squared Coefficient of Variation for interarrival & service.
"""
from __future__ import annotations
from typing import Tuple, Optional
from dataclasses import dataclass

from .state import ControllerState

def _safe(mean: float) -> float:
    return mean if mean > 0 else 0.0

def compute_rho_and_wq(st: ControllerState, c: int) -> Tuple[float, float]:
    ia = st.interarrival_stats
    sv = st.service_stats
    if ia.count < 2 or sv.count < 2:
        return (0.0, 0.0)
    mean_inter = _safe(ia.mean)
    mean_service = _safe(sv.mean)
    if mean_inter == 0 or mean_service == 0:
        return (0.0, 0.0)
    lam = 1.0 / mean_inter
    mu = 1.0 / mean_service
    if mu <= 0:
        return (0.0, 0.0)
    rho = lam / (c * mu)
    if rho >= 1.0:
        rho = 0.999
    # Squared CoV = variance / mean^2
    Ca2 = ia.variance / (mean_inter ** 2) if mean_inter > 0 else 0.0
    Cs2 = sv.variance / (mean_service ** 2) if mean_service > 0 else 0.0
    if rho <= 0:
        return (0.0, 0.0)
    Wq = (rho / (1 - rho)) * ((Ca2 + Cs2) / 2.0) * (1.0 / mu)
    return (rho, max(Wq, 0.0))

def kingman_Wq(Ca2: float, Cs2: float, rho: float, mu: float) -> float:
    """Kingman waiting time in queue (seconds)."""
    if mu <= 0 or rho <= 0 or rho >= 1:
        return 0.0
    return (rho / (1 - rho)) * ((Ca2 + Cs2) / 2.0) * (1.0 / mu)

def kingman_Wq_seconds(Ca2: float, Cs2: float, rho: float, mu: float) -> float:  # alias explicit
    return kingman_Wq(Ca2, Cs2, rho, mu)

def compute_slo_headroom(Wq_s: float, service_mean_s: float, slo_latency_target_s: float) -> float:
    if slo_latency_target_s <= 0:
        return 0.0
    total = Wq_s + service_mean_s
    return max(0.0, 1.0 - (total / slo_latency_target_s))

@dataclass
class Observations:
    err_ewma_pqc: float
    ewma_5xx: float
    pqc_rate: float
    failure_rate: float
    slo_headroom: float
    header_total_bytes: int
    binding_type: Optional[str]
    rho: float
    Ca2: float
    Cs2: float
    kingman_wq_ms: float
    pqc_rate_if_attempt: float
    fail_if_attempt: float
    pqc_rate_if_fallback: float
    fail_if_fallback: float
    consecutive_successes: int

    def as_dict(self):  # pragma: no cover - helper
        return self.__dict__.copy()
