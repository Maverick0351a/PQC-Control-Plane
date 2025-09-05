# Copilot prompt: Implement Monitor sensors for Signet as described in the user story.
#
# Features:
# - monitor.emit(event) where event has fields:
#   pch_present (bool), pch_verified (bool or None), failure_reason (str in set),
#   header_total_bytes (int), largest_header_bytes (int), signature_bytes (int),
#   latency_ms (float|None), http_status (int), is_guarded_route (bool), tls_binding_header_present (bool)
# - Maintains counters/histograms:
#   pqc_attempts_total, pqc_verified_total, pqc_fail_total_by_reason (dict),
#   header_total_bytes_hist (bucket counts), signature_bytes_hist,
#   http_5xx_total, http_431_total, http_timeout_total
# - Per-route rolling EWMA (alpha=0.2) for error rate and latency: ewma_error_rate, ewma_latency_ms
# - Per-route rho_estimate (M/M/c with c=1) using arrival rate and service rate from rolling stats.
# - Kingman's Wq approximation (ms) per-route: kingman_wq_ms
# - Rolling variance estimates for inter-arrival (Ca^2) and service (Cs^2)
# - Simple anomaly flags (global): tls_alert_spike, header_431_spike, timeout_spike toggled when short-term rate exceeds threshold relative to baseline.
# - monitor.snapshot(route=None) returns overall + per-route data; route specific if provided.
#
# Implementation notes:
# - Use thread-safe locks.
# - Maintain minimal rolling windows (store last N=128 events per route for variance & timing).
# - EWMAs updated each emit.
# - Timeout detection: http_status == 599 or failure_reason == 'transport'.
# - Spike detection uses simple ratio: recent(60s)/baseline(10m) > 3 and recent absolute > minimal threshold.
# - Provide a lightweight JSON-serializable snapshot.

from __future__ import annotations
import time
import threading
from collections import defaultdict, deque
from typing import Dict, Any, Optional, Deque, Tuple

ALPHA = 0.2
MAX_POINTS = 128
SPIKE_RATIO = 3.0
MIN_SPIKE_ABS = 5

FailureReasons = {"bad_signature","bad_binding","nonce_replay","header_budget","transport","none","missing_signature","bad_signature_input","bad_content_digest","unknown"}

class EWMA:
    def __init__(self):
        self.value = 0.0
        self.initialized = False
    def update(self, sample: float, alpha: float = ALPHA):
        if not self.initialized:
            self.value = sample
            self.initialized = True
        else:
            self.value = alpha * sample + (1 - alpha) * self.value
        return self.value

class RouteStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.ewma_error = EWMA()
        self.ewma_latency_ms = EWMA()
        self.events: Deque[Tuple[float, float]] = deque(maxlen=MAX_POINTS)  # (ts, latency_ms)
        self.arrivals: Deque[float] = deque(maxlen=MAX_POINTS)  # timestamps
        self.service_times: Deque[float] = deque(maxlen=MAX_POINTS)
        self.last_arrival_ts: Optional[float] = None
        self.total = 0
        self.errors = 0
        self.rho = 0.0
        self.kingman_wq_ms = 0.0

    def observe(self, latency_ms: Optional[float], error: bool):
        now = time.time()
        with self.lock:
            self.total += 1
            if error:
                self.errors += 1
            if latency_ms is None:
                latency_ms = 0.0
            # EWMA updates
            self.ewma_error.update(1.0 if error else 0.0)
            self.ewma_latency_ms.update(latency_ms)
            # Arrival process
            if self.last_arrival_ts is not None:
                inter = now - self.last_arrival_ts
                self.arrivals.append(inter)
            self.last_arrival_ts = now
            # Service time approx from latency (single server)
            self.service_times.append(latency_ms / 1000.0)  # convert ms to s
            self.events.append((now, latency_ms))
            self._update_queue_metrics()

    def _var(self, values: Deque[float]) -> float:
        if len(values) < 2:
            return 0.0
        m = sum(values)/len(values)
        return sum((v-m)**2 for v in values)/(len(values)-1)

    def _update_queue_metrics(self):
        # Arrival rate lambda: inverse of mean inter-arrival
        if self.arrivals:
            mean_inter = sum(self.arrivals)/len(self.arrivals)
            if mean_inter > 0:
                lam = 1.0/mean_inter
            else:
                lam = 0.0
        else:
            lam = 0.0
        # Service rate mu: inverse of mean service time
        if self.service_times:
            mean_st = sum(self.service_times)/len(self.service_times)
            mu = 1.0/mean_st if mean_st > 0 else 0.0
        else:
            mu = 0.0
        c = 1
        rho = (lam/(c*mu)) if mu > 0 else 0.0
        if rho >= 1.0:
            rho = 0.999  # cap to avoid blow-up
        self.rho = rho
        # Variability
        Ca2 = self._var(self.arrivals)/( (sum(self.arrivals)/len(self.arrivals))**2 ) if self.arrivals else 0.0
        Cs2 = self._var(self.service_times)/( (sum(self.service_times)/len(self.service_times))**2 ) if self.service_times else 0.0
        # Kingman's formula (Wq in seconds)
        if mu > 0 and lam > 0:
            Wq = (rho/(1-rho)) * ((Ca2 + Cs2)/2.0) * (1.0/mu)
        else:
            Wq = 0.0
        self.kingman_wq_ms = Wq * 1000.0

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "total": self.total,
                "errors": self.errors,
                "ewma_error_rate": self.ewma_error.value,
                "ewma_latency_ms": self.ewma_latency_ms.value,
                "rho_estimate": self.rho,
                "kingman_wq_ms": self.kingman_wq_ms,
            }

class Monitor:
    def __init__(self):
        self.lock = threading.Lock()
        # Counters
        self.pqc_attempts_total = 0
        self.pqc_verified_total = 0
        self.pqc_fail_total_by_reason: Dict[str, int] = defaultdict(int)
        self.http_5xx_total = 0
        self.http_431_total = 0
        self.http_timeout_total = 0
        # DPCP (advisory provenance) counters
        self.dpcp_total = 0
        self.dpcp_ekm_bound_total = 0
        self.dpcp_profile_counts: Dict[str, int] = defaultdict(int)
        # Histograms (simple bucket counts)
        self.header_total_bytes_hist: Dict[str, int] = defaultdict(int)
        self.signature_bytes_hist: Dict[str, int] = defaultdict(int)
        self.routes: Dict[str, RouteStats] = defaultdict(RouteStats)
        # Anomaly baseline counts
        self._recent_431: Deque[float] = deque(maxlen=256)
        self._recent_timeouts: Deque[float] = deque(maxlen=256)
        self._recent_tls_missing: Deque[float] = deque(maxlen=256)
        self.anomalies = {
            "tls_alert_spike": False,
            "header_431_spike": False,
            "timeout_spike": False,
        }

    def _bucket(self, size: int) -> str:
        # Power-of-two like buckets
        bounds = [64,128,256,512,1024,2048,4096,8192,16384,32768]
        for b in bounds:
            if size <= b:
                return f"<={b}"
        return ">32768"

    def emit(self, event: Dict[str, Any]):
        now = time.time()
        pch_present = event.get("pch_present", False)
        pch_verified = event.get("pch_verified")
        failure_reason = event.get("failure_reason", "none") or "none"
        if failure_reason not in FailureReasons:
            failure_reason = "unknown"
        header_total_bytes = int(event.get("header_total_bytes", 0))
        signature_bytes = int(event.get("signature_bytes", 0))
        http_status = int(event.get("http_status", 0))
        latency_ms = event.get("latency_ms")
        route = event.get("route", "/")
        tls_binding_present = event.get("tls_binding_header_present", False)
        timeout = (http_status == 599) or (failure_reason == "transport")

        with self.lock:
            if pch_present:
                self.pqc_attempts_total += 1
                if pch_verified:
                    self.pqc_verified_total += 1
                else:
                    if pch_verified is False:
                        self.pqc_fail_total_by_reason[failure_reason] += 1
            if 500 <= http_status < 600:
                self.http_5xx_total += 1
            if http_status == 431:
                self.http_431_total += 1
                self._recent_431.append(now)
            if timeout:
                self.http_timeout_total += 1
                self._recent_timeouts.append(now)
            if not tls_binding_present:
                self._recent_tls_missing.append(now)
            self.header_total_bytes_hist[self._bucket(header_total_bytes)] += 1
            self.signature_bytes_hist[self._bucket(signature_bytes)] += 1

        rs = self.routes[route]
        route_error = bool((pch_present and not pch_verified) or http_status == 431 or (500 <= http_status < 600))
        rs.observe(latency_ms=latency_ms, error=route_error)
        self._update_anomalies(now)

    def _recent_rate(self, dq: Deque[float], window: float) -> float:
        if not dq:
            return 0.0
        cutoff = time.time() - window
        count = sum(1 for t in dq if t >= cutoff)
        return count / window

    def _update_anomalies(self, now: float):
        # Compare recent short (60s) vs long (600s)
        short_win = 60.0
        long_win = 600.0
        r_431_short = self._recent_rate(self._recent_431, short_win)
        r_431_long = self._recent_rate(self._recent_431, long_win)
        r_to_short = self._recent_rate(self._recent_timeouts, short_win)
        r_to_long = self._recent_rate(self._recent_timeouts, long_win)
        r_tls_short = self._recent_rate(self._recent_tls_missing, short_win)
        r_tls_long = self._recent_rate(self._recent_tls_missing, long_win)
        with self.lock:
            self.anomalies["header_431_spike"] = (r_431_short > SPIKE_RATIO * max(r_431_long, 1e-6) and r_431_short * short_win >= MIN_SPIKE_ABS)
            self.anomalies["timeout_spike"] = (r_to_short > SPIKE_RATIO * max(r_to_long, 1e-6) and r_to_short * short_win >= MIN_SPIKE_ABS)
            self.anomalies["tls_alert_spike"] = (r_tls_short > SPIKE_RATIO * max(r_tls_long, 1e-6) and r_tls_short * short_win >= MIN_SPIKE_ABS)

    def snapshot(self, route: Optional[str] = None) -> Dict[str, Any]:
        with self.lock:
            base = {
                "pqc_attempts_total": self.pqc_attempts_total,
                "pqc_verified_total": self.pqc_verified_total,
                "pqc_fail_total_by_reason": dict(self.pqc_fail_total_by_reason),
                "http_5xx_total": self.http_5xx_total,
                "http_431_total": self.http_431_total,
                "http_timeout_total": self.http_timeout_total,
                "dpcp_total": self.dpcp_total,
                "dpcp_ekm_bound_total": self.dpcp_ekm_bound_total,
                "dpcp_profile_counts": dict(self.dpcp_profile_counts),
                "header_total_bytes_hist": dict(self.header_total_bytes_hist),
                "signature_bytes_hist": dict(self.signature_bytes_hist),
                "anomalies": dict(self.anomalies),
            }
        if route:
            rs = self.routes.get(route)
            if rs:
                base["route"] = route
                base["route_stats"] = rs.snapshot()
        else:
            base["routes"] = {r: rs.snapshot() for r, rs in self.routes.items()}
        return base

    def record_dpcp(self, profile: str, ekm_bound: bool):
        with self.lock:
            self.dpcp_total += 1
            if ekm_bound:
                self.dpcp_ekm_bound_total += 1
            if profile:
                self.dpcp_profile_counts[profile] += 1

monitor = Monitor()
