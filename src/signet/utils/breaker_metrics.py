import time
import threading
from collections import deque
from typing import Deque, Dict, Any

class SlidingStat:
    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self.points: Deque[tuple[float, float]] = deque()  # (timestamp, value)
        self._lock = threading.Lock()

    def add(self, value: float):
        now = time.time()
        with self._lock:
            self.points.append((now, value))
            self._trim(now)

    def _trim(self, now: float):
        cutoff = now - self.window
        while self.points and self.points[0][0] < cutoff:
            self.points.popleft()

    def avg(self) -> float:
        with self._lock:
            now = time.time(); self._trim(now)
            if not self.points:
                return 0.0
            return sum(v for _, v in self.points) / len(self.points)

    def count(self) -> int:
        with self._lock:
            now = time.time(); self._trim(now)
            return len(self.points)

class BreakerMetrics:
    """Advisory circuit-breaker style metrics (error rate & latency moving averages)."""
    def __init__(self):
        # Windows: short (60s), medium (300s), long (900s)
        self.latency_short = SlidingStat(60)
        self.latency_med = SlidingStat(300)
        self.latency_long = SlidingStat(900)
        self.error_short = SlidingStat(60)
        self.error_med = SlidingStat(300)
        self.error_long = SlidingStat(900)
        self.total_requests = 0
        self.total_errors = 0
        self.state = "closed"  # advisory only
        self._lock = threading.Lock()

    def observe(self, latency_s: float, error: bool):
        with self._lock:
            self.total_requests += 1
            if error:
                self.total_errors += 1
        self.latency_short.add(latency_s)
        self.latency_med.add(latency_s)
        self.latency_long.add(latency_s)
        self.error_short.add(1.0 if error else 0.0)
        self.error_med.add(1.0 if error else 0.0)
        self.error_long.add(1.0 if error else 0.0)
        # Simple advisory heuristic (not enforcing)
        err_rate = self.error_short.avg()
        with self._lock:
            if err_rate > 0.5 and self.state == "closed":
                self.state = "open-advisory"
            elif err_rate < 0.2 and self.state != "closed":
                self.state = "closed"

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "state": self.state,
                "total_requests": self.total_requests,
                "total_errors": self.total_errors,
                "error_rate_short": self.error_short.avg(),
                "error_rate_med": self.error_med.avg(),
                "error_rate_long": self.error_long.avg(),
                "latency_avg_short_ms": self.latency_short.avg() * 1000,
                "latency_avg_med_ms": self.latency_med.avg() * 1000,
                "latency_avg_long_ms": self.latency_long.avg() * 1000,
            }

breaker_metrics = BreakerMetrics()
