"""Redis-backed circuit breaker state management."""
from __future__ import annotations
import time
from dataclasses import dataclass
# (no unused typing imports required)
import redis
from ..config import REDIS_URL

_r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

STATE_KEY = "breaker:state:{route}"

@dataclass
class BreakerSnapshot:
    name: str
    err_ewma: float
    lat_ewma: float
    rho_est: float
    kingman_wq_ms: float
    consecutive_successes: int
    last_transition_ts: float
    in_flight_probe: bool

DEFAULT = {
    "name": "Closed",
    "err_ewma": 0.0,
    "lat_ewma": 0.0,
    "rho_est": 0.0,
    "kingman_wq_ms": 0.0,
    "consecutive_successes": 0,
    "last_transition_ts": 0.0,
    "in_flight_probe": 0,
}

def load_state(route: str) -> BreakerSnapshot:
    key = STATE_KEY.format(route=route)
    data = _r.hgetall(key)
    if not data:
        _r.hset(key, mapping=DEFAULT)
        data = DEFAULT
    return BreakerSnapshot(
        name=data.get("name","Closed"),
        err_ewma=float(data.get("err_ewma",0.0)),
        lat_ewma=float(data.get("lat_ewma",0.0)),
        rho_est=float(data.get("rho_est",0.0)),
        kingman_wq_ms=float(data.get("kingman_wq_ms",0.0)),
        consecutive_successes=int(data.get("consecutive_successes",0)),
        last_transition_ts=float(data.get("last_transition_ts",0.0)),
        in_flight_probe=bool(int(data.get("in_flight_probe",0))),
    )

def save_state(route: str, snap: BreakerSnapshot):
    key = STATE_KEY.format(route=route)
    _r.hset(key, mapping={
        "name": snap.name,
        "err_ewma": snap.err_ewma,
        "lat_ewma": snap.lat_ewma,
        "rho_est": snap.rho_est,
        "kingman_wq_ms": snap.kingman_wq_ms,
        "consecutive_successes": snap.consecutive_successes,
        "last_transition_ts": snap.last_transition_ts,
        "in_flight_probe": int(snap.in_flight_probe),
    })

def transition(route: str, snap: BreakerSnapshot, new_name: str):
    snap.name = new_name
    snap.last_transition_ts = time.time()
    snap.consecutive_successes = 0
    snap.in_flight_probe = False
    save_state(route, snap)

def mark_success(route: str, snap: BreakerSnapshot):
    snap.consecutive_successes += 1
    save_state(route, snap)

def mark_failure(route: str, snap: BreakerSnapshot):
    snap.consecutive_successes = 0
    save_state(route, snap)

def set_probe(route: str, snap: BreakerSnapshot, val: bool):
    snap.in_flight_probe = val
    save_state(route, snap)
