import time

from src.signet.controller.plan import plan, clear_utility_context, set_utility_context
from src.signet.controller.state import load_state, save_state
from src.signet.controller.plan import outcome, register_probe
from src.signet.controller.monitor import monitor

ROUTE = "/protected"


def reset_state():
    clear_utility_context()
    snap = load_state(ROUTE)
    snap.name = "Closed"
    snap.consecutive_successes = 0
    snap.in_flight_probe = False
    snap.last_transition_ts = 0.0
    save_state(ROUTE, snap)


def test_trip_open_on_error_ewma():
    reset_state()
    # Simulate high error EWMA (> TRIP_ERR=0.2)
    rs = monitor.routes[ROUTE]
    rs.ewma_error.value = 0.5
    rs.kingman_wq_ms = 0.0
    clear_utility_context()
    p = plan(ROUTE)
    assert p["state"] == "Open"
    assert p["action"] == "THROTTLE_PCH"
    assert p["reason"].startswith("trip_open")


def test_half_open_after_cooldown_and_reclose_on_success():
    reset_state()
    # First, trip it open
    rs = monitor.routes[ROUTE]
    rs.ewma_error.value = 0.5
    p1 = plan(ROUTE)
    assert p1["state"] == "Open"
    # Force cooldown expiry
    snap = load_state(ROUTE)
    snap.last_transition_ts = time.time() - 10.0  # > COOLDOWN_SEC (5s)
    save_state(ROUTE, snap)
    p2 = plan(ROUTE)
    assert p2["state"] == "HalfOpen"
    assert p2["action"] == "PROBE_HALF_OPEN"
    # Register probe then simulate successes to close
    register_probe(ROUTE)
    # Simulate probe success 3 times (CLOSE_SUCCESSES)
    for _ in range(3):
        outcome(ROUTE, True)
    # Improve underlying error metric to allow staying closed
    rs.ewma_error.value = 0.0
    p3 = plan(ROUTE)
    assert p3["state"] == "Closed"  # remains closed since error metric recovered
    assert p3["action"] == "ATTEMPT_PQC"


def test_probe_in_flight_throttles():
    reset_state()
    # Trip open then cooldown to half-open
    rs = monitor.routes[ROUTE]
    rs.ewma_error.value = 0.5
    plan(ROUTE)
    snap = load_state(ROUTE)
    snap.last_transition_ts = time.time() - 10.0
    save_state(ROUTE, snap)
    plan(ROUTE)  # enter HalfOpen
    register_probe(ROUTE)
    p = plan(ROUTE)
    assert p["state"] == "HalfOpen"
    assert p["action"] == "THROTTLE_PCH"
    assert p["reason"] == "probe_in_flight"


def test_safety_gate_availability():
    reset_state()
    set_utility_context(
        {
            "availability_floor_5xx_ewma": 0.05,  # max tolerated 5xx rate
            "ewma_5xx": 0.10,  # current exceeds floor -> negative headroom
            "header_budget_total": 8000,
            "header_total_bytes": 1000,
        }
    )
    p = plan(ROUTE)
    assert p["action"] == "FALLBACK_CLASSIC"
    assert p["reason"].startswith("safety_availability")


def test_safety_gate_both_violated_prefers_relax():
    reset_state()
    set_utility_context(
        {
            "availability_floor_5xx_ewma": 0.05,
            "ewma_5xx": 0.10,  # availability violated
            "header_budget_total": 4000,
            "header_total_bytes": 5000,  # header budget violated
        }
    )
    p = plan(ROUTE)
    assert p["action"] == "RELAX_HEADER_BUDGET"
    assert p["reason"] == "safety_both_violated"
