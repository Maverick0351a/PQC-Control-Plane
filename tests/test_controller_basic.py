import time
from src.signet.controller.state import load_state, BreakerState
from src.signet.controller.plan import plan_action, set_utility_context, clear_utility_context
from src.signet.controller.config import ControllerConfig

def make_cfg():
    return ControllerConfig(trip_open=0.35, close_successes=3, cooldown_sec=1, c_servers=4)

ROUTE = "/protected"

def test_hysteresis_trip_and_recover():
    st = load_state(ROUTE)
    cfg = make_cfg()
    # Simulate rising error EWMA beyond trip threshold
    st.err_ewma_pqc = 0.4
    act, ns, rat = plan_action({}, cfg, st)
    assert ns == BreakerState.OPEN
    # Advance time for cooldown
    st.state = ns
    st.cooldown_until_monotonic = time.time() - 1
    act, ns, rat = plan_action({}, cfg, st)
    assert ns == BreakerState.HALF_OPEN
    st.state = ns
    # Provide consecutive successes
    st.err_ewma_pqc = 0.05
    st.consecutive_successes = cfg.close_successes
    act, ns, rat = plan_action({}, cfg, st)
    assert ns == BreakerState.CLOSED


def test_safety_gate_header_budget():
    st = load_state(ROUTE + "hb")
    cfg = make_cfg()
    st.err_ewma_pqc = 0.0
    set_utility_context({"header_total_bytes": cfg.header_budget_max + 100, "ewma_5xx": 0.0, "pqc_rate":1.0})
    act, ns, rat = plan_action({"header_total_bytes": cfg.header_budget_max + 100}, cfg, st)
    clear_utility_context()
    assert act == "FALLBACK_CLASSIC"


def test_utility_prefers_attempt_with_headroom():
    st = load_state(ROUTE + "util")
    cfg = make_cfg()
    st.err_ewma_pqc = 0.05
    # Good conditions
    set_utility_context({
        "header_total_bytes": 1000,
        "ewma_5xx": 0.0,
        "pqc_rate": 0.9,
    })
    act, ns, rat = plan_action({}, cfg, st)
    clear_utility_context()
    assert act == "ATTEMPT_PQC" or rat.get("reason") == "utility_attempt"
