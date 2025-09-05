import time, json
from src.signet.controller.state import load_state, save_state, BreakerState
from src.signet.controller.plan import plan

ROUTE = "/protected"

# Trip breaker open
st = load_state(ROUTE)
st.err_ewma_pqc = 0.5
save_state(ROUTE, st)
print("plan1", plan(ROUTE))

# Inspect state
st = load_state(ROUTE)
print("after trip state", st.state, "cooldown_until", st.cooldown_until_monotonic, "last_ts", getattr(st, "last_transition_ts", None))

# Force cooldown expiry
st.last_transition_ts = time.time() - 10
save_state(ROUTE, st)
print("manipulated", st.cooldown_until_monotonic, st.last_transition_ts)

# Recompute plan (should enter HalfOpen if logic correct)
print("plan2", plan(ROUTE))
