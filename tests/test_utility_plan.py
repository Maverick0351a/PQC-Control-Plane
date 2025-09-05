from src.signet.controller.plan import set_utility_context, clear_utility_context, plan
from src.signet.controller.state import load_state, save_state

ROUTE = '/protected'

def setup_function(_):
    clear_utility_context()
    # ensure state closed baseline
    snap = load_state(ROUTE)
    snap.name = 'Closed'
    save_state(ROUTE, snap)


def test_utility_prefers_attempt_when_failure_low():
    set_utility_context({
        'availability_floor_5xx_ewma': 0.05,  # allow up to 5% 5xx
        'ewma_5xx': 0.01,
        'header_budget_total': 8000,
        'header_total_bytes': 2000,
        'alpha': 0.4,
        'beta': 0.4,
        'gamma': 0.2,
        'pqc_rate': 0.9,
        'failure_rate': 0.05,
        'slo_headroom': 0.5,
        'fallback_pqc_rate': 0.3,
        'fallback_failure_rate': 0.02,
        'fallback_slo_headroom': 0.5,
    })
    p = plan(ROUTE)
    assert p['action'] == 'ATTEMPT_PQC'
    assert p['utility']['u_attempt'] >= p['utility']['u_fallback']
    assert p['reason'].startswith('utility_')


def test_utility_prefers_fallback_when_failure_high():
    set_utility_context({
        'availability_floor_5xx_ewma': 0.10,
        'ewma_5xx': 0.02,
        'header_budget_total': 8000,
        'header_total_bytes': 2000,
    'alpha': 0.5,
    'beta': 0.6,  # heavier penalty on failures
    'gamma': 0.2,
    'pqc_rate': 0.6,
    'failure_rate': 0.55,  # very high failure
    'slo_headroom': 0.3,
    'fallback_pqc_rate': 0.45,
    'fallback_failure_rate': 0.10,
    'fallback_slo_headroom': 0.5,
    })
    p = plan(ROUTE)
    assert p['action'] == 'FALLBACK_CLASSIC'
    assert p['utility']['u_fallback'] > p['utility']['u_attempt']
    assert p['reason'] == 'utility_fallback'


def test_safety_gate_header_budget():
    set_utility_context({
        'availability_floor_5xx_ewma': 0.10,
        'ewma_5xx': 0.02,
        'header_budget_total': 4000,
        'header_total_bytes': 5000,  # exceeds budget
        'pqc_rate': 0.9,
        'failure_rate': 0.05,
        'slo_headroom': 0.5,
    })
    p = plan(ROUTE)
    assert p['action'] == 'RELAX_HEADER_BUDGET'
    assert p['reason'].startswith('safety_header_budget')
