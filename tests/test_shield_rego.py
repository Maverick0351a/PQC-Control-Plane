import os
import shutil
from src.signet.controller.shield import check

POLICY_PRESENT = os.path.exists(os.path.join(os.getcwd(), 'policy', 'shield.rego'))
OPA_PRESENT = shutil.which('opa') is not None

import pytest

@pytest.mark.skipif(not POLICY_PRESENT or not OPA_PRESENT, reason="opa or policy missing")
def test_rego_binding_enforced():
    allowed, override, reason = check(
        plan_action='ATTEMPT_PQC',
        obs={'binding_type':'tls-session-id','ewma_5xx':0.0},
        cfg={'require_tls_exporter': True, 'thresholds': {'trip_open':0.2}}
    )
    assert allowed is False
    assert override == 'THROTTLE_PCH'
    assert 'exporter' in reason

@pytest.mark.skipif(not POLICY_PRESENT or not OPA_PRESENT, reason="opa or policy missing")
def test_rego_fallback_trigger():
    allowed, override, reason = check(
        plan_action='ATTEMPT_PQC',
        obs={'binding_type':'tls-exporter','ewma_5xx':0.5},
        cfg={'require_tls_exporter': True, 'thresholds': {'trip_open':0.2}}
    )
    assert allowed is False
    assert override == 'FALLBACK_CLASSIC'
