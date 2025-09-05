from src.signet.controller.shield import check


def test_shield_binding_mismatch_exports_required():
    allowed, override, reason = check(
        plan_action='ATTEMPT_PQC',
        obs={'binding_type':'tls-session-id','ewma_5xx':0.01},
        cfg={'require_tls_exporter':True,'thresholds':{'trip_open':0.2}}
    )
    assert allowed is False
    assert override == 'THROTTLE_PCH'
    assert reason == 'require_tls_exporter_binding_mismatch'


def test_shield_high_5xx_forces_fallback():
    allowed, override, reason = check(
        plan_action='ATTEMPT_PQC',
        obs={'binding_type':'tls-exporter','ewma_5xx':0.5},
        cfg={'require_tls_exporter':False,'thresholds':{'trip_open':0.2}}
    )
    assert allowed is False
    assert override == 'FALLBACK_CLASSIC'
    assert reason == 'high_5xx_rate'
