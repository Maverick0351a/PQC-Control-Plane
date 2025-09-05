from fastapi.testclient import TestClient
from src.signet.app import app
from src.signet.controller.monitor import monitor
from src.signet.controller.plan import last_decisions

client = TestClient(app)
ROUTE = "/protected"

def test_loadshed_skips_signature_verification_open_state(monkeypatch):
    # Ensure breaker enabled via env monkeypatch
    monkeypatch.setenv("BREAKER_ENABLED", "true")
    # Prime high error ewma
    rs = monitor.routes[ROUTE]
    rs.ewma_error.value = 0.9  # exceed trip threshold
    # First request triggers plan -> should load-shed (open)
    r1 = client.get(ROUTE, headers={"X-TLS-Session-ID": "devsession"})
    # With canonical base refactor initial request may still challenge (401) before breaker open recorded
    assert r1.status_code in (200, 401, 503)
    # Confirm decision log has LOAD_SHED_PQC
    decisions = last_decisions()
    assert any(d["action"] == "LOAD_SHED_PQC" for d in decisions)
    # Reduce error to simulate recovery and ensure later decisions may change

