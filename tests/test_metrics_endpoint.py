from starlette.testclient import TestClient
from src.signet.app import app

def test_metrics_endpoint_structure():
    client = TestClient(app)
    r = client.get('/__metrics')
    assert r.status_code == 200
    data = r.json()
    assert 'routes' in data
    assert 'monitor' in data
    # After no traffic routes may be empty; generate some traffic
    client.get('/protected')
    client.get('/__metrics')  # refresh once
    r2 = client.get('/__metrics')
    data2 = r2.json()
    assert any(rt.get('route') == '/protected' for rt in data2.get('routes', []))
