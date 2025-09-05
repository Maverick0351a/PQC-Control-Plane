from starlette.testclient import TestClient
from src.signet.app import app


def test_metrics_endpoint_fields(monkeypatch):
    monkeypatch.setenv('BREAKER_ENABLED', 'true')
    client = TestClient(app)
    # generate some traffic
    for _ in range(3):
        client.get('/protected')
    r = client.get('/__metrics')
    assert r.status_code == 200
    data = r.json()
    assert 'routes' in data
    assert 'decisions' in data
    if data['routes']:
        sample = data['routes'][0]
        expected_keys = [
            'state', 'rho', 'Ca2', 'Cs2', 'kingman_wq_ms', 'err_ewma_pqc',
            'lat_ewma_ms_pqc', 'ewma_5xx', 'consecutive_successes', 'deadband'
        ]
        for k in expected_keys:
            assert k in sample, f'missing field {k}'
        assert isinstance(sample['deadband'], dict)
