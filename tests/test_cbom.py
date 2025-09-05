from starlette.testclient import TestClient
from src.signet.app import app
from src.signet.config import BINDING_TYPE, ENFORCE_PCH_ROUTES

def test_cbom_basic():
    client = TestClient(app)
    r = client.get('/cbom.json')
    assert r.status_code == 200
    data = r.json()
    assert data['bomFormat'] == 'CycloneDX'
    assert data['metadata']['bindingType'] == BINDING_TYPE
    assert data['metadata']['enforceRoutes'] == ENFORCE_PCH_ROUTES
    # client key id present
    assert len(data['keys']['client_key_ids']) >= 1
    # ed25519 component present
    names = {c['name'] for c in data['components']}
    assert 'ed25519' in names
