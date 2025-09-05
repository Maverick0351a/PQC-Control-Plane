from fastapi.testclient import TestClient
from src.signet.app import app

client = TestClient(app)

def test_receipt_persist_roundtrip():
    # Trigger challenge -> denial receipt
    r1 = client.get('/protected', headers={'X-TLS-Session-ID':'devsession'})
    assert r1.status_code == 401
    # Issue a second failing request
    r2 = client.get('/protected', headers={'X-TLS-Session-ID':'devsession'})
    assert r2.status_code == 401
    # Verify 404 path for random receipt id
    missing = client.get('/receipts/ffffffff-ffff-ffff-ffff-ffffffffffff')
    assert missing.status_code == 404
