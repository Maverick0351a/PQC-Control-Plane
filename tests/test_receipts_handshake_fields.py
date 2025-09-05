import datetime
import json
from starlette.testclient import TestClient
from src.signet.app import app

def test_receipt_includes_handshake_metadata(tmp_path, monkeypatch):
    monkeypatch.setenv('DATA_DIR', str(tmp_path/'data'))
    client = TestClient(app)
    # Force a denial receipt (challenge) with synthetic handshake headers
    r = client.get('/protected', headers={
        'X-TLS-Session-ID':'devsession',
        'X-TLS-ClientHello-Bytes':'512',
        'X-TLS-HRR-Seen':'true',
        'X-Path-Passport-ID':'ppa-1234'
    })
    assert r.status_code == 401
    date = datetime.date.today().isoformat()
    path = tmp_path/'data'/date/'receipts.jsonl'
    assert path.exists()
    rec = json.loads(path.read_text().strip().splitlines()[-1])
    # Handshake fields should be present
    assert rec.get('clienthello_bytes') == 512
    assert rec.get('hrr_seen') is True
    assert rec.get('passport_id') == 'ppa-1234'
