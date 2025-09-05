import base64
import json
import datetime
from starlette.testclient import TestClient
from src.signet.app import app

def test_session_binding_strength(tmp_path, monkeypatch):
    monkeypatch.setenv('DATA_DIR', str(tmp_path/'data'))
    client = TestClient(app)
    exporter = base64.b64encode(b'X'*32).decode()
    r = client.get('/protected', headers={'X-TLS-Session-ID':'devsession','X-TLS-Exporter-B64': exporter})
    assert r.status_code == 401
    date = datetime.date.today().isoformat()
    path = tmp_path/'data'/date/'receipts.jsonl'
    rec = json.loads(path.read_text().strip().splitlines()[-1])
    assert rec.get('session_binding_strength') == 'ekm'
    # Now one without exporter
    client.get('/protected', headers={'X-TLS-Session-ID':'devsession'})
    rec2 = json.loads(path.read_text().strip().splitlines()[-1])
    assert rec2.get('session_binding_strength') == 'none'
