import base64
import json
import datetime
from starlette.testclient import TestClient
from src.signet.app import app
from src.signet.receipts.verify import verify_session_tag

def test_verify_session_tag_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv('DATA_DIR', str(tmp_path/'data'))
    client = TestClient(app)
    exporter = b'Y'*32
    exporter_b64 = base64.b64encode(exporter).decode()
    r = client.get('/protected', headers={'X-TLS-Session-ID':'devsession','X-TLS-Exporter-B64': exporter_b64})
    assert r.status_code == 401
    date = datetime.date.today().isoformat()
    rec_path = tmp_path/'data'/date/'receipts.jsonl'
    rec_json = json.loads(rec_path.read_text().strip().splitlines()[-1])
    assert verify_session_tag(rec_json, exporter) is True
    # Tamper
    rec_json['reason'] = 'tampered'
    assert verify_session_tag(rec_json, exporter) is False
