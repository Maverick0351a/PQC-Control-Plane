import datetime
import json
from starlette.testclient import TestClient
from src.signet.app import app

def test_receipt_embeds_controller_fields(tmp_path, monkeypatch):
    # Redirect data dir
    monkeypatch.setenv('DATA_DIR', str(tmp_path/'data'))
    client = TestClient(app)
    # Trigger challenge + signed attempt (advisory mode OK)
    client.get('/protected')
    client.post('/protected')
    date = datetime.date.today().isoformat()
    path = tmp_path/'data'/date/'receipts.jsonl'
    assert path.exists()
    lines = path.read_text().strip().splitlines()
    assert lines, 'no receipts emitted'
    rec = json.loads(lines[-1])
    ctrl = rec.get('controller')
    assert ctrl, 'controller snapshot missing'
    # Required keys
    for k in ['breaker_state','err_ewma','kingman_wq_ms','rho','consecutive_successes','action','reason','deadband']:
        assert k in ctrl, f'missing controller.{k}'
    # Deadband structure
    assert isinstance(ctrl['deadband'], dict)
    # Timestamp format (Z suffix)
    assert rec['time'].endswith('Z')
