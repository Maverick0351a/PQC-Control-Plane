import base64
import json
import datetime
from starlette.testclient import TestClient
from src.signet.app import app

# This test simulates presence of a TLS exporter via internal header injection.

def test_dual_binding_fields_present(tmp_path, monkeypatch):
    monkeypatch.setenv('DATA_DIR', str(tmp_path/'data'))
    client = TestClient(app)
    # Fake exporter (32 bytes)
    exporter = b'X'*32
    exporter_b64 = base64.b64encode(exporter).decode()
    # Trigger denial receipt (challenge) which will include binding if header present
    r = client.get('/protected', headers={'X-TLS-Session-ID':'devsession', 'X-TLS-Exporter-B64': exporter_b64})
    assert r.status_code == 401
    date = datetime.date.today().isoformat()
    path = tmp_path/'data'/date/'receipts.jsonl'
    rec = json.loads(path.read_text().strip().splitlines()[-1])
    assert 'public_sig_b64' in rec and rec['public_sig_b64'], 'missing public signature'
    assert 'session_tag_b64' in rec and rec['session_tag_b64'], 'missing session binding tag'
    # Recompute expected session tag to verify
    import hashlib
    import hmac
    import base64 as b64mod
    def hkdf_expand(prk, info, length=32):
        return hmac.new(prk, info + b'\x01', hashlib.sha256).digest()[:length]
    temp = dict(rec)
    # Remove the two fields to reconstruct canonical form used in tag
    temp.pop('public_sig_b64')
    session_tag = temp.pop('session_tag_b64')
    from src.signet.crypto.jcs import jcs_canonicalize
    can_bytes = jcs_canonicalize(temp)
    mac_key = hkdf_expand(exporter, b'DPR-MAC-Key/v1', 32)
    expected_tag = b64mod.b64encode(hmac.new(mac_key, can_bytes, hashlib.sha256).digest()).decode()
    assert expected_tag == session_tag, 'session tag mismatch'
