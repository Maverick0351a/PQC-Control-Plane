from starlette.testclient import TestClient
from src.signet.app import app


def test_oversized_headers_trigger_431(monkeypatch):
    # Align with new header budget env / behavior (deny mode)
    monkeypatch.setenv('HEADER_DOWNGRADE_MODE','deny')
    monkeypatch.setenv('MAX_HEADER_BYTES','400')
    monkeypatch.setenv('MAX_SINGLE_HEADER_BYTES','256')
    client = TestClient(app)
    big_sig = 'a' * 800
    r1 = client.get('/protected')  # trigger challenge
    chal = r1.headers.get('PCH-Challenge')
    hdrs = {
        'Signature-Input': 'sig1=("@method" "@path" "@authority");keyid="caller";alg="ed25519"',
        'Signature': f'sig1=:{big_sig}:',
        'PCH-Challenge': chal,
        'X-TLS-Session-ID': 'devsession',
        'PCH-Channel-Binding': 'tls-session-id=:ZGV2c2Vzc2lvbg==:',
        'Content-Type': 'application/json'
    }
    r2 = client.post('/protected', headers=hdrs, json={})
    assert r2.status_code == 431, r2.text
    body = r2.json()
    assert body['error'] == 'header_budget'
    assert 'limit' in body and 'observed' in body
