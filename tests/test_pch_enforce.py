import base64
import time
from starlette.testclient import TestClient
from src.signet.app import app

def build_signed(client, tls_id, body: bytes):
    r1 = client.get('/protected', headers={'X-TLS-Session-ID': tls_id})
    assert r1.status_code == 401
    chal = r1.headers['PCH-Challenge']
    def b64(b): return base64.b64encode(b).decode()
    headers = {
        'content-digest': f"sha-256=:{b64(__import__('hashlib').sha256(body).digest())}:",
        'content-type': 'application/json',
        'pch-challenge': chal,
        'pch-channel-binding': f"tls-session-id=:{b64(tls_id.encode())}:",
        'x-tls-session-id': tls_id
    }
    comps = ['@method','@path','@authority','content-digest','pch-challenge','pch-channel-binding']
    params = {'created': str(int(time.time())), 'keyid':'caller-1','alg':'ed25519'}
    from src.signet.crypto.signatures import build_signature_base
    base = build_signature_base(request=client.build_request('POST','/protected',headers=headers), components=comps, params=params, evidence_sha256_hex='')
    from cryptography.hazmat.primitives import serialization
    sk = serialization.load_pem_private_key(open('keys/client_demo_sk.pem','rb').read(), password=None)
    sig = b64(sk.sign(base.encode()))
    components_str = ' '.join([f'"{c}"' for c in comps])
    headers['signature-input'] = f"pch=({components_str});created={params['created']};keyid=\"caller-1\";alg=\"ed25519\""
    headers['signature'] = f"pch=:{sig}:"
    return headers


def test_enforce_missing_pch(monkeypatch):
    monkeypatch.setenv('PCH_ADVISORY','false')
    monkeypatch.setenv('ENFORCE_PCH_ROUTES','/protected')
    client = TestClient(app)
    r = client.get('/protected', headers={'X-TLS-Session-ID':'devsession'})
    # First challenge (401) is because missing signature; enforcement also triggers same response
    assert r.status_code == 401
    assert r.json()['error'] == 'PCH required'


def test_enforce_bad_signature(monkeypatch):
    monkeypatch.setenv('PCH_ADVISORY','false')
    monkeypatch.setenv('ENFORCE_PCH_ROUTES','/protected')
    client = TestClient(app)
    # obtain challenge
    r1 = client.get('/protected', headers={'X-TLS-Session-ID':'devsession'})
    chal = r1.headers['PCH-Challenge']
    headers = {
        'content-type':'application/json',
        'pch-challenge': chal,
        'pch-channel-binding': 'tls-session-id=:ZGV2c2Vzc2lvbg==:',
        'x-tls-session-id': 'devsession',
        'signature-input': 'pch=("@method" "@path");created=0;keyid="caller-1";alg="ed25519"',
        'signature': 'pch=:INVALID:'
    }
    r2 = client.post('/protected', headers=headers, content=b'{}')
    assert r2.status_code == 401
    assert r2.json()['error'] == 'PCH required'


def test_enforce_verified(monkeypatch):
    monkeypatch.setenv('PCH_ADVISORY','false')
    monkeypatch.setenv('ENFORCE_PCH_ROUTES','/protected')
    client = TestClient(app)
    body = b'{"ok":true}'
    headers = build_signed(client, 'devsession', body)
    r = client.post('/protected', headers=headers, content=body)
    assert r.status_code == 200
    assert r.json()['pch']['verified'] is True
