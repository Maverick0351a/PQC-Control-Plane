import base64
import time
from starlette.testclient import TestClient
from src.signet.app import app


def test_pch_exporter_match(monkeypatch):
    monkeypatch.setenv('BINDING_TYPE','tls-exporter')
    client = TestClient(app)
    # Provide exporter header on challenge so nonce ties to same binding id
    r1 = client.get('/protected', headers={'x-tls-exporter': 'ZXhwb3J0ZXItYnl0ZXMtMzItcGxhY2Vob2xkZXIteHh4'})
    chal = r1.headers['PCH-Challenge']
    # Simulate exporter header (server will expect binding line with same b64)
    exporter = base64.b64encode(b'exporter-bytes-32-placeholder-xxxx')[:44].decode()
    body = b'{}'
    def b64(b): return base64.b64encode(b).decode()
    headers = {
        'content-digest': f"sha-256=:{b64(__import__('hashlib').sha256(body).digest())}:",
        'content-type': 'application/json',
        'pch-challenge': chal,
        'pch-channel-binding': f'tls-exporter=:{exporter}:',
        'x-tls-exporter': exporter,
    }
    comps = ['@method','@path','@authority','content-digest','pch-challenge','pch-channel-binding']
    params = {'created': str(int(time.time())), 'keyid':'caller-1','alg':'ed25519'}
    from src.signet.crypto.signatures import build_signature_base
    base = build_signature_base(request=client.build_request('POST','/protected',headers=headers), components=comps, params=params, evidence_sha256_hex='')
    from cryptography.hazmat.primitives import serialization
    sk = serialization.load_pem_private_key(open('keys/client_demo_sk.pem','rb').read(), password=None)
    sig = base64.b64encode(sk.sign(base.encode())).decode()
    headers['signature-input'] = f"pch=(\"{'\" '.join(comps)}\");created={params['created']};keyid=\"caller-1\";alg=\"ed25519\""
    headers['signature'] = f'pch=:{sig}:'
    r2 = client.post('/protected', headers=headers, content=body)
    print('DEBUG response', r2.json())
    assert r2.status_code == 200
    assert r2.json()['pch']['present'] is True
    assert r2.json()['pch']['verified'] is True
    assert r2.json()['pch']['channel_binding'] == 'tls-exporter'
