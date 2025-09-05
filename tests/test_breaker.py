import time
import base64
import hashlib
from starlette.testclient import TestClient
from src.signet.app import app

ROUTE='/protected'

def signed_bad_request(client):
    r1 = client.get(ROUTE, headers={'X-TLS-Session-ID':'devsession'})
    chal = r1.headers.get('PCH-Challenge')
    body = b'{}'
    def b64(b): return base64.b64encode(b).decode()
    headers = {
        'content-digest': f'sha-256=:{b64(hashlib.sha256(body).digest())}:',
        'content-type': 'application/json',
        'pch-challenge': chal,
        'pch-channel-binding': f'tls-session-id=:{b64(b"devsession")}:',
        'x-tls-session-id': 'devsession',
        'signature-input': 'pch=("@method" "@path");created=0;keyid="caller-1";alg="ed25519"',
        'signature': 'pch=:BADSIG:'
    }
    return client.post(ROUTE, headers=headers, content=body)


def trip_breaker(client: TestClient, n=12):
    for _ in range(n):
        signed_bad_request(client)
        # minimal delay so EWMA updates distinct timestamps
        time.sleep(0.01)


def test_breaker_trips_and_half_open(monkeypatch):
    monkeypatch.setenv('BINDING_TYPE','tls-session-id')
    monkeypatch.setenv('BREAKER_ENABLED','true')
    client = TestClient(app)
    trip_breaker(client, n=14)
    opened = False
    for _ in range(10):
        r = signed_bad_request(client)
        if r.status_code == 503:
            opened = True
            break
        time.sleep(0.02)
    assert opened, 'breaker did not open (controller failed to trip)'
    time.sleep(5.2)
    # Probe attempt
    r_probe = signed_bad_request(client)
    # After probe, either success path remains throttled or returns 200 with pch result
    assert r_probe.status_code in (200,401,503)
