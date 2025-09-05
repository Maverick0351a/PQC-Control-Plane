import os, json, base64, time, hashlib
from starlette.testclient import TestClient
from src.signet.app import app
from cryptography.hazmat.primitives import serialization
from src.signet.crypto.signatures import build_signature_base

os.environ['HEADER_DOWNGRADE_MODE']='hash-only'
os.environ['MAX_HEADER_BYTES']='4096'
os.environ['MAX_SINGLE_HEADER_BYTES']='4096'

c=TestClient(app)
r1=c.get('/protected', headers={'X-TLS-Session-ID':'devsession'})
chal=r1.headers['PCH-Challenge']
print('challenge status', r1.status_code)

big_evidence=json.dumps({'blob':'Y'*6000})
body=b'{"demo":true}'

def b64f(b): return base64.b64encode(b).decode()
headers={
 'content-digest': f"sha-256=:{b64f(hashlib.sha256(body).digest())}:",
 'content-type': 'application/json',
 'pch-challenge': chal,
 'pch-channel-binding': f'tls-session-id=:{b64f(b"devsession")}:',
 'x-tls-session-id':'devsession',
 'evidence': f':{b64f(big_evidence.encode())}:',
}
comps=["@method","@path","@authority","content-digest","pch-challenge","pch-channel-binding"]
params={'created':str(int(time.time())),'keyid':'caller-1','alg':'ed25519'}
base=build_signature_base(request=c.build_request('POST','/protected',headers=headers),components=comps,params=params,evidence_sha256_hex='')
sk=serialization.load_pem_private_key(open('keys/client_demo_sk.pem','rb').read(), password=None)
headers['signature-input']='pch=("@method" "@path" "@authority" "content-digest" "pch-challenge" "pch-channel-binding");created='+params['created']+';keyid="caller-1";alg="ed25519"'
headers['signature']='pch=:'+b64f(sk.sign(base.encode()))+':'

hdr_total=sum(len(k)+len(v)+4 for k,v in headers.items())
largest=max(len(k)+len(v)+4 for k,v in headers.items())
print('header_total_bytes', hdr_total, 'largest', largest)
print('evidence header length', len(headers['evidence']))
print('truncated evidence sample', headers['evidence'][:80])
print('MAX_HEADER_BYTES', os.getenv('MAX_HEADER_BYTES'))
print('Sending request...')
r2=c.post('/protected', headers=headers, content=body)
print('response status', r2.status_code)
print(r2.text)
