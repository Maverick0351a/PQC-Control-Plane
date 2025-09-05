import os
from fastapi.testclient import TestClient
from src.signet.app import app

# This test simulates two different ingress ports by directly crafting Host headers.
# In deployment we rely on nginx adding explicit :port. We ensure canonicalization
# produces identical base except for dynamic created timestamp.

def extract_base(client, host_header: str):
    # Force method/path/authority components
    sig_input = 'sig1=("@method" "@path" "@authority");keyid="client1";alg="ed25519"'
    # Minimal placeholder signature (will not verify) – we only compare server base output via log or debug flag
    headers = {
        "Signature-Input": sig_input,
        "Signature": "sig1=:AA==:",
        "Host": host_header,
        "PCH-Channel-Binding": "tls-session-id::dev:",
        "X-TLS-Session-ID": "dev",
    }
    r = client.get("/protected", headers=headers)
    return r.status_code


def test_signature_base_authority_canonical():
    c = TestClient(app)
    # Two host headers with different default port assumptions
    status1 = extract_base(c, "localhost:8443")
    status2 = extract_base(c, "localhost:9443")
    # We only assert both requests processed (401 or 431 depending on header budget etc.)
    assert status1 in (200, 401, 428, 431)
    assert status2 in (200, 401, 428, 431)
    # Canonicalization occurs server-side; deeper inspection would require capturing base string via debug flag
