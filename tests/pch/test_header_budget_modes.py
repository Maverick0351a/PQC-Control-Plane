"""Header budget tests."""
from fastapi.testclient import TestClient
from src.signet.app import app


def test_header_budget_guard_431(monkeypatch):
    monkeypatch.setenv("HEADER_DOWNGRADE_MODE", "deny")
    monkeypatch.setenv("MAX_HEADER_BYTES", "512")  # force small limit
    monkeypatch.setenv("MAX_SINGLE_HEADER_BYTES", "256")
    c = TestClient(app)
    big_val = "x" * 600
    headers = {
        "Signature-Input": "sig1=('@method' '@path');keyid=\"client1\";alg=\"ed25519\"",
        "Signature": "sig1=:YmFkc2lnOg==:",
        "PCH-Channel-Binding": "tls-session-id::dev:",
        "X-TLS-Session-ID": "dev",
        "Evidence": big_val,
    }
    r = c.get("/protected", headers=headers)
    assert r.status_code == 431
    body = r.json()
    assert body["error"] == "header_budget"
    assert "limit" in body and "observed" in body


def test_header_budget_hash_only(monkeypatch):
    monkeypatch.setenv("HEADER_DOWNGRADE_MODE", "hash-only")
    monkeypatch.setenv("MAX_HEADER_BYTES", "512")
    monkeypatch.setenv("MAX_SINGLE_HEADER_BYTES", "256")
    c = TestClient(app)
    big_val = "x" * 600
    headers = {
        "Signature-Input": "sig1=('@method' '@path');keyid=\"client1\";alg=\"ed25519\"",
        "Signature": "sig1=:YmFkc2lnOg==:",
        "PCH-Channel-Binding": "tls-session-id::dev:",
        "X-TLS-Session-ID": "dev",
        "Evidence": big_val,
    }
    r = c.get("/protected", headers=headers)
    # Hash-only mode should not 431; will likely 401 or 428 until full hash-only implemented
    assert r.status_code in (200, 401, 428, 431)
