from starlette.testclient import TestClient
from src.signet.app import app

def test_pch_challenge_headers():
    client = TestClient(app)
    r = client.get("/protected")
    assert r.status_code == 401
    assert "WWW-Authenticate" in r.headers
    assert "PCH-Challenge" in r.headers
