import httpx
from src.signet.config import BINDING_HEADER

URL = "http://localhost:8080/protected"

def test_pch_challenge():
    with httpx.Client() as c:
        r1 = c.get(URL)
        assert r1.status_code == 401
        assert "PCH-Challenge" in r1.headers
        r2 = c.get(URL, headers={BINDING_HEADER: "devsession"})
        assert r2.status_code == 401
        assert "PCH-Challenge" in r2.headers
