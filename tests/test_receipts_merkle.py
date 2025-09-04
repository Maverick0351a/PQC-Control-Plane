import os
import datetime
from src.signet.receipts.store import ReceiptStore
from src.signet.receipts.transparency import build_sth_for_date, build_inclusion_proofs

def test_receipts_and_merkle(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    s = ReceiptStore()
    from starlette.requests import Request
    scope = {"type":"http","method":"GET","path":"/protected","headers":[],"client":("127.0.0.1",12345)}
    class DummyReceive:
        async def __call__(self): return {"type":"http.request"}
    class DummySend:
        async def __call__(self, message): pass
    req = Request(scope, receive=DummyReceive())
    s.emit_enforcement_receipt(
        req,
        decision="allow",
        reason="policy_ok",
        pch={"present": False, "verified": False},
    )
    date = datetime.date.today().isoformat()
    sth_path = build_sth_for_date(date)
    proofs_dir = build_inclusion_proofs(date)
    assert os.path.exists(sth_path)
    assert os.path.isdir(proofs_dir)
