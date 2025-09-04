import base64, json, os
from src.signet.receipts.merkle import merkle_root, merkle_proof
from src.signet.receipts.store import ReceiptStore
from fastapi.testclient import TestClient
from src.signet.app import app

client = TestClient(app)

def test_receipts_and_merkle(tmp_path):
    import src.signet.config as cfg
    cfg.DATA_DIR = str(tmp_path)
    store = ReceiptStore()
    for i in range(3):
        class Dummy:
            method = 'GET'
            url = type('U', (), {'path':'/protected','query':'','netloc':''})()
            headers = {}
        rec = store.emit_enforcement_receipt(request=Dummy(), decision='allow', reason='test', pch={'present':False,'verified':False})
        assert rec['leaf_hash_b64']
    # Build root
    with open(os.path.join(cfg.DATA_DIR, f"{__import__('datetime').date.today().isoformat()}", 'receipts.jsonl'), 'r', encoding='utf-8') as f:
        leaves = [base64.b64decode(json.loads(line)['leaf_hash_b64']) for line in f]
    root = merkle_root(leaves)
    assert len(root) == 32
    proof = merkle_proof(leaves, 0)
    assert proof
