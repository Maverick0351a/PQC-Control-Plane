import os, sqlite3, threading, json, time, base64, hashlib, datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # type: ignore
from cryptography.hazmat.primitives import serialization  # type: ignore
from ..config import SERVER_SIGNING_KEY
from typing import Optional, Dict, Any, List
from ..config import DATA_DIR

_DB_PATH = os.path.join(DATA_DIR, 'receipts.db')
_LOCK = threading.Lock()
_BATCH_SIZE = int(os.getenv('RECEIPT_BATCH_SIZE','50'))
_BATCH_INTERVAL_SEC = 60

_SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts(
  id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL,
  decision TEXT NOT NULL,
  reason TEXT,
  controller_json TEXT,
  leaf_hash_b64 TEXT,
  batch_id INTEGER,
  prev_leaf_hash_b64 TEXT
);
CREATE TABLE IF NOT EXISTS batches(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_ts INTEGER NOT NULL,
  sth_sig_b64 TEXT,
  sth_json TEXT,
  prev_sth_hash_b64 TEXT
);
"""

def _connect():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=5, isolation_level=None)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA synchronous=NORMAL;')
    return conn

# Initialize
with _LOCK:
    conn = _connect()
    for stmt in _SCHEMA.strip().split(';'):
        s = stmt.strip()
        if s:
            conn.execute(s)
    conn.close()

_last_batch_check = 0.0

def persist_receipt(rec: Dict[str, Any]):
    global _last_batch_check
    now = int(time.time())
    rec_id = rec['id']
    controller_json = json.dumps(rec.get('controller')) if rec.get('controller') is not None else None
    leaf_hash_b64 = rec.get('leaf_hash_b64')
    prev_leaf = rec.get('prev_receipt_hash_b64')
    with _LOCK:
        c = _connect()
        try:
            c.execute('INSERT OR IGNORE INTO receipts(id,ts,decision,reason,controller_json,leaf_hash_b64,batch_id,prev_leaf_hash_b64) VALUES (?,?,?,?,?,?,NULL,?)',
                      (rec_id, now, rec['decision'], rec.get('reason'), controller_json, leaf_hash_b64, prev_leaf))
            # Batch trigger: count unbatched
            cnt = c.execute('SELECT COUNT(*) FROM receipts WHERE batch_id IS NULL').fetchone()[0]
            if cnt >= _BATCH_SIZE or (time.time() - _last_batch_check) > _BATCH_INTERVAL_SEC:
                _last_batch_check = time.time()
                _maybe_batch(c)
        finally:
            c.close()


def _maybe_batch(conn: sqlite3.Connection):
    rows = conn.execute('SELECT id, leaf_hash_b64 FROM receipts WHERE batch_id IS NULL ORDER BY ts').fetchall()
    if not rows:
        return
    # Simple Merkle: hash concatenation tree
    leaves = [base64.b64decode(h) for _, h in rows if h]
    if not leaves:
        return
    def merkle_layer(layer: List[bytes]) -> List[bytes]:
        out=[]
        for i in range(0,len(layer),2):
            a = layer[i]
            b = layer[i+1] if i+1 < len(layer) else layer[i]
            out.append(hashlib.sha256(a+b).digest())
        return out
    nodes = leaves
    while len(nodes) > 1:
        nodes = merkle_layer(nodes)
    root = nodes[0]
    prev_sth_hash_b64 = None
    prev = conn.execute('SELECT sth_json FROM batches ORDER BY id DESC LIMIT 1').fetchone()
    if prev:
        import json as _json
        prev_sth = _json.loads(prev[0])
        prev_sth_hash_b64 = base64.b64encode(hashlib.sha256(prev[0].encode()).digest()).decode()
    # Build STH object (will embed public key for verification convenience)
    sth_obj = {
        'type': 'sth',
        'created_ts': int(time.time()),
        'root_hash_b64': base64.b64encode(root).decode(),
        'leaf_count': len(leaves),
        'prev_sth_hash_b64': prev_sth_hash_b64,
        'sig_alg': 'ed25519',
    }
    # Attempt Ed25519 signing; fall back to hash placeholder if key missing
    sth_sig_b64 = None
    try:
        if os.path.exists(SERVER_SIGNING_KEY):
            with open(SERVER_SIGNING_KEY, 'rb') as f:
                priv = serialization.load_pem_private_key(f.read(), password=None)
            assert isinstance(priv, Ed25519PrivateKey)
            pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            sth_obj['public_key_b64'] = base64.b64encode(pub).decode()
            sth_json = json.dumps(sth_obj, sort_keys=True)
            sig = priv.sign(sth_json.encode())
            sth_sig_b64 = base64.b64encode(sig).decode()
        else:  # pragma: no cover - fallback path
            sth_json = json.dumps(sth_obj, sort_keys=True)
    except Exception:  # pragma: no cover
        sth_json = json.dumps(sth_obj, sort_keys=True)
    if not sth_sig_b64:
        # Fallback deterministic hash-as-sig marker
        sth_sig_b64 = base64.b64encode(hashlib.sha256(sth_json.encode()).digest()).decode()
    conn.execute('INSERT INTO batches(created_ts,sth_sig_b64,sth_json,prev_sth_hash_b64) VALUES (?,?,?,?)', (int(time.time()), sth_sig_b64, sth_json, prev_sth_hash_b64))
    batch_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    conn.executemany('UPDATE receipts SET batch_id=? WHERE id=?', [(batch_id, rid) for rid,_ in rows])


def fetch_receipt(rec_id: str) -> Optional[Dict[str, Any]]:
    with _LOCK:
        c = _connect()
        try:
            row = c.execute('SELECT id, ts, decision, reason, controller_json, leaf_hash_b64, batch_id, prev_leaf_hash_b64 FROM receipts WHERE id=?', (rec_id,)).fetchone()
            if not row: return None
            (rid, ts, decision, reason, controller_json, leaf_hash_b64, batch_id, prev_leaf) = row
            receipt = {
                'id': rid,
                'ts': ts,
                'decision': decision,
                'reason': reason,
                'controller': json.loads(controller_json) if controller_json else None,
                'leaf_hash_b64': leaf_hash_b64,
                'prev_receipt_hash_b64': prev_leaf,
            }
            if batch_id:
                b = c.execute('SELECT sth_json, sth_sig_b64 FROM batches WHERE id=?', (batch_id,)).fetchone()
                if b:
                    receipt['sth'] = json.loads(b[0])
                    receipt['sth_sig_b64'] = b[1]
            return receipt
        finally:
            c.close()
