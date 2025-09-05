import os
import json
import base64
import datetime
from .merkle import merkle_root, merkle_proof
from ..config import DATA_DIR, SERVER_SIGNING_KEY
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def _load_privkey(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def build_sth_for_date(date: str) -> str:
    day_dir = os.path.join(DATA_DIR, date)
    os.makedirs(day_dir, exist_ok=True)
    receipts_path = os.path.join(day_dir, "receipts.jsonl")
    leaves = []
    if os.path.exists(receipts_path):
        with open(receipts_path, "r", encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                leaves.append(base64.b64decode(rec["leaf_hash_b64"]))
    root = merkle_root(leaves)
    sth = {
        "date": date,
        "tree_size": len(leaves),
        "root_hash_b64": base64.b64encode(root).decode(),
    "time": datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),
        "alg": "ed25519"
    }
    priv = _load_privkey(SERVER_SIGNING_KEY)
    msg = json.dumps(sth, sort_keys=True).encode()
    sth_sig_b64 = base64.b64encode(priv.sign(msg)).decode()
    sth["sth_sig_b64"] = sth_sig_b64
    with open(os.path.join(day_dir, "sth.json"), "w", encoding="utf-8") as f:
        json.dump(sth, f, indent=2)
    return os.path.join(day_dir, "sth.json")

def build_inclusion_proofs(date: str) -> str:
    day_dir = os.path.join(DATA_DIR, date)
    receipts_path = os.path.join(day_dir, "receipts.jsonl")
    proofs_dir = os.path.join(day_dir, "proofs")
    os.makedirs(proofs_dir, exist_ok=True)
    leaves = []
    recs = []
    if os.path.exists(receipts_path):
        with open(receipts_path, "r", encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                recs.append(rec)
                leaves.append(base64.b64decode(rec["leaf_hash_b64"]))
    for idx, rec in enumerate(recs):
        proof = merkle_proof(leaves, idx)
        with open(os.path.join(proofs_dir, f"{rec['id']}.json"), "w", encoding="utf-8") as pf:
            json.dump({"receipt_id": rec["id"], "leaf_hash_b64": rec["leaf_hash_b64"], "path": proof}, pf, indent=2)
    return proofs_dir
