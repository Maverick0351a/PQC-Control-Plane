import base64
import hashlib
import json
import sys

def verify(sth_path, receipts_path, proofs_dir):
    # load sth
    with open(sth_path, "r", encoding="utf-8") as f:
        sth = json.load(f)
    root = base64.b64decode(sth["root_hash_b64"])
    # load receipts
    recs = []
    with open(receipts_path, "r", encoding="utf-8") as f:
        for line in f:
            recs.append(json.loads(line))
    # map id->index, leaf
    id2leaf = {r["id"]: base64.b64decode(r["leaf_hash_b64"]) for r in recs}
    ok = True
    for rid, leaf in id2leaf.items():
        # recompute root via proof
        with open(f"{proofs_dir}/{rid}.json","r",encoding="utf-8") as pf:
            proof = json.load(pf)["path"]
        h = hashlib.sha256(leaf).digest()
        for dirc, sib_b64 in proof:
            sib = base64.b64decode(sib_b64)
            h = hashlib.sha256((h + sib) if dirc=="R" else (sib + h)).digest()
        if h != root:
            print("FAIL", rid)
            ok = False
    print("OK" if ok else "FAIL")
    return ok

if __name__ == "__main__":
    sth = sys.argv[1] if len(sys.argv)>1 else "sth.json"
    recs = sys.argv[2] if len(sys.argv)>2 else "receipts.jsonl"
    proofs = sys.argv[3] if len(sys.argv)>3 else "proofs"
    ok = verify(sth, recs, proofs)
    sys.exit(0 if ok else 1)
