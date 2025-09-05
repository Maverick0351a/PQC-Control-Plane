import os
import zipfile
from .transparency import build_sth_for_date, build_inclusion_proofs
from ..config import DATA_DIR

def build_compliance_pack(date_str: str) -> str:
    sth_path = build_sth_for_date(date_str)
    proofs_dir = build_inclusion_proofs(date_str)
    day_dir = os.path.join(DATA_DIR, date_str)
    receipts_path = os.path.join(day_dir, "receipts.jsonl")
    pack_path = os.path.join(day_dir, f"compliance_pack_{date_str}.zip")
    with zipfile.ZipFile(pack_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.write(sth_path, arcname="sth.json")
        if os.path.exists(receipts_path):
            z.write(receipts_path, arcname="receipts.jsonl")
        for f in os.listdir(proofs_dir):
            z.write(os.path.join(proofs_dir, f), arcname=f"proofs/{f}")
        # Include a simple verifier
        z.writestr("verify_cli.py", VERIFY_CLI_CODE)
        z.writestr("README.md", PACK_README)
    return pack_path

VERIFY_CLI_CODE = """
import json, sys, base64, hashlib

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
"""

PACK_README = """
Compliance Pack
===============

Contents:
- sth.json — Signed Tree Head (unsigned verification of root; signature verification requires distributing the server public key separately)
- receipts.jsonl — newline-delimited enforcement receipts
- proofs/*.json — Merkle inclusion proofs for each receipt
- verify_cli.py — offline inclusion verifier (usage: `python verify_cli.py sth.json receipts.jsonl proofs`)

This pack allows an auditor to validate that each receipt is included in the committed Merkle tree root.
"""
