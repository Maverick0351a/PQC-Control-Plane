from __future__ import annotations

import argparse
import base64
import hashlib
import json
from typing import List, Dict


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


def verify_inclusion(leaf_b64: str, proof: List[Dict[str, str]], expected_root_b64: str) -> bool:
    try:
        h = base64.b64decode(leaf_b64)
        cur = h
        for pe in proof:
            sib = base64.b64decode(pe.get("sibling", ""))
            pos = pe.get("position")
            if pos == "right":
                cur = _hash_pair(cur, sib)
            elif pos == "left":
                cur = _hash_pair(sib, cur)
            else:
                return False
        return base64.b64encode(cur).decode() == expected_root_b64
    except Exception:
        return False


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Verify a compliance pack's EVG inclusion proofs")
    p.add_argument("pack", help="Path to compliance .zip produced by bundler")
    args = p.parse_args(argv)

    import zipfile

    with zipfile.ZipFile(args.pack, "r") as zf:
        sth = json.loads(zf.read("evg_sth.json").decode())
        root = sth.get("root")
        proofs = json.loads(zf.read("evg_proofs.json").decode()) if "evg_proofs.json" in zf.namelist() else {}
    # Simple verification: every proof with present==true verifies against STH root
    results = {}
    ok_all = True
    for leaf, pr in proofs.items():
        if not pr.get("present"):
            results[leaf] = False
            ok_all = False
            continue
        ok = verify_inclusion(leaf, pr.get("proof", []), root)
        results[leaf] = ok
        ok_all = ok_all and ok
    print(json.dumps({"root": root, "verified": ok_all, "results": results}, indent=2))
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
