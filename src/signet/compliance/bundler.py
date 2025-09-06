import datetime
import json
import os
import zipfile
from typing import Optional

import httpx

from ..config import DATA_DIR


def _day_dir(date: Optional[str] = None) -> str:
    d = date or datetime.date.today().isoformat()
    return os.path.join(os.getenv("DATA_DIR", DATA_DIR), d)


def bundle_compliance_pack(output_path: str, evg_url: Optional[str] = None, date: Optional[str] = None) -> str:
    """Create a minimal compliance pack zip with receipts.jsonl and optional STH.

    - output_path: where to write the .zip (directories created if needed)
    - evg_url: base URL for EVG (e.g., http://localhost:8088). If provided, fetch /sth.
    - date: ISO date (YYYY-MM-DD); defaults to today.
    Returns the output_path.
    """
    day_dir = _day_dir(date)
    receipts_path = os.path.join(day_dir, "receipts.jsonl")
    # VDC-first: reference .vdc files for the date if any
    vdc_files = []
    try:
        for name in sorted(os.listdir(day_dir)):
            if name.endswith('.vdc'):
                vdc_files.append(os.path.join(day_dir, name))
    except Exception:
        vdc_files = []

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        leaf_hashes = []
        # Include VDCs first
        for vf in vdc_files:
            try:
                zf.write(vf, arcname=os.path.basename(vf))
            except Exception:
                pass
        if os.path.exists(receipts_path):
            # copy receipts and gather leaf hashes
            with open(receipts_path, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
            zf.writestr("receipts.jsonl", "\n".join(lines))
            for ln in lines:
                if not ln.strip():
                    continue
                try:
                    obj = json.loads(ln)
                    lh = obj.get("leaf_hash_b64")
                    if lh:
                        leaf_hashes.append(lh)
                except Exception:
                    pass
        else:
            zf.writestr("receipts.jsonl", "")

        # Optional STH and proofs from EVG
        if evg_url:
            base = evg_url.rstrip('/')
            try:
                with httpx.Client(timeout=5.0) as client:
                    r = client.get(f"{base}/sth")
                    r.raise_for_status()
                    zf.writestr("evg_sth.json", json.dumps(r.json(), ensure_ascii=False))
                    # fetch proofs for each leaf
                    proofs = {}
                    for lh in leaf_hashes:
                        try:
                            pr = client.get(f"{base}/__evg/proof", params={"leaf": lh})
                            if pr.status_code == 200:
                                proofs[lh] = pr.json()
                        except Exception:
                            continue
                    zf.writestr("evg_proofs.json", json.dumps(proofs, ensure_ascii=False))
            except Exception:
                zf.writestr("evg_sth.json", json.dumps({"error": "sth_fetch_failed"}))
    return output_path
