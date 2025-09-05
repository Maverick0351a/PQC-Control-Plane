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

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if os.path.exists(receipts_path):
            zf.write(receipts_path, arcname="receipts.jsonl")
        else:
            # create an empty placeholder
            zf.writestr("receipts.jsonl", "")
        # Optional STH from EVG
        if evg_url:
            try:
                with httpx.Client(timeout=5.0) as client:
                    r = client.get(f"{evg_url.rstrip('/')}/sth")
                    r.raise_for_status()
                    zf.writestr("evg_sth.json", json.dumps(r.json(), ensure_ascii=False))
            except Exception as _:
                # Include a stub error marker (non-fatal)
                zf.writestr("evg_sth.json", json.dumps({"error": "sth_fetch_failed"}))
    return output_path
