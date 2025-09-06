import os
import zipfile
from pathlib import Path
from ..config import DATA_DIR
from ..vdc.emitter import ensure_pack_for_date

def build_compliance_pack(date_str: str) -> str:
    """Build the daily compliance pack as a VDC artifact.

    Behavior:
    - If a .vdc exists for the date, return it directly.
    - Else, flush pending entries into a new .vdc and return it.
    - As a fallback, produce a tiny zip containing README; if present, attach legacy receipts.jsonl for convenience.
    """
    vdc_path = ensure_pack_for_date(date_str, include_pending=True)
    day_dir = Path(DATA_DIR) / date_str
    if vdc_path is not None and vdc_path.exists():
        # Return the .vdc directly (VDC-first)
        return str(vdc_path)
    # Fallback: build a zip with README and include legacy JSON if present
    pack_zip = day_dir / f"compliance_pack_{date_str}.zip"
    latest = vdc_path or None
    with zipfile.ZipFile(pack_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        if latest and Path(latest).exists():
            z.write(str(latest), arcname=Path(latest).name)
        # Include legacy JSON copy if exists
        receipts_jsonl = Path(os.getenv("DATA_DIR", DATA_DIR)) / date_str / "receipts.jsonl"
        if receipts_jsonl.exists():
            z.write(str(receipts_jsonl), arcname="receipts.jsonl")
        z.writestr("README.md", PACK_README_VDC)
    return str(pack_zip)

PACK_README_VDC = """
Compliance Pack (VDC-first)
===========================

Primary artifact: .vdc (application/vdc+cbor) — self-verifying evidence container.
May include legacy receipts.jsonl for convenience.

VDC contents:
- Meta: created, producer DID, crypto_context (tls-exporter if bound), policies (cbom, optional policy metadata, route)
- Payloads: sha-384 digests for request/receipt; large artifacts may be external with uri+length
- Receipts: COSE_Sign1 (Ed25519 required; optional hybrid later)
- Anchors/Timestamps: optional EVG/CT-style inclusion proof, optional RFC 3161 timestamp

Use libvdc references (Python/Go) or the `vdc` CLI to verify.
"""
