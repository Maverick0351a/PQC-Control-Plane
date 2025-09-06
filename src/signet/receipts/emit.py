"""Emit helpers for forwarding receipts to EVG (Evidence Graph).

Environment:
  SIGNET_EVG_ENABLED=true|false
  RECEIPTS_SINK_URL=http://evg:8088/ingest
"""
from __future__ import annotations
import os
import json
import urllib.request
from typing import Optional

def _enabled() -> bool:
    return os.getenv("SIGNET_EVG_ENABLED", "true").lower() == "true"

def submit_to_evg(receipt: dict) -> bool:
    if not _enabled():
        return False
    url = os.getenv("RECEIPTS_SINK_URL", "http://evg:8088/ingest")
    body = {"format": "legacy", "payload": receipt}
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=2.5) as resp:  # nosec - internal network
            return 200 <= resp.status < 300
    except Exception:
        return False

def submit_vdc_to_evg(vdc_bytes: bytes, *, entry_id: Optional[str] = None) -> bool:
    """Submit a VDC entry to EVG; server prefers VDC format.

    The service may compute the leaf hash as SHA-256(SigBaseBytes) for anchoring.
    """
    if not _enabled():
        return False
    url = os.getenv("RECEIPTS_SINK_URL", "http://evg:8088/ingest")
    payload = {
        "format": "vdc",
        "entry_id": entry_id,
        "vdc_b64": __import__("base64").b64encode(vdc_bytes).decode(),
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=2.5) as resp:  # nosec - internal network
            return 200 <= resp.status < 300
    except Exception:
        return False
