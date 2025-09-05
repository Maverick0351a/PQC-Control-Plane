"""Emit helpers for forwarding receipts to EVG (Evidence Graph).

Environment:
  SIGNET_EVG_ENABLED=true|false
  RECEIPTS_SINK_URL=http://evg:8088/ingest
"""
from __future__ import annotations
import os
import json
import urllib.request

def submit_to_evg(receipt: dict) -> bool:
    if os.getenv("SIGNET_EVG_ENABLED", "true").lower() != "true":
        return False
    url = os.getenv("RECEIPTS_SINK_URL", "http://evg:8088/ingest")
    data = json.dumps(receipt).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=2.5) as resp:  # nosec - internal network
            return 200 <= resp.status < 300
    except Exception:
        return False
