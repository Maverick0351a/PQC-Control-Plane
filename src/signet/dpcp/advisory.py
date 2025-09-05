"""DPCP v1 (advisory)

Computes a mock data provenance checksum with optional EKM binding to estimate
exposure (FVaR proxy) per profile. Purely advisory; no enforcement.

Env:
- SIGNET_DPCP_ENABLED=true|false
- SIGNET_DPCP_HASH_FIELDS: comma list of fields to hash (method,path,headers,body)
- SIGNET_DPCP_MAX_BODY_BYTES: int, truncate body in bytes (default 8192)
- SIGNET_DPCP_PROFILE_HEADER: header carrying negotiated profile (default X-PQC-Profile)
"""
from __future__ import annotations
import os
import time
import hashlib

def _b(s: str) -> bytes:
    return s.encode("utf-8")

async def compute_dpcp_record(request, exporter_b64: str | None) -> dict | None:
    if os.getenv("SIGNET_DPCP_ENABLED", "true").lower() != "true":
        return None
    fields = [f.strip().lower() for f in os.getenv("SIGNET_DPCP_HASH_FIELDS", "method,path,headers").split(",") if f.strip()]
    max_body = int(os.getenv("SIGNET_DPCP_MAX_BODY_BYTES", "8192"))
    profile_hdr = os.getenv("SIGNET_DPCP_PROFILE_HEADER", "X-PQC-Profile")

    h = hashlib.sha384()
    if "method" in fields:
        h.update(_b("method:" + request.method + "\n"))
    if "path" in fields:
        h.update(_b("path:" + request.url.path + "\n"))
    if "headers" in fields:
        # stable order by lowercase key
        items = sorted(((k.lower(), v) for k, v in request.headers.items()), key=lambda kv: kv[0])
        for k, v in items:
            if k.startswith("authorization"):
                continue
            h.update(_b(f"h:{k}:{v}\n"))
    if "body" in fields and request.method.upper() in {"POST", "PUT", "PATCH"}:
        try:
            body = await request.body()
        except Exception:
            body = b""
        if len(body) > max_body:
            body = body[:max_body]
        h.update(_b("body:"))
        h.update(body)

    rec = {
        "v": 1,
        "ts": int(time.time()),
        "method": request.method,
        "path": request.url.path,
        "profile": request.headers.get(profile_hdr, "unknown"),
        "req_sha384": h.hexdigest(),
        "ekm_binding": "ekm" if exporter_b64 else "none",
    }
    return rec
