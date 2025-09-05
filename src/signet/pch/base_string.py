"""Canonical signature-base construction utilities (PR 18).

Centralizes canonicalization of pseudo-header components used in PCH signing.
Ensures stable base across ingress proxy chains (normal + impaired paths).
"""
from typing import List, Dict
import time

CANON_ORDER = ["@method", "@path", "@authority", "content-digest", "pch-challenge", "pch-channel-binding", "evidence-sha-256"]


def canonical_authority(host_header: str, fallback_netloc) -> str:
    """Return canonical authority including explicit port.

    If host_header already contains a colon return as-is (lowercased host part only).
    If it lacks a port but the fallback_netloc has one, append it.
    Always lowercase hostname; port preserved.
    """
    if not host_header:
        host_header = fallback_netloc or ""
    host = host_header
    if "/" in host:  # strip any accidental path leakage
        host = host.split("/")[0]
    # Ensure fallback_netloc is str
    if isinstance(fallback_netloc, bytes):
        try:
            fallback_netloc = fallback_netloc.decode()
        except Exception:
            fallback_netloc = fallback_netloc.decode(errors="ignore")
    if host.count(":") == 0 and fallback_netloc and ":" in fallback_netloc:
        # append port from fallback
        port = fallback_netloc.split(":")[-1]
        if port.isdigit():
            host = f"{host}:{port}"
    # Normalize hostname portion (case-insensitive per RFC) but keep port verbatim
    if ":" in host:
        h, p = host.split(":", 1)
        return f"{h.lower()}:{p}"
    return host.lower()


def build_canonical_base(request, components: List[str], params: Dict[str, str], evidence_sha256_hex: str) -> str:
    """Produce the canonical signature base string.

    Each line: 'component: value' followed by '@signature-params'.
    Canonicalizes @authority and @path. Other components taken verbatim (single-line sanitized).
    """
    headers = {k.lower(): v for k, v in request.headers.items()}

    lines: List[str] = []
    for comp in components:
        lc = comp.lower()
        if lc == "@method":
            val = request.method.upper()
        elif lc == "@path":
            path = request.url.path or "/"
            query = request.url.query
            val = path if not query else f"{path}?{query}"
        elif lc == "@authority":
            val = canonical_authority(request.headers.get("host"), request.url.netloc)
        elif lc == "content-digest":
            val = headers.get("content-digest", "")
        elif lc == "pch-challenge":
            val = headers.get("pch-challenge", "")
        elif lc == "pch-channel-binding":
            val = headers.get("pch-channel-binding", "")
        elif lc == "evidence-sha-256":
            val = evidence_sha256_hex
        else:
            val = headers.get(lc, "")
        if isinstance(val, str):
            val = val.replace("\r", "").replace("\n", "")
        lines.append(f"{lc}: {val}")

    comp_list = " ".join([f'"{c}"' for c in components])
    created = params.get("created") or str(int(time.time()))
    keyid = params.get("keyid", "")
    alg = params.get("alg", "ed25519")
    sig_params = f"@signature-params: ({comp_list});created={created};keyid=\"{keyid}\";alg=\"{alg}\""
    lines.append(sig_params)
    return "\n".join(lines)
