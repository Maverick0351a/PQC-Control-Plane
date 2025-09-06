from __future__ import annotations

import base64
import datetime
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from .pack import pack_vdc
from .model import compute_digest
from ..cbom.export import build_cbom
from ..obs.prom import REGISTRY
from prometheus_client import Counter


# Metrics
VDC_EMITTED = Counter(
    "signet_vdc_emitted_total",
    "Count of VDC files emitted.",
    ["mode"],
    registry=REGISTRY,
)
VDC_ERRORS = Counter(
    "signet_vdc_errors_total",
    "Count of VDC emission errors.",
    ["reason"],
    registry=REGISTRY,
)
VDC_BYTES = Counter(
    "signet_vdc_bytes_total",
    "Total bytes of VDC files emitted.",
    registry=REGISTRY,
)
VDC_WITH_EKM = Counter(
    "signet_vdc_with_ekm_total",
    "VDC packs where at least one payload was EKM-bound.",
    registry=REGISTRY,
)


def _enabled() -> bool:
    return os.getenv("FEATURE_VDC", "false").lower() == "true"


def _vdc_dir_for(date: Optional[str] = None) -> Path:
    base = Path(os.getenv("VDC_DIR", "var/vdc"))
    d = date or datetime.date.today().isoformat()
    p = base / d
    p.mkdir(parents=True, exist_ok=True)
    return p


def _load_privkey_bytes(pem_path: str) -> bytes:
    with open(pem_path, "rb") as f:
        sk = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        raise ValueError("VDC signing key must be Ed25519")
    return sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _next_pack_path(day_dir: Path) -> Path:
    existing = sorted([p.name for p in day_dir.glob("pack-*.vdc")])
    idx = 1
    if existing:
        try:
            last = existing[-1]
            idx = int(last.split("-")[1].split(".")[0]) + 1
        except Exception:
            idx = len(existing) + 1
    return day_dir / f"pack-{idx:04d}.vdc"


def _build_meta(
    exporter_b64_any: Optional[str],
    *,
    route: Optional[str] = None,
    purpose: Optional[str] = None,
    producer_did: Optional[str] = None,
    policy_name: Optional[str] = None,
    policy_version: Optional[str] = None,
) -> Dict[int, Any]:
    # Minimal meta with crypto_context and embedded CBOM under policies
    created = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    protocol = "TLS1.3" if exporter_b64_any else "offline"
    suite = os.getenv("VDC_TLS_SUITE", "TLS_AES_128_GCM_SHA256")
    crypto_ctx: Dict[int, Any] = {1: protocol, 2: suite}
    if exporter_b64_any:
        # Normative channel_binding map: {1: "tls-exporter", 2: label, 3: length}
        crypto_ctx[3] = {1: "tls-exporter", 2: "EXPORTER-Channel-Binding", 3: 32}
    policies: Dict[str, Any] = {"cbom": build_cbom()}
    # Optional policy metadata
    policy_name = policy_name or os.getenv("POLICY_NAME")
    policy_version = policy_version or os.getenv("POLICY_VERSION")
    if policy_name or policy_version:
        policies["policy"] = {
            "name": policy_name or "",
            "version": policy_version or "",
        }
    if route:
        policies["route"] = route
    # Producer DID fallback to service name if not provided
    producer = producer_did or os.getenv("VDC_PRODUCER_DID") or os.getenv("SIGNET_SERVICE", "signet-api")
    return {
        1: purpose or "daily-compliance",
        2: producer,
        3: created,
        4: crypto_ctx,
        5: policies,
    }


def _collect_payloads(entries: List[Dict[str, Any]], embed_payloads: bool) -> List[Tuple[str, str, bytes, Optional[str]]]:
    payloads: List[Tuple[str, str, bytes, Optional[str]]] = []
    for e in entries:
        # DPCP request digest (hex) -> bytes
        req_hex = e.get("req_sha384_hex")
        if req_hex:
            payloads.append((f"dpcp-{e['rid']}", "application/vnd.dpcp+json-sha384", bytes.fromhex(req_hex), "request"))
        # Receipt canonical digest (sha-384 b64 -> bytes)
        r_b64 = e.get("receipt_sha384_b64")
        if r_b64:
            payloads.append((f"receipt-{e['rid']}", "application/receipt+json-sha384", base64.b64decode(r_b64), "receipt"))
    return payloads


def _pending_path(day_dir: Path) -> Path:
    return day_dir / "pending.jsonl"


def _read_pending(day_dir: Path) -> List[Dict[str, Any]]:
    p = _pending_path(day_dir)
    if not p.exists():
        return []
    out: List[Dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
    return out


def _write_pending(day_dir: Path, entries: List[Dict[str, Any]]) -> None:
    p = _pending_path(day_dir)
    with p.open("w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def add_receipt_entry(rec: Dict[str, Any], canonical_bytes: bytes, dpcp_obj: Optional[Dict[str, Any]], exporter_b64: Optional[str]) -> None:
    """Append a minimal entry to today's pending list and flush to a .vdc pack if threshold is reached.

    This is no-op unless FEATURE_VDC=true.
    """
    if not _enabled():
        return
    try:
        day_dir = _vdc_dir_for()
        entry = {
            "rid": rec.get("id"),
            "req_sha384_hex": (dpcp_obj or {}).get("req_sha384"),
            "exporter_b64": exporter_b64,
            "receipt_sha384_b64": base64.b64encode(
                compute_digest(canonical_bytes, "sha-384")
            ).decode(),
        }
        # If staging hardening is enabled, require exporter to add entry
        if os.getenv("REQUIRE_TLS_EXPORTER", "false").lower() == "true" and not exporter_b64:
            VDC_ERRORS.labels(reason="missing_exporter").inc()
            return
        pend = _read_pending(day_dir)
        pend.append(entry)
        _write_pending(day_dir, pend)
        maxn = int(os.getenv("VDC_DAILY_MAX", "5000"))
        if len(pend) >= maxn:
            _flush_pack(day_dir, pend)
            _write_pending(day_dir, [])
    except Exception as e:
        VDC_ERRORS.labels(reason=type(e).__name__).inc()


def _flush_pack(day_dir: Path, entries: List[Dict[str, Any]]) -> Optional[Path]:
    if not entries:
        return None
    try:
        # meta takes first exporter presence as proxy for channel binding
        exporter_any = next((e.get("exporter_b64") for e in entries if e.get("exporter_b64")), None)
        meta = _build_meta(exporter_any)
        embed = os.getenv("VDC_EMBED_PAYLOADS", "false").lower() == "true"
        payloads = _collect_payloads(entries, embed)
        pem_path = os.getenv("VDC_SIGNING_KEY", os.getenv("SERVER_SIGNING_KEY", "keys/sth_ed25519_sk.pem"))
        kid = os.getenv("VDC_KID", "vdc-sth-ed25519").encode()
        priv = _load_privkey_bytes(pem_path)
        attach_anchor = os.getenv("VDC_INCLUDE_EVG", "true").lower() == "true"
        # Pass EKM if present in any entry
        ekm_raw = None
        if exporter_any:
            try:
                ekm_raw = base64.b64decode(exporter_any)
            except Exception:
                ekm_raw = None
        # Optionally attach RFC3161 timestamp tokens specified via env var (semicolon-separated file paths)
        ts_env = os.getenv("VDC_TST_FILES")
        ts_pairs = None
        if ts_env:
            ts_pairs = []
            for p in ts_env.split(";"):
                p = p.strip()
                if not p:
                    continue
                try:
                    der = Path(p).read_bytes()
                    # Choose hash_alg policy: prefer sha-384 else sha-256
                    alg = os.getenv("VDC_TST_HASH_ALG", "sha-384")
                    if alg not in ("sha-256", "sha-384"):
                        alg = "sha-384"
                    ts_pairs.append((der, alg))
                except Exception:
                    VDC_ERRORS.labels(reason="tst_read_error").inc()
        profile = os.getenv("VDC_PROFILE")
        buf = pack_vdc(
            meta,
            payloads,
            priv,
            kid,
            attach_evg_anchor=attach_anchor,
            ekm=ekm_raw,
            timestamps=ts_pairs,
            profile=profile,
        )
        out = _next_pack_path(day_dir)
        out.write_bytes(buf)
        VDC_EMITTED.labels(mode="daily").inc()
        VDC_BYTES.inc(len(buf))
        if exporter_any:
            VDC_WITH_EKM.inc()
        return out
    except Exception as e:
        VDC_ERRORS.labels(reason=type(e).__name__).inc()
        return None


def list_index() -> Dict[str, List[str]]:
    """Return date->list of VDC pack file names (latest first)."""
    base = Path(os.getenv("VDC_DIR", "var/vdc"))
    index: Dict[str, List[str]] = {}
    if not base.exists():
        return index
    for d in sorted([p for p in base.iterdir() if p.is_dir()], reverse=True):
        files = [p.name for p in sorted(d.glob("pack-*.vdc"), reverse=True)]
        if files:
            index[d.name] = files
    return index


def latest_pack_for_date(date: str) -> Optional[Path]:
    day_dir = _vdc_dir_for(date)
    files = sorted(day_dir.glob("pack-*.vdc"), reverse=True)
    return files[0] if files else None


def ensure_pack_for_date(date: str, include_pending: bool = True) -> Optional[Path]:
    """Return a VDC pack path for the given date, creating one from pending if requested.

    If include_pending is True and there are pending entries, a pack is flushed.
    """
    day_dir = _vdc_dir_for(date)
    # If already exists, return latest
    cur = latest_pack_for_date(date)
    if cur is not None:
        return cur
    if not include_pending:
        return None
    pend = _read_pending(day_dir)
    if not pend:
        return None
    out = _flush_pack(day_dir, pend)
    if out:
        _write_pending(day_dir, [])
    return out
