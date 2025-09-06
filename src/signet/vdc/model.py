from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple
import base64

import cbor2


MAGIC = b"\x89vdc\r\n\x1a\n"  # \x89 v d c \r \n \x1a \n
MEDIA_TYPE_CBOR = "application/vdc+cbor"
MEDIA_TYPE_JSON = "application/vdc+json"


def validate_no_floats(obj: Any) -> None:
    if isinstance(obj, float):
        raise ValueError("floats not allowed in VDC v0.1")
    if isinstance(obj, dict):
        for k, v in obj.items():
            validate_no_floats(k)
            validate_no_floats(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            validate_no_floats(v)


def det_cbor_dumps(obj: Any) -> bytes:
    validate_no_floats(obj)
    return cbor2.dumps(
        obj,
        canonical=True,
        timezone=None,
        datetime_as_timestamp=False,
        value_sharing=False,
        default=None,
    )


def det_cbor_loads(data: bytes) -> Any:
    obj = cbor2.loads(data)
    validate_no_floats(obj)
    return obj


def compute_meta_digest(meta: Dict[int, Any]) -> bytes:
    return hashlib.sha384(det_cbor_dumps(meta)).digest()


def validate_meta(meta: Dict[int, Any]) -> None:
    # 1: purpose, 2: producer, 3: created (RFC3339), 4: crypto_context, 5: policies
    for k in (1, 2, 3, 4, 5):
        if k not in meta:
            raise ValueError(f"meta missing key {k}")
    cc = meta[4]
    if not isinstance(cc, dict) or 1 not in cc or 2 not in cc:
        raise ValueError("crypto_context missing protocol/suite")


def build_payload_descriptor(
    pid: str,
    cty: str,
    digest_alg: str,
    digest_bstr: bytes,
    data_embedded: Optional[bytes] = None,
    external: Optional[Tuple[str, int]] = None,
    role: Optional[str] = None,
) -> Dict[int, Any]:
    if (data_embedded is None) == (external is None):
        raise ValueError("exactly one of embedded data or external must be provided")
    m: Dict[int, Any] = {1: pid, 2: cty, 3: digest_alg, 4: digest_bstr}
    if data_embedded is not None:
        m[5] = data_embedded
    else:
        uri, length = external  # type: ignore[misc]
        m[6] = {1: uri, 2: int(length)}
    if role:
        m[7] = role
    return m


def compute_digest(data: bytes, alg: str = "sha-384") -> bytes:
    if alg == "sha-384":
        return hashlib.sha384(data).digest()
    if alg == "sha-256":
        return hashlib.sha256(data).digest()
    raise ValueError("unsupported digest alg")


def build_vdc(
    meta: Dict[int, Any],
    payloads: List[Dict[int, Any]],
    receipts: Optional[List[bytes]] = None,
    anchors: Optional[List[Dict[int, Any]]] = None,
    timestamps: Optional[List[Any]] = None,
) -> Dict[int, Any]:
    validate_meta(meta)
    return {
        1: "v0.1",
        2: meta,
        3: payloads,
        4: receipts or [],
        5: anchors or [],
        6: timestamps or [],
    }


def file_write_vdc(vdc_obj: Dict[int, Any]) -> bytes:
    return MAGIC + det_cbor_dumps(vdc_obj)


def file_read_vdc(buf: bytes) -> Dict[int, Any]:
    if not buf.startswith(MAGIC):
        raise ValueError("bad magic")
    v = det_cbor_loads(buf[len(MAGIC) :])
    if not isinstance(v, dict):
        raise ValueError("VDC top-level must be CBOR map")
    return v  # type: ignore[return-value]


def anchor_evg_like(sig_payload_cbor: bytes, size: int = 0) -> Dict[int, Any]:
    # Deprecated stub
    leaf = hashlib.sha256(sig_payload_cbor).digest()
    root = leaf
    return {1: "evg", 2: {1: leaf, 2: root, 3: size + 1}}


def anchor_ct_v2_trivial(sig_payload_cbor: bytes) -> Dict[int, Any]:
    """Build a trivial CT/v2 anchor (tree_size=1, empty audit path).

    entry_hash = SHA-256(SigBase)
    proof: {1:1, 2:""}
    sth: {1:1, 2:entry_hash, 3:""}
    """
    entry = hashlib.sha256(sig_payload_cbor).digest()
    proof = {1: 1, 2: b""}
    sth = {1: 1, 2: entry, 3: b""}
    return {1: "ct/v2", 2: entry, 3: proof, 4: sth}


def to_jsonable(obj: Any) -> Any:
    """Recursively convert a VDC object to JSON-friendly types.

    - bytes -> base64 string
    - dict/list recurse
    - ints/str/bool/None unchanged
    Keys are left as-is (ints are fine; JSON encoder will handle them).
    """
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_jsonable(v) for v in obj]
    return obj
