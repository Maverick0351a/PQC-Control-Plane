from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from signet.vdc.pack import pack_vdc
from signet.vdc.verify import verify_vdc


# Simple deterministic Ed25519 test vector (random-looking but fixed for tests)
PRIV = bytes(range(1, 33))
_sk = Ed25519PrivateKey.from_private_bytes(PRIV)
PUB = _sk.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
KID = b"test-key-1"


@pytest.mark.parametrize("attach_anchor", [False, True])
def test_pack_and_verify_roundtrip(tmp_path: Path, attach_anchor: bool):
    meta = {
        1: "pch-receipt",
        2: "signet-pqc-mvp",
        3: "2024-08-01T00:00:00Z",
        4: {1: "offline", 2: "test-suite"},
        5: {},
    }
    payloads = [("p1", "text/plain", b"hello world", "request")]

    buf = pack_vdc(meta, payloads, PRIV, KID, attach_evg_anchor=attach_anchor)

    info = verify_vdc(buf, PUB, KID)
    assert info["payload_count"] == 1
    if attach_anchor:
        assert len(info["anchors"]) == 1
    else:
        assert info["anchors"] == []


def test_bad_digest_detected(tmp_path: Path):
    meta = {
        1: "pch-receipt",
        2: "signet-pqc-mvp",
        3: "2024-08-01T00:00:00Z",
        4: {1: "offline", 2: "test-suite"},
        5: {},
    }
    payloads = [("p1", "text/plain", b"hello world", "request")]
    buf = pack_vdc(meta, payloads, PRIV, KID)

    # Tamper with embedded payload bytes (flip one bit)
    ba = bytearray(buf)
    # Find last byte and flip
    ba[-1] ^= 0x01
    with pytest.raises(ValueError):
        verify_vdc(bytes(ba), PUB, KID)
