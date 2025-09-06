from __future__ import annotations

import base64
from pathlib import Path

import pytest

from signet.vdc.verify import verify_vdc


PRIV = bytes(range(1, 33))
PUB_B64 = base64.b64encode(__import__(
    'cryptography.hazmat.primitives.asymmetric.ed25519'
).hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(PRIV).public_key().public_bytes(
    __import__('cryptography.hazmat.primitives.serialization').hazmat.primitives.serialization.Encoding.Raw,
    __import__('cryptography.hazmat.primitives.serialization').hazmat.primitives.serialization.PublicFormat.Raw,
)).decode()
PUB = base64.b64decode(PUB_B64)
KID = b"did:example:acme#v1"


@pytest.mark.parametrize("name,expect_ok", [
    ("core", True),
    ("bound_ekm", True),
    ("anchored", True),
    ("negative_tamper_payload", False),
])
def test_vectors_python(name: str, expect_ok: bool):
    p = Path("vectors/vdc/%s.vdc" % name)
    if not p.exists():
        pytest.skip("vectors not generated")
    buf = p.read_bytes()
    if expect_ok:
        verify_vdc(buf, PUB, KID)
    else:
        with pytest.raises(Exception):
            verify_vdc(buf, PUB, KID)
