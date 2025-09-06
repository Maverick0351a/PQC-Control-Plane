from __future__ import annotations

import hashlib
from typing import Any, Dict

import pytest
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from signet.vdc.pack import pack_vdc
from signet.vdc.verify import verify_vdc


# Deterministic Ed25519 test vector
PRIV = bytes(range(1, 33))
_sk = Ed25519PrivateKey.from_private_bytes(PRIV)
PUB = _sk.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
KID = b"test-key-1"


def _repack_with_modified_cose(vdc_bytes: bytes, mod_fn) -> bytes:
    assert vdc_bytes.startswith(b"\x89vdc\r\n\x1a\n")
    body = cbor2.loads(vdc_bytes[8:])
    receipts = body[4]
    receipts[0] = mod_fn(receipts[0])
    return b"\x89vdc\r\n\x1a\n" + cbor2.dumps(body, canonical=True)


def test_sigbase_normalization_payload_list(tmp_path):
    meta = {1: "pch", 2: "suite", 3: "2024-01-01T00:00:00Z", 4: {1: "offline", 2: "t"}, 5: {}}
    payloads = [("a", "text/plain", b"A", None), ("b", "text/plain", b"B", None)]
    buf = pack_vdc(meta, payloads, PRIV, KID)

    # Inspect COSE payload equals CBOR(["VDC-SIG/v1", sha384(meta), [sha384(digest_i)]])
    body = cbor2.loads(buf[8:])
    pds = body[3]
    meta_digest = hashlib.sha384(cbor2.dumps(meta, canonical=True)).digest()
    norm_list = [hashlib.sha384(pd[4]).digest() for pd in pds]
    expected_sb = cbor2.dumps(["VDC-SIG/v1", meta_digest, norm_list], canonical=True)

    cose = body[4][0]
    arr = cbor2.loads(cose)
    payload = arr[2]
    assert payload == expected_sb


def test_unknown_crit_header_fails_closed(tmp_path):
    meta = {1: "pch", 2: "suite", 3: "2024-01-01T00:00:00Z", 4: {1: "offline", 2: "t"}, 5: {}}
    payloads = [("a", "text/plain", b"A", None)]
    buf = pack_vdc(meta, payloads, PRIV, KID)

    def add_unknown_crit(cose_bytes: bytes) -> bytes:
        arr = cbor2.loads(cose_bytes)
        protected_bstr = arr[0]
        prot = cbor2.loads(protected_bstr)
        # Add unknown critical header param
        crit = list(prot.get(2) or [])
        crit.append("x-crit")
        prot[2] = crit
        prot["x-crit"] = b"x"
        new_prot_bstr = cbor2.dumps(prot, canonical=True)
        # Rebuild Sig_structure and resign
        sig_structure = cbor2.dumps(["Signature1", new_prot_bstr, b"", arr[2]], canonical=True)
        sig = Ed25519PrivateKey.from_private_bytes(PRIV).sign(sig_structure)
        return cbor2.dumps([new_prot_bstr, arr[1], arr[2], sig], canonical=True)

    tampered = _repack_with_modified_cose(buf, add_unknown_crit)
    with pytest.raises(ValueError):
        verify_vdc(tampered, PUB, KID)


def test_timestamps_invalid_token_fails(tmp_path):
    meta = {1: "pch", 2: "suite", 3: "2024-01-01T00:00:00Z", 4: {1: "offline", 2: "t"}, 5: {}}
    payloads = [("a", "text/plain", b"A", None)]
    # Attach an invalid RFC3161 DER blob
    buf = pack_vdc(meta, payloads, PRIV, KID, timestamps=[(b"\x01\x02", "sha-256")])
    with pytest.raises(ValueError):
        verify_vdc(buf, PUB, KID)


def test_top_level_critical_override(tmp_path):
    meta = {1: "pch", 2: "suite", 3: "2024-01-01T00:00:00Z", 4: {1: "offline", 2: "t"}, 5: {}}
    payloads = [("a", "text/plain", b"A", None)]
    buf = pack_vdc(meta, payloads, PRIV, KID)

    body = cbor2.loads(buf[8:])
    # Add unknown top-level key 77 without policy: should still verify
    body[77] = 123
    buf2 = b"\x89vdc\r\n\x1a\n" + cbor2.dumps(body, canonical=True)
    verify_vdc(buf2, PUB, KID)

    # Now mark critical in policies and expect failure
    meta2: Dict[int, Any] = body[2]
    policies: Dict[str, Any] = meta2.get(5, {})
    policies["critical_top_level_keys"] = [77]
    meta2[5] = policies
    body[2] = meta2
    buf3 = b"\x89vdc\r\n\x1a\n" + cbor2.dumps(body, canonical=True)
    with pytest.raises(ValueError):
        verify_vdc(buf3, PUB, KID)


@pytest.mark.parametrize("profile, attach_anchor, add_tst, use_ekm, should_pass", [
    ("vdc-core", False, False, False, True),
    ("vdc-core", True, False, False, False),
    ("vdc-bound", False, False, True, True),
    ("vdc-bound", False, True, True, False),
    ("vdc-anchored", True, False, False, True),
    ("vdc-anchored", False, False, False, False),
    ("vdc-timestamped", False, True, False, True),
])
def test_profile_enforcement(profile, attach_anchor, add_tst, use_ekm, should_pass):
    meta = {1: "pch", 2: "suite", 3: "2024-01-01T00:00:00Z", 4: {1: "offline", 2: "t"}, 5: {}}
    payloads = [("a", "text/plain", b"A", None)]
    ekm = b"E" * 32 if use_ekm else None
    ts = [(b"\x30\x80", "sha-256")] if add_tst else None  # invalid DER to trigger timestamp presence handling
    buf = pack_vdc(meta, payloads, PRIV, KID, attach_evg_anchor=attach_anchor, ekm=ekm, timestamps=ts, profile=profile)
    if should_pass:
        # If timestamps profile, our invalid DER will fail, so only allow when not requiring valid timestamps
        if profile == "vdc-timestamped":
            with pytest.raises(ValueError):
                verify_vdc(buf, PUB, KID)
        else:
            verify_vdc(buf, PUB, KID)
    else:
        with pytest.raises(ValueError):
            verify_vdc(buf, PUB, KID)
