from __future__ import annotations

from typing import Any, Dict, List, Set

from .model import (
    file_read_vdc,
    compute_digest,
    det_cbor_dumps,
)
from .cose_sign import verify1_ed25519


def verify_vdc(buf: bytes, key: Dict[str, bytes] | bytes, kid: bytes | None = None) -> Dict[str, Any]:
    try:
        vdc = file_read_vdc(buf)
    except Exception as e:
        raise ValueError("invalid VDC") from e
    assert vdc[1] == "v0.1"
    meta = vdc[2]
    payloads = vdc[3]
    receipts = vdc[4]
    anchors = vdc[5]
    timestamps = vdc.get(6, [])
    anchors_present = bool(anchors)
    timestamps_present = bool(timestamps)

    # Forward-compatibility: ignore unknown top-level numeric keys unless marked critical by profile
    known_top_level: Set[int] = {1, 2, 3, 4, 5, 6}
    unknown_keys: List[int] = [k for k in vdc.keys() if isinstance(k, int) and k not in known_top_level]
    try:
        policies = (meta or {}).get(5, {})
    except Exception:
        policies = {}
    critical_keys: Set[int] = set()
    try:
        ck = policies.get("critical_top_level_keys")
        if isinstance(ck, list):
            for item in ck:
                if isinstance(item, int):
                    critical_keys.add(item)
    except Exception:
        pass
    for uk in unknown_keys:
        if uk in critical_keys:
            raise ValueError("unknown critical top-level key present")
    # Verify payload digests
    for pd in payloads:
        alg = pd[3]
        d = pd[4]
        if 5 in pd:
            data = pd[5]
            calc = compute_digest(data, alg)
            if calc != d:
                raise ValueError("payload digest mismatch")
        else:
            # external: skip fetch; verify shape only
            _ = pd[6]
    # Verify COSE_Sign1 over SigBase ["VDC-SIG/v1", meta_digest, [payload_digests...], ?ekm]
    meta_digest = compute_digest(det_cbor_dumps(meta), "sha-384")
    # Normalize payload entries in SigBase: SHA-384 of each payload digest
    payload_norm = [compute_digest(pd[4], "sha-384") for pd in payloads]
    sig_base_item = ["VDC-SIG/v1", meta_digest, payload_norm]
    # There can be multiple signatures; verify at least one
    ok = False
    sigbase_used: bytes | None = None
    ekm_used: bytes | None = None
    for cose in receipts:
        try:
            # accept raw pubkey bytes or a dict {"x": pubkey, "kid": kid}
            if isinstance(key, (bytes, bytearray)):
                pub = bytes(key)
                expected_kid = kid
            else:
                pub = key.get("x")  # type: ignore[assignment]
                expected_kid = key.get("kid")  # type: ignore[assignment]
            payload, prot = verify1_ed25519(cose, pub, expected_kid)
            # Enforce critical headers: must include vdc-sb-hash, and be sha-384
            crit = prot.get(2) or []
            # Fail-closed on unknown critical parameters
            for name in crit:
                if name not in ("vdc-sb-hash", "vdc-ekm"):
                    raise ValueError("unknown critical COSE header parameter")
            if "vdc-sb-hash" not in crit:
                raise ValueError("missing critical vdc-sb-hash")
            if prot.get("vdc-sb-hash") != "sha-384":
                raise ValueError("unsupported sb-hash")
            ekm_hdr = prot.get("vdc-ekm")
            if ekm_hdr is not None and "vdc-ekm" not in crit:
                raise ValueError("vdc-ekm must be critical if present")
            # Build expected SigBase (append ekm only if header present)
            sig_base_item2 = list(sig_base_item)
            if ekm_hdr is not None:
                sig_base_item2.append(ekm_hdr)
            # Ensure the signed payload equals our SigBase deterministic encoding
            sb_bytes = det_cbor_dumps(sig_base_item2)
            if payload == sb_bytes:
                ok = True
                sigbase_used = sb_bytes
                ekm_used = ekm_hdr
                break
        except Exception:
            continue
    if not ok:
        raise ValueError("no valid COSE signature found")
    # Basic CT/v2 anchor validation (singleton tree): ensure entry_hash = sha256(SigBase)
    import hashlib
    validated_anchors = []
    for a in anchors:
        try:
            if a.get(1) != "ct/v2":
                continue
            sth = a.get(4) or {}
            proof = a.get(3) or {}
            if sth.get(1) != 1 or proof.get(1) != 1:
                continue
            entry_hash = a.get(2)
            root = sth.get(2)
            if entry_hash != hashlib.sha256(det_cbor_dumps(sig_base_item)).digest():
                continue
            if root != entry_hash:
                continue
            validated_anchors.append(a)
        except Exception:
            continue
    # Validate RFC3161 timestamps (if present). MUST cover SHA-256/384 of SigBase bytes, and state hash_alg
    if timestamps:
        if sigbase_used is None:
            # Should not happen if a signature was verified
            raise ValueError("timestamps present but no verified SigBase")
        # Lazy import to avoid hard dependency when timestamps not used
        try:
            from asn1crypto import tsp  # type: ignore
        except Exception as e:  # pragma: no cover
            raise ValueError("missing asn1crypto for timestamp verification") from e
        # Precompute hashes
        import hashlib as _hl
        sb_sha256 = _hl.sha256(sigbase_used).digest()
        sb_sha384 = _hl.sha384(sigbase_used).digest()
        for ts in timestamps:
            # Each ts is a map: {1: tst_der, 2: hash_alg}
            if not isinstance(ts, dict) or 1 not in ts or 2 not in ts:
                raise ValueError("bad timestamp entry")
            tst_der = ts[1]
            hash_alg = ts[2]
            if not isinstance(tst_der, (bytes, bytearray)) or not isinstance(hash_alg, str):
                raise ValueError("bad timestamp entry types")
            if hash_alg not in ("sha-256", "sha-384"):
                raise ValueError("unsupported timestamp hash_alg")
            try:
                token = tsp.TimeStampToken.load(bytes(tst_der))
                ci = token["content"]
                eci = ci["encap_content_info"]
                # TSTInfo is the parsed content of encap_content_info.content
                tst_info = eci["content"].parsed
                mi = tst_info["message_imprint"]
                hashed_message = mi["hashed_message"].native
                algo_name = mi["hash_algorithm"]["algorithm"].native
            except Exception as e:
                raise ValueError("invalid RFC3161 token") from e
            # Cross-check algorithm declaration and imprint
            if hash_alg == "sha-256":
                if hashed_message != sb_sha256 or algo_name not in ("sha256",):
                    raise ValueError("timestamp imprint mismatch (sha-256)")
            else:  # sha-384
                if hashed_message != sb_sha384 or algo_name not in ("sha384",):
                    raise ValueError("timestamp imprint mismatch (sha-384)")
    # Interop profile enforcement (optional)
    profile = ((meta or {}).get(5, {}) or {}).get("profile")
    if isinstance(profile, str):
        if profile == "vdc-core":
            if ekm_used is not None or anchors_present or timestamps_present:
                raise ValueError("profile vdc-core forbids ekm/anchors/timestamps")
        elif profile == "vdc-bound":
            if ekm_used is None or anchors_present or timestamps_present:
                raise ValueError("profile vdc-bound requires ekm only")
        elif profile == "vdc-anchored":
            if not validated_anchors:
                raise ValueError("profile vdc-anchored requires at least one valid anchor")
        elif profile == "vdc-timestamped":
            if not timestamps_present:
                raise ValueError("profile vdc-timestamped requires timestamps")
        elif profile == "vdc-hybrid":
            raise ValueError("profile vdc-hybrid not supported yet")
        else:
            raise ValueError("unknown profile")

    return {"meta": meta, "payload_count": len(payloads), "anchors": validated_anchors}
