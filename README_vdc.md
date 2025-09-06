# VDC v0.1 (Verifiable Data Container) — PR‑A snapshot

This repo includes a minimal VDC core with:
- Deterministic CBOR (RFC 8949 canonical) encoding
- Magic header ("\x89vdc\r\n\x1a\n") for the file format
- Payload descriptors with embedded data and SHA‑384 digests
- COSE_Sign1 (Ed25519) receipts over a deterministic SigBase `{2: meta, 3: payloads}`
- Optional EVG-like in-repo anchor stub for demos

CLI (experimental): `python -m signet.vdc.cli pack|verify`

Notes:
- We forbid floats in VDC v0.1.
- The COSE signature is not nested or detached; we sign the SigBase CBOR bytes directly and store the COSE bytes under field 4.
- Anchors are non-normative for now.

Client SDKs (libvdc):
- Python reference: `src/libvdc/python/libvdc.py` — functions: `parse_vdc(buf)`, `verify_ed25519(buf, pubkey_bytes, kid=None)`
- Go reference: `src/libvdc/go/libvdc.go` — function: `libvdc.ParseVDC(buf)`
