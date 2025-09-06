# VDC v0.1 Test Vectors

This folder hosts canonical test vectors for interop between Python and Go SDKs.

Encoding rules (single source of truth):
- Deterministic CBOR encoding (canonical=True)
- No tags, no indefinite lengths
- Reject floats

Artifacts provided:
- cddl.cddl – schema sketch
- core.cbor (base16 + diag) – minimal Core (1 payload digest, 1 signature)
- bound_ekm.cbor – Bound (dummy 32-byte EKM)
- anchored.cbor – Anchored (toy CT/v2 inclusion)
- negative_wrong_digest.cbor – wrong payload digest (must fail)
- negative_unknown_crit.cbor – unknown crit param (must fail)
- negative_tamper_payload.cbor – tampered embedded payload (must fail)

How to (re)generate:
- Use src/signet/vdc/cli.py to pack vectors. Keep the same meta and payloads across languages.
- Export both CBOR diag and base16/base64 encodings for each artifact.

CI:
- Parse/verify vectors in both Python (libvdc.py) and Go (libvdc.go) in dedicated tests.
- Fail the job if any vector parsing or verification diverges.
