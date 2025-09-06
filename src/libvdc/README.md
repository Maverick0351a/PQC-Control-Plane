libvdc reference verifiers

- Python: src/libvdc/python/libvdc.py
- Go: src/libvdc/go/libvdc.go

Usage (Python):
- parse_vdc(buf) -> VdcInfo
- verify_ed25519(buf, pubkey_bytes, kid=None) -> bool

Usage (Go):
- info, err := libvdc.ParseVDC(buf)

Copy the Ed25519 pubkey bytes and kid from your deployment to verify signatures.
