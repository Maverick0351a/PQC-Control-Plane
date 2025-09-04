# SECURITY.md

**Threat model:** STRIDE over assets: policy integrity, client authenticity, service availability.

**Channel binding:** MVP uses `X-TLS-Session-ID` forwarded by NGINX for development only. Production MUST use TLS 1.3 **tls‑exporter** per RFC 9266 / RFC 8446; extract EKM in Envoy transport socket and inject into HTTP filter context (strip before egress).

**Receipts & Transparency:** Receipts are hash‑linked (prev‑hash) and batched into a Merkle tree. Each batch emits an STH signed by the server key. Compliance Pack includes STH, receipts, inclusion proofs, and an offline verifier.

**Cryptography:** 
- Request signatures: Ed25519 (MVP). Hook for ML‑DSA via OQS planned.
- Content integrity: `Content-Digest: sha-256=:…:` per RFC 9530.
- JSON canonicalization: JCS (subset: strings/ints). Avoid floats in signed payloads.

**Key management:** 
- Server STH signing key: `keys/sth_ed25519_sk.pem` (PEM). Generate via `tools/gen_ed25519.py` and store securely.
- Client public keys: `config/clients.json` maps `keyid` → public key/alg.

**Header budgets:** A single ML‑DSA‑65 signature base64 would be ~4.3 KB; respect header size limits (431). Keep evidence hashed (via `evidence-sha-256`) rather than embedded.

**CI:** Lint, test, coverage on PRs. Pin GitHub Actions to full SHAs in your repo before opening publicly.
