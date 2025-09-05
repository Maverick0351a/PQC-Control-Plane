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

## DPCP (Data Plane Control & Proof) – Shadow Mode Security & Privacy

The DPCP pipeline (edge DPR signer + receipt sink + controller join) operates initially in shadow mode: it collects signed Deterministic Processing Records (DPRs) and controller decisions without influencing request handling. Full details live in `THREAT_MODEL.md`; this section captures the operationally relevant security + privacy contract.

### Objectives
1. Authentic, replay‑resistant DPR telemetry (integrity & provenance).
2. Minimal, low re‑identification risk data retention (no raw payload bodies).
3. Strong channel binding (TLS exporter → non‑reversible tag) to prevent cross‑channel grafting.
4. Cryptographic agility (future PQ / hybrid signatures) with small header footprint.

### Data Minimization & Pseudonymization
- No payload storage: only streaming SHA‑384 body hashes (optionally truncated by `max_bytes_hashed`).
- Small‑payload re‑identification risk mitigated via optional per‑tenant peppered HMAC (pepper held in KMS, never logged). Hashes used only after HMAC where enabled.
- TLS exporter never persisted; only HKDF‑derived 32B `ekm_tag` retained and signed inside the DPR.

### Channel Binding Flow
Envoy TLS exporter injector filter → exporter bytes → HKDF‑SHA256(info="dpr-ekm-tag") → `ekm_tag` → DPR signer (Rust proxy‑wasm) includes + signs -> sink stores & correlates with controller decisions.

### Keys & Rotation (Separation of Domains)
| Domain | Key / Secret | Rotation | Storage |
|--------|--------------|----------|---------|
| DPR signing | Ed25519 key (daily) | 24h (retain 7) | KMS / sealed file (demo) |
| Channel binding | TLS exporter (ephemeral) | Per connection | Not stored |
| Analytics pseudonymization | Tenant pepper | 90 days (stagger) | KMS secret ref |

Signing keys and peppers are governed by separate IAM policies; exporter material never leaves process memory at the edge.

### Threats / Controls Snapshot
| Threat | Control |
|--------|---------|
| DPR forgery | Ed25519 signature + key rotation + sink verification |
| Replay | (method,path,ekm_tag,timestamp) uniqueness & future replay cache |
| Cross‑tenant correlation | Distinct peppers → unlinkable HMAC outputs |
| Exporter leakage | Only HKDF tag stored, exporter zeroed after derivation |
| Key compromise (signing) | Short rotation, monitoring unexpected key ids |
| Payload brute force (short bodies) | Pepper HMAC + (future) minimum length acceptance thresholds |

### Metrics & Observability
Prometheus metrics exposed by receipt sink (used for Grafana panels & alerting):
- `dpcp_dpr_total` – DPR ingestion rate
- `dpcp_ekm_present_total` – Channel binding coverage (SLO >95%)
- `dpcp_bytes_hashed_total` – Volume hashed (detect anomalies / truncation efficacy)
- `dpcp_top_exposure_first` – Rolling highest exposure indicator
- `dpcp_sth_age_seconds` – Merkle STH freshness (alert if >2× flush interval)

### Roadmap / TODO (Security-Relevant)
- Implement truncation flag in DPR (+ test) when `max_bytes_hashed` < body size.
- Add replay cache & duplicate detection metric.
- Hybrid / PQ signature (ML‑DSA + Ed25519) support once library maturity acceptable.
- Privacy pipeline: identity field redaction / pepper pseudonymization when `privacy.redact_identities` enabled.
- Differential privacy noise layer for exposure aggregates prior to external export.

For full rationale, risk analysis tables, and operational playbooks see `THREAT_MODEL.md`.
