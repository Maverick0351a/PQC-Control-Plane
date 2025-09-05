# DPCP Threat Model & Data Handling Notes

## Scope
Data Plane Control & Proof (DPCP) shadow mode collection of DPR (Deterministic Processing Record) telemetry and controller decisions. Focus on confidentiality of payload contents, resistance to forgery / replay, and minimizing re-identification risk.

## Data Minimization
- No payload retention: only fixed-length hashes (SHA-384 for request/response bodies) are stored.
- Channel binding (exporter) is binary => only HKDF( exporter ) derived tags (ekm_tag) retained; raw exporter never persisted at sink.
- Optional HMAC (peppered_hmac) used for analytics instead of raw hashes to reduce linkage risk across tenants.

## Re‑identification Risk & Mitigations
| Risk | Vector | Mitigation |
|------|--------|-----------|
| Small payload brute force | Short messages ("OK", "true", etc.) hashed deterministically | Enable peppered HMAC: HMAC = SHA384(pepper || req_hash || rsp_hash) where pepper is tenant secret in KMS. Raw body never stored. |
| Cross‑tenant correlation | Same small payload across tenants | Distinct per‑tenant peppers -> unlinkable HMAC outputs. |
| Exporter binding leakage | Exporter acts as channel secret | Store only HKDF derived 32B ekm_tag; never log raw exporter material. |
| Key compromise (signing) | Stolen Ed25519 key used to forge DPR | Daily rotation + short validity window + monitor unexpected signer key ids. |

## Keys & Secrets
| Key | Purpose | Storage | Rotation | Notes |
|-----|---------|---------|----------|-------|
| Ed25519 DPR signing key | Authenticity & integrity of DPR JSON | KMS or sealed file (demo: ephemeral possible) | Daily (retain N=7 previous for verification) | Distinct from exporter/HMAC secrets. |
| Exporter-derived MAC (HKDF output) | Channel binding strengthening | Derived per session; not persisted | Per connection | Not a stored secret. |
| Tenant pepper (pepper_secret_ref) | HMAC / analytics pseudonymization | KMS secret reference (dpcp/pepper) | 90 days (staggered) | Rotate triggers recomputation only if longitudinal analytics required. |

Separation of duties: Signing keys and peppers reside under different KMS policies; peppers never exposed to application logs.

## Channel Binding
Type `tls-exporter-ekm-hmac-v1`:
1. Envoy filter obtains TLS exporter (RFC 9266) bytes.
2. HKDF-SHA256(exporter, info="dpr-ekm-tag") -> 32B `ekm_tag`.
3. `ekm_tag` included & signed inside DPR; sink uses it for correlation & left-join with controller decisions.
4. Raw exporter removed before leaving edge.

## Hashing & Truncation
- Bodies hashed streaming (SHA-384). `max_bytes_hashed` (0 = unlimited) allows truncation configuration; if enforced, include boolean `trunc` flag in DPR (TODO).
- Header evidence stored as hash-only when over budget to avoid large header risk.

## Threats & Controls
| Threat | Control |
|--------|---------|
| DPR forgery | Ed25519 signature; key rotation; verification at sink. |
| Replay of DPR | Timestamp + (method,path,ekm_tag) uniqueness detection (future: reservoir of recent leaf hashes). |
| Correlation deanonymization | Pepper HMAC + hash-only storage; enforce minimum size checks before accepting unpeppered analytics. |
| Key theft (signing) | Short rotation, audit logging of key id usage, restrict export policy. |
| Pepper disclosure | KMS access segregation, no local plaintext storage, memory zeroization (future). |
| Payload reconstruction | Large entropy → infeasible; small payload risk mitigated by peppered HMAC. |

## Operational Practices
- Daily CRON: generate new Ed25519 keypair, publish public key to verifier set, revoke oldest beyond retention window.
- Pepper rotation playbook: create new pepper, update reference, dual-write period (issue DPR with new HMAC tag while accepting old) then retire old pepper.
- STH lag alert: alert if `dpcp_sth_age_seconds` > 2 * flush interval.
- EKM coverage SLO: maintain >95% EKM presence; alert if `rate(dpcp_ekm_present_total)/rate(dpcp_dpr_total)` drops below threshold.

## Privacy Configuration Flags
From `controller.yml dpcp` block:
- `hash.algorithm`: sha384 (streaming) — switchable when PQ hash functions standardized.
- `privacy.redact_identities`: if true, apply pepper pseudonymization to identifiers (future field extraction pipeline).
- `privacy.asn_granularity`: aggregate network provenance at ASN, not individual IP.

## Future Work
- Implement truncation flag & test (`test_dpcp_streaming_large_body_truncation_flag`).
- Add replay cache & duplicate detection metrics.
- Support ML-DSA (post-quantum) signing keys with hybrid signature structure.
- Differential privacy noise layer for exposure counts before export.

## Summary
Design prefers minimal, unlinkable telemetry: Signed, hashed, pepper-pseudonymized where re-identification risk exists; no raw payload retention; exporter binding reduced to non-reversible tag; distinct key domains with independent rotation cadences.
