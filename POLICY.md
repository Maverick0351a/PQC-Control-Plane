# POLICY.md

## Minimal ingress policy (MVP)

- Enforce `Content-Digest` on modifying requests (POST/PUT/PATCH).
- Verify PCH‑Lite if `FEATURE_PCH=true`:
  - On missing signature: return 401 with `WWW-Authenticate: PCH …` and `PCH-Challenge`.
  - On present signature:
    - Verify Redis nonce (single use, TTL 300s)
    - Verify channel binding (`PCH-Channel-Binding` == observed binding)
    - Verify signature over RFC‑9421 component list
- Emit `pqc.enforcement` receipt with `pch.*` fragment and decision.

## V2 (right after MVP)

- Switch binding to TLS exporter (Envoy extension).
- Flip PCH‑Lite to enforce on protected routes.
- Enable the control‑theoretic circuit breaker to shed load during PQC‑specific failures.
