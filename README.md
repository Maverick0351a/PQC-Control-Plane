# Signet PQC Control Plane — MVP (PCH‑Lite + Receipts + Merkle STH)

**Policy → Enforcement → Proof.** This MVP implements an HTTP‑layer, standards‑aligned Proof‑Carrying Handshake (PCH‑Lite) using **HTTP Message Signatures (RFC 9421)** + **Content‑Digest (RFC 9530)**, attached to a control‑theoretic enforcement plane that emits **verifiable receipts** and batches them into a **Merkle log** with **Signed Tree Heads (STHs)**.

> ⚠️ **Channel binding:** In MVP, binding uses `X-TLS-Session-ID` from NGINX for development only. Production **MUST** switch to TLS 1.3 **tls‑exporter** (RFC 9266 / RFC 8446) via an Envoy transport socket extension. See `src/signet/ingress/envoy/README.md`.

## Features

- **PCH‑Lite (advisory)**: 401 challenge + Redis nonce; client signs a RFC‑9421 base over selected components (`@method`, `@path`, `@authority`, `content-digest`, `pch-challenge`, `pch-channel-binding`, `evidence-sha-256`). Server verifies signature and binding; result attached to receipts.
- **Content Integrity**: Enforces `Content-Digest: sha-256=:…:` per **RFC 9530**.
- **JCS Canonicalization (RFC 8785)**: All signed JSON (evidence, receipts) is canonicalized (subset: strings/ints only) to ensure hash stability.
- **Receipts + Transparency**: Every decision emits a canonical, hash‑linked receipt. Daily Merkle tree + **Signed Tree Head** (Ed25519) + inclusion proofs. **Compliance Pack** bundler + offline verifier.
- **Control‑theoretic breaker (scaffold)**: EWMA + hysteresis with safe defaults (advisory; wired for future enforcement).
- **DX**: `tools/pch_client_demo.py` demo, Postman collection, curl recipes.
- **Ops**: Non‑root Dockerfile, docker‑compose with Redis, NGINX forwarding `X‑TLS‑Session‑ID` for MVP binding.
- **CI**: Ruff, pytest, coverage; GitHub Actions workflow scaffold (pin to SHA in repo).

## Quickstart

```bash
# 1) Setup
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2) Generate server and client keys (Ed25519 for MVP)
python tools/gen_ed25519.py

# 3) Start infra (app + redis)
docker compose up -d redis
uvicorn src.signet.app:app --reload --port 8080

# 4) (Optional) NGINX TLS terminator (dev)
docker compose up -d nginx

# 5) Try the PCH‑Lite demo
python tools/pch_client_demo.py --url http://localhost:8080/protected
```

### Environment

Create `.env` (or export variables):

```
FEATURE_PCH=true
PCH_ADVISORY=true             # advisory mode (no hard deny)
REDIS_URL=redis://localhost:6379/0
DATA_DIR=var/data             # receipts / STHs
SERVER_SIGNING_KEY=keys/sth_ed25519_sk.pem
CLIENT_KEYS=config/clients.json
```

### NGINX (MVP binding)

We forward the TLS session id as `X-TLS-Session-ID` (dev only). In `docker-compose.yml` the provided NGINX config uses:

```nginx
proxy_set_header X-TLS-Session-ID $ssl_session_id;
```

> **Upgrade path:** Switch to TLS 1.3 `tls-exporter` via Envoy. See `src/signet/ingress/envoy/README.md`.

## Endpoints

- `GET /__health` — health
- `GET /protected` — protected route (returns 401 with PCH challenge if missing, or 200 on valid PCH)
- `POST /protected` — same as above, with body digested/verified
- `POST /compliance/pack` — build a Compliance Pack zip for a date (JSON input: `{ "date": "YYYY-MM-DD" }`)

## Specs (anchor citations)

- HTTP Message Signatures — RFC 9421
- Digest Fields (Content‑Digest) — RFC 9530 *(obsoletes RFC 3230)*
- JSON Canonicalization Scheme — RFC 8785
- TLS 1.3 / Exporter — RFC 8446 §7.5
- TLS channel binding for TLS 1.3 — RFC 9266
- Transparency log terms (STH/inclusion proofs) — RFC 9162 (CT v2)

## Caveats

- PCH‑Lite **advisory** by default. Turn enforcement on after pilots.
- Binding is via session id in dev; **do not** treat as cryptographically strong.
- PQC sigs: Ed25519 is default for demo. Hook points are in `crypto/signatures.py` to add ML‑DSA via OQS later.

## License

MIT
