# Signet PQC Control Plane — MVP (PCH‑Lite + PQC + Relax Header Budget + Receipts + Merkle STH)

**Policy → Enforcement → Proof.** This MVP implements an HTTP‑layer, standards‑aligned Proof‑Carrying Handshake (PCH‑Lite) using **HTTP Message Signatures (RFC 9421)** + **Content‑Digest (RFC 9530)**, attached to a control‑theoretic enforcement plane that emits **verifiable receipts** and batches them into a **Merkle log** with **Signed Tree Heads (STHs)**.

> ⚠️ **Channel binding:** In MVP, binding uses `X-TLS-Session-ID` from NGINX for development only. Production **MUST** switch to TLS 1.3 **tls‑exporter** (RFC 9266 / RFC 8446) via an Envoy transport socket extension. See `src/signet/ingress/envoy/README.md`.

## Features

- **PCH‑Lite (advisory)**: 401 challenge + Redis nonce; client signs a RFC‑9421 base over selected components (`@method`, `@path`, `@authority`, `content-digest`, `pch-challenge`, `pch-channel-binding`, `evidence-sha-256`). Server verifies signature and binding; result attached to receipts.
- **Algorithm Agility (Classical + PQC + Hybrid)**: Supports `ed25519`, `ml-dsa-65` (Dilithium3 via optional liboqs), and hybrid `ecdsa-p256+ml-dsa-65` container signatures (dual verification). Client demo: `--alg ed25519|ml-dsa-65|ecdsa-p256+ml-dsa-65` with automatic skip if PQC lib missing.
- **Relax Header Budget Actuator**: When projected header bytes exceed budget, server returns 431 (too large) or 428 (must relax). Client auto‑retries in relaxed mode: moves large `evidence` JSON into the body + `evidence-sha-256` header. Heuristic keeps relaxed flow stable even if plan recalculates mid‑flight. Status & evidence reference stored in receipt (`evidence_ref`).
- **Content Integrity**: Enforces `Content-Digest: sha-256=:…:` per **RFC 9530**.
- **JCS Canonicalization (RFC 8785)**: All signed JSON (evidence, receipts) is canonicalized (subset: strings/ints only) to ensure hash stability.
- **Receipts + Transparency**: Every decision emits a canonical, hash‑linked receipt. Daily Merkle tree + **Signed Tree Head** (Ed25519) + inclusion proofs. **Compliance Pack** bundler + offline verifier.
- **Control‑theoretic breaker (scaffold)**: EWMA + hysteresis with safe defaults (advisory; wired for future enforcement).
- **DX**: `tools/pch_client_demo.py` demo, Postman collection, curl recipes.
- **Ops**: Non‑root Dockerfile, docker‑compose with Redis, Envoy (TLS exporter placeholder), Prometheus, Grafana.
- **Observability**: Dual metrics endpoints: human/dev JSON at `/__metrics`, Prometheus exposition at `/metrics` (counters, gauges, histograms: breaker state, EWMA error, rho, Kingman Wq, header + signature sizes, latency, request outcomes). Starter Grafana dashboard auto‑provisioned.
- **CI**: Ruff, pytest, coverage; GitHub Actions workflow scaffold (pin to SHA in repo).

## Quickstart

```bash
# 1) Setup
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2) Generate server and client keys (Ed25519 for MVP)
python tools/gen_ed25519.py

# 3) Start infra (app + redis + prometheus + grafana + envoy)
docker compose up -d --build redis app prometheus grafana envoy
## (Dev hot‑reload alternative)
uvicorn src.signet.app:app --reload --port 8080

# 4) Try the PCH‑Lite demo (HTTP)
python tools/pch_client_demo.py --url http://localhost:8080/protected

# 5) (Optional) PQC / Hybrid
python tools/pch_client_demo.py --url http://localhost:8080/protected --alg ml-dsa-65
python tools/pch_client_demo.py --url http://localhost:8080/protected --alg ecdsa-p256+ml-dsa-65

# 6) (Optional) Envoy + TLS exporter placeholder (HTTPS)
curl -k -I https://localhost:8443/protected
python tools/pch_client_demo.py --url https://localhost:8443/protected --binding tls-exporter --insecure

# 7) View Metrics
curl http://localhost:8080/__metrics | jq '.'     # JSON (legacy/dev)
curl http://localhost:8080/metrics                # Prometheus text

# 8) Grafana (login admin / admin)
# http://localhost:3000  (Dashboard: "Signet PQC Control Plane")
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

### Channel Binding (Envoy TLS exporter placeholder)

Development path:

1. Plain HTTP dev: pseudo binding via `X-TLS-Session-ID` (not cryptographically strong).
2. HTTPS via Envoy: placeholder `x-tls-exporter` header simulating a TLS exporter token.
3. Production upgrade: real TLS exporter (RFC 9266) implemented by a WASM/extension returning `EXPORTER-Channel-Binding` bytes (base64) — replace placeholder filter.

Environment (compose sets defaults):

```
BINDING_TYPE=tls-exporter
BINDING_HEADER=X-TLS-Exporter
REQUIRE_TLS_EXPORTER=true
```

## Endpoints

- `GET /__health` — health
- `GET /protected` — protected route (401 challenge if missing signature; 200 on valid PCH)
- `POST /protected` — same as above, enforces `Content-Digest`
- `POST /compliance/pack` — build a Compliance Pack zip (JSON: `{ "date": "YYYY-MM-DD" }`)
- `GET /__metrics` — JSON snapshot (legacy/dev friendly)
- `GET /metrics` — Prometheus exposition (text/plain; scrape target)

## Specs (anchor citations)

- HTTP Message Signatures — RFC 9421
- Digest Fields (Content‑Digest) — RFC 9530 *(obsoletes RFC 3230)*
- JSON Canonicalization Scheme — RFC 8785
- TLS 1.3 / Exporter — RFC 8446 §7.5
- TLS channel binding for TLS 1.3 — RFC 9266
- Transparency log terms (STH/inclusion proofs) — RFC 9162 (CT v2)

## Metrics (Prometheus)

Key metric families:

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `signet_pqc_requests_total` | counter | `route,result,reason,http_status` | PCH verification outcomes |
| `signet_http_responses_total` | counter | `route,code` | Status code distribution |
| `signet_pqc_breaker_state` | gauge | `route` | Circuit breaker numeric state |
| `signet_pqc_err_ewma` | gauge | `route` | EWMA error rate |
| `signet_pqc_rho` | gauge | `route` | Utilization estimate (ρ) |
| `signet_pqc_kingman_wq_ms` | gauge | `route` | Kingman queue wait (ms) |
| `signet_pqc_utility_u` | gauge | `route` | Selected utility score |
| `signet_pqc_header_total_bytes` | histogram | `route` | Header size distribution |
| `signet_pqc_signature_bytes` | histogram | `route` | Signature header size |
| `signet_pqc_latency_ms` | histogram | `route` | Middleware latency (ms) |

Dashboard panels derive p50/p90 using `histogram_quantile` over `rate()` windows.

Breaker / relax actuator interplay: spikes in header bytes + 431 / 428 responses should correlate with RELAX mode adoption (evidence shifts from header to body); watch `signet_pqc_header_total_bytes` quantiles trend downward after adaptation.

## Caveats

- PCH‑Lite **advisory** by default. Turn enforcement on after pilots.
- Binding is via session id in dev; **do not** treat as cryptographically strong.
- PQC libs: ML‑DSA (Dilithium3) requires optional liboqs / python wrapper; tests skip gracefully if absent.
- Hybrid verification requires both classical and PQC parts succeed.

## License

MIT

## TLS Exporter via Envoy (Channel Binding Upgrade)

The stack now supports an Envoy sidecar that injects a pseudo `x-tls-exporter` header (placeholder hash) consumed by the PCH middleware when `BINDING_TYPE=tls-exporter`.

Quick start (PowerShell / Windows dev):

```powershell
docker compose up -d --build redis app envoy
curl.exe -k -I https://localhost:8443/protected   # obtain PCH challenge (401)
.\.venv\Scripts\python.exe tools\pch_client_demo.py --url https://localhost:8443/protected --binding tls-exporter --insecure
curl.exe -k https://localhost:8443/__metrics | jq '.routes[] | select(.route=="/protected")'
```

Convenience script:
```powershell
scripts\e2e_envoy_exporter.ps1 -Insecure
```

Environment (see `docker-compose.yml`):

```
BINDING_TYPE=tls-exporter
BINDING_HEADER=X-TLS-Exporter
REQUIRE_TLS_EXPORTER=true
```

`/echo/headers` now returns `x-tls-exporter` to aid debugging.

> NOTE: Lua filter produces a non-RFC exporter digest. Replace with a real TLS exporter (RFC 9266) for production (WASM or compiled filter accessing SSL exporter API).

## Helm Chart (Kubernetes Deploy)

Experimental chart in `helm/signet` mounts controller config + Rego policy via ConfigMaps.

```bash
helm install demo helm/signet \
	--set image.repository=yourrepo/signet-pqc \
	--set image.tag=latest

kubectl port-forward deploy/demo-signet 8080:8080
curl http://127.0.0.1:8080/__health
```

Key values (override via `--set` or custom `values.yaml`):
- `env.FEATURE_PCH` — enable/disable middleware
- `controllerConfig` — entire YAML inlined (header budgets, thresholds)
- `regoPolicy` — Rego for safety gating

## gRPC (PCH‑Lite Metadata Prototype)

Added proto: `src/signet/grpc/protected.proto` and async server `src/signet/grpc/server.py` implementing `Protected.Call`.

Flow:
1. First unary call without metadata returns a challenge (initial metadata `pch-challenge`).
2. Client recomputes signature base over components, sends metadata:
	 - `signature-input`
	 - `signature`
	 - `pch-challenge`
	 - `pch-channel-binding` (future TLS exporter)
	 - `evidence-sha-256` (optional relaxed path)
3. Server verifies and emits receipt (decision reason `grpc_pch_ok`).

Start server (dev):
```bash
python -m src.signet.grpc.server
```

Client scaffold: `tools/grpc_client_demo.py` (currently prints initial unauth reply; full signed retry wiring TBD).

## Supply Chain: SBOM + (Minimal) Provenance

Script `scripts/gen_sbom_provenance.ps1` produces:
- CycloneDX SBOM (`sbom.json`) from `requirements.txt` (Python deps)
- Minimal SLSA‑style provenance statement (`provenance.json`) referencing Dockerfile hash

Example:
```powershell
pwsh scripts/gen_sbom_provenance.ps1 -ImageRef registry.example.com/signet-pqc:sha123
cosign sign --key cosign.key registry.example.com/signet-pqc:sha123  # (manual; key not in repo)
```

Recommended next hardening steps:
- Integrate `cosign attest --predicate provenance.json` into CI
- Add container SBOM (e.g. `syft packages dir:./ -o cyclonedx-json`)
- Generate SPDX + CycloneDX dual formats
- Issue SLSA provenance using GitHub Actions OIDC + `cosign sign --identity` constraints

---
*Stretch add-ons implemented: Helm chart, Hypothesis fuzz tests (JCS + signature base), gRPC prototype service, SBOM + minimal provenance.*
