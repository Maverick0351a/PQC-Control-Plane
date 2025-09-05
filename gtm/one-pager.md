# Signet Pilot One‑Pager

**Promise**: Closed‑loop cryptographic assurance: *Policy → Enforcement → Proof* in under a week.

**What it is**: A lightweight Proof‑Carrying Handshake (PCH‑Lite) with post‑quantum (ML‑DSA / hybrid) option, adaptive header budget, and a control‑theoretic breaker that emits immutable Merkle‑linked receipts (daily Signed Tree Heads) you can independently verify.

## Why Teams Pilot Signet

1. **Closed‑Loop Assurance** – Every enforcement decision is logged as a receipt, chained, merklized, and signed. You get cryptographic evidence, not dashboards hand‑waving.
2. **Stability Under Stress** – Breaker with EWMA + hysteresis prevents brownouts; relax header actuator shifts bulk evidence to body automatically.
3. **Safety & Auditability** – Policy invariants (binding, availability floors) externalized via Rego; TLS 1.3 channel binding (tls‑exporter) cryptographically anchors identity.

## Architecture (High Level)

```
Client ──(Challenge 401)──▶ Signet API ──▶ Receipt Store (SQLite WAL) ──▶ Merkle Batch ──▶ STH (rotating key)
   ▲               │  ▲             │
   │ (Signed Req)  │  │(Breaker)    │(Proof Pack)
   └────(Retry/Relax)┘  └────────────┘
```

## Pilot Outcomes (5 Business Days)
- Day 1: Handshake & PQC/hybrid signing demo passes.
- Day 3: Induced latency → breaker transitions (Closed→Open→Half‑Open→Closed) without flapping.
- Day 5: Compliance Pack (receipts.jsonl + sth.json + proofs/) independently verified on your laptop.

## Quick PowerShell Snippet

```powershell
# Start stack
docker compose up -d --build redis app envoy prometheus grafana
# Get challenge
curl.exe -k -I https://localhost:8443/protected
# Signed request (Ed25519)
python .\tools\pch_client_demo.py --url https://localhost:8443/protected --binding tls-exporter --insecure
# PQC (if liboqs present)
python .\tools\pch_client_demo.py --url https://localhost:8443/protected --binding tls-exporter --alg ml-dsa-65 --insecure
```

## Verification (Compliance Pack)
```powershell
# After traffic
curl.exe -X POST http://localhost:8080/compliance/pack -H "Content-Type: application/json" -d '{"date":"2025-09-04"}' -o pack.zip
```

## Differentiators
| Capability | Signet | DIY Scripts |
|------------|--------|-------------|
| Cryptographic Receipts | ✅ | ❌ |
| Breaker w/ Hysteresis | ✅ | ⚠️ (ad‑hoc) |
| PQC / Hybrid | ✅ | ❌ |
| Formal Policy (Rego) | ✅ | ❌ |
| Compliance Pack | ✅ | ❌ |

## Next Steps
1. Run the demo script once (5 minutes).  
2. Review receipts & STH.  
3. Schedule breaker fault session (30 minutes).  
4. Approve pilot success criteria.  
