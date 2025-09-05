# Pilot Plan: Signet Closed‑Loop Assurance

## Scope
Demonstrate closed‑loop Policy → Enforcement → Proof for a protected HTTP route with:
- PCH‑Lite challenge/response (401 → signed request)
- PQC / hybrid signing option (if liboqs available)
- Control‑theoretic breaker stability under induced latency & bandwidth stress
- Receipt persistence (SQLite WAL) and Merkle batching (STH chain)
- Rego policy shields (binding requirement + availability floor)

## Environments
| Component | Notes |
|-----------|-------|
| App | FastAPI + middleware (Docker) |
| Envoy | TLS 1.3 termination + exporter placeholder |
| Redis | Nonce store |
| Prometheus | Metrics scrape (/metrics) |
| Grafana | Pre‑provisioned dashboard |
| Toxiproxy (optional) | Fault injection harness |

## Success Metrics
| Category | Metric | Target |
|----------|--------|--------|
| Handshake | Signed request success | > 99% during baseline |
| Breaker Stability | No oscillation (Open↔Closed flap) | 0 flaps under induced faults |
| Latency Control |  p90 added latency under relax mode | < 50ms added vs baseline |
| Evidence Integrity | Inclusion proof verifies | 100% sampled receipts |
| Policy Safety | Binding mismatch blocked | 100% |

## Timeline (5 Business Days)
| Day | Activity | Artifact |
|-----|----------|----------|
| 1 | Setup & handshake demo | Successful signed request (log + receipt) |
| 2 | PQC / Hybrid attempt | PQC receipt shows alg field |
| 3 | Breaker fault injection (latency, bandwidth) | Grafana screenshot + breaker state transitions |
| 4 | Compliance Pack generation & independent verify | pack.zip + verify output |
| 5 | Policy tweak (raise availability floor) & fallback demo | Rego change diff & receipts showing fallback |

## Data Protection & Retention
| Aspect | Approach |
|--------|----------|
| Receipt Storage | SQLite WAL (local volume) |
| Rotation | Daily STH; key rotation optional (future) |
| PII | None stored (request refs limited to method/path/digest) |
| Export | Zip compliance pack (date‑scoped) |
| Deletion | Delete `var/data/<date>` or prune DB rows post‑pilot |

## Roles
| Role | Responsibility |
|------|----------------|
| Pilot Champion (Customer) | Run script, observe dashboard |
| Security Lead (Customer) | Verify receipts & proofs |
| Signet Engineer | Support, policy tuning |

## Change Control
- Policy edits via `policy/shield.rego` PRs (review + commit hash logged in CBOM).
- Breaker thresholds tracked in `plan.py` (versioned in repo).

## Exit Criteria
- All success metrics met or plan to remediate agreed.
- Customer independently verifies at least one Compliance Pack.
- Decision: expand scope (more routes) or productionize channel binding with real TLS exporter.
