## Summary
<!-- What and why -->

## Scope
- [ ] GSC/Shield
- [ ] CAB (PCH-Lite)
- [ ] Dynamic CBOM
- [ ] PPA
- [ ] SNDT / Digital Twin
- [ ] EVG receipts/anchors
- [ ] DPCP (advisory)
- [ ] PathLab / PQCoaster
- [ ] PQC Calibrator

## Safety Rails
- [ ] Availability floor enforced
- [ ] tls-exporter binding checked (PCH-Lite advisory unless bound)
- [ ] Header budget guard correct
- [ ] Hysteresis (no flapping) in test

## Tests
- [ ] `test_breaker_hysteresis_*`
- [ ] `test_header_budget_guard_431`
- [ ] `test_ppa_prevents_retries_on_bad_paths`
- [ ] `test_cab_cbom_export`
- [ ] `test_pch_lite_advisory_and_bound_modes`
- [ ] `test_evg_receipts_and_sth`
- [ ] `calibrator: handshake_matrix_mtu_blackhole` passes

## Evidence
Attach:
- PQC Readiness Report (PDF/JSON)
- EVG STH reference
- SNDT SASO plots
## Title
<concise, imperative summary>

## Why (background, problem, objectives)
- What user/system problem this solves
- Success metrics & SLO constraints (latency, 5xx, header budgets)
- Safety invariants touched (availability floor, binding, header budgets)

## What (changes)
- New modules/APIs/headers/filters
- Config flags and defaults
- Migrations/backward-compat

## Evidence & Observability
- New receipts (type, claims), EVG anchoring & verify path
- Metrics, dashboards, alert thresholds

## Tests
- Unit
- Integration (docker compose)
- Game-day / chaos (PathLab profiles)
- What we *won’t* test here

## Rollout Plan
- Flags, cohort %, regions/ASNs
- Hold points, success/fail gates
- Auto/Manual rollback & backout steps

## Risks & Mitigations
- Feature interaction, privacy, header budgets, path fragility

## Security & Privacy
- Keys, signing, EKM binding, data retained (none vs hashes)

## Ops Notes
- Dashboards, runbooks, SLOs
