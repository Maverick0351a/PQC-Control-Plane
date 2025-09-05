# RFC-0023: Verifiable Simulation Platform (VSP) — Proof of Simulation

Status: Draft
Date: 2025-09-05
Owners: Signet Team

## Summary
Define a Proof-of-Simulation pattern where a CBOM-attested simulation engine executes a declared scenario, emits notarized steps via SNDT, and anchors evidence receipts in the EVG log. Result: a replayable, audit-grade chaos drill with tamper-evident provenance.

## Motivation
- Regulators and SREs need high-confidence evidence that drills were performed as declared.
- Simulations must be reproducible and independently verifiable.
- Evidence should be dual-bound to session (EKM) and signed by platform keys (non-repudiation).

## Design
- Scenario manifest (YAML) defines steps with inputs/expected effects.
- VSP Engine:
  - Parses scenario, executes steps (fault injection, traffic, toggles).
  - For each step, builds an evidence envelope containing:
    - actor: {service:"vsp-engine", route: step.id}
    - claims: {scenario: metadata, step: details, sndt: notarized decision snapshot}
    - session_binding: {strength, has_tag}
  - Submits the receipt to EVG (/ingest); retrieves current STH.
- SNDT Notary: attaches notarized controller/plan snapshot to each step claim.
- CBOM: engine container is included in CBOM; version + hash included in claims.
- DPCP advisory: request provenance checksum for engine actions included in receipt.

## Evidence Model
- Each step produces a receipt compatible with existing `envelope_v1` schema used by enforcement receipts.
- Receipts chain via `prev_receipt_hash_b64` forming a per-run append-only log; the run’s STH recorded.
- Optional inclusion proofs are generated post-run for the artifacts bundle.

## Verification
- Replay runner re-executes steps in dry-run mode and compares observed system metrics vs claimed effects.
- EVG `/__evg/verify` confirms presence; inclusion proofs can be validated offline.

## Security Considerations
- Engine should use TLS exporter when available to tag receipts with session-bound HMAC.
- Keep secrets out of receipts; include stable identifiers and hashes only.
- Time skew: record both wall-clock and monotonic deltas per step.

## Open Questions
- How to bind to external CT-like logs for cross-domain anchoring.
- Which SNDT keys and policies to use for production notarization.

