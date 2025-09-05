
Compliance Pack
===============

Contents:
- sth.json — Signed Tree Head (unsigned verification of root; signature verification requires distributing the server public key separately)
- receipts.jsonl — newline-delimited enforcement receipts
- proofs/*.json — Merkle inclusion proofs for each receipt
- verify_cli.py — offline inclusion verifier (usage: `python verify_cli.py sth.json receipts.jsonl proofs`)

This pack allows an auditor to validate that each receipt is included in the committed Merkle tree root.
