"""Verification helper bridging existing signature path to new registry."""
from __future__ import annotations

from typing import Dict

from .alg_registry import verify_alg


def verify_message(alg: str, key_entry: Dict, signature_b64: str, message: str) -> bool:
    return verify_alg(alg, key_entry, signature_b64, message)


__all__ = ["verify_message"]
