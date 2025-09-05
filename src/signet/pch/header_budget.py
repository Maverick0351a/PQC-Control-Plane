"""Header budget accounting and guardrails.

We approximate raw header bytes as: len(name) + len(value) + 4 (": "+CRLF surrogate).
FastAPI/Starlette normalizes headers but preserves original casing mostly; for guardrails
we only need a deterministic upper bound.
"""
from __future__ import annotations
from typing import Iterable, Tuple, Dict

def measure(headers: Iterable[Tuple[str, str]]) -> Dict[str, int]:
    total = 0
    largest = 0
    for k, v in headers:
        sz = len(k) + len(v) + 4
        total += sz
        if sz > largest:
            largest = sz
    return {"total_bytes": total, "largest_bytes": largest}

def over_limits(measurement: Dict[str, int], max_total: int, max_single: int) -> bool:
    return measurement["total_bytes"] > max_total or measurement["largest_bytes"] > max_single
