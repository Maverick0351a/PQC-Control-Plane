from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class AegisPlan:
    route: Optional[str]
    intent: str
    actions: list[dict]
    notes: str


def plan(route: Optional[str] = None, advisory: bool = True) -> Dict[str, Any]:
    """Return a simple advisory plan stub for the requested route.

    For MVP, produce a conservative no-op plan with guidance.
    """
    actions: list[dict] = []
    if advisory:
        actions.append({
            "type": "observe",
            "what": "collect 15m metrics window for header budget and PCH verification",
        })
        actions.append({
            "type": "advise",
            "what": "dry-run tighten header budget if p95<12KB and 0 PCH failures",
        })
    else:
        actions.append({
            "type": "enforce",
            "what": "apply conservative header budget and keep breaker closed with hysteresis",
        })
    out: Dict[str, Any] = {
        "route": route,
        "intent": "stability-first",
        "actions": actions,
        "notes": "advisory mode; no changes applied",
    }
    return out
