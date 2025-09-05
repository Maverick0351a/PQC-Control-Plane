from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Dict, Any

from ..receipts.store import ReceiptStore


@dataclass
class Step:
    id: str
    action: str
    args: Dict[str, Any]


@dataclass
class Scenario:
    id: str
    title: str
    steps: List[Step]


class VSPEngine:
    """Minimal PoC engine that runs a scenario and emits step receipts.

    Each step maps to a pseudo-request and a receipt is produced via ReceiptStore.
    """

    def __init__(self) -> None:
        self.store = ReceiptStore()

    def run(self, scenario: Scenario) -> List[Dict[str, Any]]:
        receipts: List[Dict[str, Any]] = []
        for step in scenario.steps:
            # Build a pseudo pch result for binding; real PoC could contact local endpoints
            pch = {"present": True, "verified": True, "step": step.id}

            # Create a tiny Request-like shim with headers and URL path fields expected by store
            class _Req:
                def __init__(self, step_id: str):
                    self.method = "POST"
                    # Route path embeds scenario id for per-run metrics separation
                    self.url = type("U", (), {"path": f"/vsp/steps/{scenario.id}/{step_id}"})()
                    self.headers = {"User-Agent": "vsp-engine-poc"}

            req = _Req(step.id)
            decision = "execute"
            reason = f"vsp:{step.action}"
            rec = self.store.emit_enforcement_receipt(request=req, decision=decision, reason=reason, pch=pch)
            receipts.append(rec)
            # optional pacing between steps
            time.sleep(step.args.get("sleep_s", 0))
        return receipts


def parse_scenario(obj: Dict[str, Any]) -> Scenario:
    sid = obj.get("id") or obj.get("name") or "vsp-run"
    title = obj.get("title", sid)
    steps = [Step(id=str(s.get("id")), action=s.get("action", "noop"), args=s.get("args", {})) for s in obj.get("steps", [])]
    return Scenario(id=sid, title=title, steps=steps)
