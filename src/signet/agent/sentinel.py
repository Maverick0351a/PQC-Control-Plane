from __future__ import annotations

from typing import Any, Dict


def probe_headers_budget() -> Dict[str, Any]:
    # Minimal placeholder until PathLab/Envoy sandbox wired
    return {
        "skill": "headers-budget",
        "status": "ok",
        "findings": {"oversize": 0, "p95_bytes": 8192},
    }


def weekly_pathlab_job() -> Dict[str, Any]:
    # Placeholder for scheduled replay/pentest
    return {"job": "weekly-pathlab", "status": "scheduled"}
