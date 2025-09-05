from __future__ import annotations

import sys
import json
from pathlib import Path
from typing import Any, Dict

import yaml

from .engine import VSPEngine, parse_scenario


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if not argv:
        print("usage: python -m signet.vsp.cli <scenario.yaml>")
        return 2
    path = Path(argv[0])
    if not path.exists():
        print(f"file not found: {path}")
        return 2
    data: Dict[str, Any] = yaml.safe_load(path.read_text())
    scenario = parse_scenario(data)
    eng = VSPEngine()
    receipts = eng.run(scenario)
    manifest = {
        "scenario_id": scenario.id,
        "title": scenario.title,
        "step_count": len(scenario.steps),
        "receipts": [r["id"] for r in receipts],
    }
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
