from __future__ import annotations

import sys
import json
from pathlib import Path
from typing import Any, Dict
import argparse
import os

import yaml

from .engine import VSPEngine, parse_scenario
from ..compliance.bundler import bundle_compliance_pack


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run VSP scenario and optionally bundle a compliance pack")
    parser.add_argument("scenario", help="Path to scenario YAML")
    parser.add_argument("--bundle", dest="bundle", help="Output compliance pack .zip path")
    parser.add_argument("--evg", dest="evg", help="EVG base URL (default inferred from RECEIPTS_SINK_URL)")
    args = parser.parse_args(argv or sys.argv[1:])

    path = Path(args.scenario)
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
    # Optional compliance pack
    if args.bundle:
        evg_url = args.evg
        if not evg_url:
            sink = os.getenv("RECEIPTS_SINK_URL")
            # If sink like http://evg:8088/ingest, derive http://evg:8088
            if sink and "/ingest" in sink:
                evg_url = sink.split("/ingest", 1)[0]
        try:
            bundle_compliance_pack(args.bundle, evg_url=evg_url)
            manifest["compliance_pack"] = args.bundle
        except Exception as e:
            manifest["compliance_pack_error"] = str(e)
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
