from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse
import os
import datetime
from pathlib import Path

from .config import load_agent_config
from .aegis import plan as aegis_plan
from .sentinel import probe_headers_budget, weekly_pathlab_job
from .vkc import build_vkc


router = APIRouter(prefix="/agent", tags=["agent"])


@router.get("/aegis/plan")
async def get_plan(route: str | None = None):
    cfg = load_agent_config()
    p = aegis_plan(route=route, advisory=cfg.advisory)
    return JSONResponse({"advisory": cfg.advisory, "plan": p})


@router.get("/sentinel/probe/headers")
async def probe_headers():
    res = probe_headers_budget()
    return JSONResponse(res)


@router.post("/vkc/emit")
async def emit_vkc(route: str | None = None):
    cfg = load_agent_config()
    p = aegis_plan(route=route, advisory=cfg.advisory)
    vdc_bytes, summary = build_vkc(p)
    # Persist to var/vkc/YYYY-MM-DD/vkc-XXXX.vdc
    date = datetime.date.today().isoformat()
    base = Path(os.getenv("VKC_DIR", "var/vkc")) / date
    base.mkdir(parents=True, exist_ok=True)
    existing = sorted([p.name for p in base.glob("vkc-*.vdc")])
    idx = 1
    if existing:
        try:
            last = existing[-1]
            idx = int(last.split("-")[1].split(".")[0]) + 1
        except Exception:
            idx = len(existing) + 1
    out = base / f"vkc-{idx:04d}.vdc"
    out.write_bytes(vdc_bytes)
    return JSONResponse({"ok": True, "bytes": summary.get("bytes", 0), "path": str(out)})


def include_agent_routes(app):
    app.include_router(router)
