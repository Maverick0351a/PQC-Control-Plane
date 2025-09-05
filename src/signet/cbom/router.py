"""FastAPI router for CBOM endpoint."""
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from .export import build_cbom

router = APIRouter()

@router.get("/cbom", include_in_schema=False)
async def cbom():  # pragma: no cover - simple wrapper
    return JSONResponse(build_cbom())
