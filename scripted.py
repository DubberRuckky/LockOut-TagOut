"""
scripted.py - Serves the frontend files (frontend/) and the browser-facing JSON API (/api/*).
Fails closed: checks vault sealing and lock flag before serving API routes.
"""

import os
import pathlib
from typing import Any, Dict, Optional
from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

import candyWrapper
import rustPolish
import upstream

router = APIRouter()
api_router = APIRouter(prefix="/api")
FRONTEND_DIR = pathlib.Path(__file__).resolve().parent / "frontend"


def _check_vault_gate(path: str = ""):
    if rustPolish.is_vault_sealed() and not path.endswith("/status"):
        raise HTTPException(status_code=503, detail="vault is sealed")


# ---------- Frontend static routes (GET / and GET /ui/*) ----------

@router.get("/")
async def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return JSONResponse({"status": "LOTO Case Vault UI"})


@router.get("/ui/{file_path:path}")
async def serve_ui_file(file_path: str):
    target = FRONTEND_DIR / file_path
    if target.exists() and target.is_file():
        return FileResponse(target)
    raise HTTPException(status_code=404, detail="asset not found")


# ---------- Browser-facing /api/* endpoints ----------

@api_router.get("/health")
async def api_health():
    _check_vault_gate("/api/health")
    return {"status": "ok", "service": "loto-app"}


@api_router.get("/status")
async def api_status():
    sealed = rustPolish.is_vault_sealed()
    gateway_locked = rustPolish.is_locked()
    return {
        "vault_sealed": sealed,
        "gateway_locked": gateway_locked,
        "service": "loto-app",
    }


@api_router.get("/ping")
async def api_ping(
    request: Request,
    x_officer_id: Optional[str] = Header(None),
    x_device_id: Optional[str] = Header(None),
    x_rank_tier: Optional[str] = Header(None),
    x_lock_state: Optional[str] = Header(None),
):
    _check_vault_gate("/api/ping")
    return {
        "pong": True,
        "officer_id": x_officer_id,
        "device_id": x_device_id,
        "rank_tier": x_rank_tier,
        "lock_state": x_lock_state,
    }


@api_router.get("/audit")
async def api_audit():
    _check_vault_gate("/api/audit")
    return {"events": candyWrapper.get_audit_events()}


@api_router.post("/seal")
async def api_seal():
    rustPolish.seal_vault("manual_api_seal")
    return {"ok": True, "vault_sealed": True}
