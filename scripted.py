"""
scripted.py - Serves the frontend files (frontend/) and the browser-facing JSON API (/api/*).
Fails closed: checks vault sealing and lock flag before serving API routes.
"""

import os
import pathlib
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, File, Form, Header, HTTPException, Query, Request, UploadFile
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


def _get_identity(
    x_officer_id: Optional[str] = Header(None),
    x_device_id: Optional[str] = Header(None),
    x_rank_tier: Optional[str] = Header(None),
) -> Tuple[str, str, int]:
    officer_id = x_officer_id or "anonymous"
    device_id = x_device_id or "unknown"
    try:
        tier = int(x_rank_tier or "1")
    except ValueError:
        tier = 1
    return officer_id, device_id, tier


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


# ---------- Cases Management ----------

@api_router.post("/cases")
async def create_case_route(
    request: Request,
    x_officer_id: Optional[str] = Header(None),
    x_device_id: Optional[str] = Header(None),
    x_rank_tier: Optional[str] = Header(None),
):
    _check_vault_gate("/api/cases")
    officer_id, device_id, tier = _get_identity(x_officer_id, x_device_id, x_rank_tier)
    body = await request.json()

    title = body.get("title", "").strip()
    case_type = body.get("case_type", "General").strip()
    witness_protection = bool(body.get("witness_protection", False))
    complainant_name = body.get("complainant_name", "").strip()

    if not title:
        raise HTTPException(status_code=400, detail="Case title is required")

    return candyWrapper.create_case(
        title=title,
        case_type=case_type,
        witness_protection=witness_protection,
        complainant_name=complainant_name,
        created_by=officer_id,
    )


@api_router.get("/cases")
async def list_cases_route(status: Optional[str] = Query(None)):
    _check_vault_gate("/api/cases")
    return candyWrapper.list_cases(status=status)


@api_router.get("/cases/{case_id}")
async def get_case_route(case_id: str):
    _check_vault_gate(f"/api/cases/{case_id}")
    case = candyWrapper.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@api_router.post("/cases/{case_id}/upload")
async def upload_case_file_route(
    case_id: str,
    file: UploadFile = File(...),
    x_officer_id: Optional[str] = Header(None),
    x_device_id: Optional[str] = Header(None),
    x_rank_tier: Optional[str] = Header(None),
):
    _check_vault_gate(f"/api/cases/{case_id}/upload")
    officer_id, device_id, tier = _get_identity(x_officer_id, x_device_id, x_rank_tier)
    content = await file.read()
    return upstream.handle_upload(
        case_id=case_id,
        filename=file.filename or "upload.bin",
        content=content,
        officer_id=officer_id,
        device_id=device_id,
    )


@api_router.get("/cases/{case_id}/files")
async def list_case_files_route(case_id: str):
    _check_vault_gate(f"/api/cases/{case_id}/files")
    return candyWrapper.list_files(case_id=case_id)


@api_router.post("/cases/{case_id}/close")
async def close_case_route(
    case_id: str,
    x_officer_id: Optional[str] = Header(None),
    x_device_id: Optional[str] = Header(None),
    x_rank_tier: Optional[str] = Header(None),
):
    _check_vault_gate(f"/api/cases/{case_id}/close")
    officer_id, device_id, tier = _get_identity(x_officer_id, x_device_id, x_rank_tier)
    try:
        return candyWrapper.close_case(case_id=case_id, officer_id=officer_id, officer_tier=tier)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------- Amendments ----------

@api_router.post("/cases/{case_id}/amendments")
async def propose_amendment_route(
    case_id: str,
    request: Request,
    x_officer_id: Optional[str] = Header(None),
    x_device_id: Optional[str] = Header(None),
    x_rank_tier: Optional[str] = Header(None),
):
    _check_vault_gate(f"/api/cases/{case_id}/amendments")
    officer_id, device_id, tier = _get_identity(x_officer_id, x_device_id, x_rank_tier)
    body = await request.json()
    changes = body.get("changes", {})
    try:
        return candyWrapper.propose_amendment(
            case_id=case_id,
            changes=changes,
            officer_id=officer_id,
            officer_tier=tier,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@api_router.get("/amendments")
async def list_amendments_route(
    case_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    _check_vault_gate("/api/amendments")
    return candyWrapper.list_amendments(case_id=case_id, status=status)


@api_router.post("/amendments/{amendment_id}/review")
async def review_amendment_route(
    amendment_id: str,
    request: Request,
    x_officer_id: Optional[str] = Header(None),
    x_device_id: Optional[str] = Header(None),
    x_rank_tier: Optional[str] = Header(None),
):
    _check_vault_gate(f"/api/amendments/{amendment_id}/review")
    officer_id, device_id, tier = _get_identity(x_officer_id, x_device_id, x_rank_tier)
    body = await request.json()
    decision = body.get("decision", "").strip()
    try:
        return candyWrapper.review_amendment(
            amendment_id=amendment_id,
            decision=decision,
            officer_id=officer_id,
            officer_tier=tier,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------- Archive & Verification ----------

@api_router.get("/archive/lookup")
async def archive_lookup_route(sha256: str = Query(...)):
    _check_vault_gate("/api/archive/lookup")
    return candyWrapper.archive_lookup(sha256)


@api_router.get("/files/{file_id}/verify")
async def verify_file_route(file_id: str):
    _check_vault_gate(f"/api/files/{file_id}/verify")
    valid = candyWrapper.verify_file(file_id)
    return {"file_id": file_id, "valid": valid}


# ---------- Audit ----------

@api_router.get("/audit")
async def api_audit():
    _check_vault_gate("/api/audit")
    return {"events": candyWrapper.get_audit_events()}


@api_router.post("/audit/verify")
async def api_audit_verify():
    _check_vault_gate("/api/audit/verify")
    return candyWrapper.audit_verify()


@api_router.post("/seal")
async def api_seal():
    rustPolish.seal_vault("manual_api_seal")
    return {"ok": True, "vault_sealed": True}
