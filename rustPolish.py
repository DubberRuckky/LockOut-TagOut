"""
rustPolish.py - Everything between the app and the gateway.
Receives /internal/audit, /internal/seal, /internal/unseal and /internal/face-check from the gateway.
Offers read-only client functions to the app:
  gateway_status(), is_locked(), lock(reason), list_users(), list_devices(), wait_until_ready(timeout), watch(callback).
Has NO unlock, restore or enrol function, by design.
"""

import hmac
import json
import os
import pathlib
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Request

import candyWrapper

router = APIRouter(prefix="/internal")

_vault_sealed: bool = False
_seal_reason: str = ""

GATEWAY_URL = os.environ.get("LOT_GATEWAY_URL", "http://127.0.0.1:8080")


def seal_vault(reason: str = "sealed") -> None:
    """Make all routes except status return 503 (idempotent)."""
    global _vault_sealed, _seal_reason
    _vault_sealed = True
    _seal_reason = reason


def unseal_vault() -> None:
    """Reverse vault sealing (idempotent)."""
    global _vault_sealed, _seal_reason
    _vault_sealed = False
    _seal_reason = ""


def is_vault_sealed() -> bool:
    return _vault_sealed


def get_gateway_token() -> str:
    """Load the shared 32-byte hex token."""
    token_env = os.environ.get("LOT_GATEWAY_TOKEN")
    if token_env:
        return token_env.strip()

    data_dir_env = os.environ.get("LOT_DATA_DIR")
    search_paths = []
    if data_dir_env:
        search_paths.append(pathlib.Path(data_dir_env) / "gateway.token")
    search_paths.extend([
        pathlib.Path("user_gateway/lot-data/gateway.token"),
        pathlib.Path("lot-data/gateway.token"),
        pathlib.Path("./gateway.token"),
    ])

    for p in search_paths:
        try:
            if p.exists():
                text = p.read_text(encoding="utf-8").strip()
                if text:
                    return text
        except Exception:
            pass
    return ""


def verify_gateway_request(request: Request) -> None:
    """Constant-time token validation and loopback enforcement."""
    client_host = request.client.host if request.client else ""
    if client_host not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(status_code=403, detail="forbidden: loopback only")

    header_token = request.headers.get("x-gateway-token", "")
    expected_token = get_gateway_token()
    if not expected_token or not header_token or not hmac.compare_digest(header_token.strip(), expected_token.strip()):
        candyWrapper.record_audit_event({
            "action": "token_auth_failed",
            "actor": "gateway",
            "target": str(request.url.path),
        })
        raise HTTPException(status_code=401, detail="unauthorized: invalid gateway token")


# ---------- /internal routes mounted on the app ----------

@router.post("/audit")
async def internal_audit(request: Request):
    verify_gateway_request(request)
    body = await request.json()
    entry = candyWrapper.record_audit_event(body)
    return {"ok": True, "seq": entry["seq"]}


@router.post("/seal")
async def internal_seal(request: Request):
    verify_gateway_request(request)
    body = await request.json() if (await request.body()) else {}
    reason = body.get("reason", "gateway_lock")
    seal_vault(reason)
    candyWrapper.record_audit_event({
        "action": "vault_sealed",
        "actor": "gateway",
        "target": "vault",
        "reason": reason,
    })
    return {"ok": True, "vault_sealed": True}


@router.post("/unseal")
async def internal_unseal(request: Request):
    verify_gateway_request(request)
    unseal_vault()
    candyWrapper.record_audit_event({
        "action": "vault_unsealed",
        "actor": "gateway",
        "target": "vault",
    })
    return {"ok": True, "vault_sealed": False}


@router.post("/face-check")
async def internal_face_check(request: Request):
    verify_gateway_request(request)
    body = await request.json()
    frames = body.get("frames", [])
    nonce = body.get("nonce", "")
    device_id = body.get("device_id", "")
    officer_id = body.get("officer_id", "")
    res = candyWrapper.check_face(frames, nonce, device_id, officer_id)
    return res


# ---------- Client functions for the app ----------

def gateway_status() -> Dict[str, Any]:
    url = f"{GATEWAY_URL}/status"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=3) as resp:
        return json.loads(resp.read().decode("utf-8"))


def is_locked() -> bool:
    """Return True if the gateway reports LOCKED/TAGOUT or is unreachable (fail closed)."""
    try:
        st = gateway_status()
        state = str(st.get("state", "")).upper()
        return state in ("LOCKED", "TAGOUT")
    except Exception:
        return True


def lock(reason: str = "manual") -> Dict[str, Any]:
    token = get_gateway_token()
    url = f"{GATEWAY_URL}/admin/lock"
    data = json.dumps({"reason": reason}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "X-Gateway-Token": token},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def list_users() -> List[Dict[str, Any]]:
    token = get_gateway_token()
    url = f"{GATEWAY_URL}/admin/users"
    req = urllib.request.Request(
        url,
        headers={"X-Gateway-Token": token},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def list_devices() -> List[Dict[str, Any]]:
    token = get_gateway_token()
    url = f"{GATEWAY_URL}/admin/devices"
    req = urllib.request.Request(
        url,
        headers={"X-Gateway-Token": token},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def wait_until_ready(timeout: float = 10.0) -> bool:
    start = time.time()
    url = f"{GATEWAY_URL}/health"
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.1)
    raise TimeoutError(f"Gateway at {GATEWAY_URL} not ready within {timeout}s")


def watch(callback: Callable[[Dict[str, Any]], None]) -> threading.Thread:
    """Poll gateway status in background thread and notify callback of state changes."""
    def _worker():
        last_state = None
        while True:
            try:
                st = gateway_status()
                curr = st.get("state")
                if curr != last_state:
                    last_state = curr
                    callback({"event": "state_change", "state": curr, "raw": st})
            except Exception:
                pass
            time.sleep(1)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return t
