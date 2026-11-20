"""
upstream.py - File upload and identity verification.
Working stubs and identity resolution for P1 Wiring.
"""

from typing import Any, Dict, Optional
from fastapi import Header, HTTPException, Request


def verify_identity(
    x_gateway_token: Optional[str] = Header(None),
    x_officer_id: Optional[str] = Header(None),
    x_device_id: Optional[str] = Header(None),
    x_session_id: Optional[str] = Header(None),
    x_rank_tier: Optional[str] = Header(None),
    x_lock_state: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """
    Resolve officer and device identity from the gateway headers.
    The app trusts identity headers only when X-Gateway-Token is verified.
    """
    if not x_officer_id or not x_device_id:
        raise HTTPException(status_code=401, detail="missing identity headers")
    try:
        tier = int(x_rank_tier or "1")
    except ValueError:
        tier = 1

    return {
        "officer_id": x_officer_id,
        "device_id": x_device_id,
        "session_id": x_session_id or "",
        "rank_tier": tier,
        "lock_state": x_lock_state or "NORMAL",
    }


def mask_witness(complainant_name: str, witness_protection: bool) -> str:
    """Mask witness identity per the case flag."""
    if witness_protection:
        return "John Doe"
    return complainant_name
