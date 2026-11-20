"""
upstream.py - File upload validation, identity verification, and witness protection masking.
Fails closed on any signature, format or token mismatch.
"""

import os
from typing import Any, Dict, Optional, Tuple
from fastapi import Header, HTTPException, Request, UploadFile

import candyWrapper
import rustPolish

# Constants
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB limit
ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".txt", ".csv", ".docx"}


def validate_file_bytes(filename: str, content: bytes) -> Tuple[bool, str]:
    """
    Validate size limit, extension allow-list, and magic bytes.
    """
    if len(content) == 0:
        return False, "File is empty"

    if len(content) > MAX_UPLOAD_SIZE:
        return False, f"File exceeds maximum allowed size ({MAX_UPLOAD_SIZE} bytes)"

    ext = os.path.splitext(filename.lower())[1]
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Extension {ext} is not allowed"

    # Magic byte check
    if ext == ".png":
        if not content.startswith(b"\x89PNG\r\n\x1a\n"):
            return False, "Invalid PNG signature"
    elif ext in (".jpg", ".jpeg"):
        if not content.startswith(b"\xff\xd8\xff"):
            return False, "Invalid JPEG signature"
    elif ext == ".pdf":
        if not content.startswith(b"%PDF"):
            return False, "Invalid PDF signature"
    elif ext == ".docx":
        if not content.startswith(b"PK\x03\x04"):
            return False, "Invalid DOCX signature"
    elif ext in (".txt", ".csv"):
        # Must not contain null bytes and must be decodable text
        if b"\x00" in content:
            return False, "Text file contains binary null bytes"
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            return False, "Text file is not valid UTF-8"

    return True, "valid"


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
    The app trusts identity headers only when X-Gateway-Token is valid.
    """
    if not rustPolish.check_gateway_token(x_gateway_token):
        raise HTTPException(status_code=401, detail="invalid or missing gateway token")

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


def verify_uploader_match(header_officer: str, declared_officer: str) -> None:
    """Reject any mismatch between the header officer and the uploader."""
    if header_officer.strip() != declared_officer.strip():
        raise HTTPException(status_code=403, detail="Officer identity mismatch")


def mask_witness(complainant_name: str, witness_protection: bool) -> str:
    """Mask witness identity per the case flag."""
    if witness_protection:
        return "John Doe"
    return complainant_name


def handle_upload(
    case_id: str,
    filename: str,
    content: bytes,
    officer_id: str,
    device_id: str,
) -> Dict[str, Any]:
    """
    Validate and process uploaded file, adding it to the case.
    Fails closed if sealed or locked.
    """
    if rustPolish.is_vault_sealed() or rustPolish.is_locked():
        raise HTTPException(status_code=503, detail="Vault is sealed or gateway locked")

    valid, reason = validate_file_bytes(filename, content)
    if not valid:
        raise HTTPException(status_code=400, detail=f"Upload rejected: {reason}")

    try:
        return candyWrapper.add_file(
            case_id=case_id,
            filename=filename,
            file_bytes=content,
            uploaded_by=officer_id,
            device_id=device_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
