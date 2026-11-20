"""
candyWrapper.py - Mid backend: OCR, face scanning, SQLite, encrypted file storage, audit hash chain, archive.
Working stubs and audit chain for P1 Wiring.
"""

import hashlib
import json
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

_audit_chain: List[Dict[str, Any]] = []
_last_hash: str = "0" * 64


def record_audit_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Append an event to the cryptographic audit hash chain."""
    global _last_hash
    seq = len(_audit_chain) + 1
    ts = int(time.time())
    actor = event.get("actor", "system")
    device = event.get("device", "internal")
    action = event.get("action", event.get("event", "unknown"))
    target = event.get("target", event.get("endpoint", "none"))
    prev_hash = _last_hash

    payload = f"{seq}:{ts}:{actor}:{device}:{action}:{target}:{prev_hash}"
    h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    _last_hash = h

    entry = {
        "seq": seq,
        "ts": ts,
        "actor": actor,
        "device": device,
        "action": action,
        "target": target,
        "prev_hash": prev_hash,
        "hash": h,
        "raw": event,
    }
    _audit_chain.append(entry)
    return entry


def get_audit_events() -> List[Dict[str, Any]]:
    return list(_audit_chain)


def audit_verify() -> Dict[str, Any]:
    expected_prev = "0" * 64
    for idx, entry in enumerate(_audit_chain):
        if entry["prev_hash"] != expected_prev:
            return {"valid": False, "length": len(_audit_chain), "first_broken_seq": entry["seq"]}
        payload = f"{entry['seq']}:{entry['ts']}:{entry['actor']}:{entry['device']}:{entry['action']}:{entry['target']}:{entry['prev_hash']}"
        h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if h != entry["hash"]:
            return {"valid": False, "length": len(_audit_chain), "first_broken_seq": entry["seq"]}
        expected_prev = entry["hash"]
    return {"valid": True, "length": len(_audit_chain), "first_broken_seq": None}


def check_face(frames: list, nonce: str, device_id: str, officer_id: str = "") -> Dict[str, Any]:
    """Stub face check for P1 wiring."""
    return {
        "ok": True,
        "reason": "presence_ok",
        "face_count": 1,
        "frames_with_face": len(frames),
        "capture_id": f"cap_{int(time.time())}",
    }


def init_db(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Initialize SQLite database tables as specified."""
    path = db_path or os.environ.get("LOT_DB_PATH", ":memory:")
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            title TEXT,
            case_type TEXT,
            status TEXT,
            witness_protection INTEGER,
            complainant_name TEXT,
            created_by TEXT,
            created_at INTEGER,
            case_hash TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            case_id TEXT,
            filename TEXT,
            size INTEGER,
            sha256 TEXT,
            category TEXT,
            tags TEXT,
            confidence REAL,
            status TEXT,
            uploaded_by TEXT,
            device_id TEXT,
            uploaded_at INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS amendments (
            id TEXT PRIMARY KEY,
            case_id TEXT,
            proposed_by TEXT,
            proposed_at INTEGER,
            changes TEXT,
            status TEXT,
            reviewed_by TEXT,
            reviewed_at INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS captures (
            capture_id TEXT PRIMARY KEY,
            ts INTEGER,
            device_id TEXT,
            officer_id TEXT,
            nonce_hash TEXT,
            verdict TEXT,
            image_sha256 TEXT,
            retention_until INTEGER,
            hold INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit (
            seq INTEGER PRIMARY KEY,
            ts INTEGER,
            actor TEXT,
            device TEXT,
            action TEXT,
            target TEXT,
            prev_hash TEXT,
            hash TEXT
        )
        """
    )
    conn.commit()
    return conn
