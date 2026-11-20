"""
candyWrapper.py - Mid backend: OCR, face scanning, SQLite, encrypted file storage, audit hash chain, archive.
Fails closed on any security or integrity issue.
"""

import base64
import contextlib
import hashlib
import json
import os
import pathlib
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

import cv2
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants
RETENTION_DAYS_FAILED = 30
SECONDS_PER_DAY = 86400
CASCADE_PATH = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
face_cascade = cv2.CascadeClassifier(CASCADE_PATH)

# In-memory audit tracking
_last_audit_hash: str = "0" * 64


# =====================================================================
# Database Initialization & Helpers
# =====================================================================

def get_data_dir() -> pathlib.Path:
    p = pathlib.Path(os.environ.get("LOT_DATA_DIR", "./lot-data")).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_db_path() -> str:
    default_path = str(get_data_dir() / "vault.db")
    return os.environ.get("LOT_DB_PATH", default_path)


@contextlib.contextmanager
def get_db():
    conn = sqlite3.connect(get_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Initialize SQLite database tables as specified."""
    path = db_path or get_db_path()
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

    # Load last audit hash
    global _last_audit_hash
    cur = conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1")
    row = cur.fetchone()
    if row:
        _last_audit_hash = row[0]
    else:
        _last_audit_hash = "0" * 64

    conn.close()
    return None


# =====================================================================
# Encrypted File Storage (AES-GCM 256)
# =====================================================================

def get_storage_dir() -> pathlib.Path:
    p = pathlib.Path(os.environ.get("LOT_STORAGE_DIR", str(get_data_dir() / "vault_storage"))).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_vault_key() -> bytes:
    """Retrieve or generate persistent 32-byte AES key for at-rest encryption."""
    if "LOT_VAULT_KEY" in os.environ and os.environ["LOT_VAULT_KEY"].strip():
        raw = os.environ["LOT_VAULT_KEY"].strip()
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return hashlib.sha256(raw.encode("utf-8")).digest()

    key_path = get_data_dir() / "vault.key"
    if key_path.exists():
        key = key_path.read_bytes()
        if len(key) == 32:
            return key

    key = AESGCM.generate_key(bit_length=256)
    key_path.write_bytes(key)
    return key


def store_file(content_bytes: bytes) -> str:
    """
    Encrypt file content at rest (AES-GCM 256) and store content-addressed by sha256.
    Returns sha256 hex string.
    """
    file_sha256 = hashlib.sha256(content_bytes).hexdigest()
    storage_dir = get_storage_dir()
    target_path = storage_dir / f"{file_sha256}.enc"

    aes = AESGCM(get_vault_key())
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, content_bytes, file_sha256.encode("utf-8"))
    tmp_path = target_path.with_suffix(f".tmp.{os.urandom(4).hex()}")
    tmp_path.write_bytes(nonce + ciphertext)
    tmp_path.replace(target_path)

    return file_sha256


def retrieve_file(file_sha256: str) -> bytes:
    """
    Retrieve and decrypt stored file content. Verifies integrity.
    """
    storage_dir = get_storage_dir()
    target_path = storage_dir / f"{file_sha256}.enc"
    if not target_path.exists():
        raise FileNotFoundError(f"File with sha256 {file_sha256} not found in storage")

    payload = target_path.read_bytes()
    if len(payload) < 28:
        raise ValueError("Corrupt encrypted payload")

    nonce = payload[:12]
    ciphertext = payload[12:]
    aes = AESGCM(get_vault_key())
    plaintext = aes.decrypt(nonce, ciphertext, file_sha256.encode("utf-8"))

    # Re-verify sha256
    computed = hashlib.sha256(plaintext).hexdigest()
    if computed != file_sha256:
        raise ValueError("Integrity failure: decrypted sha256 does not match")

    return plaintext


def verify_file(file_id: str) -> bool:
    """Recompute the hash of a stored file and verify against its database record."""
    with get_db() as conn:
        cur = conn.execute("SELECT sha256 FROM files WHERE id = ?", (file_id,))
        row = cur.fetchone()
        if not row:
            return False
        expected_sha256 = row["sha256"]

    try:
        data = retrieve_file(expected_sha256)
        computed = hashlib.sha256(data).hexdigest()
        return computed == expected_sha256
    except Exception:
        return False


# =====================================================================
# Cryptographic Audit Hash Chain
# =====================================================================

def record_audit_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Append an event to the cryptographic audit hash chain in SQLite."""
    global _last_audit_hash
    with get_db() as conn:
        cur = conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
        if row:
            seq = row["seq"] + 1
            prev_hash = row["hash"]
        else:
            seq = 1
            prev_hash = "0" * 64

        ts = int(time.time())
        actor = str(event.get("actor", event.get("officer_id", "system")))
        device = str(event.get("device", event.get("device_id", "internal")))
        action = str(event.get("action", event.get("event", "unknown")))
        target = str(event.get("target", event.get("endpoint", "none")))

        payload = f"{seq}:{ts}:{actor}:{device}:{action}:{target}:{prev_hash}"
        h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        _last_audit_hash = h

        conn.execute(
            """
            INSERT INTO audit (seq, ts, actor, device, action, target, prev_hash, hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (seq, ts, actor, device, action, target, prev_hash, h),
        )
        conn.commit()

        return {
            "seq": seq,
            "ts": ts,
            "actor": actor,
            "device": device,
            "action": action,
            "target": target,
            "prev_hash": prev_hash,
            "hash": h,
        }


def get_audit_events() -> List[Dict[str, Any]]:
    with get_db() as conn:
        cur = conn.execute("SELECT seq, ts, actor, device, action, target, prev_hash, hash FROM audit ORDER BY seq ASC")
        return [dict(row) for row in cur.fetchall()]


def audit_verify() -> Dict[str, Any]:
    """Verify entire audit hash chain integrity."""
    events = get_audit_events()
    expected_prev = "0" * 64
    for entry in events:
        if entry["prev_hash"] != expected_prev:
            return {"valid": False, "length": len(events), "first_broken_seq": entry["seq"]}
        payload = f"{entry['seq']}:{entry['ts']}:{entry['actor']}:{entry['device']}:{entry['action']}:{entry['target']}:{entry['prev_hash']}"
        h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if h != entry["hash"]:
            return {"valid": False, "length": len(events), "first_broken_seq": entry["seq"]}
        expected_prev = entry["hash"]
    return {"valid": True, "length": len(events), "first_broken_seq": None}


# =====================================================================
# OCR & Keyword Classification
# =====================================================================

def extract_ocr_text(file_bytes: bytes, filename: str) -> Tuple[str, str]:
    """
    OCR: Tesseract through pytesseract if installed and working.
    If missing or failed, return clear 'OCR unavailable' status instead of crashing.
    """
    ext = os.path.splitext(filename.lower())[1]
    if ext in (".txt", ".csv"):
        try:
            return file_bytes.decode("utf-8", errors="replace"), "ok"
        except Exception:
            return "", "text_decode_failed"

    try:
        import pytesseract
        from PIL import Image
        import io

        if ext in (".jpg", ".jpeg", ".png", ".bmp"):
            img = Image.open(io.BytesIO(file_bytes))
            text = pytesseract.image_to_string(img)
            return text, "ok"
        return "", "unsupported_ocr_type"
    except Exception:
        # Graceful degradation per spec
        return "", "OCR unavailable"


def classify_document(text: str, filename: str) -> Tuple[str, List[str], float, str]:
    """
    Rule-based document classification with confidence score.
    Returns: (category, tags, confidence, status).
    Low confidence (< 0.7) status becomes 'needs_review', else 'classified'.
    """
    content = (text + " " + filename).lower()

    rules = [
        ("FIR", ["fir", "complaint", "police", "ipc", "crpc", "cognizable", "ps"], 0.90, ["legal", "complaint"]),
        ("FORENSIC", ["forensic", "autopsy", "dna", "toxicology", "chemical", "post-mortem", "pathology"], 0.90, ["medical", "lab"]),
        ("EVIDENCE", ["evidence", "weapon", "fingerprint", "recovery", "seized", "ballistic", "knife", "gun"], 0.85, ["physical_evidence"]),
        ("WITNESS_STATEMENT", ["witness", "statement", "depose", "testimony", "section 161", "examined"], 0.85, ["statement"]),
        ("IDENTITY", ["aadhaar", "passport", "driving license", "voter id", "pan card", "identity"], 0.90, ["id"]),
    ]

    best_cat = "GENERAL"
    best_tags = ["unclassified"]
    best_conf = 0.40

    for cat, keywords, conf, tags in rules:
        hits = sum(1 for kw in keywords if kw in content)
        if hits > 0:
            adjusted_conf = min(0.99, conf + (hits - 1) * 0.03)
            if adjusted_conf > best_conf:
                best_conf = adjusted_conf
                best_cat = cat
                best_tags = tags + [kw for kw in keywords if kw in content][:3]

    status = "classified" if best_conf >= 0.70 else "needs_review"
    return best_cat, list(set(best_tags)), round(best_conf, 2), status


# =====================================================================
# Case Management & User-dependent Editing (RBAC)
# =====================================================================

def create_case(
    title: str,
    case_type: str,
    witness_protection: bool,
    complainant_name: str,
    created_by: str,
) -> Dict[str, Any]:
    case_id = f"case-{int(time.time())}-{os.urandom(3).hex()}"
    stored_complainant = "John Doe" if witness_protection else complainant_name
    now = int(time.time())

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO cases (id, title, case_type, status, witness_protection, complainant_name, created_by, created_at, case_hash)
            VALUES (?, ?, ?, 'open', ?, ?, ?, ?, NULL)
            """,
            (case_id, title, case_type, 1 if witness_protection else 0, stored_complainant, created_by, now),
        )
        conn.commit()

    record_audit_event({
        "actor": created_by,
        "action": "case_create",
        "target": case_id,
        "witness_protection": witness_protection,
    })

    return {
        "id": case_id,
        "title": title,
        "case_type": case_type,
        "status": "open",
        "witness_protection": witness_protection,
        "complainant_name": stored_complainant,
        "created_by": created_by,
        "created_at": now,
        "case_hash": None,
    }


def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def list_cases(status: Optional[str] = None) -> List[Dict[str, Any]]:
    with get_db() as conn:
        if status:
            cur = conn.execute("SELECT * FROM cases WHERE status = ? ORDER BY created_at DESC", (status,))
        else:
            cur = conn.execute("SELECT * FROM cases ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]


def add_file(
    case_id: str,
    filename: str,
    file_bytes: bytes,
    uploaded_by: str,
    device_id: str,
) -> Dict[str, Any]:
    case = get_case(case_id)
    if not case:
        raise ValueError(f"Case {case_id} not found")
    if case["status"] == "closed":
        raise ValueError("Cannot upload to a closed case")

    sha256 = store_file(file_bytes)
    text, ocr_status = extract_ocr_text(file_bytes, filename)
    category, tags, confidence, status = classify_document(text, filename)

    file_id = f"file-{int(time.time())}-{os.urandom(3).hex()}"
    now = int(time.time())
    tags_str = json.dumps(tags)

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO files (id, case_id, filename, size, sha256, category, tags, confidence, status, uploaded_by, device_id, uploaded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (file_id, case_id, filename, len(file_bytes), sha256, category, tags_str, confidence, status, uploaded_by, device_id, now),
        )
        conn.commit()

    record_audit_event({
        "actor": uploaded_by,
        "device": device_id,
        "action": "file_upload",
        "target": f"{case_id}/{file_id}",
        "sha256": sha256,
        "category": category,
    })

    return {
        "id": file_id,
        "case_id": case_id,
        "filename": filename,
        "size": len(file_bytes),
        "sha256": sha256,
        "category": category,
        "tags": tags,
        "confidence": confidence,
        "status": status,
        "uploaded_by": uploaded_by,
        "device_id": device_id,
        "uploaded_at": now,
    }


def list_files(case_id: Optional[str] = None) -> List[Dict[str, Any]]:
    with get_db() as conn:
        if case_id:
            cur = conn.execute("SELECT * FROM files WHERE case_id = ? ORDER BY uploaded_at ASC", (case_id,))
        else:
            cur = conn.execute("SELECT * FROM files ORDER BY uploaded_at ASC")
        rows = []
        for r in cur.fetchall():
            d = dict(r)
            try:
                d["tags"] = json.loads(d["tags"])
            except Exception:
                d["tags"] = []
            rows.append(d)
        return rows


def propose_amendment(
    case_id: str,
    changes: Dict[str, Any],
    officer_id: str,
    officer_tier: int,
) -> Dict[str, Any]:
    """
    User-dependent editing:
    - Tiers 1-2 propose amendments.
    - Tier 3 edits own cases directly or proposes amendments to others.
    Every edit is recorded as an amendment; changes apply only upon approval.
    """
    case = get_case(case_id)
    if not case:
        raise ValueError(f"Case {case_id} not found")
    if case["status"] == "closed":
        raise ValueError("Cannot amend a closed case")

    # Tier 3 editing own case directly
    if officer_tier == 3 and case["created_by"] == officer_id:
        return _apply_direct_edit(case_id, changes, officer_id)

    amendment_id = f"amd-{int(time.time())}-{os.urandom(3).hex()}"
    now = int(time.time())
    changes_json = json.dumps(changes)

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO amendments (id, case_id, proposed_by, proposed_at, changes, status, reviewed_by, reviewed_at)
            VALUES (?, ?, ?, ?, ?, 'pending', NULL, NULL)
            """,
            (amendment_id, case_id, officer_id, now, changes_json),
        )
        conn.commit()

    record_audit_event({
        "actor": officer_id,
        "action": "amendment_proposed",
        "target": f"{case_id}/{amendment_id}",
    })

    return {
        "id": amendment_id,
        "case_id": case_id,
        "proposed_by": officer_id,
        "proposed_at": now,
        "changes": changes,
        "status": "pending",
    }


def _apply_direct_edit(case_id: str, changes: Dict[str, Any], officer_id: str) -> Dict[str, Any]:
    now = int(time.time())
    with get_db() as conn:
        if "title" in changes:
            conn.execute("UPDATE cases SET title = ? WHERE id = ?", (changes["title"], case_id))
        if "case_type" in changes:
            conn.execute("UPDATE cases SET case_type = ? WHERE id = ?", (changes["case_type"], case_id))
        conn.commit()

    record_audit_event({
        "actor": officer_id,
        "action": "case_direct_edit",
        "target": case_id,
        "changes": changes,
    })

    return {
        "id": f"edit-{now}",
        "case_id": case_id,
        "proposed_by": officer_id,
        "proposed_at": now,
        "changes": changes,
        "status": "approved",
    }


def review_amendment(
    amendment_id: str,
    decision: str,  # "approved" or "rejected"
    officer_id: str,
    officer_tier: int,
) -> Dict[str, Any]:
    """Tiers 4-5 approve or reject amendments."""
    if officer_tier < 4:
        raise PermissionError("Only tier 4 and above can approve or reject amendments")
    if decision not in ("approved", "rejected"):
        raise ValueError("Decision must be 'approved' or 'rejected'")

    with get_db() as conn:
        cur = conn.execute("SELECT * FROM amendments WHERE id = ?", (amendment_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"Amendment {amendment_id} not found")
        if row["status"] != "pending":
            raise ValueError(f"Amendment already reviewed: {row['status']}")

        case_id = row["case_id"]
        changes = json.loads(row["changes"])
        now = int(time.time())

        if decision == "approved":
            if "title" in changes:
                conn.execute("UPDATE cases SET title = ? WHERE id = ?", (changes["title"], case_id))
            if "case_type" in changes:
                conn.execute("UPDATE cases SET case_type = ? WHERE id = ?", (changes["case_type"], case_id))

        conn.execute(
            """
            UPDATE amendments
            SET status = ?, reviewed_by = ?, reviewed_at = ?
            WHERE id = ?
            """,
            (decision, officer_id, now, amendment_id),
        )
        conn.commit()

    record_audit_event({
        "actor": officer_id,
        "action": f"amendment_{decision}",
        "target": f"{case_id}/{amendment_id}",
    })

    return {
        "id": amendment_id,
        "case_id": case_id,
        "status": decision,
        "reviewed_by": officer_id,
        "reviewed_at": now,
    }


def list_amendments(case_id: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
    with get_db() as conn:
        query = "SELECT * FROM amendments WHERE 1=1"
        params = []
        if case_id:
            query += " AND case_id = ?"
            params.append(case_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY proposed_at ASC"

        cur = conn.execute(query, tuple(params))
        res = []
        for r in cur.fetchall():
            d = dict(r)
            try:
                d["changes"] = json.loads(d["changes"])
            except Exception:
                d["changes"] = {}
            res.append(d)
        return res


# =====================================================================
# Archive: Close Case & Archive Lookup
# =====================================================================

def close_case(case_id: str, officer_id: str, officer_tier: int = 4) -> Dict[str, Any]:
    """
    Computes case_hash over sorted file hashes and marks case closed.
    """
    if officer_tier < 3:
        raise PermissionError("Only tier 3 and above can close a case")

    case = get_case(case_id)
    if not case:
        raise ValueError(f"Case {case_id} not found")
    if case["status"] == "closed":
        return case

    files = list_files(case_id)
    sorted_hashes = sorted(f["sha256"] for f in files)
    hasher = hashlib.sha256()
    for h in sorted_hashes:
        hasher.update(h.encode("utf-8"))
    case_hash = hasher.hexdigest()

    with get_db() as conn:
        conn.execute(
            "UPDATE cases SET status = 'closed', case_hash = ? WHERE id = ?",
            (case_hash, case_id),
        )
        conn.commit()

    record_audit_event({
        "actor": officer_id,
        "action": "case_close",
        "target": case_id,
        "case_hash": case_hash,
        "files_count": len(files),
    })

    return {
        "id": case_id,
        "status": "closed",
        "case_hash": case_hash,
        "files_count": len(files),
    }


def archive_lookup(sha256_hex: str) -> Dict[str, Any]:
    """
    Proves a file belongs to a closed case.
    """
    with get_db() as conn:
        cur = conn.execute(
            """
            SELECT c.id as case_id, c.title as case_title, c.case_hash, f.id as file_id, f.filename
            FROM files f
            JOIN cases c ON f.case_id = c.id
            WHERE f.sha256 = ? AND c.status = 'closed'
            """,
            (sha256_hex,),
        )
        row = cur.fetchone()
        if row:
            return {
                "proved": True,
                "case_id": row["case_id"],
                "case_title": row["case_title"],
                "case_hash": row["case_hash"],
                "file_id": row["file_id"],
                "filename": row["filename"],
            }
        return {"proved": False}


# =====================================================================
# Face Presence Check
# =====================================================================

def is_frame_blocked(frame: np.ndarray) -> bool:
    """
    Blocked = a near-black (mean < 10) or near-uniform (std < 5) frame.
    """
    if frame is None or frame.size == 0:
        return True
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) if len(frame.shape) == 3 else frame
    mean_val = np.mean(gray)
    std_val = np.std(gray)
    return bool(mean_val < 10.0 or std_val < 5.0)


def detect_faces_in_frame(frame: np.ndarray) -> List[Tuple[int, int, int, int]]:
    """
    Detect frontal faces where face height is at least 15% of frame height.
    """
    if frame is None or frame.size == 0:
        return []
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) if len(frame.shape) == 3 else frame
    frame_h, _ = gray.shape[:2]
    min_face_h = int(frame_h * 0.15)

    faces = face_cascade.detectMultiScale(
        gray,
        scaleFactor=1.1,
        minNeighbors=4,
        minSize=(min_face_h, min_face_h),
    )
    valid_faces = []
    for (x, y, w, h) in faces:
        if h >= min_face_h:
            valid_faces.append((x, y, w, h))
    return valid_faces


def check_face(
    frames: List[str],  # list of base64 JPEG strings (max 8)
    nonce: str,
    device_id: str,
    officer_id: str = "",
) -> Dict[str, Any]:
    """
    candyWrapper.check_face(frames, nonce, device_id, officer_id)
    Returns: {ok, reason, face_count, frames_with_face, capture_id}
    """
    if not frames:
        return {"ok": False, "reason": "no_face", "face_count": 0, "frames_with_face": 0, "capture_id": ""}

    blocked_frames = 0
    frames_with_face = 0
    total_faces_seen = 0
    best_frame_data: Optional[bytes] = None
    best_face_area = 0

    decoded_frames: List[Tuple[np.ndarray, bytes]] = []

    for b64 in frames[:8]:
        try:
            raw_bytes = base64.b64decode(b64)
            arr = np.frombuffer(raw_bytes, dtype=np.uint8)
            img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if img is not None:
                decoded_frames.append((img, raw_bytes))
        except Exception:
            continue

    if not decoded_frames:
        return {"ok": False, "reason": "no_face", "face_count": 0, "frames_with_face": 0, "capture_id": ""}

    for img, raw_bytes in decoded_frames:
        if is_frame_blocked(img):
            blocked_frames += 1
            continue

        faces = detect_faces_in_frame(img)
        if len(faces) > 0:
            frames_with_face += 1
            total_faces_seen = max(total_faces_seen, len(faces))
            # Pick largest face
            area = max(w * h for (x, y, w, h) in faces)
            if area > best_face_area:
                best_face_area = area
                best_frame_data = raw_bytes

    if blocked_frames == len(decoded_frames):
        return {"ok": False, "reason": "blocked", "face_count": 0, "frames_with_face": 0, "capture_id": ""}

    # Required: face in at least 3 frames
    ok = frames_with_face >= 3
    reason = "ok" if ok else ("try_again" if frames_with_face > 0 else "no_face")

    capture_id = f"cap-{int(time.time())}-{os.urandom(4).hex()}"
    now = int(time.time())
    retention_until = now + (RETENTION_DAYS_FAILED * SECONDS_PER_DAY)

    # Store best frame encrypted
    img_bytes = best_frame_data or (decoded_frames[0][1] if decoded_frames else b"")
    img_sha256 = hashlib.sha256(img_bytes).hexdigest() if img_bytes else ""
    nonce_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()

    if img_bytes:
        store_file(img_bytes)

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO captures (capture_id, ts, device_id, officer_id, nonce_hash, verdict, image_sha256, retention_until, hold)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (capture_id, now, device_id, officer_id, nonce_hash, "ok" if ok else reason, img_sha256, retention_until),
        )
        conn.commit()

    # The audit entry holds capture_id and image_sha256 only, never the image
    record_audit_event({
        "actor": officer_id or "anonymous",
        "device": device_id,
        "action": "face_check",
        "target": capture_id,
        "verdict": "ok" if ok else reason,
        "image_sha256": img_sha256,
        "frames_with_face": frames_with_face,
        "face_count": total_faces_seen,
    })

    return {
        "ok": ok,
        "reason": reason,
        "face_count": total_faces_seen,
        "frames_with_face": frames_with_face,
        "capture_id": capture_id,
    }


def get_capture(capture_id: str, requester: str, requester_tier: int, reason: str) -> Dict[str, Any]:
    """Retrieve capture metadata and image bytes. Restricted to tier >= 4."""
    if requester_tier < 4:
        raise PermissionError("Only tier 4 and above can view face captures")

    with get_db() as conn:
        cur = conn.execute("SELECT * FROM captures WHERE capture_id = ?", (capture_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"Capture {capture_id} not found")

    record_audit_event({
        "actor": requester,
        "action": "view_capture",
        "target": capture_id,
        "reason": reason,
    })

    img_bytes = retrieve_file(row["image_sha256"])
    return {
        "capture_id": capture_id,
        "ts": row["ts"],
        "device_id": row["device_id"],
        "officer_id": row["officer_id"],
        "verdict": row["verdict"],
        "image_sha256": row["image_sha256"],
        "image_bytes": img_bytes,
    }


def purge_expired_captures() -> int:
    """Delete expired captures (> 30 days) that do not have a hold."""
    now = int(time.time())
    with get_db() as conn:
        cur = conn.execute(
            "SELECT capture_id, image_sha256 FROM captures WHERE retention_until < ? AND hold = 0",
            (now,),
        )
        expired = cur.fetchall()
        for r in expired:
            conn.execute("DELETE FROM captures WHERE capture_id = ?", (r["capture_id"],))
        conn.commit()
    return len(expired)
