# LockOut-TagOut (LOTO) Zero-Trust Evidence Gateway & Case Vault

> **Specification Authority:** [docs/SPEC.md](file:///docs/SPEC.md) is the single source of truth for all requirements, architecture, and security protocols.

A zero-trust government records vault and security gateway. The system enforces cryptographic device attestation, Argon2id passcodes, biometric camera presence verification, per-request shifting codes (HKDF-SHA256 ratchets), role-based case management, tamper-evident hash chaining, and multi-party emergency lockout/tagout protocols.

---

## 1. Architecture Diagram

```
+-----------------------------------------------------------------------------------------+
|                                      WEB BROWSER                                        |
|  - Offline Vanilla JS (ES Modules), System Fonts, Inline SVG, WebCrypto (Ed25519 & HKDF)|
|  - Live Biometric Presence Scanner (Webcam)                                             |
|  - Shifting Code Ratchet (X-Session-Id, X-Counter, X-Code)                              |
+--------------------------------------------+--------------------------------------------+
                                             | HTTP / WebSocket
                                             v 127.0.0.1:8080 (Single Browser Origin)
+-----------------------------------------------------------------------------------------+
|                    LEVEL 1: DEEP BACKEND — RUST GATEWAY (lot-gateway)                   |
|  - Zero-Trust Ingress & Gate Middleware (Fail Closed)                                   |
|  - Cryptographic Handshake (/auth/challenge, /auth/face, /auth/login)                   |
|  - Ratchet Verification (HKDF-SHA256, Forward Window 3, 16-Pair Ring Buffer Replay Gate) |
|  - State Persistence (lock-state.json, store.json, gateway.token)                       |
|  - Admin CLI: lotoctl (User/Device Enrollment, Emergency Lock, Tagout, Dual Restore)    |
+--------------------------------------------+--------------------------------------------+
                                             | Forwarded HTTP + X-Gateway-Token
                                             v 127.0.0.1:8000
+-----------------------------------------------------------------------------------------+
|                  LEVEL 2: MID BACKEND — FASTAPI & PYTHON WRAPPERS (main.py)              |
|                                                                                         |
|   +---------------------+   +--------------------+   +-------------------------------+  |
|   |   rustPolish.py     |   |    scripted.py     |   |          upstream.py          |  |
|   | Bridge & Gatekeeper |   | API & Asset Router |   | Upload Validator & Identity   |  |
|   | (/internal/*)       |   | (/api/*, /ui/*)    |   | (Magic Bytes, Witness Masking)|  |
|   +----------+----------+   +---------+----------+   +---------------+---------------+  |
|              |                        |                              |                  |
|              +------------------------+------------------------------+                  |
|                                       v                                                 |
|                     +------------------------------------+                              |
|                     |          candyWrapper.py           |                              |
|                     | - OpenCV Haar Face Presence Check  |                              |
|                     | - SQLite Database (cases, files)   |                              |
|                     | - AES-GCM 256 Encrypted Storage    |                              |
|                     | - SHA-256 Audit Hash Chain         |                              |
|                     +-----------------+------------------+                              |
|                                       v                                                 |
|                           +-----------------------+                                     |
|                           |   FILESYSTEM STORAGE  |                                     |
|                           |  - lot-data/vault.db  |                                     |
|                           |  - vault_storage/     |                                     |
|                           |  - captures/          |                                     |
|                           +-----------------------+                                     |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Threat Model

| Threat / Attack Vector | System Defense & Mitigation |
| :--- | :--- |
| **Stolen Device Keyfile** | Mitigated by **Three-Factor Authentication**: keyfile alone is useless without the officer's **Argon2id passcode** and **live biometric face presence** verified by the camera. |
| **Man-in-the-Middle & Replay Attack** | Mitigated by **Per-Request Shifting Codes**: every request derives a single-use code from HKDF-SHA256. Replaying any previously accepted code trips an instant transition to **`LOCKED`** system-wide. |
| **Tampered Evidence Files** | Mitigated by **Content-Addressed Encrypted Storage**: files are stored under their SHA-256 hash, encrypted with AES-256-GCM. Any byte change breaks decryption and fails `verify_file()`. |
| **Audit Ledger Manipulation** | Mitigated by **Cryptographic SHA-256 Hash Chaining**: each audit event binds to `H(prev_hash || timestamp || event_type || officer_id || details)`. `audit_verify()` detects any insertion, deletion, or modification. |
| **Rogue Officer Privilege Escalation** | Mitigated by **Rank Tiers 1–5**: Tiers 1–3 can only propose case amendments; approvals require independent Tier 4+ (Inspector/Superintendent) review. Case closing seals the root hash irreversibly. |
| **Brute-Force & Denial-of-Service** | Mitigated by **Device-Level Lockout**: 3 failed credential attempts lock *only that device* in `store.json`. System state remains `NORMAL`, preventing an attacker from locking out all officers. |
| **Host System Compromise Recovery** | Mitigated by **Dual-Control Restoration**: unlocking a locked or tagged-out vault requires two distinct Tier 4+ officers and an ephemeral 2-minute restore key executed directly on the host console. |

---

## 3. Getting Started in 3 Commands

From a clean repository checkout in PowerShell:

```powershell
# 1. Boot up the entire system (Gateway, Backend, and UI)
.\dev.ps1
```
*(Or double-click `bootup.bat` in File Explorer).*

That's it! The automated script builds the gateway, starts the services, enrolls demo officers, and launches the UI in your default browser at [http://127.0.0.1:8080/](http://127.0.0.1:8080/).

---

## 4. `lotoctl` Cheat Sheet

The administrative tool is located at `user_gateway\target\debug\lotoctl.exe`.

```powershell
$LOTOCTL = ".\user_gateway\target\debug\lotoctl.exe"

# --- User Management ---
# Add an officer with passcode and rank tier (1-5)
& $LOTOCTL user add <officer_id> --keyfile <path> --passcode "<passcode>" --rank-tier <1-5>

# List all enrolled officers and status
& $LOTOCTL user list

# Revoke an officer and all their associated devices
& $LOTOCTL user revoke <officer_id>

# --- Device Management ---
# List all devices and lockout states
& $LOTOCTL device list

# Reset a device locked out by 3 failed attempts
& $LOTOCTL device reset <device_id>

# --- Security & Lockout ---
# Trigger immediate emergency system LOCKOUT
& $LOTOCTL lock

# Trigger formal investigative TAGOUT lockdown
& $LOTOCTL tagout [--officer <initiator_id>]

# --- Dual-Officer Recovery ---
# 1. Generate an ephemeral 2-minute restore key
& $LOTOCTL generate-restore-key --out .\lot-data\restore.key.json

# 2. Execute dual-officer restoration (requires two distinct Tier 4+ keyfiles)
& $LOTOCTL restore --restore-key .\lot-data\restore.key.json --officer-keyfile <kf1> --officer-keyfile <kf2>

# --- Client Cryptographic Helpers ---
# Build POST /auth/login request body
& $LOTOCTL sign-login --keyfile <path> --nonce <hex> [--passcode "<passcode>"]

# Generate shifting code headers for Counter N
& $LOTOCTL sign-request --keyfile <path> --nonce <hex> --session-id <id> --counter <n> [--curl]
```

---

## 5. How to Trigger Every Security State

### 1. `NORMAL` State
- **Condition:** Default operational state upon first-run initialization.
- **Access:** Full proxy access to `/api/*` conforming to officer rank tiers.

### 2. `DEVICE LOCKOUT`
- **Trigger:** Enter 3 wrong passcodes or invalid signatures on a single device.
- **Effect:** That specific device is marked `locked_out: true` in `store.json`. All future login attempts on that device are blocked with generic 401. System-wide state remains `NORMAL`.
- **Reset:** Run `& $LOTOCTL device reset <device_id>`.

### 3. `RESTRICTED` State
- **Trigger:** Send 3 invalid shifting codes within a single active session.
- **Effect:** Offending session is revoked; `/api/*` proxy demotes to read-only methods (`GET`, `HEAD`, `OPTIONS`). Mutating methods return `503`.
- **Reset:** Log in with a fresh authenticated session.

### 4. `LOCKED` State
- **Trigger:** Replay an already-accepted counter/code pair, or execute `& $LOTOCTL lock`.
- **Effect:** System immediately drops all active sessions, deletes nonces, and writes `LOCKED` to `lock-state.json`. All endpoints return `503 Service Unavailable` except `GET /status`. Upstream vault is sealed.
- **Restoration:** Execute dual-officer restore via `lotoctl restore`.

### 5. `TAGOUT` State
- **Trigger:** Run `& $LOTOCTL tagout` on the host, or click "Engage Tagout" from an authenticated Tier 4+ session in the UI.
- **Effect:** Vault is sealed for forensic investigation. Records the initiator and timestamp. Network is severed (503).
- **Restoration:** Execute dual-officer restore via `lotoctl restore` with two Tier 4+ officers.

---

## 6. Exact Wrapper Functions

### `rustPolish.py` (Gateway Bridge & Vault Sealing)
- `gateway_status() -> Dict[str, Any]`: Queries gateway `/status`.
- `is_locked() -> bool`: Returns `True` if gateway is in `LOCKED`, `TAGOUT`, or unreachable.
- `lock(reason: str) -> None`: Calls gateway `/admin/lock`.
- `list_users() -> List[Dict[str, Any]]`: Calls gateway `/admin/users`.
- `list_devices() -> List[Dict[str, Any]]`: Calls gateway `/admin/devices`.
- `wait_until_ready(timeout: float) -> bool`: Blocks until gateway is responsive.
- `watch(callback: Callable) -> None`: Subscribes to gateway `/ws` broadcast events.
- `seal_vault(reason: str) -> None`: Idempotently seals the mid-backend vault.
- `unseal_vault() -> None`: Idempotently unseals the mid-backend vault.
- `is_vault_sealed() -> bool`: Returns current vault seal flag.

### `scripted.py` (Asset Delivery & Public API)
- Serves `/` and `/ui/*` from `frontend/` directory.
- Mounts and protects `/api/*` endpoints with vault gating and identity extraction.

### `candyWrapper.py` (Storage, Crypto, Audit, OCR & Biometrics)
- `init_db(db_path) -> Connection`: Creates SQLite tables (`cases`, `files`, `amendments`, `captures`, `audit`).
- `create_case(title, case_type, witness_protection, complainant_name, created_by) -> Dict`: Creates new case record.
- `list_cases(status) -> List[Dict]`: Lists cases.
- `get_case(case_id) -> Optional[Dict]`: Retrieves case details.
- `close_case(case_id, officer_id, officer_tier) -> Dict`: Verifies tier $\ge 3$ or creator, computes case SHA-256 Merkle root, seals case.
- `store_file(content: bytes) -> str`: AES-256-GCM encryption in `vault_storage/` keyed by SHA-256.
- `get_file(sha256: str) -> bytes`: Decrypts and retrieves stored file.
- `verify_file(file_id: str) -> bool`: Validates AES-GCM decryption and SHA-256 integrity.
- `list_files(case_id) -> List[Dict]`: Lists deposited evidence files.
- `log_audit(event_type, officer_id, details) -> Dict`: Appends sequential event to SHA-256 hash chain.
- `get_audit_events() -> List[Dict]`: Retrieves complete audit log.
- `audit_verify() -> Dict`: Cryptographically verifies sequential hash chain integrity.
- `propose_amendment(case_id, changes, officer_id, officer_tier) -> Dict`: Submits proposed change for review.
- `list_amendments(case_id, status) -> List[Dict]`: Lists amendments.
- `review_amendment(amendment_id, decision, officer_id, officer_tier) -> Dict`: Verifies tier $\ge 4$, applies change if approved.
- `archive_lookup(sha256: str) -> Dict`: Zero-knowledge proof-of-existence check.
- `check_face(frames, nonce, device_id, officer_id) -> Dict`: Multi-frame Haar cascade face verification.
- `detect_faces_in_frame(frame) -> List[Tuple]`: Detects frontal faces where height $\ge 10\%$ of frame.
- `is_frame_blocked(frame) -> bool`: Detects dark (mean < 10) or uniform (std < 5) frames.

### `upstream.py` (Upload Validation & Identity)
- `validate_upload(filename, content) -> Tuple[str, str]`: Enforces $\le 10$ MB, extension allow-list, magic byte headers.
- `handle_upload(case_id, filename, content, officer_id, device_id) -> Dict`: Integrates validation, OCR, AES storage, and auditing.
- `verify_uploader_match(header_officer, declared_officer) -> None`: Rejects mismatched upload identities.
- `mask_witness_identity(case_id, complainant_name) -> str`: Masks name if witness protection is enabled.

---

## 7. Endpoint Reference

### User Gateway (`127.0.0.1:8080`)
| Method | Path | Authentication / Gate | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Gate (Blocked when LOCKED) | Gateway health check |
| `GET` | `/status` | Always Open | Current lock state, anomalies, since |
| `GET` | `/ws` | Gate (Blocked when LOCKED) | Real-time JSON event stream |
| `POST` | `/auth/challenge` | Gate | Issue 90s single-use challenge nonce |
| `POST` | `/auth/face` | Gate | Biometric face presence verification |
| `POST` | `/auth/login` | Gate | Ed25519 signature + passcode verification |
| `GET` | `/admin/users` | Token (X-Gateway-Token) | List officers (internal app only) |
| `GET` | `/admin/devices` | Token (X-Gateway-Token) | List devices (internal app only) |
| `POST` | `/admin/lock` | Token (X-Gateway-Token) | Administrative trigger for LOCKED state |
| `POST` | `/api/tagout` | Shifting Code (Tier $\ge 4$) | Engage Tagout investigation lockdown |
| `ANY` | `/api/*` | Shifting Code (X-Session-Id, etc.) | Proxied to Mid-Backend App (8000) |
| `GET` | `/` | Open | Serves Case Vault web application |
| `GET` | `/ui/*` | Open | Serves static assets (`styles.css`, `app.js`, etc.) |

### Upstream Internal Endpoints (`127.0.0.1:8000/internal/*`)
- `POST /internal/audit`: Ingest gateway audit events.
- `POST /internal/seal`: Seal vault on gateway lock.
- `POST /internal/unseal`: Unseal vault on gateway recovery.
- `POST /internal/face-check`: Perform OpenCV biometric verification on camera frames.

### Browser-Facing API Routes (`127.0.0.1:8080/api/*`)
- `GET /api/cases`, `POST /api/cases`: Case ledger management.
- `GET /api/cases/{id}`, `POST /api/cases/{id}/close`: Case detail and sealing.
- `POST /api/cases/{id}/upload`: Evidence deposition with OCR.
- `GET /api/cases/{id}/files`: List evidence files.
- `GET /api/files/{id}/verify`: Verify AES-GCM file integrity.
- `GET /api/amendments`, `POST /api/cases/{id}/amendments`: Propose case amendments.
- `POST /api/amendments/{id}/review`: Approve/reject amendments (Tier 4+).
- `GET /api/archive/lookup?sha256=...`: Zero-knowledge proof of existence.
- `GET /api/audit`, `POST /api/audit/verify`: Audit ledger and hash chain verification.

---

## 8. Environment Variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `LOT_BIND` | `127.0.0.1:8080` | Address and port the gateway listens on |
| `LOT_UPSTREAM` | `http://127.0.0.1:8000` | Target URL for the internal FastAPI service |
| `LOT_GATEWAY_URL`| `http://127.0.0.1:8080` | Gateway address used by Python helpers |
| `LOT_DATA_DIR` | `./lot-data` | Directory storing `store.json`, `lock-state.json`, and `gateway.token` |
| `LOT_APP_HOST` | `127.0.0.1` | Bind address for `main.py` |
| `LOT_APP_PORT` | `8000` | Port for `main.py` |
| `LOT_REQUIRE_FACE`| `1` | Enforce camera biometric check (set `0` for headless testing) |
| `DEV_TOOLS` | `0` | Enable dev tools in `dev/dashboard` (set `1` to allow dev resets) |

---

## 9. Known Limits

- **Single-Host Loopback Architecture:** Designed for local/on-premise deployment on a single host. Serverless/cloud edge hosts (e.g., Vercel) are not supported because the gateway requires persistent local lock files, WebSockets, in-memory shifting code chains, and direct hardware camera feeds.
- **Biometric Presence vs. Identity:** The camera check confirms the physical presence of a human face in the camera frame (using OpenCV Haar cascades). It does not perform facial recognition against an enrolled photo or 3D liveness detection.
- **Shifting Code Forward Window:** The forward ratchet window is capped at 3 counters to tolerate network drops. Skips exceeding 3 counters are rejected as bad codes.
- **Encrypted Capture Retention:** Biometric capture frames associated with failed handshakes are encrypted and retained for 30 days for forensic audit before automatic purge.
