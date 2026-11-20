# LockOut-TagOut (LOTO) Zero-Trust Gateway & Case Vault

> **Specification Authority:** [docs/SPEC.md](file:///docs/SPEC.md) is the single source of truth for all requirements, architecture, and protocols.

A zero-trust security gateway and evidence vault for sensitive records. The system governs officer authentication, device attestation, session seeds, per-request shifting codes (ratchet), biometric presence verification, and automated/manual lockdown mechanisms.

---

## Architecture Overview (Three Levels)

The system is organized into three levels centered around `main.py` (`127.0.0.1:8000`):

1. **Level 1 (Deep Backend - Rust): `user_gateway` (`lot-gateway`, `lotoctl`)**
   - Listens on `127.0.0.1:8080` (the only origin accessed by the browser).
   - Handles login/logout, sessions, shifting codes (HKDF ratchet), device lockout, tagout, and token validation.
   - Forwards authenticated `/api/*` traffic to the app on `127.0.0.1:8000` and serves public static UI assets (`/` and `/ui/*`).
   - Mutual loopback trust via `X-Gateway-Token` (`LOT_DATA_DIR/gateway.token`).

2. **Level 2 (Mid Backend - Python Modules)**
   - `rustPolish.py`: Bridge between app and gateway (`/internal/audit`, `/internal/seal`, `/internal/unseal`, `/internal/face-check`). Read-only client helpers (no unlock/restore/enrol).
   - `candyWrapper.py`: OCR, face detection (OpenCV Haar cascade), SQLite persistence, encrypted file storage (AES-GCM), hash chain audit log, case archive verification.
   - `upstream.py`: Multipart file upload with magic-byte validation, officer identity & rank verification, witness protection masking.

3. **Level 3 (Frontend - Vanilla Web)**
   - `scripted.py`: Mounts static frontend assets and browser-facing `/api/*` endpoints.
   - Fully offline vanilla HTML, CSS, and ES modules (no frameworks, no bundlers, no external CDNs).
   - WebCrypto Ed25519 & HKDF running in-browser for request signing.

---

## State Machine & Lockout Protocols

- **Device-Level Lockout:** Three consecutive failed credential attempts on a single device (bad signature, bad passcode, or wrong config hash) lock that specific device until reset via `lotoctl device reset <device_id>`. This survives restarts and never alters system-wide state.
- **RESTRICTED State:** Triggered by 3 bad shifting codes in a single session. Demotes `/api/*` to read-only methods (`GET`, `HEAD`, `OPTIONS`) and terminates the offending session.
- **LOCKED State:** Triggered by a true replay of an accepted code, `lotoctl lock`, or tagout. Returns `503 Service Unavailable` on all routes except `GET /status`. Drops sessions and seals the app vault.
- **TAGOUT Protocol:** Triggered by an officer of rank tier 4+ via `POST /api/tagout` or `lotoctl tagout`. Terminates all sessions, seals the vault, and enters `TAGOUT` state (network inaccessible; server terminal only).
- **Dual-Control Restore:** Recovery from `LOCKED` or `TAGOUT` requires `lotoctl restore` with two distinct tier-4+ officer approvals and a short-lived restore key (2-minute window).

---

## Security Model & Ranks

- **Officer Ranks:**
  - Tier 1: Constable
  - Tier 2: Head Constable
  - Tier 3: Sub-Inspector
  - Tier 4: Inspector
  - Tier 5: Superintendent
- **Login Factors:**
  1. Device Key (Ed25519 signature + config hash attestation)
  2. Officer Passcode (Argon2id hash)
  3. Face Presence Check (Haar cascade frontal-face detection across captured frames)
- **Known Limitations:**
  - Face presence verifies camera presence only, not biological liveness or officer identity; a physical photo can pass.
  - Face captures are encrypted and retained for security audit for 30 days before automatic purge.

---

## Quick Start & Dev Tools

### Environment Configuration

| Variable | Default | Purpose |
|---|---|---|
| `LOT_BIND` | `127.0.0.1:8080` | Address and port the gateway listens on |
| `LOT_UPSTREAM` | `http://127.0.0.1:8000` | Target URL for the internal app service |
| `LOT_DATA_DIR` | `./lot-data` | Directory holding `store.json`, `lock-state.json`, and `gateway.token` |
| `LOT_REQUIRE_FACE` | `1` | Enforce facial presence verification at login (0 for offline testing) |
| `DEV_TOOLS` | `0` | Set `1` to enable dev-only reset/unlock actions in `dev/dashboard` |

### Dev Smoke-Test Dashboard
The smoke-test dashboard is located in `dev/dashboard/` and launched via `run_dashboard.ps1` or `run_dashboard.bat`. Its `/api/unlock` endpoint requires `DEV_TOOLS=1` to prevent accidental resets.

---

## Quick Start: Building & Running

### Prerequisites
- [Rust & Cargo](https://rustup.rs/) (1.80+ recommended)

### 1. Build and Test
```powershell
# Navigate to the Rust gateway
cd user_gateway

# Run all unit and integration test suites
cargo test

# Build debug or release binaries
cargo build
cargo build --release
```

### 2. Configure Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `LOT_BIND` | `127.0.0.1:8080` | Address and port the gateway listens on |
| `LOT_UPSTREAM` | `http://127.0.0.1:9000` | Target URL for the internal upstream service |
| `LOT_DATA_DIR` | `./lot-data` | Directory holding `store.json` and `lock-state.json` |

### 3. Start the Gateway
```powershell
cargo run --bin lot-gateway
```

---

## Administrative CLI: `lotoctl`

The `lotoctl` tool manages officers, devices, and manual locks:

```powershell
# 1. Register an officer and write their private device keyfile
cargo run --bin lotoctl -- user add alice --keyfile ./alice.keyfile.json

# 2. List officers and devices
cargo run --bin lotoctl -- user list
cargo run --bin lotoctl -- device list

# 3. Trigger immediate emergency manual lock
cargo run --bin lotoctl -- lock

# 4. Sign login request (client helper)
cargo run --bin lotoctl -- sign-login --keyfile ./alice.keyfile.json --nonce <NONCE_HEX>

# 5. Generate signed request headers
cargo run --bin lotoctl -- sign-request --keyfile ./alice.keyfile.json --nonce <NONCE_HEX> --session-id <SESSION_ID> --counter 1 --curl

# 6. Revoke an officer and all attached devices
cargo run --bin lotoctl -- user revoke alice
```

---

## Gateway Endpoints

| Method | Path | Auth / Gate | Description |
|---|---|---|---|
| `GET` | `/health` | Blocked when `LOCKED` | Basic health check (`{"status":"ok"}`) |
| `GET` | `/status` | Always accessible | Returns coarse lock state, anomaly count, and timestamp |
| `GET` | `/ws` | Blocked when `LOCKED` | Real-time WebSocket event feed (max 32 clients) |
| `POST` | `/auth/challenge` | Blocked when `LOCKED` | Issue cryptographic challenge nonce |
| `POST` | `/auth/login` | Blocked when `LOCKED` | Authenticate Ed25519 signature and create session |
| `ANY` | `/api/*` | Evaluated by Gate | Forwarded upstream proxy (read-only when `RESTRICTED`) |
| `POST` | `/restore` | Allowed when `LOCKED` | System recovery endpoint |

---

## Documentation Links

- Gateway Specification & Details: [user_gateway/README.md](file:///user_gateway/README.md)
- Upstream Service Contract: [user_gateway/docs/CONTRACT.md](file:///user_gateway/docs/CONTRACT.md)
