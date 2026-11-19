# LockOut-TagOut (LOTO) Zero-Trust Gateway

A zero-trust security gateway and lockout system for legal case vaults. The gateway governs officer authentication, device attestation, session seeds, per-request shifting codes (ratchet), and automated/manual lockdown mechanisms.

---

## Architecture Overview

The system is split into two layers:
1. **`user_gateway` (`lot-gateway`)**: A high-performance Rust gateway that manages:
   - Officer & device registry and authentication handshakes (Ed25519 signatures).
   - Per-request shifting one-time verification codes derived via HKDF-SHA256 hash chains.
   - Genuine replay attack detection using a ring buffer of accepted request hashes.
   - Multi-stage lockout state machine (`NORMAL` -> `RESTRICTED` -> `LOCKED`).
   - Atomic disk persistence (`store.json` and `lock-state.json`).
   - Real-time event broadcasting over WebSocket (`/ws`).
   - Upstream sealing notification (`/internal/seal`).
2. **Upstream Service**: The internal backend service (FastAPI / Python) handling case files, OCR, AI pipelines, and persistent audit logging, accessible only through the gateway.

---

## State Machine: Lockout States & Transitions

The gateway enforces fail-closed state isolation:

| State | Allowed Operations |
|---|---|
| **`NORMAL`** | All traffic permitted; read/write `/api/*` forwards enabled. |
| **`RESTRICTED`** | Triggered on 1st anomaly (3 bad codes in a session or 3 failed handshakes on a device). `/api/*` accepts read-only methods (`GET`, `HEAD`, `OPTIONS`); writes return `403 Forbidden`. Logins still permitted. |
| **`LOCKED`** | Triggered immediately on `Replay`, `Manual` lock, or 2nd anomaly. Returns `503 Service Unavailable` on all routes except `GET /status` and `/restore`. Drops all active sessions and nonces, persists `LOCKED` state, and invokes upstream seal. |

*Note: Once `LOCKED`, the system can only return to `NORMAL` through an authorized restore procedure.*

---

## Authentication & Shifting Codes (Ratchet)

1. **Challenge-Response Login**:
   - Client requests challenge via `POST /auth/challenge` (receives a single-use 32-byte hex nonce, valid for 30 seconds).
   - Client signs nonce with Ed25519 private key and submits `POST /auth/login`.
   - On verification, a session seed is derived via HKDF-SHA256 from the shared secret, nonce, and device ID.
2. **Per-Request Shifting Codes**:
   - Each request carries `X-Session-Id`, `X-Counter`, and `X-Code`.
   - Code ratchet advances using HKDF-SHA256 (`key_n` and `code_n`).
   - Forward window allows jumping ahead up to 3 counters (`WINDOW = 3`) to tolerate dropped packets.
3. **Replay Protection**:
   - The gateway maintains a ring buffer of the last 16 accepted `(counter, SHA256(code))` pairs per session.
   - An exact replay of an accepted request triggers immediate `LOCKED` lockdown.
   - Forged old counters or skipped counter arrivals that were not accepted evaluate to `BadCode` without causing a denial-of-service lockout.

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
