# lot-gateway

Rust gateway for the zero-trust legal case vault prototype. It handles ONLY users,
devices, sessions, per-message shifting codes, lockout state and live WebSocket
status. Files, OCR/AI and the audit log live in the separate Python (FastAPI)
service that this gateway forwards to.

**Status: M0, M1, M2, M3, M4 implemented and tested.** Unit tests and integration
test suites (`cargo test`) pass.

## Build and run

    cargo build
    cargo test
    cargo run --bin lot-gateway          # the server
    cargo run --bin lotoctl -- <args>    # the admin CLI

## Environment variables

| Variable       | Default                 | Meaning                          |
|----------------|-------------------------|----------------------------------|
| LOT_BIND       | 127.0.0.1:8080          | Address the gateway listens on   |
| LOT_UPSTREAM   | http://127.0.0.1:9000   | The Python service               |
| LOT_DATA_DIR   | ./lot-data              | Holds `store.json` and `lock-state.json` |

## lotoctl commands

    lotoctl user add <officer_id> --keyfile <path> [--device-config <string>]
    lotoctl user list
    lotoctl user revoke <officer_id>
    lotoctl device list
    lotoctl lock                                        # manual lockout (M4)
    lotoctl sign-login --keyfile <path> --nonce <hex>    # prints the /auth/login body
    lotoctl sign-request --keyfile <path> --nonce <hex> --session-id <id> --counter <n> [--curl]

`user add` refuses to overwrite an existing keyfile. Keyfiles and `store.json` are
created with mode 0600 on unix. `device list` never prints secrets.
The server re-reads `store.json` on every /auth/challenge and /auth/login, so users
added or revoked with `lotoctl` take effect without a restart. If the file cannot be
read, the request is denied.

## Endpoints

| Method | Path            | Auth | Milestone | Success            | Failure |
|--------|-----------------|------|-----------|--------------------|---------|
| GET    | /health         | none | M0        | `{"status":"ok"}`  |         |
| POST   | /auth/challenge | none | M2        | `{"nonce","expires_in_secs"}` | 401 `unauthorized` |
| POST   | /auth/login     | none | M2        | `{"session_id"}`   | 401 `unauthorized` |
| GET    | /status         | none | M4        | `{"state","anomalies","since"}` | |
| GET    | /ws             | none | M4        | WebSocket, JSON events (below) | 503 if LOCKED or 32 clients |

Later milestones add /api/* (M5) and the restore flow (M6; `/restore` is reserved).
Every response is also subject to the lockout gate below.

No route calls the shifting-code check yet: `ratchet::check_request` is built and
unit/integration tested in M3, and the first route that uses it is the /api/* proxy in M5.

## Handshake (M2)

1. `POST /auth/challenge` with `{"device_id":"dev-..."}`. Returns a random 32-byte
   nonce as 64 hex chars, valid 30 seconds, single use. Unknown device ids also
   get a nonce (it is not stored and can never be used) so ids cannot be enumerated.
2. The device signs the RAW nonce bytes (the hex decoded to 32 bytes) with its
   ed25519 key.
3. `POST /auth/login` with
   `{"device_id","nonce","signature","config_hash"}`:
   `signature` = 128 hex chars; `config_hash` = SHA-256 hex of the device-config string.
   `lotoctl sign-login` builds this body.
4. Checks, in order: device exists and is not flagged; nonce exists, belongs to this
   device, is not expired (30 s); device and officer not revoked; ed25519 signature
   (verify_strict); config hash equals the stored one. Anything else = deny.
5. Session seed = HKDF-SHA256(ikm = shared secret, salt = nonce bytes,
   info = `"lot-gateway/session-seed/v1"` + device_id text, 32 bytes).
   The response contains only `session_id` (32 hex chars).

Every failure returns the same `401 unauthorized`; the real reason goes to the log.
Each failure for a KNOWN device is counted; the third flags the device and emits a
lockout signal (currently only recorded and logged; M4 makes it real). A flagged
device is refused even with valid credentials.

Manual test:

    lotoctl user add alice --keyfile ./alice.keyfile.json
    cargo run --bin lot-gateway &
    DEV=$(grep device_id alice.keyfile.json | cut -d'"' -f4)
    curl -s localhost:8080/auth/challenge -d "{\"device_id\":\"$DEV\"}"
    lotoctl sign-login --keyfile ./alice.keyfile.json --nonce <nonce from above>
    curl -s localhost:8080/auth/login -d '<output of sign-login>'

## Shifting codes (M3)

Every protected request must carry:

| Header       | Value |
|--------------|-------|
| X-Session-Id | the `session_id` from /auth/login |
| X-Counter    | decimal integer, first request = 1, then increasing |
| X-Code       | 32 hex chars (case-insensitive), the code for that counter |

Hash chain (exact, so a device can reproduce it):

    key_0  = session seed (see Handshake, step 5)
    key_n  = HKDF-SHA256(ikm = key_{n-1}, no salt, info = "lot-gateway/chain/v1")      -> 32 bytes
    code_n = HKDF-SHA256(ikm = key_n,     no salt, info = "lot-gateway/code/v1"
                                                         + n as 8 big-endian bytes)    -> 16 bytes

The server keeps only the key for the last accepted counter, so old codes cannot be
recomputed. To distinguish genuine replays from forged attacks, the server maintains a
ring buffer of the last 16 accepted `(counter, code_hash)` pairs per session.

Results of `check_request` (nothing is forwarded or changed unless Accepted):

| Verdict        | When |
|----------------|------|
| Accepted       | counter in last+1 ..= last+3 and the code matches; the chain moves forward; `(counter, SHA256(code))` is added to the 16-pair ring buffer |
| Replay         | counter <= last accepted AND the exact `(counter, code)` pair was previously accepted in this session (matched against the last 16 accepted pairs) |
| BadCode        | wrong code; counter more than 3 ahead; counter <= last accepted but not in the accepted ring buffer; malformed or missing X-Counter / X-Code. Counted per session (`bad_codes`) for M4 |
| UnknownSession | session id not found |
| Malformed      | X-Session-Id missing or sent twice |
| InternalError  | a crypto call failed (deny) |

Manual test (use the nonce from your login):

    lotoctl sign-request --keyfile ./alice.keyfile.json --nonce <login nonce> \
        --session-id <session id> --counter 1

The unit tests include known-answer vectors computed independently with a Python
HKDF-SHA256 (checked against RFC 5869 test case 1), so a wrong Rust implementation
should be caught on the first `cargo test`.

## Lockout (M4)

States: NORMAL, RESTRICTED, LOCKED. Triggers: `replay` (a Replay verdict), `bad_codes`
(the 3rd bad code in one session, once per session), `failed_handshakes` (a device
reaches 3 failed logins), `manual` (`lotoctl lock`).

| Current state | Trigger                         | New state  |
|---------------|---------------------------------|------------|
| NORMAL        | bad_codes, failed_handshakes    | RESTRICTED (first anomaly) |
| NORMAL        | replay, manual                  | LOCKED     |
| RESTRICTED    | any trigger                     | LOCKED (second anomaly) |
| LOCKED        | any trigger                     | LOCKED     |

There is no way down from here: only the M6 restore flow returns to NORMAL.
Anomalies are counted (`anomalies` in /status) and never decay.

What each state allows (applied before every route by a middleware):

| State      | Rule |
|------------|------|
| NORMAL     | everything |
| RESTRICTED | /api/* accepts only GET, HEAD, OPTIONS (others get 403); login still works |
| LOCKED     | 503 for every request except `GET /status` and `/restore`, `/restore/*` |

Note: `/health`, `/ws` and `/auth/*` also return 503 while LOCKED (literal reading of the spec).
Entering LOCKED: all sessions and pending nonces are dropped, the state is written to
`LOT_DATA_DIR/lock-state.json`, events are pushed, and `POST {LOT_UPSTREAM}/internal/seal`
is called (3 attempts, 2 s apart; failure is logged and never unlocks anything).

Persistence: the lock state is loaded at startup. A missing file = NORMAL (fresh install);
an unreadable or corrupt file = LOCKED (fail closed). If the gateway starts LOCKED it asks
the upstream to seal again.

`lotoctl lock` writes LOCKED into the lock file. A running gateway checks the file every
second and applies it (the file can only escalate to LOCKED); a stopped gateway starts LOCKED.

### WebSocket events (GET /ws)

Read-only; the first message is `{"event":"hello","state":"..."}`. Every other event has
`event` and `time` (unix seconds) plus:

| event          | extra fields |
|----------------|--------------|
| login_success  | device_id |
| login_failure  | device_id (null if the device is unknown), known_device |
| replay_rejected| device_id |
| state_change   | from, to, reason, anomalies |
| lockout        | reason |
| seal_failed    | (none) |

Events never contain officer ids, session ids, nonces, codes or client-supplied text.
`reason` is one of replay, bad_codes, failed_handshakes, manual.

## Source layout

main.rs (server), bin/lotoctl.rs (CLI entry), lib.rs, config.rs, state.rs
(one `Arc<AppState>`), store.rs (JSON persistence), crypto.rs (keys, hashes, HKDF,
login signing), handshake.rs (challenge/login), ratchet.rs (shifting codes), lockout.rs
lockout.rs (state machine, persistence, gate), upstream.rs (seal call), ws.rs, log.rs, cli.rs,
cli_print.rs, server.rs (router + gate middleware). Later: proxy.

## Prototype simplifications

- No Noise handshake. At enrolment `lotoctl` generates, per officer+device, an
  ed25519 keypair and a 32-byte shared secret. The device keyfile (JSON, hex)
  holds the private key and shared secret; the server stores only the public key
  and the shared secret.
- "Device integrity attestation" is a stored SHA-256 of an expected device-config
  string, compared at handshake. This is a PROTOTYPE of attestation, not real attestation.
- The shared secret is stored in plaintext in `store.json` (needed to derive codes).
- One officer gets one device at enrolment; revoking an officer revokes all their devices.
- Single JSON store written atomically. A corrupt store stops startup and is never overwritten.
- Sessions, nonces, failure counters and the "flagged" set are IN MEMORY ONLY. A restart
  clears them, including flagged devices. Only the lock state is persisted.
- Failed-handshake counts are never reset by a successful login (stricter, simpler).
- Known risk (denial of service, follows from the spec): anyone who knows a device id can
  send 3 bad logins and cause one anomaly; two such device ids lock the whole gateway.
  Device ids must stay secret. Note that forging old counters with invalid codes does NOT
  trigger Replay lockout (it is treated as BadCode); only an exact replay of an accepted request locks.
- /status and /ws are unauthenticated by design (the spec requires /status to work while
  LOCKED). They expose only coarse state; see the event table.
- Manual lock uses file polling (1 s). If `lotoctl lock` and a gateway trigger write the
  lock file at the same moment, the later write wins and a manual lock could be lost.
  M6 restore must write the lock file BEFORE changing memory, or the watcher re-locks.
- If the lock file cannot be written, the gateway stays locked in memory only (logged).
- RESTRICTED path matching uses the raw request path; re-check this when the M5 proxy exists.
- reqwest is built without a TLS backend, so an https:// LOT_UPSTREAM will not work yet.
- A message that arrives after a LATER counter was accepted is treated as BadCode if it was
  never accepted, or Replay if it was previously accepted in this session (within the last 16).
  Retries must use a new counter.
- Sessions have no expiry yet and live in memory only; the seed is kept in memory.
- Pending nonces are capped at 1000 (more requests are denied) and cleared on expiry.
- `tracing` macros are used, but `tracing-subscriber` is not on the approved crate
  list, so `log.rs` also prints with `eprintln!`. Remove those lines if a subscriber is added.
