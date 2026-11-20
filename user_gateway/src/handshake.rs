use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use std::time::{Duration, Instant};

use crate::crypto;
use crate::log;
use crate::state::{Live, PendingNonce, Session, SharedState};
use crate::store::{Device, Res};
use std::collections::VecDeque;

pub const NONCE_TTL: Duration = Duration::from_secs(30);
pub const MAX_NONCES: usize = 1000;
pub const MAX_FAILURES: u32 = 3;
const MAX_BODY: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    pub device_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub device_id: String,
    pub nonce: String,
    pub signature: String,
    pub config_hash: String,
    #[serde(default)]
    pub passcode: String,
}

// ---------- logic (no HTTP here, so tests can call it directly) ----------

/// Hand out a nonce. Unknown devices ALSO get a nonce (so the endpoint does not
/// reveal which device ids exist), but it is not stored and can never be used.
pub async fn issue_challenge(state: &SharedState, device_id: &str, now: Instant) -> Res<String> {
    let known = state.store.read().await.find_device(device_id).is_some();
    let nonce = crypto::random_hex(32);

    let mut live = state.live.lock().await;
    live.nonces
        .retain(|_, p| now.saturating_duration_since(p.issued_at) <= NONCE_TTL);
    if known {
        if live.nonces.len() >= MAX_NONCES {
            return Err("too many pending nonces".to_string());
        }
        live.nonces.insert(
            nonce.clone(),
            PendingNonce {
                device_id: device_id.to_string(),
                issued_at: now,
            },
        );
    }
    Ok(nonce)
}

/// Verify a login. Ok = new session id. Err = the INTERNAL reason (log it,
/// never send it to the client).
pub async fn login(state: &SharedState, req: &LoginRequest, now: Instant) -> Res<String> {
    let result = login_inner(state, req, now).await;
    match &result {
        Ok(_) => state.publish("login_success", serde_json::json!({})),
        Err(_) => {
            let known = state.store.read().await.find_device(&req.device_id).is_some();
            state.publish(
                "login_failure",
                serde_json::json!({ "known_device": known }),
            );
        }
    }
    result
}

async fn login_inner(state: &SharedState, req: &LoginRequest, now: Instant) -> Res<String> {
    let (device, officer_revoked, passcode_hash) = {
        let store = state.store.read().await;
        let device = match store.find_device(&req.device_id) {
            Some(d) => d.clone(),
            None => return Err("unknown device".to_string()),
        };
        let (revoked, hash) = match store.find_officer(&device.officer_id) {
            Some(o) => (o.revoked, o.passcode_hash.clone()),
            None => (true, String::new()),
        };
        (device, revoked, hash)
    };

    let mut live = state.live.lock().await;
    if !device.locked_out && device.failed_attempts == 0 {
        live.flagged.remove(&device.device_id);
        live.failures.remove(&device.device_id);
    }

    if device.locked_out || live.flagged.contains(&device.device_id) {
        return Err("device is locked out".to_string());
    }

    match verify_login(&mut live, &device, officer_revoked, &passcode_hash, req, now) {
        Ok(seed) => {
            live.failures.remove(&device.device_id);
            // Prune expired sessions
            live.sessions.retain(|_, s| now.saturating_duration_since(s.created_at) <= crate::state::SESSION_MAX_AGE);
            if live.sessions.len() >= crate::state::MAX_SESSIONS {
                return Err("too many active sessions".to_string());
            }

            let session_id = crypto::random_hex(16);
            live.sessions.insert(
                session_id.clone(),
                Session {
                    session_id: session_id.clone(),
                    officer_id: device.officer_id.clone(),
                    device_id: device.device_id.clone(),
                    seed,
                    chain_key: seed,
                    last_counter: 0,
                    bad_codes: 0,
                    created_at: now,
                    accepted_pairs: VecDeque::new(),
                },
            );
            Ok(session_id)
        }
        Err(reason) => {
            record_failure(state, &mut live, &device.device_id).await;
            Err(reason)
        }
    }
}

/// All the checks. Any problem returns Err. The nonce is consumed as soon as
/// it is found, even if a later check fails (single use).
fn verify_login(
    live: &mut Live,
    device: &Device,
    officer_revoked: bool,
    passcode_hash: &str,
    req: &LoginRequest,
    now: Instant,
) -> Res<[u8; 32]> {
    let pending = match live.nonces.get(&req.nonce).cloned() {
        Some(p) => p,
        None => return Err("unknown, expired or already used nonce".to_string()),
    };
    if pending.device_id != device.device_id {
        return Err("nonce was issued to a different device".to_string());
    }
    live.nonces.remove(&req.nonce);

    if now.saturating_duration_since(pending.issued_at) > NONCE_TTL {
        return Err("nonce expired".to_string());
    }
    if device.revoked || officer_revoked {
        return Err("device or officer is revoked".to_string());
    }

    // Passcode check
    if !passcode_hash.is_empty() {
        if !crate::store::verify_passcode(&req.passcode, passcode_hash) {
            return Err("bad passcode".to_string());
        }
    }

    let nonce_bytes = hex::decode(&req.nonce).map_err(|_| "nonce is not hex".to_string())?;
    let pk_bytes: [u8; 32] = hex::decode(&device.public_key_hex)
        .map_err(|_| "stored public key is not hex".to_string())?
        .try_into()
        .map_err(|_| "stored public key has wrong length".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| "stored public key is invalid".to_string())?;
    let sig_bytes: [u8; 64] = hex::decode(&req.signature)
        .map_err(|_| "signature is not hex".to_string())?
        .try_into()
        .map_err(|_| "signature has wrong length".to_string())?;
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify_strict(&nonce_bytes, &signature)
        .map_err(|_| "bad signature".to_string())?;

    // PROTOTYPE of device attestation: compare the stored config hash.
    if req.config_hash != device.config_hash_hex {
        return Err("device config hash mismatch".to_string());
    }

    let secret = hex::decode(&device.shared_secret_hex)
        .map_err(|_| "stored shared secret is not hex".to_string())?;
    crypto::derive_session_seed(&secret, &nonce_bytes, &device.device_id)
}

/// Count a failed handshake on a device. The third failure locks THAT DEVICE
/// (persisted in store.json) and never triggers system-wide lockout.
async fn record_failure(state: &SharedState, live: &mut Live, device_id: &str) {
    let count = live.failures.entry(device_id.to_string()).or_insert(0);
    *count += 1;
    let total = *count;
    if total >= MAX_FAILURES && !live.flagged.contains(device_id) {
        live.flagged.insert(device_id.to_string());
        log::warn(&format!("device {device_id:?} flagged in memory after {total} failed handshakes"));
    }
    // Persist to store.json
    let mut store = state.store.write().await;
    if let Ok((attempts, newly_locked)) = store.increment_device_failure(device_id) {
        let _ = store.save();
        if newly_locked {
            log::warn(&format!("device {device_id:?} LOCKED OUT after {attempts} failed handshakes (device level)"));
        }
    }
}

// ---------- HTTP handlers ----------

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
}

pub async fn challenge_handler(State(state): State<SharedState>, body: Bytes) -> Response {
    if body.len() > MAX_BODY {
        log::warn("challenge denied: body too large");
        return unauthorized();
    }
    let req: ChallengeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            log::warn(&format!("challenge denied: bad json: {e}"));
            return unauthorized();
        }
    };
    if let Err(e) = state.refresh_store().await {
        log::warn(&format!("challenge denied: store reload failed: {e}"));
        return unauthorized();
    }
    match issue_challenge(&state, &req.device_id, Instant::now()).await {
        Ok(nonce) => Json(serde_json::json!({
            "nonce": nonce,
            "expires_in_secs": NONCE_TTL.as_secs()
        }))
        .into_response(),
        Err(e) => {
            log::warn(&format!("challenge denied: {e}"));
            unauthorized()
        }
    }
}

pub async fn login_handler(State(state): State<SharedState>, body: Bytes) -> Response {
    if body.len() > MAX_BODY {
        log::warn("login denied: body too large");
        return unauthorized();
    }
    let req: LoginRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            log::warn(&format!("login denied: bad json: {e}"));
            return unauthorized();
        }
    };
    if let Err(e) = state.refresh_store().await {
        log::warn(&format!("login denied: store reload failed: {e}"));
        return unauthorized();
    }
    match login(&state, &req, Instant::now()).await {
        Ok(session_id) => {
            log::info(&format!("login ok: device {:?}", req.device_id));
            Json(serde_json::json!({ "session_id": session_id })).into_response()
        }
        Err(reason) => {
            // {:?} escapes odd characters so clients cannot forge log lines.
            log::warn(&format!("login denied: device {:?}: {reason}", req.device_id));
            unauthorized()
        }
    }
}
