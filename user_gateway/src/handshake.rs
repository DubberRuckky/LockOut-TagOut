use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use std::time::{Duration, Instant};

use crate::crypto;
use crate::lockout::{self, Trigger};
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
        Ok(_) => state.publish("login_success", serde_json::json!({ "device_id": req.device_id })),
        Err(_) => {
            // Only echo the device id if it really exists; never reflect arbitrary client text.
            let known = state.store.read().await.find_device(&req.device_id).is_some();
            let device = if known { Some(req.device_id.clone()) } else { None };
            state.publish(
                "login_failure",
                serde_json::json!({ "device_id": device, "known_device": known }),
            );
        }
    }
    result
}

async fn login_inner(state: &SharedState, req: &LoginRequest, now: Instant) -> Res<String> {
    let (device, officer_revoked) = {
        let store = state.store.read().await;
        let device = match store.find_device(&req.device_id) {
            Some(d) => d.clone(),
            None => return Err("unknown device".to_string()),
        };
        // A device whose officer is missing is treated as revoked (fail closed).
        let revoked = match store.find_officer(&device.officer_id) {
            Some(o) => o.revoked,
            None => true,
        };
        (device, revoked)
    };

    let mut live = state.live.lock().await;
    if live.flagged.contains(&device.device_id) {
        return Err("device is flagged".to_string());
    }

    match verify_login(&mut live, &device, officer_revoked, req, now) {
        Ok(seed) => {
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
            record_failure(state, &mut live, &device.device_id);
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
    req: &LoginRequest,
    now: Instant,
) -> Res<[u8; 32]> {
    let pending = match live.nonces.get(&req.nonce).cloned() {
        Some(p) => p,
        None => return Err("unknown, expired or already used nonce".to_string()),
    };
    // A nonce issued to another device is NOT consumed, so nobody can burn
    // someone else's nonce by guessing; the attempt still counts as a failure.
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

/// Count a failed handshake. The third failure flags the device (once) and
/// emits a lockout signal. Failures are never reset by a success.
fn record_failure(state: &SharedState, live: &mut Live, device_id: &str) {
    let count = live.failures.entry(device_id.to_string()).or_insert(0);
    *count += 1;
    let total = *count;
    if total >= MAX_FAILURES && !live.flagged.contains(device_id) {
        live.flagged.insert(device_id.to_string());
        log::warn(&format!("device {device_id:?} flagged after {total} failed handshakes"));
        lockout::trigger(state, live, Trigger::FailedHandshakes);
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
