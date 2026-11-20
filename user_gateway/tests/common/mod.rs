#![allow(dead_code)]
// Helpers shared by the integration tests.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

use lot_gateway::config::Config;
use lot_gateway::crypto::{self, Keyfile, DEFAULT_DEVICE_CONFIG};
use lot_gateway::handshake::LoginRequest;
use lot_gateway::state::{AppState, SharedState};
use lot_gateway::store::{Device, Store, StoreData};

pub fn temp_dir(tag: &str) -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("lot-it-{tag}-{}-{nanos}-{id}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub struct Env {
    pub state: SharedState,
    pub keyfile: Keyfile,
    pub device: Device,
}

/// State with one officer ("alice") and one device, using a fresh temp data dir
/// (so lock-state.json can really be written). The upstream is a dead local port.
pub fn make_env() -> Env {
    make_env_upstream("http://127.0.0.1:9000")
}

pub fn make_env_upstream(upstream: &str) -> Env {
    let (device, keyfile) = crypto::new_device("alice", DEFAULT_DEVICE_CONFIG);
    let data_dir = temp_dir("env");
    let config = Config {
        bind: "127.0.0.1:0".to_string(),
        upstream: upstream.to_string(),
        data_dir: data_dir.clone(),
        require_face: false,
    };
    let mut store = Store {
        path: config.store_path(),
        data: StoreData::default(),
    };
    store.add_user(device.clone()).unwrap();
    store.save().unwrap();
    let _ = lot_gateway::lockout::persist_lock(&config.lock_path(), &lot_gateway::lockout::LockInfo::normal());
    Env {
        state: AppState::new(config, store),
        keyfile,
        device,
    }
}

/// A correctly signed login request for `nonce`, built the same way a real client does.
pub fn make_req(keyfile: &Keyfile, nonce: &str) -> LoginRequest {
    let body = crypto::sign_login_body(keyfile, nonce).unwrap();
    serde_json::from_str(&body).unwrap()
}

// ---------- helpers for the shifting-code tests (M3) ----------

use axum::http::{HeaderMap, HeaderValue};
use lot_gateway::handshake::{issue_challenge, login};
use lot_gateway::ratchet;
use std::time::Instant;

/// Log in and return (session_id, the nonce used for the login).
pub async fn new_session(env: &Env) -> (String, String) {
    let t0 = Instant::now();
    let nonce = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let req = make_req(&env.keyfile, &nonce);
    let session_id = login(&env.state, &req, t0).await.unwrap();
    (session_id, nonce)
}

pub fn headers(session_id: &str, counter: &str, code: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("x-session-id", HeaderValue::from_str(session_id).unwrap());
    h.insert("x-counter", HeaderValue::from_str(counter).unwrap());
    h.insert("x-code", HeaderValue::from_str(code).unwrap());
    h
}

/// Headers built by the same function `lotoctl sign-request` uses.
pub fn valid_headers(env: &Env, nonce: &str, session_id: &str, counter: u64) -> HeaderMap {
    let list = ratchet::request_headers(&env.keyfile, nonce, session_id, counter).unwrap();
    let mut h = HeaderMap::new();
    for (name, value) in list {
        let name = axum::http::HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()).unwrap();
        h.insert(name, HeaderValue::from_str(&value).unwrap());
    }
    h
}

pub async fn last_counter(env: &Env, session_id: &str) -> u64 {
    env.state.live.lock().await.sessions.get(session_id).unwrap().last_counter
}

pub async fn bad_codes(env: &Env, session_id: &str) -> u32 {
    env.state.live.lock().await.sessions.get(session_id).unwrap().bad_codes
}

/// Feed a trigger to the lockout machine the way the gateway does.
pub async fn trip(env: &Env, trigger: lot_gateway::lockout::Trigger) {
    let mut live = env.state.live.lock().await;
    lot_gateway::lockout::trigger(&env.state, &mut live, trigger);
}

pub async fn lock_state(env: &Env) -> lot_gateway::lockout::LockState {
    env.state.live.lock().await.lock.state
}
