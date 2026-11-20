use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Mutex, RwLock};

use crate::config::Config;
use crate::crypto;
use crate::lockout::{self, LockInfo};
use crate::store::{now_unix, Res, Store};

/// A nonce handed out by /auth/challenge, waiting to be used once.
#[derive(Clone, Debug)]
pub struct PendingNonce {
    pub device_id: String,
    pub issued_at: Instant,
    pub face_ok: bool,
    pub face_attempts: u32,
    pub capture_id: Option<String>,
}

/// How many recently-accepted (counter, code_hash) pairs to remember per session.
/// Only a replay of one of these is treated as a true Replay; older or forged
/// old counters with wrong codes are BadCode (not Replay).
pub const REPLAY_HISTORY_CAP: usize = 16;

/// Maximum session lifetime (8 hours).
pub const SESSION_MAX_AGE: Duration = Duration::from_secs(8 * 3600);

/// Maximum concurrent active sessions.
pub const MAX_SESSIONS: usize = 1000;

/// A logged-in session. `seed` is the ratchet seed; `chain_key` is the hash-chain
/// key for `last_counter` (starts equal to the seed at counter 0).
#[derive(Clone)]
pub struct Session {
    pub session_id: String,
    pub officer_id: String,
    pub device_id: String,
    pub seed: [u8; 32],
    pub chain_key: [u8; 32],
    pub last_counter: u64,
    pub bad_codes: u32,
    pub created_at: Instant,
    /// Ring buffer of the last REPLAY_HISTORY_CAP accepted (counter, code_hash) pairs.
    /// Used to distinguish genuine replays from forged old-counter requests.
    pub accepted_pairs: VecDeque<(u64, [u8; 32])>,
}

/// Everything that changes while the server runs. It lives behind ONE mutex so
/// there is never a lock-order problem. `lock` is also saved to lock-state.json.
#[derive(Default)]
pub struct Live {
    pub nonces: HashMap<String, PendingNonce>,
    pub sessions: HashMap<String, Session>,
    pub failures: HashMap<String, u32>,
    pub flagged: HashSet<String>,
    pub lockout_signals: Vec<String>,
    pub lock: LockInfo,
    pub ws_clients: usize,
}

/// The ONE shared state of the gateway.
pub struct AppState {
    pub config: Config,
    pub store: RwLock<Store>,
    pub live: Mutex<Live>,
    /// Every event is sent here as a JSON string; /ws clients subscribe to it.
    pub events: broadcast::Sender<String>,
    /// Shared HTTP client for calls to the upstream.
    pub http: reqwest::Client,
    /// 32-byte hex token shared with the upstream app.
    pub gateway_token: String,
}

pub type SharedState = Arc<AppState>;

fn load_or_create_token(path: &std::path::Path) -> String {
    if let Ok(content) = std::fs::read_to_string(path) {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let token = crypto::random_hex(32);
    let _ = crate::store::write_private(path, token.as_bytes(), false);
    token
}

impl AppState {
    /// Also loads the saved lock state, so a restart can never unlock the system.
    pub fn new(config: Config, store: Store) -> SharedState {
        // First-run initialization writes NORMAL; missing lock file afterwards means LOCKED
        if !config.lock_path().exists() && !config.store_path().exists() {
            let _ = lockout::persist_lock(&config.lock_path(), &LockInfo::normal());
        }
        let mut live = Live::default();
        live.lock = lockout::load_lock(&config.lock_path());
        for d in &store.data.devices {
            if d.locked_out {
                live.flagged.insert(d.device_id.clone());
            }
        }
        let token = load_or_create_token(&config.token_path());
        let (events, _first_receiver) = broadcast::channel(256);
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Arc::new(AppState {
            config,
            store: RwLock::new(store),
            live: Mutex::new(live),
            events,
            http,
            gateway_token: token,
        })
    }

    /// Re-read store.json so users added or revoked with lotoctl take effect
    /// without a restart. If the file cannot be read, the old store is kept
    /// and the error is returned (callers must then DENY the request).
    pub async fn refresh_store(&self) -> Res<()> {
        let fresh = Store::load(&self.config.store_path())?;
        {
            let mut live = self.live.lock().await;
            live.flagged.clear();
            for d in &fresh.data.devices {
                if d.locked_out {
                    live.flagged.insert(d.device_id.clone());
                }
            }
        }
        *self.store.write().await = fresh;
        Ok(())
    }

    /// Announce an event to /ws clients. `details` must be a JSON object; its
    /// fields are merged next to "event" and "time". (M5 also sends it to the audit log.)
    pub fn publish(&self, kind: &str, details: serde_json::Value) {
        let mut event = serde_json::json!({ "event": kind, "time": now_unix() });
        if let (Some(target), Some(extra)) = (event.as_object_mut(), details.as_object()) {
            for (key, value) in extra {
                target.insert(key.clone(), value.clone());
            }
        }
        // An error here only means nobody is listening.
        let _ = self.events.send(event.to_string());
    }
}
