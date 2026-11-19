use axum::http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

use crate::config::Config;
use crate::log;
use crate::state::{Live, SharedState};
use crate::store::{now_unix, write_private, Res};
use crate::upstream;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LockState {
    Normal,
    Restricted,
    Locked,
}

/// What is saved in lock-state.json. `reason` is a coarse code, never an id.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LockInfo {
    pub state: LockState,
    pub anomalies: u32,
    pub reason: String,
    pub since: u64,
}

impl LockInfo {
    pub fn normal() -> LockInfo {
        LockInfo { state: LockState::Normal, anomalies: 0, reason: "none".to_string(), since: now_unix() }
    }
    fn locked(reason: &str) -> LockInfo {
        LockInfo { state: LockState::Locked, anomalies: 0, reason: reason.to_string(), since: now_unix() }
    }
}

impl Default for LockInfo {
    fn default() -> LockInfo {
        LockInfo::normal()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    Replay,
    BadCodes,
    FailedHandshakes,
    Manual,
}

impl Trigger {
    pub fn code(&self) -> &'static str {
        match self {
            Trigger::Replay => "replay",
            Trigger::BadCodes => "bad_codes",
            Trigger::FailedHandshakes => "failed_handshakes",
            Trigger::Manual => "manual",
        }
    }
}

/// The transition table (pure, no I/O). There is no way DOWN from here;
/// only the M6 restore flow may return to NORMAL.
///   LOCKED     + anything          -> LOCKED
///   any state  + Manual or Replay  -> LOCKED
///   RESTRICTED + any other anomaly -> LOCKED   (second anomaly)
///   NORMAL     + BadCodes / FailedHandshakes   -> RESTRICTED (first anomaly)
pub fn next_state(current: &LockInfo, trigger: Trigger) -> LockInfo {
    let anomalies = if trigger == Trigger::Manual {
        current.anomalies
    } else {
        current.anomalies.saturating_add(1)
    };
    let state = match (current.state, trigger) {
        (LockState::Locked, _) => LockState::Locked,
        (_, Trigger::Manual) | (_, Trigger::Replay) => LockState::Locked,
        (LockState::Restricted, _) => LockState::Locked,
        (LockState::Normal, _) => LockState::Restricted,
    };
    let (reason, since) = if state == current.state {
        (current.reason.clone(), current.since)
    } else {
        (trigger.code().to_string(), now_unix())
    };
    LockInfo { state, anomalies, reason, since }
}

/// Load the saved lock state. FAIL CLOSED: a missing file is a fresh install
/// (NORMAL), but an unreadable or corrupt file means LOCKED.
pub fn load_lock(path: &Path) -> LockInfo {
    match std::fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<LockInfo>(&text) {
            Ok(info) => info,
            Err(e) => {
                log::warn(&format!("lock state file is corrupt, starting LOCKED: {e}"));
                LockInfo::locked("lock_file_corrupt")
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => LockInfo::normal(),
        Err(e) => {
            log::warn(&format!("lock state file unreadable, starting LOCKED: {e}"));
            LockInfo::locked("lock_file_unreadable")
        }
    }
}

pub fn persist_lock(path: &Path, info: &LockInfo) -> Res<()> {
    let bytes = serde_json::to_vec_pretty(info).map_err(|e| format!("cannot serialize lock state: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    write_private(&tmp, &bytes, false)?;
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot replace lock file {:?}: {e}", path))
}

/// Record an anomaly. Applies the transition table, saves to disk, announces
/// the change, and on LOCKED: drops every session and nonce and calls the
/// upstream seal. Called with the live mutex already held (so it never locks).
pub fn trigger(state: &SharedState, live: &mut Live, t: Trigger) {
    live.lockout_signals.push(t.code().to_string());
    let old = live.lock.clone();
    let new = next_state(&old, t);
    log::warn(&format!("LOCKOUT TRIGGER {}: {} -> {}", t.code(), old.state_name(), new.state_name()));
    if new == old {
        return;
    }
    live.lock = new.clone();
    // If this save fails we stay locked in memory, but a restart could lose it.
    if let Err(e) = persist_lock(&state.config.lock_path(), &new) {
        log::warn(&format!("CANNOT PERSIST LOCK STATE (restart may unlock): {e}"));
    }
    if new.state == old.state {
        return;
    }
    state.publish(
        "state_change",
        serde_json::json!({ "from": old.state, "to": new.state, "reason": t.code(), "anomalies": new.anomalies }),
    );
    if new.state == LockState::Locked {
        live.sessions.clear();
        live.nonces.clear();
        state.publish("lockout", serde_json::json!({ "reason": t.code() }));
        tokio::spawn(upstream::seal_with_retry(state.clone(), t.code().to_string()));
    }
}

impl LockInfo {
    pub fn state_name(&self) -> &'static str {
        match self.state {
            LockState::Normal => "NORMAL",
            LockState::Restricted => "RESTRICTED",
            LockState::Locked => "LOCKED",
        }
    }
}

/// Paths still served while LOCKED. `/restore` is reserved for the M6 restore endpoint.
fn allowed_when_locked(method: &Method, path: &str) -> bool {
    (method == Method::GET && path == "/status") || path == "/restore" || path.starts_with("/restore/")
}

/// Decide whether a request may proceed in the current state (None = proceed).
/// LOCKED: 503 for everything except the allowed paths.
/// RESTRICTED: only read-only methods on /api/*.
pub fn gate_decision(info: &LockInfo, method: &Method, path: &str) -> Option<StatusCode> {
    match info.state {
        LockState::Normal => None,
        LockState::Restricted => {
            let read_only = method == Method::GET || method == Method::HEAD || method == Method::OPTIONS;
            if (path == "/api" || path.starts_with("/api/")) && !read_only {
                Some(StatusCode::FORBIDDEN)
            } else {
                None
            }
        }
        LockState::Locked => {
            if allowed_when_locked(method, path) {
                None
            } else {
                Some(StatusCode::SERVICE_UNAVAILABLE)
            }
        }
    }
}

/// Used by `lotoctl lock`: write LOCKED into the lock file. A running gateway
/// notices within about a second (watch_lock_file); a stopped one starts LOCKED.
pub fn manual_lock_file(config: &Config) -> Res<()> {
    let path = config.lock_path();
    let mut info = load_lock(&path);
    if info.state == LockState::Locked {
        return Ok(());
    }
    info.state = LockState::Locked;
    info.reason = Trigger::Manual.code().to_string();
    info.since = now_unix();
    persist_lock(&path, &info)
}

/// Background task: the lock file can only ESCALATE a running gateway to LOCKED.
pub async fn watch_lock_file(state: SharedState) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let on_disk = load_lock(&state.config.lock_path());
        if on_disk.state == LockState::Locked {
            let mut live = state.live.lock().await;
            if live.lock.state != LockState::Locked {
                trigger(&state, &mut live, Trigger::Manual);
            }
        }
    }
}

/// At startup: if we come up LOCKED, ask the upstream to seal (it may have been missed).
pub async fn seal_if_locked(state: SharedState) {
    let locked = state.live.lock().await.lock.state == LockState::Locked;
    if locked {
        log::warn("starting in LOCKED state, requesting upstream seal");
        tokio::spawn(upstream::seal_with_retry(state.clone(), "startup_locked".to_string()));
    }
}
