use axum::http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

use crate::config::Config;
use crate::log;
use crate::state::{Live, SharedState};
use crate::store::{now_unix, write_private, Res};
use crate::upstream;

pub const TAGOUT_MIN_RANK: u8 = 4;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LockState {
    Normal,
    Restricted,
    Locked,
    Tagout,
}

/// What is saved in lock-state.json. `reason` is a coarse code, never an id.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LockInfo {
    pub state: LockState,
    pub anomalies: u32,
    pub reason: String,
    pub since: u64,
    #[serde(default)]
    pub initiator: Option<String>,
}

impl LockInfo {
    pub fn normal() -> LockInfo {
        LockInfo {
            state: LockState::Normal,
            anomalies: 0,
            reason: "none".to_string(),
            since: now_unix(),
            initiator: None,
        }
    }
    pub fn locked(reason: &str) -> LockInfo {
        LockInfo {
            state: LockState::Locked,
            anomalies: 0,
            reason: reason.to_string(),
            since: now_unix(),
            initiator: None,
        }
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

/// The transition table (pure, no I/O).
/// Replay and Manual lock immediately.
/// BadCodes in a session transitions NORMAL -> RESTRICTED -> LOCKED.
/// Device-level FailedHandshakes never alter the system-wide state.
pub fn next_state(current: &LockInfo, trigger: Trigger) -> LockInfo {
    let anomalies = match trigger {
        Trigger::Manual | Trigger::FailedHandshakes => current.anomalies,
        _ => current.anomalies.saturating_add(1),
    };
    let state = match (current.state, trigger) {
        (LockState::Locked, _) => LockState::Locked,
        (LockState::Tagout, _) => LockState::Tagout,
        (_, Trigger::Manual) | (_, Trigger::Replay) => LockState::Locked,
        (LockState::Restricted, Trigger::BadCodes) => LockState::Locked,
        (LockState::Restricted, _) => current.state,
        (LockState::Normal, Trigger::BadCodes) => LockState::Restricted,
        (LockState::Normal, _) => LockState::Normal,
    };
    let (reason, since) = if state == current.state {
        (current.reason.clone(), current.since)
    } else {
        (trigger.code().to_string(), now_unix())
    };
    LockInfo {
        state,
        anomalies,
        reason,
        since,
        initiator: current.initiator.clone(),
    }
}

/// Load the saved lock state. FAIL CLOSED: a missing file means LOCKED.
pub fn load_lock(path: &Path) -> LockInfo {
    match std::fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<LockInfo>(&text) {
            Ok(info) => info,
            Err(e) => {
                log::warn(&format!("lock state file is corrupt, starting LOCKED: {e}"));
                LockInfo::locked("lock_file_corrupt")
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            log::warn("lock state file missing, starting LOCKED (fail closed)");
            LockInfo::locked("missing_lock_file")
        }
        Err(e) => {
            log::warn(&format!("lock state file unreadable, starting LOCKED: {e}"));
            LockInfo::locked("lock_file_unreadable")
        }
    }
}

pub fn persist_lock(path: &Path, info: &LockInfo) -> Res<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let bytes = serde_json::to_vec_pretty(info).map_err(|e| format!("cannot serialize lock state: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    write_private(&tmp, &bytes, false)?;
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot replace lock file {:?}: {e}", path))
}

/// Record an anomaly.
pub fn trigger(state: &SharedState, live: &mut Live, t: Trigger) {
    live.lockout_signals.push(t.code().to_string());
    let old = live.lock.clone();
    let new = next_state(&old, t);
    log::warn(&format!("LOCKOUT TRIGGER {}: {} -> {}", t.code(), old.state_name(), new.state_name()));
    if new == old {
        return;
    }
    live.lock = new.clone();
    if let Err(e) = persist_lock(&state.config.lock_path(), &new) {
        log::warn(&format!("CANNOT PERSIST LOCK STATE: {e}"));
        if new.state == LockState::Locked || new.state == LockState::Tagout {
            let path = state.config.lock_path();
            let info = new.clone();
            tokio::spawn(async move {
                for attempt in 1..=5 {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    if let Err(err) = persist_lock(&path, &info) {
                        log::warn(&format!("RETRY {attempt} TO PERSIST LOCK STATE FAILED: {err}"));
                    } else {
                        log::info("Background persist of lock state succeeded");
                        break;
                    }
                }
            });
        }
    }
    if new.state == old.state {
        return;
    }
    state.publish(
        "state_change",
        serde_json::json!({ "from": old.state, "to": new.state, "reason": t.code(), "anomalies": new.anomalies }),
    );
    if new.state == LockState::Locked || new.state == LockState::Tagout {
        live.sessions.clear();
        live.nonces.clear();
        state.publish("lockout", serde_json::json!({ "reason": t.code() }));
        tokio::spawn(upstream::seal_with_retry(state.clone(), t.code().to_string()));
    }
}

pub fn trigger_tagout(state: &SharedState, live: &mut Live, initiator: &str) {
    let new = LockInfo {
        state: LockState::Tagout,
        anomalies: live.lock.anomalies,
        reason: "tagout".to_string(),
        since: now_unix(),
        initiator: Some(initiator.to_string()),
    };
    live.lock = new.clone();
    let _ = persist_lock(&state.config.lock_path(), &new);
    live.sessions.clear();
    live.nonces.clear();
    state.publish("state_change", serde_json::json!({
        "from": "UNKNOWN",
        "to": "TAGOUT",
        "reason": "tagout",
        "initiator": initiator
    }));
    tokio::spawn(upstream::seal_with_retry(state.clone(), "tagout".to_string()));
}

impl LockInfo {
    pub fn state_name(&self) -> &'static str {
        match self.state {
            LockState::Normal => "NORMAL",
            LockState::Restricted => "RESTRICTED",
            LockState::Locked => "LOCKED",
            LockState::Tagout => "TAGOUT",
        }
    }
}

fn allowed_when_locked(method: &Method, path: &str) -> bool {
    (method == Method::GET && path == "/status") || path == "/restore" || path.starts_with("/restore/")
}

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
        LockState::Locked | LockState::Tagout => {
            if allowed_when_locked(method, path) {
                None
            } else {
                Some(StatusCode::SERVICE_UNAVAILABLE)
            }
        }
    }
}

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

pub fn manual_tagout_file(config: &Config, initiator: &str) -> Res<()> {
    let path = config.lock_path();
    let old = load_lock(&path);
    let new = LockInfo {
        state: LockState::Tagout,
        anomalies: old.anomalies,
        reason: "tagout".to_string(),
        since: now_unix(),
        initiator: Some(initiator.to_string()),
    };
    persist_lock(&path, &new)
}

pub async fn watch_lock_file(state: SharedState) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let on_disk = load_lock(&state.config.lock_path());
        if on_disk.state == LockState::Locked || on_disk.state == LockState::Tagout {
            let mut live = state.live.lock().await;
            if live.lock.state != on_disk.state {
                live.lock = on_disk.clone();
                live.sessions.clear();
                live.nonces.clear();
                tokio::spawn(upstream::seal_with_retry(state.clone(), on_disk.reason.clone()));
            }
        } else if on_disk.state == LockState::Normal {
            let mut live = state.live.lock().await;
            if live.lock.state != LockState::Normal {
                log::info("Restoring gateway to NORMAL state from disk");
                live.lock = on_disk.clone();
                tokio::spawn(upstream::unseal_upstream(state.clone()));
            }
        }
    }
}

pub async fn seal_if_locked(state: SharedState) {
    let locked = {
        let s = state.live.lock().await.lock.state;
        s == LockState::Locked || s == LockState::Tagout
    };
    if locked {
        log::warn("starting in LOCKED/TAGOUT state, requesting upstream seal");
        tokio::spawn(upstream::seal_with_retry(state.clone(), "startup_locked".to_string()));
    }
}
