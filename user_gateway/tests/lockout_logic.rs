mod common;

use axum::http::{Method, StatusCode};
use common::*;
use std::time::{Duration, Instant};

use lot_gateway::handshake::{issue_challenge, login};
use lot_gateway::lockout::{
    self, gate_decision, load_lock, next_state, persist_lock, LockInfo, LockState, Trigger,
};
use lot_gateway::ratchet::{check_request, Verdict};
use lot_gateway::state::AppState;
use lot_gateway::store::Store;

fn info(state: LockState) -> LockInfo {
    LockInfo { state, anomalies: 0, reason: "t".to_string(), since: 1, initiator: None }
}

// ---------- the pure transition table ----------

#[test]
fn transition_table() {
    use LockState::*;
    use Trigger::*;
    let cases = [
        (Normal, BadCodes, Restricted),
        (Normal, FailedHandshakes, Normal),
        (Normal, Replay, Locked),
        (Normal, Manual, Locked),
        (Restricted, BadCodes, Locked),
        (Restricted, FailedHandshakes, Restricted),
        (Restricted, Replay, Locked),
        (Restricted, Manual, Locked),
        (Locked, BadCodes, Locked),
        (Locked, FailedHandshakes, Locked),
        (Locked, Replay, Locked),
        (Locked, Manual, Locked),
        (Tagout, BadCodes, Tagout),
        (Tagout, FailedHandshakes, Tagout),
        (Tagout, Replay, Tagout),
        (Tagout, Manual, Tagout),
    ];
    for (from, trigger, expected) in cases {
        assert_eq!(next_state(&info(from), trigger).state, expected, "{from:?} + {trigger:?}");
    }
}

#[test]
fn anomalies_are_counted_but_manual_lock_is_not_an_anomaly() {
    let after_one = next_state(&info(LockState::Normal), Trigger::BadCodes);
    assert_eq!(after_one.anomalies, 1);
    assert_eq!(after_one.reason, "bad_codes");
    let after_manual = next_state(&after_one, Trigger::Manual);
    assert_eq!(after_manual.anomalies, 1);
    assert_eq!(after_manual.reason, "manual");
}

// ---------- which requests each state lets through ----------

#[test]
fn gate_rules() {
    let normal = info(LockState::Normal);
    let restricted = info(LockState::Restricted);
    let locked = info(LockState::Locked);
    let (get, post) = (Method::GET, Method::POST);

    assert_eq!(gate_decision(&normal, &post, "/api/cases"), None);

    assert_eq!(gate_decision(&restricted, &get, "/api/cases"), None);
    assert_eq!(gate_decision(&restricted, &Method::HEAD, "/api/cases"), None);
    assert_eq!(gate_decision(&restricted, &post, "/api/cases"), Some(StatusCode::FORBIDDEN));
    assert_eq!(gate_decision(&restricted, &Method::DELETE, "/api"), Some(StatusCode::FORBIDDEN));
    assert_eq!(gate_decision(&restricted, &post, "/auth/login"), None);

    let denied = Some(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(gate_decision(&locked, &get, "/status"), None);
    assert_eq!(gate_decision(&locked, &post, "/status"), denied);
    assert_eq!(gate_decision(&locked, &get, "/health"), denied);
    assert_eq!(gate_decision(&locked, &get, "/ws"), denied);
    assert_eq!(gate_decision(&locked, &post, "/auth/login"), denied);
    assert_eq!(gate_decision(&locked, &post, "/auth/challenge"), denied);
    assert_eq!(gate_decision(&locked, &get, "/api/cases"), denied);
    assert_eq!(gate_decision(&locked, &post, "/restore"), None);
    assert_eq!(gate_decision(&locked, &post, "/restore/approve"), None);
    assert_eq!(gate_decision(&locked, &post, "/restorefoo"), denied);
    assert_eq!(gate_decision(&locked, &get, "/status/"), denied);
}

// ---------- persistence ----------

#[test]
fn lock_file_round_trip_missing_and_corrupt() {
    let dir = temp_dir("lockfile");
    let path = dir.join("lock-state.json");

    assert_eq!(load_lock(&path).state, LockState::Locked); // missing file means LOCKED (fail closed)

    let saved = LockInfo { state: LockState::Locked, anomalies: 2, reason: "replay".to_string(), since: 42, initiator: None };
    persist_lock(&path, &saved).unwrap();
    assert_eq!(load_lock(&path), saved);

    std::fs::write(&path, "{ garbage").unwrap();
    assert_eq!(load_lock(&path).state, LockState::Locked); // fail closed
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn restart_cannot_unlock() {
    let env = make_env();
    trip(&env, Trigger::Replay).await;
    assert_eq!(lock_state(&env).await, LockState::Locked);

    // "restart": build a brand new AppState from the same data dir
    let config = env.state.config.clone();
    let store = Store::load(&config.store_path()).unwrap();
    let restarted = AppState::new(config, store);
    assert_eq!(restarted.live.lock().await.lock.state, LockState::Locked);
}

#[tokio::test]
async fn restricted_also_survives_restart() {
    let env = make_env();
    trip(&env, Trigger::BadCodes).await;
    let config = env.state.config.clone();
    let store = Store::load(&config.store_path()).unwrap();
    let restarted = AppState::new(config, store);
    assert_eq!(restarted.live.lock().await.lock.state, LockState::Restricted);
}

// ---------- what happens when the system locks ----------

#[tokio::test]
async fn locking_drops_sessions_and_pending_nonces_and_saves_to_disk() {
    let env = make_env();
    let (_sid, _nonce) = new_session(&env).await;
    issue_challenge(&env.state, &env.device.device_id, Instant::now()).await.unwrap();
    {
        let live = env.state.live.lock().await;
        assert_eq!(live.sessions.len(), 1);
        assert_eq!(live.nonces.len(), 1);
    }
    trip(&env, Trigger::Replay).await;
    let live = env.state.live.lock().await;
    assert!(live.sessions.is_empty());
    assert!(live.nonces.is_empty());
    assert_eq!(load_lock(&env.state.config.lock_path()).state, LockState::Locked);
}

#[tokio::test]
async fn state_changes_and_lockout_are_announced_in_order() {
    let env = make_env();
    let mut rx = env.state.events.subscribe();
    trip(&env, Trigger::BadCodes).await;
    trip(&env, Trigger::BadCodes).await;

    let mut events = Vec::new();
    while let Ok(text) = rx.try_recv() {
        events.push(serde_json::from_str::<serde_json::Value>(&text).unwrap());
    }
    let names: Vec<&str> = events.iter().map(|e| e["event"].as_str().unwrap()).collect();
    assert_eq!(names, ["state_change", "state_change", "lockout"]);
    assert_eq!(events[0]["to"], "RESTRICTED");
    assert_eq!(events[1]["from"], "RESTRICTED");
    assert_eq!(events[1]["to"], "LOCKED");
    assert_eq!(events[2]["reason"], "bad_codes");
}

// ---------- triggers coming from the ratchet and the handshake ----------

#[tokio::test]
async fn replay_locks_immediately_and_is_announced() {
    let env = make_env();
    let mut rx = env.state.events.subscribe();
    let (sid, nonce) = new_session(&env).await;
    let h = valid_headers(&env, &nonce, &sid, 1);
    assert!(matches!(check_request(&env.state, &h).await, Verdict::Accepted(_)));
    assert_eq!(check_request(&env.state, &h).await, Verdict::Replay);

    assert_eq!(lock_state(&env).await, LockState::Locked);
    assert!(env.state.live.lock().await.sessions.is_empty());
    // the old session no longer works at all
    assert_eq!(check_request(&env.state, &h).await, Verdict::UnknownSession);

    let mut seen = Vec::new();
    while let Ok(text) = rx.try_recv() {
        seen.push(serde_json::from_str::<serde_json::Value>(&text).unwrap());
    }
    let replay = seen.iter().find(|e| e["event"] == "replay_rejected").unwrap();
    assert_eq!(replay["device_id"], env.device.device_id.as_str());
    assert!(seen.iter().any(|e| e["event"] == "lockout"));
}

#[tokio::test]
async fn three_bad_codes_in_a_session_restrict_once() {
    let env = make_env();
    let (sid, _nonce) = new_session(&env).await;
    let wrong = headers(&sid, "1", &"ab".repeat(16));
    for _ in 0..2 {
        assert_eq!(check_request(&env.state, &wrong).await, Verdict::BadCode);
    }
    assert_eq!(lock_state(&env).await, LockState::Normal);
    assert_eq!(check_request(&env.state, &wrong).await, Verdict::BadCode);
    assert_eq!(lock_state(&env).await, LockState::Restricted);

    // further bad codes in the same session do not raise another trigger
    for _ in 0..3 {
        assert_eq!(check_request(&env.state, &wrong).await, Verdict::BadCode);
    }
    assert_eq!(lock_state(&env).await, LockState::Restricted);
    assert_eq!(env.state.live.lock().await.lock.anomalies, 1);
}

#[tokio::test]
async fn second_anomaly_locks() {
    let env = make_env();
    let (sid, nonce) = new_session(&env).await;
    let wrong = headers(&sid, "1", &"ab".repeat(16));
    for _ in 0..3 {
        check_request(&env.state, &wrong).await;
    }
    assert_eq!(lock_state(&env).await, LockState::Restricted);

    // the second anomaly: another session with 3 bad codes
    let (sid2, _nonce2) = new_session(&env).await;
    let wrong2 = headers(&sid2, "1", &"cd".repeat(16));
    for _ in 0..3 {
        check_request(&env.state, &wrong2).await;
    }
    assert_eq!(lock_state(&env).await, LockState::Locked);
    drop(nonce);
}

#[tokio::test]
async fn failure_on_one_device_never_changes_system_state() {
    let env = make_env();
    let t0 = Instant::now();
    for _ in 0..3 {
        let n = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
        let mut req = make_req(&env.keyfile, &n);
        req.signature = "00".repeat(64);
        assert!(login(&env.state, &req, t0).await.is_err());
    }
    // Device is locked out...
    assert!(env.state.store.read().await.find_device(&env.device.device_id).unwrap().locked_out);
    // ...but system lock state NEVER changes (stays NORMAL)
    assert_eq!(lock_state(&env).await, LockState::Normal);
}

#[tokio::test]
async fn login_events_success_and_failure() {
    let env = make_env();
    let mut rx = env.state.events.subscribe();
    let t0 = Instant::now();

    let n = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let mut bad = make_req(&env.keyfile, &n);
    bad.signature = "00".repeat(64);
    assert!(login(&env.state, &bad, t0).await.is_err());

    let n = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let good = make_req(&env.keyfile, &n);
    assert!(login(&env.state, &good, t0).await.is_ok());

    // an unknown device: the claimed id must NOT be echoed back
    let mut ghost = make_req(&env.keyfile, &n);
    ghost.device_id = "<script>alert(1)</script>".to_string();
    assert!(login(&env.state, &ghost, t0).await.is_err());

    let mut seen = Vec::new();
    while let Ok(text) = rx.try_recv() {
        seen.push(serde_json::from_str::<serde_json::Value>(&text).unwrap());
    }
    let names: Vec<&str> = seen.iter().map(|e| e["event"].as_str().unwrap()).collect();
    assert_eq!(names, ["login_failure", "login_success", "login_failure"]);
    assert_eq!(seen[0]["known_device"], true);
    assert!(seen[0]["device_id"].is_null());
    assert_eq!(seen[2]["known_device"], false);
    assert!(seen[2]["device_id"].is_null());
    assert!(!seen[2].to_string().contains("script"));
}

// ---------- manual lock through the lock file ----------

#[tokio::test]
async fn manual_lock_file_is_applied_by_the_running_gateway() {
    let env = make_env();
    let (_sid, _nonce) = new_session(&env).await;
    tokio::spawn(lockout::watch_lock_file(env.state.clone()));

    lockout::manual_lock_file(&env.state.config).unwrap();

    let mut locked = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if lock_state(&env).await == LockState::Locked {
            locked = true;
            break;
        }
    }
    assert!(locked, "gateway did not pick up the manual lock within 4 seconds");
    assert!(env.state.live.lock().await.sessions.is_empty());
}

#[test]
fn manual_lock_file_keeps_anomaly_count_and_is_idempotent() {
    let dir = temp_dir("manual");
    let config = lot_gateway::config::Config {
        bind: "127.0.0.1:0".to_string(),
        upstream: "http://127.0.0.1:9000".to_string(),
        data_dir: dir.clone(),
    };
    let restricted = LockInfo { state: LockState::Restricted, anomalies: 1, reason: "bad_codes".to_string(), since: 5, initiator: None };
    persist_lock(&config.lock_path(), &restricted).unwrap();

    lockout::manual_lock_file(&config).unwrap();
    let after = load_lock(&config.lock_path());
    assert_eq!(after.state, LockState::Locked);
    assert_eq!(after.anomalies, 1);
    assert_eq!(after.reason, "manual");

    lockout::manual_lock_file(&config).unwrap(); // second call changes nothing
    assert_eq!(load_lock(&config.lock_path()), after);
    let _ = std::fs::remove_dir_all(&dir);
}
