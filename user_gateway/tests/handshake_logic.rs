mod common;

use common::*;
use std::time::{Duration, Instant};

use lot_gateway::crypto::{self, DEFAULT_DEVICE_CONFIG};
use lot_gateway::handshake::{issue_challenge, login, LoginRequest, MAX_NONCES};

#[tokio::test]
async fn valid_login_creates_session_with_documented_seed() {
    let env = make_env();
    let t0 = Instant::now();
    let nonce = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let req = make_req(&env.keyfile, &nonce);
    let session_id = login(&env.state, &req, t0).await.unwrap();

    assert_eq!(session_id.len(), 32);
    let live = env.state.live.lock().await;
    let session = live.sessions.get(&session_id).unwrap();
    assert_eq!(session.officer_id, "alice");
    assert_eq!(session.device_id, env.device.device_id);
    let expected = crypto::derive_session_seed(
        &hex::decode(&env.device.shared_secret_hex).unwrap(),
        &hex::decode(&nonce).unwrap(),
        &env.device.device_id,
    )
    .unwrap();
    assert_eq!(session.seed, expected);
}

#[tokio::test]
async fn nonce_is_single_use() {
    let env = make_env();
    let t0 = Instant::now();
    let nonce = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let req = make_req(&env.keyfile, &nonce);
    assert!(login(&env.state, &req, t0).await.is_ok());
    assert!(login(&env.state, &req, t0).await.is_err());
}

#[tokio::test]
async fn nonce_expiry_edge_30_ok_31_fails() {
    let env = make_env();
    let t0 = Instant::now();

    let n1 = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let r1 = make_req(&env.keyfile, &n1);
    assert!(login(&env.state, &r1, t0 + Duration::from_secs(30)).await.is_ok());

    let n2 = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let r2 = make_req(&env.keyfile, &n2);
    assert!(login(&env.state, &r2, t0 + Duration::from_secs(31)).await.is_err());
}

#[tokio::test]
async fn bad_signature_is_denied_and_counted() {
    let env = make_env();
    let t0 = Instant::now();
    let nonce = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let mut req = make_req(&env.keyfile, &nonce);
    req.signature = "00".repeat(64);
    assert!(login(&env.state, &req, t0).await.is_err());
    let live = env.state.live.lock().await;
    assert_eq!(live.failures.get(&env.device.device_id), Some(&1));
    assert!(live.sessions.is_empty());
}

#[tokio::test]
async fn malformed_signature_is_denied() {
    let env = make_env();
    let t0 = Instant::now();
    let nonce = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let mut req = make_req(&env.keyfile, &nonce);
    req.signature = "not-hex".to_string();
    assert!(login(&env.state, &req, t0).await.is_err());
}

#[tokio::test]
async fn wrong_config_hash_is_denied() {
    let env = make_env();
    let t0 = Instant::now();
    let nonce = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let mut req = make_req(&env.keyfile, &nonce);
    req.config_hash = crypto::config_hash_hex("tampered-device-config");
    assert!(login(&env.state, &req, t0).await.is_err());
}

#[tokio::test]
async fn unknown_nonce_is_denied_and_counted() {
    let env = make_env();
    let req = make_req(&env.keyfile, &"ab".repeat(32));
    assert!(login(&env.state, &req, Instant::now()).await.is_err());
    let live = env.state.live.lock().await;
    assert_eq!(live.failures.get(&env.device.device_id), Some(&1));
}

#[tokio::test]
async fn three_failures_flag_device_once_and_block_even_valid_login() {
    let env = make_env();
    let t0 = Instant::now();
    for _ in 0..3 {
        let nonce = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
        let mut req = make_req(&env.keyfile, &nonce);
        req.signature = "00".repeat(64);
        assert!(login(&env.state, &req, t0).await.is_err());
    }
    {
        let live = env.state.live.lock().await;
        assert!(live.flagged.contains(&env.device.device_id));
        let store = env.state.store.read().await;
        assert!(store.find_device(&env.device.device_id).unwrap().locked_out);
    }
    // Fully valid credentials are now refused.
    let nonce = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let req = make_req(&env.keyfile, &nonce);
    assert!(login(&env.state, &req, t0).await.is_err());
    let live = env.state.live.lock().await;
    assert!(live.sessions.is_empty());
}

#[tokio::test]
async fn unknown_device_gets_nonce_but_nothing_is_stored_or_counted() {
    let env = make_env();
    let t0 = Instant::now();
    let nonce = issue_challenge(&env.state, "dev-doesnotexist", t0).await.unwrap();
    assert_eq!(nonce.len(), 64);
    assert!(env.state.live.lock().await.nonces.is_empty());

    let req = LoginRequest {
        device_id: "dev-doesnotexist".to_string(),
        nonce,
        signature: "00".repeat(64),
        config_hash: crypto::config_hash_hex(DEFAULT_DEVICE_CONFIG),
        passcode: String::new(),
    };
    assert!(login(&env.state, &req, t0).await.is_err());
    assert!(env.state.live.lock().await.failures.is_empty());
}

#[tokio::test]
async fn nonce_is_bound_to_the_device_it_was_issued_to() {
    let env = make_env();
    let (bob_device, bob_keyfile) = crypto::new_device("bob", DEFAULT_DEVICE_CONFIG);
    env.state.store.write().await.add_user(bob_device.clone()).unwrap();

    let t0 = Instant::now();
    let nonce = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();

    // Bob presents alice's nonce, correctly signed with bob's own key: denied.
    let bob_req = make_req(&bob_keyfile, &nonce);
    assert!(login(&env.state, &bob_req, t0).await.is_err());

    // The nonce was not burned, so alice can still use it.
    let alice_req = make_req(&env.keyfile, &nonce);
    assert!(login(&env.state, &alice_req, t0).await.is_ok());
}

#[tokio::test]
async fn revoked_officer_cannot_log_in() {
    let env = make_env();
    env.state.store.write().await.revoke_officer("alice").unwrap();
    let t0 = Instant::now();
    let nonce = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let req = make_req(&env.keyfile, &nonce);
    assert!(login(&env.state, &req, t0).await.is_err());
    assert!(env.state.live.lock().await.sessions.is_empty());
}

#[tokio::test]
async fn pending_nonce_cap_is_enforced_and_expiry_frees_space() {
    let env = make_env();
    let t0 = Instant::now();
    for _ in 0..MAX_NONCES {
        issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    }
    assert!(issue_challenge(&env.state, &env.device.device_id, t0).await.is_err());
    let later = t0 + Duration::from_secs(31);
    assert!(issue_challenge(&env.state, &env.device.device_id, later).await.is_ok());
}

#[tokio::test]
async fn passcode_verification_success_and_failure() {
    let env = make_env();
    let (device, keyfile) = crypto::new_device("dave", DEFAULT_DEVICE_CONFIG);
    let hash = lot_gateway::store::hash_passcode("Secret123!").unwrap();
    env.state.store.write().await.add_user_with_rank(device.clone(), hash, 1).unwrap();

    let t0 = Instant::now();
    // 1. Wrong passcode fails
    let nonce = issue_challenge(&env.state, &device.device_id, t0).await.unwrap();
    let mut req = make_req(&keyfile, &nonce);
    req.passcode = "WrongPass".to_string();
    assert!(login(&env.state, &req, t0).await.is_err());

    // 2. Correct passcode succeeds
    let nonce = issue_challenge(&env.state, &device.device_id, t0).await.unwrap();
    let mut req = make_req(&keyfile, &nonce);
    req.passcode = "Secret123!".to_string();
    let res = login(&env.state, &req, t0).await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn device_reset_clears_lockout_and_allows_login() {
    let env = make_env();
    let t0 = Instant::now();
    // 3 failed handshakes lock the device
    for _ in 0..3 {
        let nonce = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
        let mut req = make_req(&env.keyfile, &nonce);
        req.signature = "00".repeat(64);
        assert!(login(&env.state, &req, t0).await.is_err());
    }
    assert!(env.state.store.read().await.find_device(&env.device.device_id).unwrap().locked_out);

    // Reset device
    env.state.store.write().await.reset_device(&env.device.device_id).unwrap();
    assert!(!env.state.store.read().await.find_device(&env.device.device_id).unwrap().locked_out);

    // Now login succeeds
    let nonce = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let req = make_req(&env.keyfile, &nonce);
    assert!(login(&env.state, &req, t0).await.is_ok());
}
