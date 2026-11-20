mod common;

use axum::routing::post;
use axum::Router;
use common::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use lot_gateway::handshake::issue_challenge;
use lot_gateway::server::build_router;

async fn serve(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

async fn http_post(addr: SocketAddr, path: &str, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await.unwrap();
    let status: u16 = reply.split_whitespace().nth(1).unwrap().parse().unwrap();
    let resp_body = reply.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, resp_body)
}

#[tokio::test]
async fn face_check_refused_without_face_and_accepted_with_face() {
    // 1. Mock upstream that accepts face check
    let mock = Router::new().route(
        "/internal/face-check",
        post(|| async {
            axum::Json(serde_json::json!({
                "ok": true,
                "reason": "presence_ok",
                "face_count": 1,
                "frames_with_face": 3,
                "capture_id": "cap_test_123"
            }))
        }),
    );
    let upstream_addr = serve(mock).await;

    // Gateway with require_face = true
    let mut env = make_env_upstream(&format!("http://{upstream_addr}"));
    let mut config = env.state.config.clone();
    config.require_face = true;
    let store = lot_gateway::store::Store::load(&config.store_path()).unwrap();
    let state = lot_gateway::state::AppState::new(config, store);
    env.state = state;

    let gw_addr = serve(build_router(env.state.clone())).await;

    // 1. Challenge 1: attempt login BEFORE face check -> MUST BE REFUSED (401)
    let t0 = Instant::now();
    let nonce1 = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let login_body1 = lot_gateway::crypto::sign_login_body(&env.keyfile, &nonce1).unwrap();
    let (status, _) = http_post(gw_addr, "/auth/login", &login_body1).await;
    assert_eq!(status, 401, "login without face check must be rejected");

    // 2. Challenge 2: perform face check first, then login -> SUCCEEDS (200)
    let nonce2 = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let face_body = serde_json::json!({
        "device_id": env.device.device_id,
        "nonce": nonce2,
        "frames": ["dGVzdF9mcmFtZQ=="]
    }).to_string();
    let (status, body) = http_post(gw_addr, "/auth/face", &face_body).await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["ok"], true);

    let login_body2 = lot_gateway::crypto::sign_login_body(&env.keyfile, &nonce2).unwrap();
    let (status, body) = http_post(gw_addr, "/auth/login", &login_body2).await;
    assert_eq!(status, 200, "login after valid face check must succeed");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["session_id"].as_str().is_some());
}

#[tokio::test]
async fn app_down_means_deny() {
    // Gateway points to dead port (app down)
    let env = make_env_upstream("http://127.0.0.1:54321");
    let gw_addr = serve(build_router(env.state.clone())).await;

    let t0 = Instant::now();
    let nonce = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();

    let face_body = serde_json::json!({
        "device_id": env.device.device_id,
        "nonce": nonce,
        "frames": ["dGVzdF9mcmFtZQ=="]
    }).to_string();

    let (status, body) = http_post(gw_addr, "/auth/face", &face_body).await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["ok"], false);
    assert_eq!(json["reason"], "try_again");
}

#[tokio::test]
async fn oversize_body_rejected() {
    let env = make_env();
    let gw_addr = serve(build_router(env.state.clone())).await;

    // Exceed 1.5 MB body limit
    let big_frame = "a".repeat(1_600_000);
    let face_body = serde_json::json!({
        "device_id": env.device.device_id,
        "nonce": "testnonce",
        "frames": [big_frame]
    }).to_string();

    let (status, _) = http_post(gw_addr, "/auth/face", &face_body).await;
    assert_eq!(status, 401, "oversize face body must be rejected with 401");
}

#[tokio::test]
async fn unknown_device_makes_no_app_call() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = call_count.clone();

    let mock = Router::new().route(
        "/internal/face-check",
        post(move || {
            let c = counter.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                axum::Json(serde_json::json!({ "ok": true }))
            }
        }),
    );
    let upstream_addr = serve(mock).await;

    let env = make_env_upstream(&format!("http://{upstream_addr}"));
    let gw_addr = serve(build_router(env.state.clone())).await;

    let face_body = serde_json::json!({
        "device_id": "dev-unknown-ghost-999",
        "nonce": "dummy_nonce",
        "frames": ["dGVzdF9mcmFtZQ=="]
    }).to_string();

    let (status, _) = http_post(gw_addr, "/auth/face", &face_body).await;
    assert_eq!(status, 401);
    assert_eq!(call_count.load(Ordering::SeqCst), 0, "upstream must not be called for unknown device");
}

#[tokio::test]
async fn face_failures_never_change_system_lock_state() {
    let mock = Router::new().route(
        "/internal/face-check",
        post(|| async {
            axum::Json(serde_json::json!({
                "ok": false,
                "reason": "no_face",
            }))
        }),
    );
    let upstream_addr = serve(mock).await;

    let env = make_env_upstream(&format!("http://{upstream_addr}"));
    let gw_addr = serve(build_router(env.state.clone())).await;

    let t0 = Instant::now();
    let nonce = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();

    let face_body = serde_json::json!({
        "device_id": env.device.device_id,
        "nonce": nonce,
        "frames": ["dGVzdF9mcmFtZQ=="]
    }).to_string();

    // 5 repeated face failures
    for _ in 0..5 {
        let (status, body) = http_post(gw_addr, "/auth/face", &face_body).await;
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["ok"], false);
    }

    // System state MUST remain NORMAL
    assert_eq!(lock_state(&env).await, lot_gateway::lockout::LockState::Normal);
}
