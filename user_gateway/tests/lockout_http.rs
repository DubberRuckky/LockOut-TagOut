mod common;

use axum::routing::post;
use axum::Router;
use common::*;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use lot_gateway::handshake::{issue_challenge, login};
use lot_gateway::lockout::Trigger;
use lot_gateway::server::build_router;

async fn serve(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

async fn http(addr: SocketAddr, method: &str, path: &str, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await.unwrap();
    let status: u16 = reply.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = reply.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

#[tokio::test]
async fn status_endpoint_reports_state() {
    let env = make_env();
    let addr = serve(build_router(env.state.clone())).await;

    let (code, body) = http(addr, "GET", "/status", "").await;
    assert_eq!(code, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["state"], "NORMAL");
    assert_eq!(json["anomalies"], 0);

    trip(&env, Trigger::BadCodes).await;
    let (_, body) = http(addr, "GET", "/status", "").await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["state"], "RESTRICTED");
    assert_eq!(json["anomalies"], 1);
}

#[tokio::test]
async fn locked_gateway_answers_503_except_status_and_restore() {
    let env = make_env();
    let addr = serve(build_router(env.state.clone())).await;
    trip(&env, Trigger::Replay).await;

    let device = format!("{{\"device_id\":\"{}\"}}", env.device.device_id);
    assert_eq!(http(addr, "GET", "/health", "").await.0, 503);
    assert_eq!(http(addr, "POST", "/auth/challenge", &device).await.0, 503);
    assert_eq!(http(addr, "POST", "/auth/login", "{}").await.0, 503);
    assert_eq!(http(addr, "GET", "/ws", "").await.0, 503);
    assert_eq!(http(addr, "POST", "/status", "").await.0, 503);
    assert_eq!(http(addr, "GET", "/api/cases", "").await.0, 503);

    let (code, body) = http(addr, "GET", "/status", "").await;
    assert_eq!(code, 200);
    assert!(body.contains("LOCKED"));

    // /restore is reserved for M6: the gate lets it through (no route yet, so 404, not 503)
    assert_eq!(http(addr, "POST", "/restore", "{}").await.0, 404);
}

#[tokio::test]
async fn restricted_gateway_blocks_writes_to_api_only() {
    let env = make_env();
    let addr = serve(build_router(env.state.clone())).await;
    trip(&env, Trigger::BadCodes).await;

    assert_eq!(http(addr, "GET", "/health", "").await.0, 200);
    assert_eq!(http(addr, "POST", "/api/cases", "{}").await.0, 403);
    assert_eq!(http(addr, "PUT", "/api/cases/1", "{}").await.0, 403);
    // a read-only request passes the gate (now handled by /api proxy, which checks auth -> 401)
    assert_eq!(http(addr, "GET", "/api/cases", "").await.0, 401);
    // logging in is still possible while RESTRICTED
    let device = format!("{{\"device_id\":\"{}\"}}", env.device.device_id);
    assert_eq!(http(addr, "POST", "/auth/challenge", &device).await.0, 200);
}

// ---------- WebSocket feed (hand-rolled client, no extra crates) ----------

async fn ws_connect(addr: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = "GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
                   Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap()); // byte by byte: do not swallow the first frame
    }
    let head = String::from_utf8(head).unwrap();
    assert!(head.starts_with("HTTP/1.1 101"), "got: {head}");
    stream
}

/// Read one unmasked server text frame (handles 7-bit and 16-bit lengths).
async fn ws_next_event(stream: &mut TcpStream) -> serde_json::Value {
    let read = async {
        let mut first = [0u8; 2];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(first[0] & 0x0f, 1, "expected a text frame");
        let mut len = (first[1] & 0x7f) as usize;
        if len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).await.unwrap();
            len = u16::from_be_bytes(ext) as usize;
        }
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await.unwrap();
        serde_json::from_slice::<serde_json::Value>(&payload).unwrap()
    };
    tokio::time::timeout(Duration::from_secs(5), read).await.expect("timed out waiting for a ws event")
}

#[tokio::test]
async fn websocket_pushes_hello_login_and_lockout_events() {
    let env = make_env();
    let addr = serve(build_router(env.state.clone())).await;
    let mut ws = ws_connect(addr).await;

    let hello = ws_next_event(&mut ws).await;
    assert_eq!(hello["event"], "hello");
    assert_eq!(hello["state"], "NORMAL");

    let t0 = Instant::now();
    let n = issue_challenge(&env.state, &env.device.device_id, t0).await.unwrap();
    let mut bad = make_req(&env.keyfile, &n);
    bad.signature = "00".repeat(64);
    assert!(login(&env.state, &bad, t0).await.is_err());
    let failure = ws_next_event(&mut ws).await;
    assert_eq!(failure["event"], "login_failure");

    trip(&env, Trigger::Replay).await;
    let change = ws_next_event(&mut ws).await;
    assert_eq!(change["event"], "state_change");
    assert_eq!(change["to"], "LOCKED");
    let lockout = ws_next_event(&mut ws).await;
    assert_eq!(lockout["event"], "lockout");
    assert_eq!(lockout["reason"], "replay");
}

// ---------- the seal call to the upstream ----------

#[tokio::test]
async fn locking_calls_upstream_seal() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
    let mock = Router::new().route(
        "/internal/seal",
        post(move |body: String| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(body).await;
                "ok"
            }
        }),
    );
    let upstream = serve(mock).await;

    let env = make_env_upstream(&format!("http://{upstream}"));
    trip(&env, Trigger::Replay).await;

    let body = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("upstream /internal/seal was not called")
        .unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["reason"], "replay");
}

#[tokio::test]
async fn unreachable_upstream_does_not_stop_the_lock() {
    // default env points at a dead port: the lock must still hold
    let env = make_env();
    trip(&env, Trigger::Replay).await;
    assert_eq!(lock_state(&env).await, lot_gateway::lockout::LockState::Locked);
}
