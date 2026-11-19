mod common;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use lot_gateway::cli;
use lot_gateway::config::Config;
use lot_gateway::crypto::{self, Keyfile, DEFAULT_DEVICE_CONFIG};
use lot_gateway::server::build_router;
use lot_gateway::state::AppState;
use lot_gateway::store::Store;

async fn http_post(addr: std::net::SocketAddr, path: &str, body: &str) -> (u16, String) {
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
    let body = reply.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

#[tokio::test]
async fn full_handshake_over_http_with_live_store_reload() {
    // The server starts with an EMPTY store on disk...
    let dir = temp_dir("http");
    let config = Config {
        bind: "127.0.0.1:0".to_string(),
        upstream: "http://127.0.0.1:9000".to_string(),
        data_dir: dir.clone(),
    };
    let store_path = config.store_path();
    let store = Store::load(&store_path).unwrap();
    let app = build_router(AppState::new(config, store));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // ...then lotoctl adds an officer while it is running.
    let key_path = dir.join("carol.keyfile.json");
    let mut disk_store = Store::load(&store_path).unwrap();
    cli::add_user(&mut disk_store, "carol", DEFAULT_DEVICE_CONFIG, &key_path).unwrap();
    let keyfile: Keyfile =
        serde_json::from_str(&std::fs::read_to_string(&key_path).unwrap()).unwrap();

    // Challenge.
    let challenge_body = format!("{{\"device_id\":\"{}\"}}", keyfile.device_id);
    let (status, body) = http_post(addr, "/auth/challenge", &challenge_body).await;
    assert_eq!(status, 200, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let nonce = json["nonce"].as_str().unwrap().to_string();

    // Login succeeds once...
    let login_body = crypto::sign_login_body(&keyfile, &nonce).unwrap();
    let (status, body) = http_post(addr, "/auth/login", &login_body).await;
    assert_eq!(status, 200, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["session_id"].as_str().unwrap().len(), 32);

    // ...and replaying the same body gets a generic 401 that leaks no reason.
    let (status, body) = http_post(addr, "/auth/login", &login_body).await;
    assert_eq!(status, 401);
    assert_eq!(body, "unauthorized");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn malformed_and_unknown_requests_are_denied_generically() {
    let env = make_env();
    let app = build_router(env.state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // The in-memory env points at a store file that does not exist, so a reload
    // yields an empty store: every device is unknown. All of these must be 401.
    let (s, b) = http_post(addr, "/auth/login", "{ not json").await;
    assert_eq!((s, b.as_str()), (401, "unauthorized"));

    let (s, _) = http_post(addr, "/auth/login", "{\"device_id\":\"x\"}").await;
    assert_eq!(s, 401);

    let (s, _) = http_post(addr, "/auth/challenge", "").await;
    assert_eq!(s, 401);

    let big = "x".repeat(10_000);
    let (s, _) = http_post(addr, "/auth/login", &big).await;
    assert_eq!(s, 401);

    // Unknown device: challenge still answers 200 (no device enumeration).
    let (s, b) = http_post(addr, "/auth/challenge", "{\"device_id\":\"dev-nope\"}").await;
    assert_eq!(s, 200);
    assert!(b.contains("\"nonce\""));
}
