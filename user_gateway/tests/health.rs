use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use lot_gateway::config::Config;
use lot_gateway::server::build_router;
use lot_gateway::state::AppState;
use lot_gateway::store::Store;

#[tokio::test]
async fn health_returns_200_and_ok() {
    let data_dir = std::env::temp_dir().join("lot-health-test-nonexistent");
    let config = Config {
        bind: "127.0.0.1:0".to_string(),
        upstream: "http://127.0.0.1:9000".to_string(),
        data_dir: data_dir.clone(),
        require_face: false,
    };
    let store_path: PathBuf = data_dir.join("store.json");
    let store = Store::load(&store_path).unwrap(); // missing file = empty store
    let app = build_router(AppState::new(config, store));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await.unwrap();

    assert!(reply.starts_with("HTTP/1.1 200"), "got: {reply}");
    assert!(reply.contains("\"status\":\"ok\""), "got: {reply}");
}
