use std::net::SocketAddr;

use lot_gateway::config::Config;
use lot_gateway::lockout;
use lot_gateway::server;
use lot_gateway::state::AppState;
use lot_gateway::store::Store;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    // NOTE: tracing macros print nothing until a subscriber is installed.
    // tracing-subscriber is not on the approved crate list, so the eprintln!
    // lines below are the visible startup log for now.
    let config = Config::from_env();

    std::fs::create_dir_all(&config.data_dir)
        .map_err(|e| format!("cannot create data dir {:?}: {e}", config.data_dir))?;

    let addr: SocketAddr = config
        .bind
        .parse()
        .map_err(|e| format!("LOT_BIND {:?} is not a valid address: {e}", config.bind))?;

    // Fail closed: a corrupt store stops startup instead of being overwritten.
    let store = Store::load(&config.store_path())?;

    tracing::info!("starting lot-gateway on {}", addr);
    eprintln!(
        "lot-gateway listening on {addr} (data dir {:?}, upstream {})",
        config.data_dir, config.upstream
    );

    let state = AppState::new(config, store);
    lockout::seal_if_locked(state.clone()).await;
    tokio::spawn(lockout::watch_lock_file(state.clone()));
    let app = server::build_router(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot bind {addr}: {e}"))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| format!("server error: {e}"))?;
    Ok(())
}
