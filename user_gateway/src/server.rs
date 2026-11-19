use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::handshake;
use crate::lockout;
use crate::state::SharedState;
use crate::ws;

pub fn build_router(state: SharedState) -> Router {
    let gate_layer = middleware::from_fn_with_state(state.clone(), gate);
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/ws", get(ws::ws_handler))
        .route("/auth/challenge", post(handshake::challenge_handler))
        .route("/auth/login", post(handshake::login_handler))
        .layer(gate_layer)
        .with_state(state)
}

/// Runs before every route: applies the lockout rules (503 when LOCKED, read-only
/// /api/* when RESTRICTED). Fails closed: the decision is made from the live state.
async fn gate(State(state): State<SharedState>, request: Request, next: Next) -> Response {
    let decision = {
        let live = state.live.lock().await;
        lockout::gate_decision(&live.lock, request.method(), request.uri().path())
    };
    match decision {
        Some(code) => (code, "denied by lockout state").into_response(),
        None => next.run(request).await,
    }
}

// Deliberately returns nothing about users or devices (unauthenticated route).
async fn health(State(_state): State<SharedState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "lot-gateway" }))
}

/// Unauthenticated by design (it must work while LOCKED). Coarse info only.
async fn status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let live = state.live.lock().await;
    Json(serde_json::json!({
        "state": live.lock.state,
        "anomalies": live.lock.anomalies,
        "since": live.lock.since,
    }))
}
