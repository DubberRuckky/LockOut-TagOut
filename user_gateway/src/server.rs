use axum::body::Bytes;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::net::SocketAddr;

use crate::handshake;
use crate::lockout::{self, Trigger};
use crate::ratchet::{self, Verdict};
use crate::state::SharedState;
use crate::upstream;
use crate::ws;

pub fn build_router(state: SharedState) -> Router {
    let gate_layer = middleware::from_fn_with_state(state.clone(), gate);
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/ws", get(ws::ws_handler))
        .route("/auth/challenge", post(handshake::challenge_handler))
        .route("/auth/login", post(handshake::login_handler))
        .route("/admin/users", get(admin_users))
        .route("/admin/devices", get(admin_devices))
        .route("/admin/lock", post(admin_lock))
        .route("/", get(static_proxy))
        .route("/ui", get(static_proxy))
        .route("/ui/*path", get(static_proxy))
        .route("/api/tagout", post(api_tagout))
        .route("/api", axum::routing::any(api_proxy))
        .route("/api/*path", axum::routing::any(api_proxy))
        .layer(gate_layer)
        .with_state(state)
}

/// Runs before every route: applies lockout rules.
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

async fn health(State(_state): State<SharedState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "lot-gateway" }))
}

async fn status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let live = state.live.lock().await;
    Json(serde_json::json!({
        "state": live.lock.state,
        "anomalies": live.lock.anomalies,
        "since": live.lock.since,
    }))
}

fn check_admin_token(
    state: &SharedState,
    headers: &HeaderMap,
    connect_info: Option<&ConnectInfo<SocketAddr>>,
) -> bool {
    if let Some(ci) = connect_info {
        if !ci.0.ip().is_loopback() {
            return false;
        }
    }
    match headers.get("x-gateway-token").and_then(|v| v.to_str().ok()) {
        Some(t) => crate::crypto::ct_eq(t.trim(), &state.gateway_token),
        None => false,
    }
}

async fn admin_users(
    State(state): State<SharedState>,
    request: Request,
) -> Response {
    let ci = request.extensions().get::<ConnectInfo<SocketAddr>>();
    if !check_admin_token(&state, request.headers(), ci) {
        upstream::send_audit_event(
            &state,
            serde_json::json!({ "event": "token_auth_failed", "endpoint": "/admin/users" }),
        ).await;
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let officers = state.store.read().await.data.officers.clone();
    Json(officers).into_response()
}

async fn admin_devices(
    State(state): State<SharedState>,
    request: Request,
) -> Response {
    let ci = request.extensions().get::<ConnectInfo<SocketAddr>>();
    if !check_admin_token(&state, request.headers(), ci) {
        upstream::send_audit_event(
            &state,
            serde_json::json!({ "event": "token_auth_failed", "endpoint": "/admin/devices" }),
        ).await;
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let store = state.store.read().await;
    let safe_devices: Vec<_> = store.data.devices.iter().map(|d| {
        serde_json::json!({
            "device_id": d.device_id,
            "officer_id": d.officer_id,
            "public_key_hex": d.public_key_hex,
            "config_hash_hex": d.config_hash_hex,
            "revoked": d.revoked,
            "created_at": d.created_at,
        })
    }).collect();
    Json(safe_devices).into_response()
}

async fn admin_lock(
    State(state): State<SharedState>,
    request: Request,
) -> Response {
    let ci = request.extensions().get::<ConnectInfo<SocketAddr>>();
    if !check_admin_token(&state, request.headers(), ci) {
        upstream::send_audit_event(
            &state,
            serde_json::json!({ "event": "token_auth_failed", "endpoint": "/admin/lock" }),
        ).await;
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let mut live = state.live.lock().await;
    lockout::trigger(&state, &mut live, Trigger::Manual);
    Json(serde_json::json!({ "ok": true, "state": "LOCKED" })).into_response()
}

async fn static_proxy(
    State(state): State<SharedState>,
    request: Request,
) -> Response {
    if request.method() != Method::GET {
        return (StatusCode::METHOD_NOT_ALLOWED, "method not allowed").into_response();
    }
    let path = request.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or(request.uri().path());
    let target_url = format!("{}{path}", state.config.upstream.trim_end_matches('/'));

    let mut req_builder = state.http.get(&target_url);
    for (name, value) in request.headers().iter() {
        if name != "host" {
            req_builder = req_builder.header(name, value);
        }
    }

    match req_builder.send().await {
        Ok(resp) => forward_response(resp).await,
        Err(_) => (StatusCode::BAD_GATEWAY, "upstream unreachable").into_response(),
    }
}

async fn api_proxy(
    State(state): State<SharedState>,
    request: Request,
) -> Response {
    let verdict = ratchet::check_request(&state, request.headers()).await;
    let authed = match verdict {
        Verdict::Accepted(a) => a,
        _ => return (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
    };

    let (rank_tier, lock_state) = {
        let live = state.live.lock().await;
        let ls = live.lock.state_name().to_string();
        let store = state.store.read().await;
        let tier = store.find_officer(&authed.officer_id).map(|o| o.rank_tier).unwrap_or(1);
        (tier, ls)
    };

    let path = request.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or(request.uri().path());
    let target_url = format!("{}{path}", state.config.upstream.trim_end_matches('/'));
    let method = request.method().clone();
    let incoming_headers = request.headers().clone();

    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid body").into_response(),
    };

    let mut req_builder = state.http.request(method, &target_url);
    for (name, value) in incoming_headers.iter() {
        let name_str = name.as_str().to_ascii_lowercase();
        if !name_str.starts_with("x-") && name_str != "host" {
            req_builder = req_builder.header(name, value);
        }
    }

    req_builder = req_builder
        .header("x-gateway-token", &state.gateway_token)
        .header("x-officer-id", &authed.officer_id)
        .header("x-device-id", &authed.device_id)
        .header("x-session-id", &authed.session_id)
        .header("x-rank-tier", rank_tier.to_string())
        .header("x-lock-state", &lock_state)
        .body(body_bytes);

    match req_builder.send().await {
        Ok(resp) => forward_response(resp).await,
        Err(_) => (StatusCode::BAD_GATEWAY, "upstream unreachable").into_response(),
    }
}

async fn api_tagout(
    State(state): State<SharedState>,
    request: Request,
) -> Response {
    let verdict = ratchet::check_request(&state, request.headers()).await;
    let authed = match verdict {
        Verdict::Accepted(a) => a,
        _ => return (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
    };

    let rank_tier = {
        let store = state.store.read().await;
        store.find_officer(&authed.officer_id).map(|o| o.rank_tier).unwrap_or(1)
    };

    if rank_tier < lockout::TAGOUT_MIN_RANK {
        return (StatusCode::FORBIDDEN, "insufficient rank tier for tagout").into_response();
    }

    {
        let mut live = state.live.lock().await;
        lockout::trigger_tagout(&state, &mut live, &authed.officer_id);
    }

    Json(serde_json::json!({
        "ok": true,
        "state": "TAGOUT",
        "initiator": authed.officer_id
    })).into_response()
}

async fn forward_response(resp: reqwest::Response) -> Response {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = Response::builder().status(status);
    for (k, v) in resp.headers() {
        let name = k.as_str().to_ascii_lowercase();
        if name != "transfer-encoding" && name != "connection" {
            builder = builder.header(k, v);
        }
    }
    let body = resp.bytes().await.unwrap_or_else(|_| Bytes::new());
    builder.body(axum::body::Body::from(body)).unwrap_or_else(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "failed to build response").into_response()
    })
}
