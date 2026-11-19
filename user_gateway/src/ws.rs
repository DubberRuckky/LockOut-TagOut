use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tokio::sync::broadcast::error::RecvError;

use crate::state::SharedState;

pub const MAX_WS_CLIENTS: usize = 32;

/// GET /ws: a read-only feed of JSON events. Anything the client sends is ignored.
pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<SharedState>) -> Response {
    if state.live.lock().await.ws_clients >= MAX_WS_CLIENTS {
        return (StatusCode::SERVICE_UNAVAILABLE, "too many clients").into_response();
    }
    ws.on_upgrade(move |socket| run_socket(socket, state))
}

async fn run_socket(mut socket: WebSocket, state: SharedState) {
    // Subscribe BEFORE reading the snapshot so no event can fall in between.
    let mut rx = state.events.subscribe();
    let hello = {
        let mut live = state.live.lock().await;
        live.ws_clients += 1;
        serde_json::json!({ "event": "hello", "state": live.lock.state }).to_string()
    };

    if socket.send(Message::Text(hello)).await.is_ok() {
        loop {
            tokio::select! {
                event = rx.recv() => match event {
                    Ok(text) => {
                        if socket.send(Message::Text(text)).await.is_err() {
                            break;
                        }
                    }
                    Err(RecvError::Lagged(_)) => {} // slow client missed some events; carry on
                    Err(RecvError::Closed) => break,
                },
                incoming = socket.recv() => match incoming {
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => {}
                },
            }
        }
    }

    let mut live = state.live.lock().await;
    live.ws_clients = live.ws_clients.saturating_sub(1);
}
