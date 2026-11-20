use std::time::Duration;

use crate::log;
use crate::state::SharedState;
use crate::store::now_unix;

const SEAL_ATTEMPTS: u32 = 3;

/// POST {LOT_UPSTREAM}/internal/seal, retried a few times. Failure never
/// unlocks anything: the gateway stays LOCKED whether or not the upstream answered.
pub async fn seal_with_retry(state: SharedState, reason: String) {
    let url = format!("{}/internal/seal", state.config.upstream.trim_end_matches('/'));
    let body = serde_json::json!({ "reason": reason, "time": now_unix() }).to_string();

    for attempt in 1..=SEAL_ATTEMPTS {
        let result = state
            .http
            .post(&url)
            .header("content-type", "application/json")
            .header("x-gateway-token", &state.gateway_token)
            .body(body.clone())
            .send()
            .await;
        match result {
            Ok(resp) if resp.status().is_success() => {
                log::info("upstream seal acknowledged");
                return;
            }
            Ok(resp) => log::warn(&format!("seal attempt {attempt}: upstream answered {}", resp.status())),
            Err(e) => log::warn(&format!("seal attempt {attempt} failed: {e}")),
        }
        if attempt < SEAL_ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    log::warn("upstream seal FAILED after retries; gateway stays LOCKED regardless");
    state.publish("seal_failed", serde_json::json!({}));
}

/// Send an audit event to the upstream app.
pub async fn send_audit_event(state: &SharedState, mut event: serde_json::Value) {
    let url = format!("{}/internal/audit", state.config.upstream.trim_end_matches('/'));
    if let Some(obj) = event.as_object_mut() {
        if !obj.contains_key("time") {
            obj.insert("time".to_string(), serde_json::json!(now_unix()));
        }
    }
    let body = event.to_string();
    let res = state
        .http
        .post(&url)
        .header("content-type", "application/json")
        .header("x-gateway-token", &state.gateway_token)
        .body(body)
        .send()
        .await;
    if let Err(e) = res {
        log::warn(&format!("failed to send audit event to upstream: {e}"));
    }
}

/// Call POST /internal/unseal on the upstream app.
pub async fn unseal_upstream(state: SharedState) {
    let url = format!("{}/internal/unseal", state.config.upstream.trim_end_matches('/'));
    let body = serde_json::json!({ "time": now_unix() }).to_string();
    let res = state
        .http
        .post(&url)
        .header("content-type", "application/json")
        .header("x-gateway-token", &state.gateway_token)
        .body(body)
        .send()
        .await;
    if let Err(e) = res {
        log::warn(&format!("failed to unseal upstream: {e}"));
    }
}

