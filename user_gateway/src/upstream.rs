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
