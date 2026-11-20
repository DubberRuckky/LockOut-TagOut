use axum::http::HeaderMap;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::crypto::{self, Keyfile};
use crate::lockout::{self, Trigger};
use crate::log;
use crate::state::{Live, Session, SharedState, REPLAY_HISTORY_CAP};
use crate::store::Res;

/// How many counters a message may skip ahead (to survive dropped messages).
pub const WINDOW: u64 = 3;
/// The device-side helper walks the chain from the start, so cap it.
const MAX_CLIENT_COUNTER: u64 = 1_000_000;

// The hash chain:
//   key_0 = session seed
//   key_n = HKDF-SHA256(ikm = key_{n-1}, salt = none, info = "lot-gateway/chain/v1")      (32 bytes)
//   code_n = HKDF-SHA256(ikm = key_n,    salt = none,
//                        info = "lot-gateway/code/v1" + counter as 8 big-endian bytes)    (16 bytes, 32 hex chars)
// The first request uses counter 1. The server keeps only the key for the last
// accepted counter, so it cannot recompute older codes (that is on purpose).

pub fn next_key(key: &[u8; 32]) -> Res<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, key);
    let mut out = [0u8; 32];
    hk.expand(b"lot-gateway/chain/v1", &mut out)
        .map_err(|_| "hkdf expand failed".to_string())?;
    Ok(out)
}

pub fn code_from_key(key: &[u8; 32], counter: u64) -> Res<String> {
    let hk = Hkdf::<Sha256>::new(None, key);
    let mut info = b"lot-gateway/code/v1".to_vec();
    info.extend_from_slice(&counter.to_be_bytes());
    let mut out = [0u8; 16];
    hk.expand(&info, &mut out)
        .map_err(|_| "hkdf expand failed".to_string())?;
    Ok(hex::encode(out))
}

/// Device side: the code for `counter`, computed from the seed.
pub fn client_code(seed: &[u8; 32], counter: u64) -> Res<String> {
    if counter == 0 || counter > MAX_CLIENT_COUNTER {
        return Err(format!("counter must be between 1 and {MAX_CLIENT_COUNTER}"));
    }
    let mut key = *seed;
    for _ in 0..counter {
        key = next_key(&key)?;
    }
    code_from_key(&key, counter)
}

/// Device side: the three headers for one request (used by `lotoctl sign-request`).
/// `nonce_hex` is the nonce that was used for the login that created the session.
pub fn request_headers(
    keyfile: &Keyfile,
    nonce_hex: &str,
    session_id: &str,
    counter: u64,
) -> Res<Vec<(String, String)>> {
    let nonce = hex::decode(nonce_hex).map_err(|_| "nonce is not valid hex".to_string())?;
    let secret = hex::decode(&keyfile.shared_secret_hex)
        .map_err(|_| "shared secret is not valid hex".to_string())?;
    let seed = crypto::derive_session_seed(&secret, &nonce, &keyfile.device_id)?;
    let code = client_code(&seed, counter)?;
    Ok(vec![
        ("X-Session-Id".to_string(), session_id.to_string()),
        ("X-Counter".to_string(), counter.to_string()),
        ("X-Code".to_string(), code),
    ])
}

pub use crate::crypto::ct_eq;

// ---------------- server side ----------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authed {
    pub session_id: String,
    pub officer_id: String,
    pub device_id: String,
}

/// The outcome of checking one request. M4 turns Replay and BadCode into lockout
/// triggers; M5 forwards only Accepted requests. Everything else is a denial.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Accepted(Authed),
    /// Counter not greater than the last accepted one (already used or backwards).
    Replay,
    /// Wrong code, malformed counter/code, or counter beyond the window.
    BadCode,
    /// No such session (unknown, invalidated or never created).
    UnknownSession,
    /// X-Session-Id missing, duplicated or unreadable.
    Malformed,
    InternalError,
}

/// Exactly one value for the header, or None (missing, duplicated or not text).
fn single_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    first.to_str().ok().map(|s| s.trim().to_string())
}

fn parse_counter(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok()
}

/// The third bad code in one session raises a BadCodes lockout trigger (once per session).
const MAX_BAD_CODES: u32 = 3;

/// (verdict, lockout trigger to raise, device id for events)
type Checked = (Verdict, Option<Trigger>, Option<String>);

fn bad_code(session: &mut Session) -> Checked {
    session.bad_codes += 1;
    let trigger = if session.bad_codes == MAX_BAD_CODES { Some(Trigger::BadCodes) } else { None };
    (Verdict::BadCode, trigger, Some(session.device_id.clone()))
}

/// SHA-256 hash of a code string, used for the replay-detection ring buffer.
/// We store a hash rather than the code itself so the buffer never holds secrets.
fn hash_code(code: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// The actual checks. Only on Accepted does the session's chain move forward.
fn check_in(live: &mut Live, headers: &HeaderMap) -> Checked {
    let session_id = match single_header(headers, "x-session-id") {
        Some(s) => s,
        None => {
            log::warn("request denied: missing or duplicated X-Session-Id");
            return (Verdict::Malformed, None, None);
        }
    };
    let session = match live.sessions.get_mut(&session_id) {
        Some(s) => s,
        None => {
            log::warn("request denied: unknown session");
            return (Verdict::UnknownSession, None, None);
        }
    };

    let counter = single_header(headers, "x-counter").and_then(|t| parse_counter(&t));
    let code = single_header(headers, "x-code").map(|c| c.to_ascii_lowercase());
    let (counter, code) = match (counter, code) {
        (Some(n), Some(c)) if !c.is_empty() && c.len() <= 64 => (n, c),
        _ => {
            log::warn(&format!("BAD CODE (malformed headers): device {:?}", session.device_id));
            return bad_code(session);
        }
    };

    if counter <= session.last_counter {
        // Old or zero counter: only a genuine replay (exact counter+code pair
        // previously accepted in this session) triggers a Replay lockout.
        // Anything else is a BadCode — an attacker forging old counters with
        // garbage codes must NOT be able to lock the system.
        let code_hash = hash_code(&code);
        let is_genuine_replay = session
            .accepted_pairs
            .iter()
            .any(|(c, h)| *c == counter && *h == code_hash);
        if is_genuine_replay {
            log::warn(&format!(
                "REPLAY: device {:?}, counter {counter} <= last accepted {}",
                session.device_id, session.last_counter
            ));
            return (Verdict::Replay, Some(Trigger::Replay), Some(session.device_id.clone()));
        } else {
            log::warn(&format!(
                "BAD CODE (old counter {counter}, not a genuine replay): device {:?}",
                session.device_id
            ));
            return bad_code(session);
        }
    }
    if counter > session.last_counter.saturating_add(WINDOW) {
        log::warn(&format!(
            "BAD CODE (counter {counter} outside window after {}): device {:?}",
            session.last_counter, session.device_id
        ));
        return bad_code(session);
    }

    let mut key = session.chain_key;
    for _ in 0..(counter - session.last_counter) {
        key = match next_key(&key) {
            Ok(k) => k,
            Err(_) => return (Verdict::InternalError, None, None),
        };
    }
    let expected = match code_from_key(&key, counter) {
        Ok(c) => c,
        Err(_) => return (Verdict::InternalError, None, None),
    };
    if !ct_eq(&expected, &code) {
        log::warn(&format!("BAD CODE: device {:?}, counter {counter}", session.device_id));
        return bad_code(session);
    }

    session.chain_key = key;
    session.last_counter = counter;
    // Record for replay detection.
    let code_hash = hash_code(&code);
    session.accepted_pairs.push_back((counter, code_hash));
    if session.accepted_pairs.len() > REPLAY_HISTORY_CAP {
        session.accepted_pairs.pop_front();
    }
    let authed = Authed {
        session_id: session.session_id.clone(),
        officer_id: session.officer_id.clone(),
        device_id: session.device_id.clone(),
    };
    (Verdict::Accepted(authed), None, None)
}

/// Check X-Session-Id / X-Counter / X-Code, then feed any anomaly to the lockout machine.
/// Replay is announced as an event and locks the system (see lockout::next_state).
pub async fn check_request(state: &SharedState, headers: &HeaderMap) -> Verdict {
    let mut live = state.live.lock().await;
    let (verdict, trigger, device_id) = check_in(&mut live, headers);
    if verdict == Verdict::Replay {
        state.publish("replay_rejected", serde_json::json!({ "device_id": device_id }));
    }
    if let Some(t) = trigger {
        lockout::trigger(state, &mut live, t);
    }
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected values computed independently with a Python HKDF-SHA256
    // (validated against RFC 5869 test case 1), seed = 32 bytes of 0x01.
    const KAT: [(u64, &str); 4] = [
        (1, "9d92b1b62f3ce7c8085a97cbc2bd5a0f"),
        (2, "46c68eb891454a8d6fd58bc536973ae8"),
        (3, "50a4af0ba54b4021832b5d78841fca8f"),
        (4, "9157fc331132170879a753437c015144"),
    ];

    #[test]
    fn client_code_matches_independent_known_answers() {
        let seed = [1u8; 32];
        for (counter, expected) in KAT {
            assert_eq!(client_code(&seed, counter).unwrap(), expected);
        }
    }

    #[test]
    fn incremental_chain_equals_client_code() {
        let seed = [5u8; 32];
        let mut key = seed;
        for n in 1..=10u64 {
            key = next_key(&key).unwrap();
            assert_eq!(code_from_key(&key, n).unwrap(), client_code(&seed, n).unwrap());
        }
    }

    #[test]
    fn codes_are_distinct_and_32_hex_chars() {
        let seed = [3u8; 32];
        let mut seen = std::collections::HashSet::new();
        for n in 1..=50u64 {
            let c = client_code(&seed, n).unwrap();
            assert_eq!(c.len(), 32);
            assert!(seen.insert(c));
        }
    }

    #[test]
    fn client_code_rejects_bad_counters() {
        assert!(client_code(&[1u8; 32], 0).is_err());
        assert!(client_code(&[1u8; 32], MAX_CLIENT_COUNTER + 1).is_err());
    }

    #[test]
    fn ct_eq_behaves_like_equality() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
        assert!(ct_eq("", ""));
    }

    #[test]
    fn counter_parsing_is_strict() {
        assert_eq!(parse_counter("12"), Some(12));
        assert_eq!(parse_counter("0"), Some(0));
        assert_eq!(parse_counter("+1"), None);
        assert_eq!(parse_counter("-1"), None);
        assert_eq!(parse_counter("1a"), None);
        assert_eq!(parse_counter(""), None);
        assert_eq!(parse_counter("99999999999999999999999"), None);
    }
}
