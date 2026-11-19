mod common;

use common::*;
use lot_gateway::ratchet::{check_request, Authed, Verdict, WINDOW};

#[tokio::test]
async fn valid_code_is_accepted_and_advances_the_chain() {
    let env = make_env();
    let (sid, nonce) = new_session(&env).await;
    let h = valid_headers(&env, &nonce, &sid, 1);
    let expected = Verdict::Accepted(Authed {
        session_id: sid.clone(),
        officer_id: "alice".to_string(),
        device_id: env.device.device_id.clone(),
    });
    assert_eq!(check_request(&env.state, &h).await, expected);
    assert_eq!(last_counter(&env, &sid).await, 1);
}

#[tokio::test]
async fn consecutive_counters_are_accepted() {
    let env = make_env();
    let (sid, nonce) = new_session(&env).await;
    for n in 1..=5u64 {
        let h = valid_headers(&env, &nonce, &sid, n);
        assert!(matches!(check_request(&env.state, &h).await, Verdict::Accepted(_)), "n={n}");
    }
    assert_eq!(last_counter(&env, &sid).await, 5);
}

// A Replay now locks the system and drops every session (M4), so each replay
// case gets its own fresh environment.

#[tokio::test]
async fn reusing_a_code_is_replay() {
    let env = make_env();
    let (sid, nonce) = new_session(&env).await;
    let first = valid_headers(&env, &nonce, &sid, 1);
    assert!(matches!(check_request(&env.state, &first).await, Verdict::Accepted(_)));
    assert_eq!(check_request(&env.state, &first).await, Verdict::Replay);
}

#[tokio::test]
async fn counter_zero_is_bad_code() {
    let env = make_env();
    let (sid, _nonce) = new_session(&env).await;
    let zero = headers(&sid, "0", &"00".repeat(16));
    // Counter 0 with a garbage code is NOT a genuine replay (never accepted),
    // so it must be BadCode, not Replay.
    assert_eq!(check_request(&env.state, &zero).await, Verdict::BadCode);
}

#[tokio::test]
async fn going_backwards_is_replay() {
    let env = make_env();
    let (sid, nonce) = new_session(&env).await;
    let first = valid_headers(&env, &nonce, &sid, 1);
    let second = valid_headers(&env, &nonce, &sid, 2);
    assert!(matches!(check_request(&env.state, &first).await, Verdict::Accepted(_)));
    assert!(matches!(check_request(&env.state, &second).await, Verdict::Accepted(_)));
    assert_eq!(check_request(&env.state, &first).await, Verdict::Replay);
}

#[tokio::test]
async fn wrong_code_is_bad_code_and_does_not_advance() {
    let env = make_env();
    let (sid, nonce) = new_session(&env).await;
    let wrong = headers(&sid, "1", &"ab".repeat(16));
    assert_eq!(check_request(&env.state, &wrong).await, Verdict::BadCode);
    assert_eq!(bad_codes(&env, &sid).await, 1);
    assert_eq!(last_counter(&env, &sid).await, 0);

    // the genuine code for counter 1 still works afterwards
    let good = valid_headers(&env, &nonce, &sid, 1);
    assert!(matches!(check_request(&env.state, &good).await, Verdict::Accepted(_)));
}

#[tokio::test]
async fn forward_window_edge() {
    assert_eq!(WINDOW, 3);
    let env = make_env();
    let (sid, nonce) = new_session(&env).await;

    // last = 0: counter 4 is one past the window
    let c4 = valid_headers(&env, &nonce, &sid, 4);
    assert_eq!(check_request(&env.state, &c4).await, Verdict::BadCode);
    assert_eq!(last_counter(&env, &sid).await, 0);

    // counter 3 is exactly at the edge (counters 1 and 2 were "dropped")
    let c3 = valid_headers(&env, &nonce, &sid, 3);
    assert!(matches!(check_request(&env.state, &c3).await, Verdict::Accepted(_)));

    // last = 3: counter 6 is the edge, 10 is outside (2 bad codes so far: no lockout yet)
    let c6 = valid_headers(&env, &nonce, &sid, 6);
    assert!(matches!(check_request(&env.state, &c6).await, Verdict::Accepted(_)));
    let c10 = valid_headers(&env, &nonce, &sid, 10);
    assert_eq!(check_request(&env.state, &c10).await, Verdict::BadCode);
    assert_eq!(last_counter(&env, &sid).await, 6);
}

#[tokio::test]
async fn skipped_counter_arriving_late_is_bad_code() {
    let env = make_env();
    let (sid, nonce) = new_session(&env).await;
    let c3 = valid_headers(&env, &nonce, &sid, 3);
    assert!(matches!(check_request(&env.state, &c3).await, Verdict::Accepted(_)));
    // Counter 2 was skipped (never accepted), so even though the code is valid
    // for that counter, it cannot be a genuine replay. It's a BadCode.
    let c2 = valid_headers(&env, &nonce, &sid, 2);
    assert_eq!(check_request(&env.state, &c2).await, Verdict::BadCode);
}

#[tokio::test]
async fn unknown_missing_or_duplicated_session_is_denied() {
    let env = make_env();
    let (sid, nonce) = new_session(&env).await;

    let unknown = headers("00000000000000000000000000000000", "1", &"ab".repeat(16));
    assert_eq!(check_request(&env.state, &unknown).await, Verdict::UnknownSession);

    let mut missing = valid_headers(&env, &nonce, &sid, 1);
    missing.remove("x-session-id");
    assert_eq!(check_request(&env.state, &missing).await, Verdict::Malformed);

    let mut dup = valid_headers(&env, &nonce, &sid, 1);
    dup.append("x-session-id", axum::http::HeaderValue::from_static("other"));
    assert_eq!(check_request(&env.state, &dup).await, Verdict::Malformed);

    assert_eq!(last_counter(&env, &sid).await, 0);
}

#[tokio::test]
async fn code_from_another_session_is_a_bad_code() {
    let env = make_env();
    let (sid_a, nonce_a) = new_session(&env).await;
    let (sid_b, nonce_b) = new_session(&env).await;

    // A's valid code presented under B's session id
    let a_headers = valid_headers(&env, &nonce_a, &sid_a, 1);
    let code_a = a_headers.get("x-code").unwrap().to_str().unwrap().to_string();
    let crossed = headers(&sid_b, "1", &code_a);
    assert_eq!(check_request(&env.state, &crossed).await, Verdict::BadCode);

    // sessions are independent: both accept their own counter 1
    assert!(matches!(check_request(&env.state, &a_headers).await, Verdict::Accepted(_)));
    let b_headers = valid_headers(&env, &nonce_b, &sid_b, 1);
    assert!(matches!(check_request(&env.state, &b_headers).await, Verdict::Accepted(_)));
}

#[tokio::test]
async fn malformed_counter_or_code_is_a_counted_bad_code() {
    let env = make_env();
    let (sid, nonce) = new_session(&env).await;
    let good_code = valid_headers(&env, &nonce, &sid, 1)
        .get("x-code").unwrap().to_str().unwrap().to_string();

    for bad_counter in ["+1", "-1", "1a", "", "99999999999999999999999"] {
        let h = headers(&sid, bad_counter, &good_code);
        assert_eq!(check_request(&env.state, &h).await, Verdict::BadCode, "counter {bad_counter:?}");
    }

    let mut no_code = headers(&sid, "1", &good_code);
    no_code.remove("x-code");
    assert_eq!(check_request(&env.state, &no_code).await, Verdict::BadCode);

    let mut no_counter = headers(&sid, "1", &good_code);
    no_counter.remove("x-counter");
    assert_eq!(check_request(&env.state, &no_counter).await, Verdict::BadCode);

    assert_eq!(bad_codes(&env, &sid).await, 7);
    assert_eq!(last_counter(&env, &sid).await, 0);
}

#[tokio::test]
async fn uppercase_hex_code_is_accepted() {
    let env = make_env();
    let (sid, nonce) = new_session(&env).await;
    let code = valid_headers(&env, &nonce, &sid, 1)
        .get("x-code").unwrap().to_str().unwrap().to_ascii_uppercase();
    let h = headers(&sid, "1", &code);
    assert!(matches!(check_request(&env.state, &h).await, Verdict::Accepted(_)));
}

// ---------- replay-detection ring buffer tests ----------

#[tokio::test]
async fn forged_old_counter_with_garbage_code_does_not_lock() {
    // An attacker who sends an old counter with a wrong code must NOT trigger
    // a Replay lockout — it should be BadCode only.
    let env = make_env();
    let (sid, nonce) = new_session(&env).await;
    // Accept counter 1 normally
    let h = valid_headers(&env, &nonce, &sid, 1);
    assert!(matches!(check_request(&env.state, &h).await, Verdict::Accepted(_)));

    // Now send counter 1 again but with a garbage code
    let forged = headers(&sid, "1", &"ff".repeat(16));
    assert_eq!(check_request(&env.state, &forged).await, Verdict::BadCode);
    // The system must NOT be locked
    assert_eq!(lock_state(&env).await, lot_gateway::lockout::LockState::Normal);
}

#[tokio::test]
async fn genuine_replay_of_accepted_request_still_locks() {
    // An exact replay of a previously-accepted (counter, code) pair triggers
    // Replay and locks the system.
    let env = make_env();
    let (sid, nonce) = new_session(&env).await;
    let h = valid_headers(&env, &nonce, &sid, 1);
    assert!(matches!(check_request(&env.state, &h).await, Verdict::Accepted(_)));
    // Replay the exact same headers
    assert_eq!(check_request(&env.state, &h).await, Verdict::Replay);
    assert_eq!(lock_state(&env).await, lot_gateway::lockout::LockState::Locked);
}

#[tokio::test]
async fn replay_older_than_stored_16_counts_as_bad_code() {
    // After 16+ accepted requests, a replay of the oldest accepted counter
    // should be BadCode (evicted from the ring buffer), not Replay.
    let env = make_env();
    let (sid, nonce) = new_session(&env).await;

    // Save the headers for counter 1 so we can replay it later
    let h1 = valid_headers(&env, &nonce, &sid, 1);
    assert!(matches!(check_request(&env.state, &h1).await, Verdict::Accepted(_)));

    // Accept counters 2 through 17 (16 more), pushing counter 1 out of the ring buffer
    for n in 2..=17u64 {
        let h = valid_headers(&env, &nonce, &sid, n);
        assert!(matches!(check_request(&env.state, &h).await, Verdict::Accepted(_)), "n={n}");
    }

    // Counter 1 is no longer in the ring buffer; replaying it is now BadCode
    assert_eq!(check_request(&env.state, &h1).await, Verdict::BadCode);
    // The system must NOT be locked from this
    assert_eq!(lock_state(&env).await, lot_gateway::lockout::LockState::Normal);
}
