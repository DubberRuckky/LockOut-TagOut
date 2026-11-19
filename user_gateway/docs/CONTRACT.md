# Contract: lot-gateway <-> Python upstream (DRAFT)

Derived from the milestone spec. If you supply your own contract, that one wins.
Nothing here is implemented yet (M0/M1 only); items are marked with the milestone
that will use them.

## Endpoints the gateway expects from the upstream

| Method | Path              | Used in | Purpose |
|--------|-------------------|---------|---------|
| POST   | /internal/audit   | M5      | Fire-and-forget JSON audit event. Gateway ignores the response and enforces security locally if unreachable. |
| POST   | /internal/seal    | M4 (implemented) | Called when the state becomes LOCKED, and again at startup if the gateway starts LOCKED. Body: `{"reason":"replay|bad_codes|failed_handshakes|manual|startup_locked","time":<unix seconds>}`. Any 2xx = sealed. Retried 3 times, 2 s apart; if it never succeeds the gateway still stays LOCKED. Must be idempotent. |
| any    | /api/*            | M5      | Forwarded client requests; response is streamed back. |

## Headers the gateway adds on /api/* forwards (M5)

X-Officer-Id, X-Device-Id, X-Session-Id, X-Lock-State.
The client's own auth headers (X-Session-Id, X-Counter, X-Code as sent) are never forwarded.

## Audit event body (PROPOSED, not yet fixed)

JSON object with `event` (login | rejection | state_change | forwarded_request |
restore), `time` (unix seconds), and event-specific fields such as `officer_id`,
`device_id`, `session_id`, `reason`, `old_state`, `new_state`. Exact schema to be
agreed before M5.
