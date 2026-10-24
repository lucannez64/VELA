# Sharing handlers vs the M19b/M21 state machine (bounded conformance)

Test: `serverVELA/vela-server/tests/share_channel_model.rs` (CI: `formal-rekey`,
step "Check bounded policies and rekey handler/database conformance", depth 3).

Every command sequence up to the stated depth over an 11-command alphabet
(share-key registration, send, inbox delete, linked update, linked revoke; by
sender, recipient and a third user; two share slots) runs against a reference
state machine **and** the real Axum router with the real Turso schema. After
every step the test compares the HTTP status and, for each of the three users,
the inbox (ids, senders) and the linked shares (ids, sender, recipient, exact
current capsule bytes).

| Depth | Traces | Steps | Result |
|---|---:|---:|---|
| 3 (CI default) | 1,464 | 4,246 | pass, 22 s |
| 4 (`VELA_SHARE_MODEL_DEPTH=4`, local) | 16,105 | 62,810 | pass, 558 s (`depth4.log`) |

## The test can fail (mutation checks, run locally and reverted)

| Mutation in `share/mod.rs` | Detected | Shortest failing trace |
|---|---|---|
| `put_linked_item` also lets the recipient update (`sender_user_id = ? OR recipient_user_id = ?`) | yes, 2 s | `RegisterEk(Bob), Send(Alice→Bob), Update(by Bob)`: status mismatch |
| `get_linked_items` drops `AND revoked = 0` | yes, 0.5 s | first revoke: "a revoked share was listed" |

## Scope

Executable evidence for bounded sequential traces, not a proof. Concurrency
(racing requests), rate limits, quotas, inbox expiry and web-session tokens
are not explored. The database's single-statement atomicity is trusted.

Findings while writing it: the linked-share update and revoke handlers
enforce "sender only, not revoked" in SQL and do **not** call
`vela_share_policy::plan_link_mutation`; there is no `If-Match`/ETag check on
updates, although earlier M21 notes described one.
