# Possession-proof recovery handlers vs the M18/M26a chain (bounded conformance)

Test: `serverVELA/vela-server/tests/recovery_possession_model.rs` (CI:
`formal-rekey`, step "Check bounded policies and rekey handler/database
conformance", depth 4).

Every command sequence up to depth 4 over an 11-command alphabet runs against
a reference state machine and the real Axum router with the real Turso schema
and sled store: `/recovery/initiate-proof`, `/recovery/recover/proof` (honest
and wrong-RMS proofs, two attempt slots), `/recovery/enroll-device` (two grant
slots), and account events applied to the row the handlers read (key
rotation, freeze/unfreeze, delete/re-stage the possession commitment). After
every step the HTTP status and the account's enrolled-device count must match.
Every successful proof response is also checked not to carry the server share.

| Depth | Traces | Steps | Result |
|---|---:|---:|---|
| 3 | 1,464 | 4,246 | pass, 5 s |
| 4 (CI default) | 16,105 | 62,810 | pass, 60 s (`depth4.log`) |

All ten distinguished outcomes are exercised (initiate 200/404/409, prove
200/400/401/409, enroll 200/401/409).

## The test can fail (mutation checks, run locally and reverted)

| Mutation in `recovery/possess.rs` | Shortest failing trace |
|---|---|
| attempts not single-use (`get_del` → `get`) | `Initiate, Prove(honest), Prove(honest)` |
| proof ignores the account's current epoch | `Initiate, Rotate, Prove(honest)` |

## Scope

Executable evidence for bounded sequential traces, not a proof. Not driven:
the WebAuthn recovery path (needs real authenticator assertions), recovery
publication (`/recovery/share`, covered by integration tests and M16/M17),
rate limits (kept out of the way by fresh accounts and source addresses), and
concurrency (the racing single-redemption case is an integration test).
Rotation is applied as the epoch/state change a committed rotation leaves in
the row; the rotation protocol is M11 and `rekey_state_model.rs`.
