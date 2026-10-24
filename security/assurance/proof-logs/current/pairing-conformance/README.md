# Device pairing (invitation + rendezvous) handler/database conformance

Test: `serverVELA/vela-server/tests/pairing_model.rs` (CI: `security.yml`,
step "Check bounded policies and rekey handler/database conformance").

Every command sequence up to depth 3 (CI default) over a 17-command alphabet
runs against an independent reference state machine and against the real Axum
router with the real Turso schema and sled store. A second, deterministic test
(`a_pairing_ceremony_completes_once_and_replays_are_refused`) runs one full
ceremony and every replay/refusal as a readable regression sequence.

| Depth | Traces | Steps | Result |
|---|---:|---:|---|
| 3 (CI default) | 5,220 | 15,334 | pass, 20 s (`depth3.log`) |
| 4 (local only) | 88,741 | 349,418 | pass, 428 s (`depth4.log`) |

Depth 4 passes but takes ~7 minutes, over the ~3 minute budget, so CI keeps the
default of 3. Depth 4 adds `enrolled` result polling to the exhaustive search
(it needs open + claim + complete + poll), and it exercises traces that open a
second grant on top of the addressed one; nothing enumerates extra grants, so
only their creation is driven, not their contents.

## What is modeled

Invitation (`src/device/invitation.rs`):

- `POST /device/enrollment-package` stores a capsule under a bearer-less token
  (`set_ex`, 15 min); storing again replaces it; a token outside the 32..=96
  byte alphabet → 400.
- `GET /device/enrollment-package/:token` releases the capsule once
  (`get_del`) → 200; a replay, or a token that was never stored → 404; an
  invalid token → 400.

Rendezvous (`src/device/rendezvous.rs`, M13 v3):

- `POST /device/enrollment-grant` (device session only) opens a grant bound to
  `(user, opener device)`; without a session → 401.
- `POST /device/enrollment-grant/:id/claim` (unauthenticated) fixes the joining
  public keys for the first claimant only: 200, then 409, and 404 once the grant
  is consumed or never existed. Wrong key lengths → 400 and never a claim.
- `GET /device/enrollment-grant/:id` (opener only) shows the stored keys: 200
  when claimed, 404 otherwise — including for a sibling device of the same
  account and for another account entirely.
- `POST /device/enrollment-grant/:id/complete` (opener only) consumes grant and
  claim in one store transaction and inserts the device row with the *stored
  claim's* keys: 200, 401 for a well-formed signature over the wrong message
  (which does not spend the ceremony), 404 for a missing claim/grant and for
  any other caller.
- `POST /device/enrollment-grant/:id/result` (unauthenticated, signed under the
  claimed key) answers `pending` while claimed, `enrolled` after completion,
  401 for the other joining key, 404 when nothing is stored.

The reference model is written from the protocol description, not the handler
code. Its state names follow `security/formal/m13_device_enrollment_ceremony.spthy`:

| M13 | reference model |
|---|---|
| `Open` | `Phase::Open` |
| `Claimed` | `Phase::Claimed` |
| `Inspected` | not stored by the server (`/result` reads the claim), no extra state |
| `Confirmed` + `ResultReady` | `Phase::Completed` (one `take_live_pair`, one row, one result record) |
| `ResultCollected` | client-side; observed only as the `/result` answer |
| `Revoked` / `Expired` | not reachable: no revoke/cancel/expire endpoint, TTL is 5 min |

Universe per trace: one account with devices `primary` (the opener) and
`secondary` (a sibling that must not drive the ceremony), a second account with
device `eve`, two candidate joining devices `J1`/`J2` with real hybrid
(ML-DSA-87 + Ed25519) keys, one invitation token, and one addressed grant slot.
Opening extra grants is exercised too, but nothing enumerates or addresses
them, exactly as on the server.

## What is compared at every step

1. HTTP status of the command, plus response shape: the capsule a fetch
   returns, `stored`/`claimed`, the claim view's keys and name, the enrolled
   `device_id`, and the `pending`/`enrolled` result view.
2. sled records, read through the store: `enrollment_package:{token}` present
   and byte-identical, `enroll_grant:{id}` present iff the grant was not
   consumed, `enroll_claim:{id}` present iff a claim is outstanding and holding
   the claimant's exact keys, `enroll_result:{id}` present iff completed and
   naming the enrolled device.
3. `GET /devices` for the opening account: exactly `primary`, `secondary` and
   (after a completion) the joining device, with `enrolled_by = primary`.
4. SQL rows for both accounts: the enrolled row's `hybrid_ek`/`hybrid_vk` are
   the *claimed* keys (not anything the completion request carried), and the
   other account still has exactly its one device.

## Properties asserted (not just statuses)

- **At most one redemption per invitation**: successful fetches per trace ≤
  successful stores, and the record is gone after the fetch. A second fetch
  (even after re-storing, which replaces) cannot return the old capsule.
- **A grant is claimed at most once, ever**: ≤ 1 successful claim per trace;
  the loser sees 409 while the ceremony is live and 404 once it is consumed.
- **Replay/stale tokens never enroll**: ≤ 1 successful completion per trace, it
  equals the model's enrolled-device count, and every later completion or claim
  is a 404. The 401 path does not consume the ceremony, so a bad signature
  cannot burn it.
- **Never the wrong account**: completing as `eve` is 404 in every state; the
  eve account's device list is asserted unchanged after every step, and the
  enrolled row is asserted to belong to the opening account.
- **Only the opener drives** the ceremony: a sibling device gets 404 from
  `/claim` and `/complete` in every state.

## Non-vacuity

The exhaustive run asserts that all of these were reached somewhere in the
exploration: store 200/400, fetch 200/404/400, open 200/401, claim
200/404/409/400, read 200/404, complete 200/401/404, result 200/401/404, and
the `pending` result view. `enrolled` needs four steps, so at depth 3 it is
covered by the deterministic ceremony test (enforced unconditionally there);
at depth 4 the exhaustive run asserts it too.

## The test can fail (mutation check, run locally and reverted)

Mutation in `src/device/invitation.rs`, `get_enrollment_package`: replace
`store.get_del(...)` with `store.get(...)` so the invitation is not consumed:

```
thread '...' panicked at vela-server/tests/pairing_model.rs:836:
assertion `left == right` failed: invitation package at step 1 of [StorePackage, FetchPackage]
  left: Some("pairing-capsule-1")
 right: None
```

The shortest failing trace is `[StorePackage, FetchPackage]`; the deterministic
test fails at step 2 with the same record mismatch. Full log:
`mutation-get-del-to-get.log`. The mutation was reverted exactly
(`sha256sum src/device/invitation.rs` restored, `git diff` clean), and no
handler bug was found: model and server agreed on every explored trace.

## NOT covered

- Cryptographic validity as a property. The test holds genuine hybrid keys, so
  it does exercise a real signature verify and a real wrong-message refusal,
  but it cannot check that the *client* computes the enrollment/result messages
  or seals the capsule to the claimed key (see the M13 theory and the client
  tests for that).
- Real concurrency. Each trace is sequential; the racing single-claim and
  single-completion cases are asserted at the store level in `src/store.rs`
  (`set_ex_nx_if_live`, `take_live_pair`) and by
  `tests/enrollment_ceremony_model.rs` over the verified policy.
- Clock/TTL expiry. The grant TTL is 5 minutes and the package TTL 15 minutes;
  a trace lasts milliseconds, and there is no HTTP cancel/expire endpoint to
  drive. Expiry is covered by the store's own unit test for expired claims.
- Rate limits: bypassed deliberately with a fresh source address per request
  and a fresh account per trace, so they never mask or cause a result.
- The sled record checks read the store's key layout as written in the
  handlers (`enrollment_package:`, `enroll_grant:`, `enroll_claim:`,
  `enroll_result:`). Renaming those keys is a test update, not a behaviour
  change; the test fails loudly rather than silently skipping the check if the
  layout drifts.
- Account key rotation and rekey freezing during completion (the completion
  handler's epoch guard) — `tests/rekey_state_model.rs` and
  `tests/integration.rs` cover those; here the row is always `key_epoch = 1`,
  `rekey_state = NULL`.
- The legacy `POST /device/enroll` + challenge path (v2), which the app no
  longer uses for pairing.

## Reproduce

```sh
cd serverVELA
CARGO_TARGET_DIR=$HOME/.t3/worktrees/VELA/t3-700776df/target \
  CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm \
  ~/.local/opt/vela-tools/bin/vela-heavy \
  cargo test -p vela-server --test pairing_model
# deeper, locally:
VELA_PAIRING_MODEL_DEPTH=4 ... cargo test -p vela-server --test pairing_model
```
