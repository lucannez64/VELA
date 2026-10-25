# Device revocation / logout driver (F*)

This evidence directory backs the pure device-revocation, logout and token
admission decisions extracted from

- `serverVELA/vela-session-policy/src/revocation_driver.rs`;
- the rewired handlers `serverVELA/vela-server/src/device/revoke.rs`,
  `serverVELA/vela-server/src/auth/logout.rs` and the revocation-based
  refusals in `serverVELA/vela-server/src/middleware.rs`;
- the focused gate
  `serverVELA/vela-session-policy/verify-fstar-revocation-driver.sh`, invoked
  from the crate's `verify-fstar.sh`.

Base commit: `3d4608f1ef3656874b4073217c7ae12de4490a70`.
Worktree: `/home/hirew/.t3/worktrees/VELA/t3-70c1e16e`.

## The gap this closes

`post_revoke` used to inline every post-validation decision: the target lookup
classification, the same-account check, the already-revoked retry, and the
lockout/record/cascade order. `post_logout` inlined its single JTI-marker
decision, and the middleware inlined the JTI/device-sentinel/account/active-row
precedence. None of those decisions was extracted, and no unbounded trace or
concurrency theorem covered them.

The driver now owns every decision:

- `begin_revocation` refuses an actor that was not authenticated and active at
  request start, with no effect at all;
- `lookup_target` classifies absent, query-failed, malformed, cross-account,
  already-revoked and fresh targets;
- `/device/revoke` performs only the effect the driver returns:
  `LockoutDevice` (every tracked JTI + `device:revoked:` sentinel), then
  `RecordRevocation` (`revoked = 1`), then `CascadeWebSessions`, then
  `Complete`/`Fail`; the already-revoked retry repeats lockout and cascade but
  never the SQL record;
- `logout_step` owns the one-marker decision;
- `plan_admission` owns the middleware precedence: JTI marker, device
  sentinel, account existence, device-scoped active row.

Statuses, messages, the logged fields, and the order of effects are unchanged.

## Contract and theorem statements

Focused extraction: `proofs/fstar/extraction-revocation-driver/` (13 selected
Rust functions, 13 `ensures`, 7 `requires`). Per-request module:
`proofs/fstar/revocation-driver-lemmas/`. Composition:
`proofs/fstar/revocation-driver-composition/`.

Per-request (`revocation_trace_theorem`, every actor observation and every
event list):

```fstar
let d = run_from_actor actor events in
trace_sound d /\
(d.f_responded ==> (d.f_recorded && d.f_cascade_done && not d.f_already_revoked)) /\
(d.f_recorded ==> (d.f_locked_out && d.f_lockout_done)) /\
(d.f_cascade_done ==> (d.f_locked_out && d.f_lockout_done &&
                       (d.f_recorded || d.f_already_revoked))) /\
not (d.f_responded && d.f_failed) /\
count_complete ... <= 1 /\ count_fail ... <= 1 /\
trace_order (begin_revocation actor).f_driver events 0
```

Effect-order lemmas:

- `revoke_effect_requires_authority`: a `LockoutDevice` effect has an active
  actor and a same-account target; a `RecordRevocation` effect additionally
  has a not-yet-revoked target and an instructed lockout.
- `record_effect_prestate`: a `RecordRevocation` effect is only emitted from a
  state that already instructed the lockout.
- `locked_out_origin`: `locked_out` is only ever set by a `LockoutDevice`
  effect.
- `trace_order` / `record_follows_lockout`: a running counter of
  `LockoutDevice` effects is threaded through the whole trace; every
  `RecordRevocation` effect requires it to be at least one, so the SQL record
  strictly follows the lockout. This is a property of the extracted driver, not
  of the modelled SQL guard.
- `cascade_effect_prestate`: a `CascadeWebSessions` effect is only emitted when
  the driver has observed the lockout and either recorded the SQL row or is on
  the already-revoked retry path.
- Logout: `logout_step_sound`, `logout_success_implies_marker` (success implies
  the JTI marker was written; a failed write is terminal).
- Reachability witnesses: success, already-revoked retry, cross-account,
  missing target, inactive actor, lockout/record/cascade storage failures,
  logout success/failure.

Concurrent composition (`revocation_composition_theorem`, every schedule over
spawn revoke/logout, lookup, delivered observations, login and use):

```fstar
let w = run_world initial schedule in
inv w /\
w.w_cross_account = 0 /\
w.w_revoked_actor = 0 /\
w.w_admitted_after_revoke = 0
```

Named consequences: `no_cross_account_revocation`,
`revoked_actor_never_revokes`, `revoked_device_tokens_never_admitted`.
Every counter is incremented at the point the extracted driver authorizes the
forbidden effect (`LockoutDevice` / `RecordRevocation`) or the extracted
`plan_admission` admits the token. No counter is incremented by a modelled SQL
guard refusing a write. Witness schedules show a legitimate revoke, a token
issued before the revoke that is refused afterwards, a cross-account refusal, a
revoked-actor refusal, an already-revoked retry that writes no second SQL
record, and a logout that kills its JTI.

## What depends on the driver vs on modelled SQL/store

Depends on the extracted driver (proved):

- same-account refusal, already-revoked classification, actor-activity check;
- effect selection and order (lockout → SQL record → cascade);
- cascade only after a successful or repeated revoke;
- terminality of storage failures and at-most-one success/failure;
- admission refusal for a revoked JTI, device sentinel, absent account or
  inactive device row, with the historical precedence.

Modelled/assumed, not proved:

- the target lookup query returns the row the handler then decodes; the
  driver sees only `Present {same_account, already_revoked}`, `Absent`,
  `QueryFailed` or `Malformed`;
- `revoke_all_device_jtis` and `Store::set_ex` report success/failure and are
  linearizable; the modelled world applies the lockout when the driver emits
  `LockoutDevice`;
- the SQL `UPDATE devices ... WHERE id = ?` is linearizable and reports
  success/failure; the modelled world marks the row revoked when the driver
  emits `RecordRevocation` (a `Failed` observation is compatible with a
  committed row, as in the handler's comment);
- the web-session cascade query/update is linearizable;
- the middleware's PASETO verification, hard cap, rate limiter and account
  query precede the extracted admission observations;
- device ownership does not change during a trace (no transfer action), so the
  spawn-time owner comparison remains valid;
- the composition's login/use actions create and consume device-scoped tokens
  only; web-session tokens are represented for the cascade but are not used as
  admission witnesses;
- the handler performs exactly the effect the driver returns in the same
  request step as its observation.

## Explicit assumptions, non-claims and open obligations

- No refinement theorem connects the Rust handlers to the F* trace: the
  handlers are reviewed to call the extracted functions and to perform the
  returned effect, but that wiring is not mechanically refined.
- No proof of sled/Turso atomicity, durability, replication, TTL expiry,
  crash/retry behaviour, or multi-node sentinel visibility. The 15-minute TTL
  and the 8-hour device-JTI set are constants outside the model.
- No proof of PASETO cryptography, JTI generation, rate limiting, account
  deletion, or the web-session grant path. `account_deletion_model` and
  `session_capability_model` are bounded Rust conformance tests, not F*.
- The composition's "revoked actor never revokes" is a spawn-time property: an
  actor authenticated before a concurrent revoke may still finish its request,
  matching the historical handler and `device_revocation_model`. A future
  requirement to cancel in-flight handlers would need a different model.
- The composition's "once revoked, no later use admitted" is about the durable
  row. The lockout-before-record property is proved separately per request; the
  composition does not import that module, so the two results are independent.
- The advisory SQL `WHERE id = ?` has no `revoked = 0` guard; the driver's
  already-revoked branch and the idempotent effects are what make retries safe.
  The handler still relies on `revoked_at`/`revoked_by` being overwritten on a
  repeat; that is unchanged.
- Middleware now reads both marker observations before deciding (the historical
  code returned after the JTI hit without reading the device sentinel). Status,
  message and precedence are unchanged.
- Imported hax models (`Core_models`, `Rust_primitives`, `Alloc`) and the
  solver remain trusted; zero warnings are not claimed.

## Mutation checks

Three mutants are copies of the regenerated extraction under
`/tmp/opencode/`, never committed; the checked-in extraction is byte-identical
to the successful run. Each runs the composition module against the mutant; all
three exit 1.

| Mutant | Change | Failure |
|---|---|---|
| `mutation-same-account.diff` | `on_target_observed` drops the `same_account` refusal and proceeds as fresh | `lookup_account` in the composition module (lines 480-486): the post-state claims the accounts match while the request's owner facts differ. The cross-account counter would also increment. |
| `mutation-actor.diff` | `begin_revocation` always takes the active branch | `spawn_revoke_inv` (lines 604-619): the driver records `actor_active = true` while the spawn fact is `false`. The revoked-actor counter would also increment. |
| `mutation-admission.diff` | `plan_admission` drops the device-row guard, the spec's `Admit` case is weakened to `true`, and the now-false negative theorem is removed | `admit_implies_active_row` (lines 599): a `plan_admission` `Admit` no longer implies an active row, so `use_inv` cannot keep `w_admitted_after_revoke = 0`. |

The first two specifically remove the driver's same-account and
actor-activity checks; the third removes the admission decision. The
corresponding counters are therefore load-bearing, not true by construction.

## Tests and gates

| Gate | Result | Log |
|---|---|---|
| `verify-fstar-revocation-driver.sh` | exit 0; 3 F* modules verified | `focused-verify.log` |
| crate `verify-fstar.sh` (historical + login + revocation) | exit 0; historical and login modules unchanged, revocation modules verified | `full-verify.log` |
| `vela-session-policy` unit tests | 34 passed (11 new driver tests) | `cargo-test-session-policy.log` |
| `device_revocation_model` | 7 passed | `cargo-test-device-revocation-model.log` |
| `integration` `revoking_a_device_revokes_the_web_sessions_it_approved` | 1 passed | `cargo-test-integration-revoke-cascade.log` |
| `account_deletion_model` | 1 passed | `cargo-test-account-deletion-model.log` |
| `session_capability_model` | 3 passed | `cargo-test-session-capability-model.log` |
| `check-proof-boundary.py` | 249 selected postconditions | (command in `commands.txt`) |
| formal unittest suite | 50 passed | (command in `commands.txt`) |

F* 2025.10.06, Z3 4.13.3, hax 0.3.7. One `cargo hax` and one `fstar.exe`
invocation per focused increment; no `admit`, `assume`, `axiom`, `--lax` or
unreviewed pragma. The source guard reports one extracted module and two proof
modules with no escapes.

## Reproduction

From `serverVELA/vela-session-policy`, with the environment in `commands.txt`:

```
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-revocation-driver.sh
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh
```

The focused extraction is regenerated into
`proofs/fstar/extraction-revocation-driver/`; it is never mixed with the
historical `extraction/` or the focused `extraction-login-driver/` artifacts.

## Counts and hashes

See `counts.txt` and `source-hashes.txt`. Summary: 13 extracted Rust
functions; 28 per-request lemmas with 9 recursive definitions; 56 composition
lemmas/witnesses over 9 actions and 6 witness schedules; 11 new Rust tests;
three rejected mutants.
