# POST /account/register: registration driver

## Claim

The pure `vela_session_policy::registration_driver` owns every decision the
registration handler makes between effects: the per-IP limiter, the optional
`MAX_ACCOUNTS` count, the request-side key validity, the transaction begin, the
account and first-device inserts, the commit, PASETO issuance and JTI tracking.
The extracted `step` is total; every mismatched or out-of-order event is inert.
`registration_trace_theorem` quantifies over every request observation and every
event list:

```fstar
let d = run_from_observation observation events in
trace_sound d /\
(d.f_responded ==>
  (d.f_account_inserted && d.f_device_inserted && d.f_committed &&
   d.f_token_issued && d.f_token_tracked)) /\
(d.f_committed ==> (d.f_device_inserted && d.f_account_inserted)) /\
(d.f_device_inserted ==> d.f_account_inserted) /\
not (d.f_responded && d.f_failed) /\
count_complete (begin_registration observation).f_driver events <= 1 /\
count_fail (begin_registration observation).f_driver events <= 1
```

Ordering facts (`insert_device_effect_requires_account`,
`commit_effect_requires_both_inserts`, `issue_effect_requires_commit`,
`track_effect_requires_issued`, `complete_effect_requires_everything`) state the
one-account/one-device chain on the *result* driver of the extracted step.
`fail_effect_is_terminal` states that a failure never responds. Reachability
witnesses cover the full success path, the account ceiling, a denied limiter,
invalid keys, a device-insert failure (rollback), a commit failure and an
untracked token.

## The one handler change

`post_register` previously inserted the `users` row and the `devices` row with
two independent `execute` calls. A device-insert failure left an account with
no device. The handler now opens one `TursoDb::tx()` and performs both inserts
inside it; a failure drops the guard, which rolls the account row back. Statuses,
messages, SQL text, store keys and effect order are otherwise unchanged. The
new integration test `failed_registration_rolls_back_the_account` drops the
`devices` table, registers, observes `500`, and asserts zero `users` rows.

## Handler wiring

`serverVELA/vela-server/src/account/mod.rs` expands
`registration_interpreter!` exactly once with `await` over `RegisterIo`, which
holds the request's I/O. The policy crate defines the macro once and expands it
into `run_registration`; `security/formal/tests/test_handler_interpreters.py`
enforces both facts. The handler never imports or calls `begin_registration`,
`step` or an `on_*` transition.

## Mutation

`mutation-1.diff` changes the extracted `on_device_insert` failure branch to
transition into `Commit` with `device_inserted = true`. The per-request witness
`device_insert_failure_rolls_back` (and the extracted state contract) fails;
`mutation-1.log` records the rejected run. The mutant is a copy under
`/tmp/vela-f2-account-a-mut/`, never committed.

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly. The transaction is linearizable and dropping an unfinished
  `TxGuard` rolls back (the `sqldb` unit tests exercise commit/rollback).
- The confirmation insert, PASETO issuance, JTI tracking and the OS/SQL/storage
  sources are outside the driver; their outcomes reach it only as observations.
- The hax Rust/Vec/Option models and the solver remain trusted.

## Reproduction

```bash
cd serverVELA/vela-session-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-registration-driver.sh
~/.local/opt/vela-tools/bin/vela-heavy cargo test --manifest-path ../Cargo.toml -p vela-server --test integration failed_registration_rolls_back_the_account
```

`focused-verify.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).
