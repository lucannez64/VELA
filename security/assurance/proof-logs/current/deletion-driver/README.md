# Account deletion driver (F*)

This evidence directory backs the pure `DELETE /account` decision driver
extracted from

- `serverVELA/vela-session-policy/src/deletion_driver.rs`;
- the rewired handler `serverVELA/vela-server/src/account/delete.rs`;
- the focused gate
  `serverVELA/vela-session-policy/verify-fstar-deletion-driver.sh`, invoked from
  the crate's `verify-fstar.sh`.

Base commit: `5dda745` (the device-revocation driver increment).
Worktree: `/home/hirew/.t3/worktrees/VELA/t3-d4e0322e`.

## The gap this closes

`delete_account` used to inline every post-validation decision: how the device
and web-session scans are classified, that a store-side lockout failure does
not abort the deletion while a scan or SQL failure does, which table is deleted
next, that the `users` delete's own row count is the account-existence signal,
and therefore whether to commit or let the transaction roll back. None of those
decisions was extracted, and no unbounded trace or concurrency theorem covered
them.

The driver now owns every decision:

- `begin_deletion` refuses an actor the middleware did not verify as an
  authenticated, active device, and refuses a request whose statements are not
  scoped to the session's own account, with no effect at all;
- `step` classifies both row scans, both lockout outcomes, the transaction
  begin, each table delete, the `users` delete and the commit; every mismatch
  or out-of-order event is inert;
- `/account` performs only the effect the driver returns: `ScanDevices`,
  `LockoutDevices`, `ScanWebSessions`, `LockoutWebSessions`, `BeginTransaction`,
  the seven `DeleteTable` statements in the historical order, `DeleteUsers`,
  `CommitTransaction`, then `Complete`/`Fail`;
- a `users` delete that reports the row absent (`Absent`) or errors produces a
  terminal failure and the handler drops the transaction, which rolls it back;
- the driver's contract states that a `CommitTransaction` effect exists exactly
  when the `users` row was observed deleted from the `DeleteUsers` stage.

Statuses, messages, SQL text, the store writes and the order of effects are
unchanged.

## Contract and theorem statements

Focused extraction: `proofs/fstar/extraction-deletion-driver/` — 10 deletion
functions with 10 contracts plus the middleware's `plan_admission` with 1
contract (its spec functions are extracted as dependencies). Per-request module:
`proofs/fstar/deletion-driver-lemmas/`. Bridge: `proofs/fstar/deletion-driver-bridge/`
(small `step` corollaries kept out of the big composition context).
Composition: `proofs/fstar/deletion-driver-composition/`.

Per-request (`deletion_trace_theorem`, every actor observation and every event
list):

```fstar
let d = run_from_actor actor events in
trace_sound d /\
(d.f_responded ==> (d.f_committed && d.f_users_deleted && d.f_transaction_started)) /\
(d.f_committed ==> (d.f_users_deleted && d.f_transaction_started)) /\
not (d.f_responded && d.f_failed) /\
(not d.f_failed || not d.f_committed) /\
count_complete ... <= 1 /\ count_fail ... <= 1 /\ count_commit ... <= 1 /\
trace_order (begin_deletion actor).f_driver events 0 0 0 0
```

Effect-order lemmas:

- `trace_order` / `deletion_trace_order` thread four running counters (device
  lockouts, web-session lockouts, confirmed table deletes, confirmed `users`
  deletes) through the whole trace and check, at the point the extracted driver
  emits each effect:
  - `BeginTransaction`, every table delete, the `users` delete and the commit
    require both store-side lockouts to have happened;
  - a `DeleteTable` effect names the table right after the confirmed ones, so
    the trace confirms `WebSessions`, `ShareInbox`, `SharedItems`, `Sends`,
    `VaultChunks`, `OramBuckets`, `Devices` in that order, each once;
  - `DeleteUsers` requires all seven tables confirmed;
  - `CommitTransaction` requires all seven tables and the `users` row confirmed
    deleted.
- `scoped_effect_requires_authority`: a lockout, table delete, `users` delete or
  commit effect only exists for an active actor and a request scoped to its own
  account.
- `fail_effect_is_terminal`: a `Fail` effect leaves the driver `Done`, failed
  and not committed; `success_and_failure_are_exclusive` and
  `done_suffix_inert` make every later event inert, so a failed request never
  reports a success.
- `begin_deletion`'s contract plus `inactive_actor_never_deletes`: an inactive
  or cross-account actor reaches a terminal failure without any effect.
- Reachability witnesses: device and web-session lockout prefix, transaction
  begin, all eight SQL deletes and the commit, absent account, device and
  web-session scan failures, transaction failure, table failure, `users`
  failure, commit failure, lockout storage failure, inactive actor.

Concurrent composition (`deletion_composition_theorem`, every schedule over
spawn / deliver / admission attempt):

```fstar
let w = run_world initial schedule in
inv w /\ w.w_cross_account = 0 /\ w.w_second_commit = 0 /\
w.w_admitted_after_lockout = 0
```

Named consequences: `no_cross_account_deletion`, `no_second_commit`,
`locked_account_admission_never_authorized`.

Every counter is incremented at the point the extracted driver authorizes the
forbidden thing:

- `w_cross_account` — a scoped effect authorized while the request's session
  account differs from the account its statements are scoped to;
- `w_second_commit` — a `CommitTransaction` effect authorized in the step whose
  `users` observation said the row was absent or the delete failed;
- `w_admitted_after_lockout` — an `Admit` from the extracted `plan_admission`
  for an account whose deletion driver completed both lockouts.

No counter is incremented by a modelled SQL guard refusing a write. Witness
schedules show a complete deletion (2 lockout effects, 8 delete effects, 1
commit, then the account refused), a second deletion that sees the row owned
and never commits, a refused cross-account spawn, and an admission attempt
after the complete lockout.

## What depends on the driver vs on modelled SQL/store

Depends on the extracted driver (proved):

- the actor/scope refusal, the scan and lockout classification, the table
  order, the account-existence decision (absent/failed `users` delete never
  commits), the transaction-begin and commit classification;
- lockouts before the transaction, all-or-nothing commit after all seven tables
  and the `users` row, at-most-one complete/fail/commit, terminality of every
  failure;
- the concurrent statements: no cross-account effect, no second commit, no
  admission of a locked-out account by the extracted admission decision.

Modelled/assumed, not proved:

- the two scans return the rows the handler locks out; the driver sees only
  `Rows`/`QueryFailed`;
- `rate_limit::revoke_all_device_jtis` and `Store::set_ex` report success/failure
  and are linearizable. The handler ignores a lockout storage failure (as it
  always did); the composition therefore models the lockout as setting the
  account's sentinel, and the "the lockout marks every token of the account"
  linkage is an assumption, not an invariant over a real token table;
- the SQL transaction is linearizable and the unit of atomicity: the first
  `users` delete owns the row, other open deletions observe it absent, and
  dropping the guard rolls back. One SQLite writer serializes the statements;
- `DELETE ... WHERE user_id = ?` affects exactly the account's rows; the
  deletion of the other party's share rows is intended;
- the middleware's PASETO verification, hard cap, rate limiter and account query
  precede the extracted admission observations;
- accounts are not added or transferred during a trace, so the spawn-time owner
  comparison stands. The composition world fixes two accounts, which is enough
  to distinguish "the same account" from "another account"; requests are
  unbounded.

## Explicit assumptions, non-claims and open obligations

- No refinement theorem connects the Rust handler to the F* trace: the handler
  is reviewed to call the extracted functions and to perform the returned
  effect, but that wiring is not mechanically refined.
- No proof of sled/Turso durability, crash recovery, replication, TTL expiry or
  multi-node sentinel visibility. The lockout TTLs (24 h web sessions, 8 h
  device JTIs) are constants outside the model.
- **Ignored lockout failure (existing behaviour, now documented):** if
  `revoke_all_device_jtis` or `set_ex` fails for one endpoint, the deletion
  proceeds. Concrete sequence: device A's `set_ex` fails → the SQL transaction
  deletes A's rows and commits → the account row is gone, so the middleware
  rejects A's token anyway; the exposure is only the window between the failed
  write and the commit. The handler keeps the historical behaviour because a
  store failure must not block permanent deletion. The composition models the
  lockout as applied, so this window is not covered.
- **Two-flag lockout model:** the composition records one device sentinel and
  one web-session sentinel per account. The per-request theorem proves the
  device lockout is instructed before the web-session lockout and both before
  the transaction; the composition does not model individual JTIs.
- The `users`-row ownership is a modelling device for SQLite's single writer. A
  commit failure is treated as a rollback in the model; the handler reports it
  as an error without claiming a commit (the row may or may not be gone).
- Imported hax models (`Core_models`, `Rust_primitives`, `Alloc`) and the solver
  remain trusted; zero warnings are not claimed.
- The proof-boundary registration of this new extraction (and any
  correspondence-table row) is left to the integrating commit; this increment
  does not touch `security/assurance/proof-boundary.json` or the correspondence
  table.

## Mutation checks

Three mutants are copies of the regenerated extraction under
`/tmp/opencode/mut/extraction-N`, never committed; the checked-in extraction is
byte-identical to the successful run. Each is checked with the same `fstar.exe`
argv as the gate, swapping the include directory.

| Mutant | Change | Failure |
|---|---|---|
| `mutation-scope.diff` | `begin_deletion` ignores `scoped_to_session_account` (an active actor always proceeds) | `inactive_actor_never_deletes` (lemma module, the cross-account refusal) fails, and the composition's `w_cross_account` counter would be non-zero for such a request |
| `mutation-second-commit.diff` | an absent `users` row proceeds to `Commit`, and the commit-iff conjunct is removed from the mutant's `step` contract | the per-request trace theorem (`deletion_trace_theorem`, lemma module) rejects the mutant; the composition's `w_second_commit` counter is keyed exactly on that decision |
| `mutation-admission.diff` | the extracted `plan_admission` drops the device-sentinel guard and `admission_is_authorized` no longer checks the sentinel | the mutant extraction's own contract fails (the weakened decision no longer matches the historical-precedence spec), and `admit_implies_sentinel_clear` — the composition's admission lemma — cannot hold, so the admission counter is load-bearing |

## Tests and gates

| Gate | Result | Log |
|---|---|---|
| `verify-fstar-deletion-driver.sh` | exit 0; 5 modules verified | `focused-verify.log` |
| crate `verify-fstar.sh` (historical + login + revocation + deletion) | exit 0 | `full-verify.log` |
| `vela-session-policy` unit tests | 44 passed (10 new driver tests) | `full-verify.log` |
| `account_deletion_model` | 1 passed (216.84 s) | `cargo-test-account-deletion-model.log` |
| `integration` | 68 passed (incl. `failed_account_deletion_rolls_back_every_table`) | `cargo-test-integration.log` |
| `device_revocation_model` | 7 passed | `cargo-test-device-revocation-model.log` |
| `check-proof-boundary.py` | 249 selected postconditions (after generating the pre-existing `vela-rekey-policy` extraction with its `cargo hax into` filter; it is a gitignored generated artifact) | (command in `commands.txt`) |
| formal unittest suite | 50 passed | (command in `commands.txt`) |

F* 2025.10.06, Z3 4.13.3, hax 0.3.7. One `cargo hax` and one `fstar.exe`
invocation per focused increment; no `admit`, `assume`, `axiom`, `--lax` or
unreviewed pragma. The source guard reports one extracted pair of modules and
three proof modules with no escapes.

## Reproduction

From `serverVELA/vela-session-policy`, with the environment in `commands.txt`:

```
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-deletion-driver.sh
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh
```

The focused extraction is regenerated into
`proofs/fstar/extraction-deletion-driver/`; it is never mixed with the
historical `extraction/`, the login or the revocation artifacts.

## Counts and hashes

See `counts.txt` and `source-hashes.txt`. Summary: 11 focused Rust functions;
37 per-request lemmas over 12 recursive definitions; 5 bridge lemmas; 19
composition lemmas/witnesses over 3 actions and 4 witness schedules; 10 new
Rust tests; three rejected mutants.

## Exact CI commands to add

```
~/.local/opt/vela-tools/bin/vela-heavy bash serverVELA/vela-session-policy/verify-fstar-deletion-driver.sh
CARGO_TARGET_DIR=$PWD/target cargo test -p vela-server --test account_deletion_model
CARGO_TARGET_DIR=$PWD/target cargo test -p vela-server --test integration
CARGO_TARGET_DIR=$PWD/target cargo test -p vela-server --test device_revocation_model
```

## Hosted reproduction

The [cdffe46 security workflow](https://github.com/lucannez64/VELA/actions/runs/40408500479) verified the deletion extraction, per-request, bridge and composition modules, and ran the deletion driver unit tests;
all fifteen PR checks passed. `hosted-cdffe46.log` holds the summary and
hashes, which match the local run.
