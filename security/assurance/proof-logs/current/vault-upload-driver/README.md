# Vault chunk upload / read driver (F*)

This evidence directory backs the pure upload and read decision drivers
extracted from

- `serverVELA/vela-rekey-policy/src/vault_upload_driver.rs`;
- the rewired handlers `serverVELA/vela-server/src/vault/chunk.rs`
  (`put_chunk`, `get_chunk`);
- the focused gate
  `serverVELA/vela-rekey-policy/verify-fstar-vault-upload-driver.sh`, invoked
  from the crate's `verify-fstar.sh`.

Worktree (round 1): `/home/hirew/.t3/worktrees/VELA/t3-8aeb93c6`.
Worktree (round 2, store-world composition):
`/home/hirew/.t3/worktrees/VELA/t3-d0ca44cd`.

## The gap this closes

`put_chunk` used to inline every post-validation decision: the declared-epoch
resolution, the shadow-writer authority check, the session mutation permit, the
ordinary/shadow quota choice, the create/upsert/update guard classification,
the already-exists and unique-race mapping, the zero-row re-resolution, the
version read-back, the shadow-activity refresh and the publication order.
`get_chunk` inlined the resolved read epoch and the row lookup classification.
None of those decisions was extracted, and no unbounded trace or concurrency
theorem covered them.

The driver now owns every decision:

- `begin_upload` refuses an unauthenticated writer with no effect;
- `resolve_write_epoch`, `authorize_shadow` and `plan_active_mutation` (the
  existing pure rekey-policy functions, called rather than re-implemented)
  decide the route, the shadow authority and the mutation permit;
- the quota, guarded write, recheck, read-back, activity and publication
  outcomes are classified into the handler's historical statuses/messages;
- `begin_read`/`read_step` decide the current read epoch and whether a returned
  row is same-account and current-epoch.

Statuses, messages, the logged fields and the effect order are unchanged.

## Contract and theorem statements

Focused extraction: `proofs/fstar/extraction-vault-upload-driver/` (14 selected
Rust functions, 2 `ensures`). The regenerated policy root dependency is kept in
`proofs/fstar/extraction-vault-upload-driver-root/`; it is the historical
policy module with hax's `PartialEq Phase` instance assumption, so it is
deliberately outside the focused source guard (its contracts are covered by
`check-proof-boundary.py`). Per-request module:
`proofs/fstar/vault-upload-driver-lemmas/`. Composition:
`proofs/fstar/vault-upload-driver-composition/`.

Per-request (`upload_trace_theorem`, every request and every event list):

```fstar
let d = run_from_request request events in
trace_sound d /\
(d.f_responded ==> d.f_write_matched) /\
(d.f_responded ==> (d.f_shadow ==> d.f_activity_done)) /\
(d.f_responded ==> (not d.f_shadow ==> d.f_published)) /\
(d.f_write_matched ==> route_clean d) /\
(d.f_shadow ==> shadow_route d) /\
not (d.f_responded && d.f_failed) /\
count_complete (begin_upload request).f_driver events <= 1 /\
count_fail (begin_upload request).f_driver events <= 1
```

`route_clean` is either the authoritative route (ACTIVE at the live epoch with
`write_epoch = read_epoch = state_epoch`) or the shadow route (FREEZING with
`next_epoch state_epoch = write_epoch` and `read_epoch = state_epoch`).

Write-authorization lemmas:

- `write_effect_route`: a `Write` effect carries the driver's route, permit
  epoch, shadow bit, web bit and captured state; a shadow permit requires the
  exact `N -> N+1` successor; an active permit requires the captured ACTIVE
  epoch.
- `write_effect_authority`: a `Write` effect has an authenticated writer and
  the route above.

Read (`read_trace_theorem`): a served row has a valid positive epoch and an
authenticated reader behind it; a failure is never paired with a response.

Concurrent composition (`upload_composition_theorem`, every schedule over
spawn device/web, resolve, attempt, quota, write, re-read, activity, publish and
rekey start/commit/abort):

```fstar
let w = run_world initial schedule in
inv w /\ w.w_stale_active = 0 /\ w.w_web_shadow = 0
```

Named consequences: `no_stale_active_write`, `no_web_shadow_write`.
`w_stale_active` increments when the extracted driver emits an active `Write`
effect whose captured route is not the live ACTIVE epoch; `w_web_shadow`
increments when it emits a shadow `Write` effect for a web session. Neither is
incremented by a modelled SQL guard refusing a write.

The commit boundary is stated separately as facts about the extracted guards:

- `active_guard_rejects_stale`: `authorize_active_mutation` rejects any state
  that is not valid, ACTIVE and at exactly the permit epoch. The handler embeds
  this predicate in the guarded `UPDATE`/`INSERT` as
  `key_epoch = permit AND rekey_state IS NULL`; therefore an active write cannot
  commit at a stale epoch or during rotation.
- `shadow_guard_requires_device`: `authorize_shadow` allows only a device
  authority. The handler embeds this in the shadow `INSERT ... SELECT ... WHERE
  rekey_starter = ? AND rekey_id = ?`; therefore a web session cannot commit
  shadow ciphertext.

Cross-account writes are structurally excluded by the SQL tenant key
(`WHERE user_id = session.user_id`, modelled as a per-account slot); the driver
supplies only the authenticated account and never a caller-chosen target. The
composition exercises another account's concurrent upload and keeps both
counters zero.

## Store-world composition (round 2)

Round 1 compares the driver's permit with the route *that same request
resolved*, so its two counters are per-request. Round 2 adds the shared
`users` table and the shared `vault_chunks` store to the world and models the
guarded statement as one atomic, linearizable step evaluated against the
**live** account row. The composition module
`proofs/fstar/vault-upload-driver-composition/` is extended in place; the
round-1 theorems are kept as consequences.

World state: two accounts (`key_epoch`, `rekey_state`, `rekey_id`,
`rekey_starter`), the request list (writer, chunk, claimed rotation id, driver,
the permit emitted by the driver's `Write` effect, and whether that request's
own statement committed), the `vault_chunks` rows (account, chunk, epoch) and
five counters. Actions add `GuardedWrite` and give `Spawn` the writer device,
chunk and claimed rotation id. `RekeyStart` freezes at the unchanged
`key_epoch`, `RekeyCommit` advances to `next(key_epoch)` and clears the attempt
(so a stale `rekey_id` cannot match a later attempt), `RekeyAbort` returns to
ACTIVE(N). Rotations may occur between any two steps.

The modelled guard is the SQL in `vela-server/src/vault/chunk.rs`, with the
parameters the handler passes:

| statement | modelled guard | observation |
|---|---|---|
| active create | `SELECT 1 ... (user_id, chunk, write_epoch)` then `key_epoch = permit_epoch AND rekey_state IS NULL` | `Existing` if the row is present, else `Inserted`/`Skipped` |
| active update | row present at `write_epoch` and `key_epoch = permit_epoch AND rekey_state IS NULL` | `Updated`/`Skipped` |
| shadow upsert | `key_epoch = read_epoch AND rekey_state = 'freezing' AND rekey_starter = device AND rekey_id = rotation_id`, row written at `write_epoch` | `Inserted`/`Skipped` |

The statement's result is delivered back to the driver as its
`WriteObservation`; `GuardedWrite` is the only source of `Write` events, and it
clears the permit. The update's `version = ?` conjunct is modelled as row
presence at the permit's write epoch: ignoring a version check can only make the
guard accept more writes, never fewer, so it cannot hide a bad commit. Commit's
shadow sweep and abort's cleanup are not modelled because they only delete rows.

Headline theorem (`upload_store_theorem`, every schedule):

```fstar
let w = run_world initial schedule in
inv w /\
w.w_stale_commit = 0 /\
w.w_bad_shadow_commit = 0 /\
w.w_success_without_commit = 0
```

`inv` = two accounts with well-formed rotation ids, every request sound
(`trace_sound` + stored permit agrees with the current write route + matched
write implies this request committed), request accounts in range, store rows
belonging to the two accounts, and all five counters zero.

The counters are incremented at the commit/response step from the world's real
account state, not from the permit's captured copy:

- `w_stale_commit` increments when a non-shadow row is committed and the live
  account is not ACTIVE or `row epoch <> live key_epoch`;
- `w_bad_shadow_commit` increments when a shadow row is committed and the live
  account is not FREEZING, `next(live key_epoch) <> row epoch`, the writer is
  not the rotation's starter, the rotation id does not match, or the writer is a
  web session;
- `w_success_without_commit` increments when a request's `responded` flips true
  but its own guarded statement never committed.

Named consequences: `no_stale_commit`, `no_bad_shadow_commit`,
`no_success_without_commit`, `no_stale_active_write`, `no_web_shadow_write`.
The load-bearing commit lemmas are:

```fstar
(* sql_active_guard a p = a.key_epoch = p.permit_epoch /\ a.phase = ACTIVE
   active_row_ok a p   = a.phase = ACTIVE /\ p.write_epoch = a.key_epoch *)
let active_guard_commit_ok (a: account) (d: t_UploadDriver)
                           (p: t_UploadWritePermit)
  : Lemma (requires (sql_active_guard a p /\ trace_sound d /\ is_write d /\
                     permit_matches_driver p d /\ not p.f_shadow))
          (ensures (active_row_ok a p))

(* shadow_row_ok a wr rid p =
     rid > 0 /\ a.phase = FREEZING /\ next(a.key_epoch) = Some p.write_epoch /\
     a.starter = wr.device /\ a.rid = rid /\ not p.web *)
let shadow_guard_commit_ok (a: account) (wr: writer) (rid: nat)
                           (d: t_UploadDriver) (p: t_UploadWritePermit)
  : Lemma (requires (sql_shadow_guard a wr rid p /\ trace_sound d /\ is_write d /\
                     permit_matches_driver p d /\ p.f_shadow))
          (ensures (shadow_row_ok a wr rid p))
```

Commit reachability witnesses: a successful active commit at the live epoch
(`active_commit_is_reachable`), a successful rotation shadow commit at the
successor epoch (`shadow_commit_is_reachable`), a rotation committed between
resolve and write that makes the guard skip with no row
(`rotation_between_resolve_and_write_skips`), a refused web-session shadow
attempt (`web_shadow_is_refused`), and two accounts committing concurrently
(`two_account_is_reachable`).

### Modelled vs assumed

Modelled and proved:

- the three guarded statements above, evaluated atomically against the live
  account row, with the permit the driver emitted and the request's writer;
- the delivered observation and the driver's response to it;
- rotation start/commit/abort mutating the shared account between steps;
- the store's existing-row and upsert behaviour, tenant scoping and the fact
  that a commit only adds a row for the request's account.

Assumed, not proved:

- SQL statements and the key-state load are linearizable and report the
  observation the driver consumes (the driver itself runs between statements);
- the driver's observations come from the world construction above, devices are
  not transferred between accounts, and `rekey_id`/`rekey_starter` compare as
  the SQL compares them;
- quota accounting, storage errors/durability, the version read-back, commit's
  completeness checks and sweep, abort's cleanup, clock monotonicity and
  multi-node replication;
- the Rust handler is reviewed to perform the effect the driver returns, but no
  refinement theorem connects it mechanically to the F* trace.

No stale-commit bug was found in the SQL as written: with the driver's route
(`permit_epoch = write_epoch`, `next(read_epoch) = write_epoch` for shadows) the
modelled guards imply both commit predicates.

## What depends on the driver vs on modelled SQL/store

Depends on the extracted driver (proved):

- authentication, route selection, shadow authority, mutation permit and quota
  choice;
- create/update/upsert classification and the already-exists/unique/rekey
  precedence;
- zero-row recheck, read-back, activity refresh and publication order;
- success implies a matched guarded statement;
- at most one success/failure and no success paired with failure;
- read scope for the returned row.

Modelled/assumed, not proved:

- the key-state load and rollback, quota query, guarded SQL statement, version
  read-back and shadow-activity refresh are linearizable and report the
  observation the driver consumes;
- the SQL guard is exactly `authorize_active_mutation`/`authorize_shadow`
  against the live account row; round 2 models this statement atomically against
  the shared store (see the store-world section above), so the no-stale-commit
  and no-bad-shadow-commit claims are derived rather than assumed;
- quota accounting, ciphertext storage, response rendering and the clock;
- the handler performs exactly the effect the driver returns, in order;
- the server does **not** enforce Lamport-clock monotonicity on uploads. The
  write paths store the client-supplied `x-lamport-clock` and guard only the row
  version, the account epoch and the rotation state. Lamport rollback is
  rejected by the client download policy (`vela-sync-policy`,
  `plan_chunk_download`); the server theorems therefore make no
  clock-decrease claim. `docs/VAULT_REKEYING_DESIGN.md` §5 and
  `security/assurance/17-universal-chunk-admission.md` /
  `18-mobile-sync-admission.md` describe the same split: the server guarantees
  epoch/rotation authority, while clock floors are a client-side rule.

## Explicit assumptions, non-claims and open obligations

- No refinement theorem connects the Rust handlers to the F* trace: the
  handlers are reviewed to call the extracted functions and perform the
  returned effect, but that wiring is not mechanically refined.
- No proof of Turso/sled atomicity, durability, replication, crash/retry
  behaviour, quota accounting, or multi-node visibility.
- No proof of PASETO cryptography, session issuance, rate limiting or account
  deletion; those are existing focused models/tests.
- `get_chunk`'s account/epoch scope is also enforced by the SQL `WHERE`
  clause; the driver re-checks it but cannot observe other accounts' rows.
- The composition's `Spawn` action only creates writers for the two modelled
  accounts; devices are not transferred between accounts.
- Imported hax models (`Core_models`, `Rust_primitives`, `Alloc`) and the
  solver remain trusted.

## Mutation checks

Round-1 mutants (three) and round-2 mutants (four) are copies of the regenerated
extraction or the proof modules under `/tmp/opencode/`, never committed. Each
runs the per-request/composition modules against the mutant; all exit 1.

| Mutant | Change | Failure |
|---|---|---|
| `mutation-web` | `on_attempt` drops the driver's `driver.web` refusal and the root `attempt_is_authorized` drops `device_scope` | `on_attempt_sound`/`write_effect_not_web`: a web writer reaches an authorized shadow write, so `w_web_shadow` would increment. The two checks are redundant defense in depth, so both are removed to expose the counter. |
| `mutation-stale` | `on_rekey` forces `shadow = false` (treats a freezing route as active) | `on_rekey_sound`/`write_effect_stale_active`: the driver records an active write from a FREEZING route, so `w_stale_active` would increment. |
| `mutation-guard` | root `authorize_active_mutation` always allows and its `ensures` is weakened | `active_guard_rejects_stale` in the composition: a stale active state is accepted, so a stale-epoch commit would be possible. |

Round 2 (each kills a commit-step counter; diffs and logs are in this
directory):

| Mutant | Change | Failure (composition module) |
|---|---|---|
| `guard-epoch` | `sql_active_guard` drops `key_epoch = permit_epoch` | `active_guard_commit_ok`: a stale permit commits, so `w_stale_commit` can rise (`mutation-guard-epoch.*`). |
| `guard-starter` | `sql_shadow_guard` drops `rekey_starter = ?` and `rekey_id = ?` | `shadow_guard_commit_ok`: a non-starter/wrong-attempt shadow commits, so `w_bad_shadow_commit` can rise (`mutation-guard-starter.*`). |
| `shadow-epoch` | extracted `write_permit` sends `read_epoch` as the shadow `write_epoch` | `write_effect_permit_matches`: the permit no longer carries the driver's route; the guard still matches on `read_epoch`, so the row lands at `read_epoch` and `w_bad_shadow_commit` can rise (`mutation-shadow-epoch.*`; the lemmas copy drops the killed equality so the composition is reached). |
| `success-after-skip` | extracted `on_write` sends a `Create`+`Skipped` statement to `Reread` with `write_matched = true` | `on_write_matched`: the driver claims a matched write after a skipped statement, so `w_success_without_commit` can rise (`mutation-success-after-skip.*`). |

Concrete counterexamples: in three extra `/tmp` trees the killed proof
obligation is admitted only so the module checks and the concrete schedule can
be evaluated. There, `w_stale_commit = 1` with a row at epoch 1 while the live
account is at epoch 2 (`mutation-guard-epoch-witness.*`),
`w_bad_shadow_commit = 1` with the shadow row at the read epoch
(`mutation-shadow-epoch-witness.*`), and `w_success_without_commit = 1` with no
committed row (`mutation-success-after-skip-witness.*`). The checked-in
witnesses prove the same schedules keep the counters at 0 with the real
guard/driver.

## Tests and gates

| Gate | Result | Log |
|---|---|---|
| `verify-fstar-vault-upload-driver.sh` | exit 0; 4 F* modules verified | `focused-verify.log` |
| crate `verify-fstar.sh` (historical + focused) | exit 0 | `full-verify.log` |
| `vela-rekey-policy` unit tests | 25 passed (12 new driver tests) | `focused-verify.log` |
| `rekey_state_model` | 5 passed | `server-tests.log` |
| `session_capability_model` | 3 passed | `server-tests.log` |
| `account_deletion_model` | 1 passed | `server-tests.log` |
| `integration` | 68 passed | `server-tests.log` |
| `check-proof-boundary.py` | 249 selected postconditions | commands.txt |
| formal unittest suite | 50 passed (after staging the executable runner) | commands.txt |

F* 2025.10.06, Z3 4.13.3, hax 0.3.7. No `admit`, `assume`, `axiom`, `--lax` or
unreviewed pragma in the focused driver/proof sources. The source guard reports
one extracted driver module and two proof modules with no escapes.

## Exact cargo test commands CI should add

```
cargo test -p vela-rekey-policy --lib
cargo test -p vela-server --test rekey_state_model
cargo test -p vela-server --test session_capability_model
cargo test -p vela-server --test account_deletion_model
cargo test -p vela-server --test integration
```

and the focused F* gate:

```
cd serverVELA/vela-rekey-policy && ./verify-fstar-vault-upload-driver.sh
```

## Reproduction

From `serverVELA/vela-rekey-policy`, with the environment in `commands.txt`:

```
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-vault-upload-driver.sh
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh
```

The focused extraction is regenerated into
`proofs/fstar/extraction-vault-upload-driver/`; the root dependency goes to
`proofs/fstar/extraction-vault-upload-driver-root/`; neither is mixed with the
historical `extraction/` artifact.

## Counts and hashes

See `counts.txt` and `source-hashes.txt`. Summary: 14 extracted Rust functions;
42 per-request lemmas with 8 recursive definitions; 67 composition lemmas with
19 recursive definitions over 11 actions and 5 witness schedules; 12 new Rust
tests; three round-1 mutants and four round-2 mutants rejected, plus three
concrete counterexamples for the round-2 counters. Round 2 changes no Rust
source and keeps `check-proof-boundary.py` at 249 selected postconditions.

## Hosted reproduction

The [cdffe46 security workflow](https://github.com/lucannez64/VELA/actions/runs/40408500479) verified the round-1 vault
extraction, per-request lemmas and composition, and ran the rekey policy unit
tests; all fifteen PR checks passed. `hosted-cdffe46.log` holds the summary
and hashes, which match the local run. The [727d447 workflow](https://github.com/lucannez64/VELA/actions/runs/40426119764) reproduced the round-2
store-world composition; `hosted-727d447.log` holds its summary and hashes.
