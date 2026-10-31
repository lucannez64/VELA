# Enrollment and pairing executors against a store model (F-1)

## Claim

The pairing and enrollment drivers assume their executors report the truth
about what their SQL and sled operations did. For all seven executors that
assumption is now proved against a store model, for every starting state and
failing statement, and checked on the real stores (turso and sled). Verified
on 06fbb5d. The seven executors are:

- `StorePackageIo` and `RedeemPackageIo` (`device/invitation.rs`);
- `OpenGrantIo`, `ClaimIo`, `CompleteIo` and `ResultIo`
  (`device/rendezvous.rs`);
- `EnrollIo` (`device/enroll.rs`).

Each method is a thin loop (plan → render → run → classify) over pure pieces
in `vela-enrollment-policy/src/executor.rs`. hax extracts the plans and
classifiers. The rendering is pinned byte for byte by unit tests: SQL text,
store keys, TTLs (900 s packages; 300 s grants, claims and results) and
serialized records.

## Model

`Vela_enrollment_policy_executor_model.fst` has 16 statement types
(`PairingStmt`). It covers:

- the `users` and `devices` tables and the grant index;
- the grant, claim, result, package and challenge keys;
- the unique `id` and `enrollment_grant_id` constraints;
- the epoch- and rekey-guarded device inserts;
- the first-writer-wins claim write;
- the all-or-nothing ceremony take;
- a failure at any statement.

## Exact theorems

`Vela_enrollment_policy_executor_lemmas.fst`, for every starting state and
fault point:

- **16 honesty theorems:** `store_package_is_honest`,
  `redeem_package_is_honest`, `store_grant_is_honest`,
  `claim_check_is_honest`, `claim_write_is_honest`, `account_read_is_honest`,
  `completion_preflight_is_honest`, `take_ceremony_is_honest`,
  `completion_insert_is_honest`, `enroll_insert_is_honest`,
  `result_write_is_honest`, `result_read_is_honest`, `claim_read_is_honest`,
  `enrolled_device_is_honest`, `active_device_is_honest` and
  `challenge_take_is_honest`.
- **Facts the drivers rely on:**
  - `claim_is_first_writer_wins` and `claim_only_while_grant_live`;
  - `ceremony_take_is_single_use`;
  - `completion_insert_only_from_live_epoch` and
    `enroll_insert_only_from_live_epoch`;
  - `completion_preflight_admits_only_stored_claim` and
    `completion_preflight_admits_only_active_opener`;
  - `account_read_reports_the_stored_row`;
  - `result_read_only_from_stored_record`;
  - `device_check_only_from_active_row`.
- **Vectors:** five `vector_*` runs, shared with
  `executor_model.rs::tests::shared_vectors`.

Every module is checked in its own process under 650 MB, `--z3rlimit 100`, no
admits: `Executor` 55 s, `executor_model` 47 s, `executor_lemmas` 68 s.

## Mutations

`verify-fstar-enrollment-executors-mutations.sh`; each mutant must fail the
named theorem:

| Mutant | Rejected at |
|---|---|
| `classify-error` | `store_package_is_honest` |
| `classify-claim-write` | `claim_write_is_honest` |
| `classify-skip` | `completion_insert_is_honest` |
| `classify-take` | `take_ceremony_is_honest` |
| `classify-device` | `active_device_is_honest` |
| `plan-drop` | `completion_preflight_is_honest` |
| `plan-swap` | `store_grant_is_honest` |
| `account-classify` | `account_read_is_honest` |

## Real-store conformance

`vela-server/src/device/executor_conformance.rs` runs the real executors on
turso and sled, with a failure injected at every statement:

| Family | States | Cases | With a failure |
|---|---|---|---|
| Package store and take | 8 | 120 | 56 |
| Claim and ceremony | 8 | 64 | 32 |
| Completion | 25 | 76 | 42 |
| Result | 8 | 48 | 24 |
| Enroll | 5 | 60 | 30 |
| **Total** | | **368** | **184** |

The schema check pins every modelled column and both unique constraints.

## Findings

- No executor was found dishonest.
- Conformance found a database fact the first model missed:
  `devices.enrollment_grant_id` is UNIQUE, so a second completion insert for
  the same grant fails. It is now modelled and schema-checked; the executor
  reports that failure truthfully.
- Unreachable path, documented and unchanged: `take_ceremony` consumes the pair
  before comparing it with the validated claim. If the ceremony had no
  observed claim, it would consume the pair yet report `Missing`. The proved
  driver only issues the take after a usable claim, so this cannot happen.

## Rust changes

- SQL text, keys, TTLs, JSON field order, statuses and error text are
  unchanged.
- Challenge consumption runs its one-shot get-and-delete through the plan.
  The stored purpose tag is classified by the existing session-policy
  classifier.
- Both guarded inserts bind `key_epoch` as an integer, as before.

## Assumptions and limits

- TTL expiry is assumed: a key stays live for one request.
- Store operations are linearizable across requests; sled's compare-and-swap
  is trusted.
- Not covered yet:
  - `post_claim`'s grant existence check before the driver;
  - `post_complete`'s grant read before the driver and its restore on the two
    failing arms;
  - all of `get_claim`, which has no driver;
  - the rate limiters.

## Reproduction

```bash
cd serverVELA/vela-enrollment-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh     # chains verify-fstar-enrollment-executors.sh
cd .. && ~/.local/opt/vela-tools/bin/vela-heavy cargo test -p vela-server --lib executor_conformance
```
