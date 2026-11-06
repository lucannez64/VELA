# Enrollment and pairing executors against a store model (F-1)

## Claim

The pairing and enrollment drivers assume their executors report the truth
about what their SQL and sled operations did. For all seven executors that
assumption is proved against a store model, for every starting state and
failing statement, and checked on the real stores (turso and sled). The seven
executors are:

- `StorePackageIo` and `RedeemPackageIo` (`device/invitation.rs`);
- `OpenGrantIo`, `ClaimIo`, `CompleteIo` and `ResultIo`
  (`device/rendezvous.rs`);
- `EnrollIo` (`device/enroll.rs`).

Every remaining SQL/store operation in those handlers is now a proved plan too
(wave 2, F-1):

- `post_claim`'s pre-driver `exists(grant_key)` liveness bit;
- `post_complete`'s pre-driver grant read and the atomic `set_ex_pair` restore
  on its failing arms;
- all of `get_claim`: `authorize_grant`'s non-consuming grant read and
  `load_claim`'s payload read;
- every enrollment rate-limit counter (`rate_limit::enroll_by_ip`,
  `enrollment_package_store_by_ip`, `enrollment_package_fetch_by_ip`,
  `enrollment_grant_by_user`, `enrollment_claim_by_ip`,
  `enrollment_result_by_ip`).

Each method is a thin loop (plan → render → run → classify) over pure pieces
in `vela-enrollment-policy/src/executor.rs`. hax extracts the plans and
classifiers. The rendering is pinned byte for byte by unit tests: SQL text,
store keys, TTLs (900 s packages; 300 s grants, claims and results), counter
keys and windows, and serialized records.

## Model

`Vela_enrollment_policy_executor_model.fst` has 20 statement types
(`PairingStmt`). It covers:

- the `users` and `devices` tables and the grant index;
- the grant, claim, result, package and challenge keys;
- the unique `id` and `enrollment_grant_id` constraints;
- the epoch- and rekey-guarded device inserts;
- the first-writer-wins claim write;
- the all-or-nothing ceremony take;
- the non-consuming grant read and liveness probe;
- the atomic two-key ceremony restore;
- the fixed-window counters (a counter table, saturating increments);
- a failure at any statement.

## Exact theorems

`Vela_enrollment_policy_executor_lemmas.fst`, for every starting state and
fault point:

- **21 honesty theorems:** `store_package_is_honest`,
  `redeem_package_is_honest`, `store_grant_is_honest`,
  `claim_check_is_honest`, `claim_write_is_honest`, `account_read_is_honest`,
  `completion_preflight_is_honest`, `take_ceremony_is_honest`,
  `completion_insert_is_honest`, `enroll_insert_is_honest`,
  `result_write_is_honest`, `result_read_is_honest`, `claim_read_is_honest`,
  `enrolled_device_is_honest`, `active_device_is_honest`,
  `challenge_take_is_honest`, `grant_exists_is_honest`,
  `grant_read_is_honest`, `claim_inspection_is_honest`,
  `ceremony_restore_is_honest` and `rate_limit_is_honest`.
- **Facts the drivers rely on:**
  - `claim_is_first_writer_wins` and `claim_only_while_grant_live`;
  - `ceremony_take_is_single_use`;
  - `completion_insert_only_from_live_epoch` and
    `enroll_insert_only_from_live_epoch`;
  - `completion_preflight_admits_only_stored_claim` and
    `completion_preflight_admits_only_active_opener`;
  - `account_read_reports_the_stored_row`;
  - `result_read_only_from_stored_record`;
  - `device_check_only_from_active_row`;
  - `grant_live_is_the_stored_grant` and
    `grant_read_admits_only_the_stored_opener`;
  - `claim_inspection_admits_only_the_stored_claim` and
    `rate_limit_only_counts_one`.
- **Vectors:** nine `vector_*` runs, shared with
  `executor_model.rs::tests::shared_vectors` and
  `::tests::pre_driver_and_rate_vectors`.

Every module is checked in its own process under 800 MB, `--z3rlimit 100`, no
admits: `Executor` 42 s at 736 MB peak, `executor_model` 37 s at 663 MB,
`executor_lemmas` 51 s at 757 MB.

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
| `grant-exists` | `grant_exists_is_honest` |
| `grant-read-binding` | `grant_read_is_honest` |
| `claim-inspect` | `claim_inspection_is_honest` |
| `restore-classify` | `ceremony_restore_is_honest` |
| `rate-classify` | `rate_limit_is_honest` |
| `rate-plan-key` | `rate_limit_is_honest` |

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
| Pre-driver reads, restore and rate limits | 16 | 132 | 66 |
| **Total** | | **500** | **250** |

The schema check pins every modelled column and both unique constraints.

## Findings

- No executor was found dishonest. The wave-2 pre-driver reads, restore and
  rate limiters were already honest; their plans only moved existing I/O under
  the model.
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
- The pre-driver grant read, the claim payload read, the ceremony restore and
  the six named rate limiters now run through `ExecIo::run_reads` /
  `run_writes` / `run_rate` and the extracted plans. SQL text, keys, TTLs,
  counter keys and windows, statuses, error text and ordering are unchanged;
  `rate_limit::check` keeps its old body for the limiters outside these
  handlers.
- `post_complete` keeps the same separate statement numbering for its own
  `CompleteIo`: the pre-driver read runs on a fresh `ExecIo`, as before.
- `Grant` became `pub(crate)` only so the conformance test can name the
  decoded record.

## Assumptions and limits

- TTL expiry is assumed: a key stays live for one request.
- Store operations are linearizable across requests; sled's compare-and-swap
  is trusted.
- Not covered: none of the SQL/store I/O in the enrollment and invitation
  handlers remains outside a plan. `device/revoke.rs` is covered by the
  session-executor gate, not this one.
- `get_claim` has no driver; its two reads are planned and its payload
  classifier is proved, but the handler's inspect decision remains the
  separately proved `authorize_inspection` policy.
- TTL expiry is assumed: a counter's window and a key's lifetime are
  scheduler choices, not modelled.

## Reproduction

```bash
cd serverVELA/vela-enrollment-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh     # chains verify-fstar-enrollment-executors.sh
cd .. && ~/.local/opt/vela-tools/bin/vela-heavy cargo test -p vela-server --lib executor_conformance
```
