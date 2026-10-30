# Login, logout, device-revocation and account-deletion executors against a store model (F-1)

## Claim

The session drivers assume their executors report the truth about what their
SQL and sled operations did. That assumption is now proved against a store
model for four executors, for every starting state and failing statement, and
checked on the real stores (turso and sled). Verified on 6ccd31c, and on
e9c797b for login. The four executors are:

- `VerifyIo` (`auth/verify.rs`, login);
- `LogoutJtiIo` (`auth/logout.rs`);
- `RevokeDeviceIo` (`device/revoke.rs`);
- `DeleteAccountIo` (`account/delete.rs`).

Not covered yet: registration and challenge (`RegisterIo`,
`ChallengeIssueIo`) and web sessions (`StartIo`, `GrantIo`, `TokenIo`,
`DeleteSessionIo`).

Each method is a thin loop (plan → render → run → classify) over pure pieces
in `vela-session-policy/src/store.rs`. hax extracts the plans and classifiers.
`vela-server/src/auth/session_store.rs` holds the database handles, including
the transaction guard and rollback on drop. Errors are passed back unchanged,
so messages are identical.

## Model

There are 15 SQL statement types (`SqlStmt`):

- the device and web-session scans and lookups;
- one guarded delete for each of the eight account tables;
- the device revocation and web-session cascade updates;
- `Commit`.

There are 2 store statement types (`StoreStmt`):

- `SetEx`: a key, a value byte and a TTL;
- `RevokeJtis`: the token markers plus the set drop, as one logical statement;
- for login: `Take` (atomic read-and-delete of the challenge), `Incr` (the
  failure counter, which grows before it refuses), `BackoffFailure` and
  `ResetBackoff` (each rate-limit helper as one logical statement) and
  `AddMember` (adding the token id to the device's set).

Login adds three SQL statements: `SelectUnrevokedDeviceById` and the two
last-active stamps.

The deletion transaction publishes only at `Commit`. A failure can be injected
at any statement.

## Exact theorems

`Vela_session_policy_store_lemmas.fst`, for every starting database, store and
fault point:

- **Honesty:** `logout_is_honest`, `lockout_device_is_honest`,
  `revoke_observe_is_honest`, `revoke_record_is_honest`,
  `scan_devices_is_honest`, `scan_web_sessions_is_honest`,
  `ignored_lockout_reports_applied`, `begin_tx_is_honest`,
  `delete_table_is_honest`, `delete_users_is_honest` and `commit_is_honest`.
- **Facts the drivers rely on:**
  - `logout_completes_only_with_the_marker`;
  - `revocation_completes_only_locked_out`;
  - `lookup_observes_only_stored_rows`;
  - `account_existed_exactly_when_deleted`;
  - `record_revokes_exactly_the_target`.
- **Login:** `login_challenge_storage_failed`, `login_challenge_accepts`,
  `login_challenge_missing`, `login_challenge_store`,
  `login_challenge_removes_only_its_key`, `login_device_is_honest`,
  `login_present_observes_the_stored_row`,
  `login_failure_counter_reports_its_run`, `login_failure_record_state`,
  `login_reset_is_honest` and `login_track_is_honest`. Its driver facts are
  `login_completes_only_with_the_unrevoked_row`,
  `login_accepts_only_its_stored_tag` and `login_tracks_the_issued_jti`.
- **Plan shapes:** 11 `plan_*_shape` lemmas state the statements each plan must
  emit; the honesty proofs build on them.
- **Vectors:** four, shared with `store_model.rs`.

Every module is checked in its own process under 640 MB, `--z3rlimit 200`, no
admits: `Store` 32 s, `store_model` 35 s, `store_lemmas` 39 s.

## Mutations

`verify-fstar-session-executors-mutations.sh`; each mutant must fail the named
theorem:

| Mutant | Rejected at |
|---|---|
| `classify-logout-error` | `logout_is_honest` |
| `classify-record-error` | `revoke_record_is_honest` |
| `classify-delete-failed` | `delete_table_is_honest` |
| `classify-users-absent` | `delete_users_is_honest` |
| `classify-target-owner` | `revoke_observe_is_honest` |
| `classify-commit-error` | `commit_is_honest` |
| `plan-table-swap` | `plan_delete_table_shape` |
| `plan-users-swap` | `plan_delete_users_shape` |
| `plan-logout-ttl` | `plan_logout_shape` |
| `plan-sentinel-ttl` | `plan_lockout_device_shape` |
| `classify-login-challenge-failed` | `login_challenge_storage_failed` |
| `classify-login-device-failed` | `login_device_is_honest` |
| `classify-failure-counter-error` | `login_failure_counter_reports_its_run` |
| `classify-reset-error` | `login_reset_is_honest` |
| `classify-track-error` | `login_track_is_honest` |
| `plan-counter-limit` | `plan_failure_counter_shape` |
| `plan-jti-ttl` | `plan_track_jti_shape` |

## Real-store conformance

`vela-server/src/auth/session_conformance.rs` runs the real executors on turso
and sled, with a failure injected at every statement:

| Family | States | Cases | With a failure |
|---|---|---|---|
| Account deletion | 3 | 153 | 111 |
| Logout | 2 | 4 | 2 |
| Revocation | 3 | 60 | 33 |
| Login | 3 | 78 | 36 |
| **Total** | | **295** | **182** |

Every statement kind is faulted at least once. The schema check pins the
modelled columns of all eight tables and rejects a duplicate id. No executor
was found dishonest.

## Assumptions and limits

- `revoke_all_device_jtis` is modelled as one atomic logical statement, which
  matches what the executor observes. The partial marker writes a failing call
  can leave are not modelled.
- The deletion transaction and the revocation cascade are proved statement by
  statement, and checked whole by conformance. There is no single F* theorem
  over the whole run.
- Each operation is atomic and requests serialize.
- TTLs are abstracted.
- Login's per-IP limiter and backoff precheck before the driver are not
  covered; token issuance and signature verdicts are inputs.

## Reproduction

```bash
cd serverVELA/vela-session-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh session   # the executor gate
cd .. && ~/.local/opt/vela-tools/bin/vela-heavy cargo test -p vela-server --lib session_conformance
```
