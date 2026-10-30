# Logout, device-revocation and account-deletion executors against a store model (F-1)

## Claim

The session drivers assume their executors report the truth about what their
SQL and sled operations did. That assumption is now proved against a store
model for three executors, for every starting state and failing statement, and
checked on the real stores (turso and sled). Verified on 6ccd31c. The three
executors are:

- `LogoutJtiIo` (`auth/logout.rs`);
- `RevokeDeviceIo` (`device/revoke.rs`);
- `DeleteAccountIo` (`account/delete.rs`).

Not covered yet: login (`VerifyIo`), registration and challenge (`RegisterIo`,
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
- `RevokeJtis`: the token markers plus the set drop, as one logical statement.

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

## Real-store conformance

`vela-server/src/auth/session_conformance.rs` runs the real executors on turso
and sled, with a failure injected at every statement:

| Family | States | Cases | With a failure |
|---|---|---|---|
| Account deletion | 3 | 153 | 111 |
| Logout | 2 | 4 | 2 |
| Revocation | 3 | 60 | 33 |
| **Total** | | **217** | **146** |

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

## Reproduction

```bash
cd serverVELA/vela-session-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh session   # the executor gate
cd .. && ~/.local/opt/vela-tools/bin/vela-heavy cargo test -p vela-server --lib session_conformance
```
