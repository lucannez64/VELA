# Session executors against a store model (F-1): login, logout, device
# revocation, account deletion, registration, challenge issuance and the
# web-session start/grant/token/delete executors

## Claim

The session drivers assume their executors report the truth about what their
SQL and sled operations did. That assumption is now proved against a store
model for six executors, for every starting state and failing statement, and
checked on the real stores (turso and sled). The four original ones were
verified on 6ccd31c (login on e9c797b); registration and challenge issue are
covered by the same model since this log, and the four web-session executors
since the same increment.

- `VerifyIo` (`auth/verify.rs`, login);
- `LogoutJtiIo` (`auth/logout.rs`);
- `RevokeDeviceIo` (`device/revoke.rs`);
- `DeleteAccountIo` (`account/delete.rs`);
- `ChallengeIssueIo` (`auth/challenge.rs`): `check_rate_limit`, `store_nonce`;
- `RegisterIo` (`account/mod.rs`): `check_rate_limit`, `check_account_budget`,
  `begin_transaction`, `insert_account`, `insert_device`, `commit`,
  `track_token`.
- `StartIo` (`web_session/mod.rs`): `insert_pending`;
- `GrantIo` (`web_session/mod.rs`): `update_grant` (the epoch/approver/device
  CAS);
- `TokenIo` (`web_session/mod.rs`): `claim_token` and the `issue_token`
  sentinel re-check plus JTI tracking;
- `DeleteSessionIo` (`web_session/mod.rs`): `lockout_session` and
  `record_revocation`.

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

Registration and challenge add:

- `InsertUser` and `InsertDevice`: `INSERT` into `users` / `devices` with the
  exact columns the handler binds. The id is `UNIQUE`, so an existing id is a
  statement failure (the handler's `Failed` observation), not a second row.
  `register_tx` runs them, plus `Commit`, inside one transaction: `Commit`
  publishes, and a failed statement (injected or duplicate id) leaves the
  state the transaction began from;
- `CountUsers`: `SELECT COUNT(*) FROM users`, whose exact count is the
  registration budget observation;
- in the store: `SetExNx`, the first-writer-wins `set_ex_nx` that issues a
  challenge only on a fresh key and reports a collision without overwriting
  the live nonce. The `Incr` limiter statement is shared with login, with the
  registration and challenge keys/limits pinned by `plan_*_shape` lemmas.

The deletion transaction publishes only at `Commit`. A failure can be injected
at any statement.

The web-session executors add three SQL statements and two store statements:

- `InsertPendingSession`: the `start` insert with `user_id`, `mode`, `capsule`,
  `approved_by`, `key_epoch` and `expires_at` NULL and `status = 'pending'`.
  The id is `UNIQUE`: an existing row is the statement failure (the handler's
  `Failed` observation);
- `GrantWebSession`: the grant CAS. It rewrites the one row only while
  `status = 'pending'` and `approver_user_id = ?`, AND `EXISTS (SELECT 1 FROM
  users WHERE id = ? AND rekey_state IS NULL AND key_epoch = ?)` AND `EXISTS
  (SELECT 1 FROM devices WHERE id = ? AND user_id = ? AND revoked = 0)`. Those
  two `EXISTS` guards are evaluated against the modelled `users` and `devices`
  tables, not free inputs. Zero rows is `Conflict`, one row is `Updated`;
- `RevokeSessionById`: the delete handler's audit update (`status = 'revoked',
  capsule = NULL WHERE id = ?`, whose row count the handler does not observe);
- in the store, `SetExNxByte`, the first-writer-wins `web_session:token_issued:`
  marker (exact one-byte value), and `Exists`, the read-only
  `device:revoked:` sentinel check at the point of token issue.

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
- **Registration and challenge:** `account_count_is_honest`,
  `registration_rate_limit_is_honest`, `challenge_rate_limit_is_honest`,
  `insert_account_is_honest`, `insert_device_is_honest`,
  `registration_begin_is_honest`, `registration_commit_is_honest`,
  `registration_track_is_honest`, `challenge_nonce_is_honest` and
  `registration_tx_is_honest` (the whole account+device+commit transaction).
  Its driver facts are `inserted_account_is_stored`,
  `inserted_device_is_stored`, `registration_publishes_both_rows`,
  `budget_counts_the_stored_accounts`,
  `challenge_issued_nonce_is_stored`,
  `challenge_collision_keeps_the_live_nonce` and
  `registration_tracks_the_issued_jti`.
- **Login:** `login_challenge_storage_failed`, `login_challenge_accepts`,
  `login_challenge_missing`, `login_challenge_store`,
  `login_challenge_removes_only_its_key`, `login_device_is_honest`,
  `login_present_observes_the_stored_row`,
  `login_failure_counter_reports_its_run`, `login_failure_record_state`,
  `login_reset_is_honest` and `login_track_is_honest`. Its driver facts are
  `login_completes_only_with_the_unrevoked_row`,
  `login_accepts_only_its_stored_tag` and `login_tracks_the_issued_jti`.
- **Web sessions:** `insert_pending_is_honest`, `grant_update_is_honest`,
  `revoke_session_is_honest`, `lockout_session_is_honest`,
  `token_claim_is_honest`, `token_sentinel_is_honest` and
  `token_issue_is_honest`. Its driver facts are `inserted_pending_is_stored`,
  `grant_updated_only_pending_guarded`, `grant_updated_changes_only_sessions`,
  `token_claim_is_first_writer_wins`, `issued_token_is_not_locked_out`,
  `issued_token_is_tracked`, `lockout_applied_means_sentinel_stored` and
  `revoke_record_marks_the_session`.
- **Plan shapes:** 31 `plan_*_shape` lemmas state the statements each plan must
  emit; the honesty proofs build on them.
- **Vectors:** 27 `vector_*` lemmas and state definitions, shared with
  `store_model.rs`.

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
| `classify-store-nonce-failed` | `challenge_nonce_is_honest` |
| `plan-store-nonce-ttl` | `plan_store_nonce_shape` |
| `classify-insert-error` | `insert_account_is_honest` |
| `classify-budget-failed` | `account_count_is_honest` |
| `plan-registration-limit` | `plan_registration_rate_limit_shape` |
| `plan-insert-account-swap` | `plan_insert_account_shape` |
| `classify-start-insert-error` | `insert_pending_is_honest` |
| `plan-insert-pending-swap` | `plan_insert_pending_shape` |
| `classify-grant-conflict` | `grant_update_is_honest` |
| `classify-grant-error` | `grant_update_is_honest` |
| `plan-grant-swap` | `plan_grant_update_shape` |
| `classify-claim-error` | `token_claim_is_honest` |
| `plan-claim-ttl` | `plan_token_claim_shape` |
| `classify-issue-track` | `token_issue_is_honest` |
| `classify-lockout-session-error` | `lockout_session_is_honest` |
| `plan-revoke-session-key` | `plan_revoke_session_shape` |
| `classify-revoke-session-error` | `revoke_session_observes_its_run` |

## Real-store conformance

`vela-server/src/auth/session_conformance.rs` runs the real executors on turso
and sled, with a failure injected at every statement:

| Family | States | Cases | With a failure |
|---|---|---|---|
| Account deletion | 3 | 153 | 111 |
| Logout | 2 | 4 | 2 |
| Revocation | 3 | 60 | 33 |
| Login | 3 | 78 | 36 |
| Challenge issue | 2 | 10 | 5 |
| Registration | 3 | 96 | 57 |
| Web sessions | 37 | 97 | 50 |
| **Total** | | **498** | **294** |

Every statement kind is faulted at least once. The schema check pins the
modelled columns of all eight tables and rejects a duplicate id. The
registration harness also opens and rolls back the real transaction, so a
duplicate id and a fault both have to leave turso unchanged, and a committed
run has to publish exactly the two intended rows. No executor was found
dishonest.

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
- Registration's PASETO issuance is an input, exactly as login's is; its
  per-IP limiter and account-count budget *are* covered.
- The challenge's 32-byte nonce and its uniqueness are the OS random source's
  input (the driver proves the length); the executor proof is that an
  `Inserted` observation stored exactly the purpose tag under the nonce key
  and that a collision overwrote nothing.
- `users` count saturation at `i64::MAX` is unreachable for a real table; the
  model states the exact count below that bound.
- The web-session `start` insert draws its id inside the executor, so the
  conformance harness feeds the model the reported id; the duplicate-id
  semantics are proved in the model and pinned by the `web_sessions.id UNIQUE`
  schema check.
- Web-session PASETO issuance is an input (the plan policy is proved
  elsewhere); the executor's proof is that `Issued` is only reported while no
  `device:revoked:` sentinel is stored and the JTI was tracked.
- `TokenIo`'s per-IP/per-session limiters and backoff precheck before the
  driver are not covered (the same shape as login's per-IP limiter).

## Reproduction

```bash
cd serverVELA/vela-session-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh session   # the executor gate
cd .. && ~/.local/opt/vela-tools/bin/vela-heavy cargo test -p vela-server --lib session_conformance
```
