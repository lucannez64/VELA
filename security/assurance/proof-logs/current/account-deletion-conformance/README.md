# Account deletion conformance (bounded exhaustive model + residue scan)

Test: `serverVELA/vela-server/tests/account_deletion_model.rs` (CI: `security`
workflow, step "Check bounded policies and rekey handler/database conformance",
default depth 3).

`DELETE /account` (`src/account/delete.rs`) now runs all SQL deletions in one
transaction (U-17; earlier it was a sequence of separate statements). This test drives the real Axum router and the real Turso schema
through every command sequence up to a bounded depth and compares it with an
independent reference model after every step. After every successful delete it
also queries the database and the sled store directly for anything that still
names the deleted account or its devices.

## Reference model

Two accounts (Alice, Bob), each with one enrolled device and one device token.
The model tracks, per account: alive, registered share key, vault chunk ids,
send-link ids, and recovery publication; and globally the cross-account shares
in both directions.

| Command | Server effect | Model rule |
|---|---|---|
| `WriteVault(u)` | `PUT /vault/chunk/:id` (`If-Match: 0`) | 200 + chunk if alive, else 401 |
| `RegisterEk(u)` | `PUT /share/my-ek`, device-signed binding | 200 + registered if alive, else 401 |
| `Share{from,to}` | `POST /share/send` | 401 if sender dead; 404 if recipient dead or has no share key; else 200 and the share appears in the recipient inbox and both linked views |
| `SendLink(u)` | `POST /send` | 200 + owned link if alive, else 401 |
| `SetupRecovery(u)` | `PUT /recovery/share` then `POST /recovery/share/finalize` | 401 if dead; 409 if already finalized; else 200 |
| `Delete(u)` | `DELETE /account` | 200 and the account's whole footprint disappears; 401 if already dead |
| `UseToken(u)` | `GET /vault/sync` with the original token | 200 if alive, else 401 |
| `Relogin(u)` | `GET /auth/challenge` + `POST /auth/verify` with the device key | 200 if alive, else 401 |

A successful delete removes the user row, devices, vault chunks, ORAM buckets,
recovery record, owned send links, web sessions the account approved, and every
share in which the account was **either sender or recipient**. The other account
keeps its own rows and its own send links; it loses only the shares that involved
the deleted account.

Deleting twice is refused with **401**, not 404: the middleware's user-existence
check rejects the token before the handler's own "account not found" branch can
run. The model records that observable behaviour.

## Exploration

Every sequence of length `0..=3` over the 13-command alphabet is replayed on a
fresh pair of accounts against the model and the real router. After every step
the test compares the status and all client-visible views for both accounts:
`GET /vault/sync` (token liveness + chunk ids), `GET /devices`,
`GET /share/inbox`, `GET /share/linked`, `GET /sends`, and
`GET /recovery/share`.

| Depth | Traces | Steps | Result |
|---|---:|---:|---|
| 3 (CI default) | 2,380 | 6,942 | pass, 200 s (`depth3.log`, final post-revert run `revert-confirm.log`) |
| 4 (`VELA_DELETION_MODEL_DEPTH=4`) | 30,941 | 121,186 | not run: ~13x depth 3 (≈43 min), outside the local budget |

`VELA_DELETION_MODEL_DEPTH` selects the depth. Depth 4 was not attempted because
depth 3 already takes ~3.3 minutes; the test is exhaustive at depth 3, which is
the CI shape.

Non-vacuity guards in the test itself:

- every command kind reaches both a success and its documented refusal(s) —
  `Share` reaches 401 (dead sender) and 404 (dead/unregistered recipient),
  `SetupRecovery` reaches 401 and 409;
- every table in `USER_SCOPED` held at least one row for an account at the
  moment that account was deleted, so no residue query is vacuous.

## Residue scan

Immediately after every successful delete the test runs
`SELECT COUNT(*) FROM <table> WHERE <column> = ?` for the deleted user id and
each of its device ids, over every account/device reference in the schema:

| Table | Columns checked |
|---|---|
| `users` | `id` |
| `devices` | `id`, `user_id`, `enrolled_by`, `revoked_by` |
| `vault_chunks` | `user_id`, `last_writer` |
| `oram_buckets` | `user_id`, `last_writer` |
| `share_inbox` | `sender_user_id`, `recipient_user_id` |
| `shared_items` | `sender_user_id`, `recipient_user_id` |
| `web_sessions` | `user_id`, `approver_user_id`, `approved_by` |
| `sends` | `owner_user_id` |

The table list is also compared against `sqlite_master`: a new table makes the
test fail until it is added to `USER_SCOPED` (or proven to hold no account data).
Recovery shares/WebAuthn credentials live as columns of the `users` row, so they
are covered by the `users.id` check; there is no separate recovery-contacts
table in the server schema.

Sled is checked the same way. Two documented exceptions are allowed:

- `device:revoked:{device_id}` and `jti:revoked:*` are **revocation tombstones**
  deliberately retained for the token's maximum lifetime so a stolen token stays
  dead. They contain no account payload.
- `rl:*` keys are rate-limit counters keyed by user/device id. They contain no
  account data and expire.

Any other sled key, or any sled tree name, that still contains the deleted user
id or device id fails the test.

## Properties asserted after every delete

1. No row in any table above references the deleted user or any of its devices.
2. No token of the account works anywhere: the original token is refused
   (`401 unauthorized`) on `GET /vault/sync`, `GET /devices`, `GET /share/inbox`,
   `GET /share/linked`, `GET /sends`, `GET /recovery/share`, `POST /send`, and a
   second `DELETE /account`.
3. A **freshly minted, correctly signed** token for the deleted user id is
   refused both for the old device id and for a device id that never existed —
   the middleware's user-existence check is what closes this, not only the
   revocation tombstone.
4. The account's device cannot complete `GET /auth/challenge` +
   `POST /auth/verify`.
5. Deleting twice is refused consistently with `401 unauthorized`.
6. The other account still works (unless the trace already deleted it too), and
   its observable views match the model at every step.
7. Sled contains only the documented tombstones/counters.

## Bugs found (fixed)

The model test was written first and failed against the unmodified handler. Two
real residues were found and fixed in `src/account/delete.rs`; the model was not
weakened. Each log below reproduces the original failure by reverting the
corresponding fix.

1. **`sends` rows survived deletion.** `DELETE /account` never touched the
   `sends` table. A one-off link created by the account remains fetchable
   anonymously via `GET /send/:id` until its TTL (up to 30 days), so the deleted
   account's ciphertext stayed readable by anyone holding the link. Minimal
   failing trace: `[SendLink(Alice), Delete(Alice)]` —
   `sends.owner_user_id still has 1 row(s) referencing it after step 1`
   (`bug-evidence-sends-residue.log`). Fix: `DELETE FROM sends WHERE
   owner_user_id = ?`.

2. **Pending web sessions survived deletion.** `POST /web-session/start` is
   unauthenticated and stores the target account only in `approver_user_id`
   (`user_id` is NULL until grant). The delete only matched `user_id = ?`, so a
   pending row kept naming the deleted account for the pending TTL (5 minutes)
   and could never be granted. Minimal failing trace: `[Delete(Alice)]` (the
   test seeds one pending session per account at setup via the real endpoint) —
   `web_sessions.approver_user_id still has 1 row(s) referencing it after step 0`
   (`bug-evidence-web-session-residue.log`). Fix: match and delete
   `user_id = ? OR approver_user_id = ?`.

Both fixes are single-statement changes; this test is their regression test.

## Mutation check (applied locally, then reverted)

Mutation: remove the `DELETE FROM vault_chunks WHERE user_id = ?` statement from
`src/account/delete.rs`.

The test fails immediately at the first trace that writes and deletes:
`[WriteVault(Alice), Delete(Alice)]` reports
`vault_chunks.last_writer still has 1 row(s) referencing it after step 1`
(`mutation-skip-vault.log`). The mutation was reverted exactly; `git diff` on
`src/` shows only the two fixes above and no mutation remnant. A clean run after
the revert is in `revert-confirm.log`.

## Not covered

Executable evidence for bounded sequential traces, not a proof.

- **Backups, replicas and point-in-time recovery**: a restore can resurrect
  deleted rows; that is outside this server process and this test.
- **Crash or SQL error mid-delete**: now one transaction. The integration test
  `failed_account_deletion_rolls_back_every_table` drops a table deleted late
  and checks that earlier deletions roll back (it fails against the old
  statement-by-statement handler). This bounded model still observes only
  completed deletes. Store-side token revocations run before the transaction
  and are not rolled back; they only lock out.
- **Concurrency**: another device of the same account issuing requests while the
  delete runs; two deletes racing; a send-link fetch racing the delete.
- **Clock/TTL expiry** of tombstones, pending sessions and send links.
- **WebAuthn recovery credentials and the recovery ceremony**: only the stored
  `users` columns are covered by the residue scan; no command drives WebAuthn.
- **ORAM write handler**: ORAM rows are seeded directly (one per account) so the
  residue scan is non-vacuous; the ORAM handler itself is covered by integration
  tests, not by this alphabet.
- **Cryptographic assumptions** about the device signature and PASETO tokens.

## Reproduce

```sh
# CI shape (heavy wrapper used locally on this machine)
cargo test --manifest-path serverVELA/Cargo.toml --test account_deletion_model

# explicit depth / verbose transcript
VELA_DELETION_MODEL_DEPTH=3 \
  cargo test --manifest-path serverVELA/Cargo.toml \
  --test account_deletion_model -- --nocapture
```
