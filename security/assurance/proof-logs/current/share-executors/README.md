# Sharing executors against a store model (F-1 pilot)

## Claim

The driver proofs assume each executor method is honest: the observation it
hands the driver is the truth about what its SQL did. For the five sharing
executors (`SendIo`, `InboxDeleteIo`, `LinkUpdateIo`, `LinkRevokeIo`,
`ShareEkIo` in `serverVELA/vela-server/src/share/mod.rs`) that assumption is
now proved against a store model, for every starting database and every
failing statement, and checked against the real database.

Each executor method is now a thin loop over three pure pieces in
`vela-share-policy/src/store.rs`:

- `plan_*`: the method's inputs → a list of typed statements (`ShareStmt`:
  `SelectLink`, `SelectDevice`, `InsertSharedItem`, `InsertInboxItem`,
  `UpdateLinkedCapsule`, `RevokeLinkedItem`, `DeleteLinkedInbox`,
  `DeleteInboxItem`, `UpdateShareEk`, `Commit`);
- `render`: each statement → the exact SQL text and parameters used before,
  pinned byte for byte by unit tests;
- `classify_*`: the per-statement outcomes (`Applied(n)`, `Row(..)` or
  `Failed`) → the observation.

hax extracts the 8 `plan_*` and 5 `classify_*` functions.

## Model

`Vela_share_policy_store_model.fst`:
- **Tables:** `shared_items`, `share_inbox`, `users` (share-key columns) and
  `devices` (`user_id`, `hybrid_vk`, `revoked`), each a map from its unique id
  to a row.
- **Writes:** an INSERT of an existing id fails; a guarded UPDATE or DELETE
  changes the one matching row or none, and reports the count.
- **Transactions:** `run_tx` works on a copy and publishes it only at
  `Commit`; a failed statement, failed commit or missing commit leaves the
  starting state. `run_auto` runs each statement as its own transaction (the
  pool path).
- **Faults:** `f = Some k` fails the k-th statement, including the commit.
- **Reads:** `read_link` and `read_device` model the two SELECTs, including the
  device read's join on `users`.

## Exact theorems

`Vela_share_policy_store_lemmas.fst`, for every starting state and fault
point:

- **Writes:** `send_insert_is_honest`, `link_update_is_honest`,
  `link_revoke_is_honest`, `linked_inbox_cleanup_is_honest`,
  `inbox_delete_is_honest` and `share_ek_update_is_honest`. Each proves that
  success holds exactly when the SQL guard held and no statement failed; on
  success the post-state differs from the pre-state in exactly the intended
  rows; on failure the post-state equals the pre-state. Send also proves that
  `CommitConflict` holds exactly when the id was fresh and only the commit
  failed. For send, revoke and inbox delete, success also holds exactly when
  the post-state contains the intended rows. That form is false for the two
  updates, whose intended row can already equal the starting one, so they use
  the statement-applied form.
- **Reads:** `link_observation_is_honest` and `device_observation_is_honest`.
  The observation equals the truth of the stored rows, and a failed read gives
  the rejecting observation used before.
- **Facts the drivers rely on:** `send_commit_reaches_recipient`,
  `link_observation_authorizes_only_live_sender_rows`,
  `device_observation_admits_only_owned_active_devices`,
  `revocation_is_final_in_store`, `inbox_delete_only_by_recipient` and
  `link_update_commits_only_live_sender_rows`.

Three modules, each checked in its own process under 650 MB (`Store` 23 s,
`store_model` 23 s, `store_lemmas` 28 s), `--z3rlimit 200`, no admits.

## Mutations

`verify-fstar-share-executors-mutations.sh`; each mutant must fail the named
theorem:

| Mutant | Rejected at |
|---|---|
| `classify-error`: a failed commit classified as `Committed` | `send_insert_is_honest` |
| `classify-rows`: a failed write reports 1 row | `link_update_is_honest` |
| `plan-drop`: send drops the inbox insert | `send_insert_is_honest` |
| `plan-swap`: send swaps sender and recipient in the inbox row | `send_insert_is_honest` |
| `link-sender`: the link classifier ignores the caller | `link_observation_is_honest` |

## Real-database conformance

`vela-server/src/share/conformance.rs` runs the real executor (plan, rendered
SQL, row decoding, classifier) on a real turso database. A `Faulty` wrapper
fails the k-th query, execute or commit. Each case compares all four tables,
the observation and the error side channels with a Rust mirror of the model.
The Rust mirror and the F* model share seven test vectors.

- Links, inbox and send: 50 states (3 users; 3 item slots: live, revoked,
  reverse and orphan inbox), 5,100 cases, 2,850 with an injected failure.
- Share key: 27 states, 972 cases, 486 with an injected failure.
- Total: 6,072 cases, 3,336 with an injected failure, every fault point
  covered.
- Schema check: the columns the model uses exist with the expected
  declarations, and a duplicate-id insert is rejected.

No executor was found dishonest.

## Assumptions and limits

- Transactions serialize; the driver compositions model concurrency.
- Each statement is atomic. An error returned after a commit actually landed
  is not modelled, and the conformance test cannot produce it.
- The quota reads and the transaction begin in `post_send` are not executor
  methods, so they are not covered yet.

## Reproduction

```bash
cd serverVELA/vela-share-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh     # chains verify-fstar-share-executors.sh
cd .. && ~/.local/opt/vela-tools/bin/vela-heavy cargo test -p vela-server share::conformance
```
