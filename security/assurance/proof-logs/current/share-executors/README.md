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

Four modules, each checked in its own process under 690 MB and `--z3rlimit
200`, no admits: `Store` 59 s, `store_model` 65 s, `store_lemmas` 82 s,
`handler_lemmas` 85 s (and the send gate adds `send_store_lemmas`, 78 s).

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
| `admission-classify`: a ready admission is reported as a failed begin | `send_admission_is_honest` |
| `admission-swap`: the pair quota read filters by the recipient as sender | `admission_plan` |
| `probe-empty`: the recipient gate accepts an empty share key | `recipient_probe_is_honest` |
| `page-has-more`: a page that fit reports that more rows exist | `pagination_is_honest` |
| `page-before`: the inbox page drops the caller's cursor | `inbox_page_plan_facts` |
| `sweep-classify`: a failed sweep reports success | `inbox_sweep_is_honest` |
| `sweep-swap`: the inbox sweep plans the one-off-link delete | `inbox_sweep_is_honest` |
| `linked-limit`: the linked-items page is planned with size 0 | `linked_items_plan_facts` |
| `rate-allow`: a counter at the budget is refused (off by one) | `rate_limit_is_honest` |
| `rate-fail`: a failed store operation is reported as allowed | `rate_limit_is_honest` |

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

## Wave 2: the I/O outside the executors

The sharing handlers also read and write outside their executor methods. That
I/O is now planned, rendered and classified the same way, in
`vela-share-policy/src/store.rs` (`HandlerStmt`, `HandlerOutcome`, `RateStmt`)
with ordinary `vela-server` loops:

- **`post_send`'s admission** — `plan_recipient_probe` (the recipient's
  `share_ek` cell) and `plan_send_admission` (the transaction `Begin`, then
  `SELECT COUNT(*)`, the pair's `SUM(LENGTH(capsule))` and the recipient's
  `SUM(LENGTH(capsule))`), classified by `classify_recipient_probe` and
  `classify_send_admission`.
- **`get_recipient_ek`** — `plan_recipient_ek` (`share_ek`,
  `share_ek_since`), `classify_recipient_ek`.
- **`get_inbox`** — `plan_inbox_cursor` (the caller's inbox row's
  `created_at`) and `plan_inbox_page` (the caller's unrevoked rows, older
  than the cursor when one is given), `classify_inbox_cursor` and
  `classify_listing`.
- **`get_linked_items`** — `plan_linked_items` (the caller's live linked
  items, page size 1000), `classify_listing`.
- **the expiry sweeps** — `plan_expired_inbox_cleanup` /
  `plan_expired_sends_cleanup`, `classify_sweep`.
- **the four share/send rate limiters** — `plan_rate_limit` with the exact
  key, budget and window, `render_rate`, `classify_rate_limit`.

The model grew a finite association for the aggregates: each table now carries
its key list (`item_ids`, `inbox_ids`, `send_ids`), `tables_wf` says the lists
are duplicate-free and complete, and the quota reads fold over the inbox's
capsule lengths. `run_handler` runs a plan of handler statements; `sweep` runs
one statement; `read_recipient_ek`, `read_inbox_cursor`, `inbox_page_spec`,
`linked_item_spec` and `own_send_spec` give the reads their SQL meaning;
`kv`/`kv_incr` model the sled counter.

Exact theorems in `Vela_share_policy_handler_lemmas.fst`, for every starting
database and every fault point:

- `send_admission_is_honest` — `Ready` exactly when nothing failed, and then
  the three quota values are the inbox's true count and byte sums; each
  failure names the step, and none of the four statements publishes anything;
- `admission_reports_the_true_inbox_bytes` — the driver's quota decision sees
  the recipient's true pending bytes;
- `recipient_probe_is_honest`, `probe_admits_only_a_nonempty_share_ek` — the
  gate admits exactly a stored, non-empty share key;
- `recipient_ek_is_honest` — the published key is the stored one unless it is
  absent or empty, with its stored binding instant;
- `inbox_cursor_is_honest` — the cursor is the caller's own row's timestamp;
  another recipient's row and a missing row are the same absence;
- `inbox_page_plan_facts`, `inbox_page_is_honest` — the plan carries the
  caller's cursor and limit byte for byte, the model's rows are exactly the
  caller's older, unrevoked items, and the classified page keeps at most the
  page size, reports `has_more` exactly when the read returned more, and
  exposes only those rows (`pagination_is_honest`);
- `linked_items_plan_facts`, `linked_items_are_the_store_truth`,
  `linked_item_spec_is_live` — the same for `get_linked_items`;
- `inbox_sweep_is_honest`, `inbox_sweep_deletes_only_expired` — the sweep
  deletes exactly the rows the cutoff names, reports the exact count, and a
  failure changes nothing;
- `rate_limit_is_honest` — allowed exactly when the counter was below the
  budget, exactly one more request recorded against its own key, and a store
  failure reported as such.

Ten wave-2 mutants (two per family, plus the platform ones) each break a named
theorem; see the table below.

Real-database conformance: 1,900 share cases (850 with an injected failure) over
50 states, covering the probe, the admission (each of the four statements),
the cursor, the page with and without a cursor at two page sizes, the
linked-items listing for every caller, and the inbox sweep at three cutoffs;
plus the counter test for the rate limiters against a real sled store. The send
side covers `list_share_links` and the link sweep (120 cases, 60 faulted).

## Assumptions and limits

- Transactions serialize; the driver compositions model concurrency.
- Each statement is atomic. An error returned after a commit actually landed
  is not modelled, and the conformance test cannot produce it.
- `tables_wf` (each table's key list is duplicate-free and complete) is a
  property of a table keyed by a `UNIQUE` id, not an extra SQL assumption; the
  conformance mirror derives the lists from the tables.
- The quota aggregates are `nat`s converted to machine integers; the bounds
  are hypotheses of the theorems (`<= maxint I64`) and hold for any real inbox.
  `LENGTH()` on the ASCII base64 capsules the handlers store is the string
  length.
- A listing's engine order (`ORDER BY ... DESC`) and its page limit are not
  modelled as a function; the theorems state that a returned page is a page of
  the store: every returned row matches and, when one page could hold them all,
  every matching row is returned. The conformance test checks both directions.
- The counter's window rollover (`incr_fixed_window`'s expiry) is a scheduler
  choice; only the count within a live window is modelled. A store failure has
  no injectable fault point in the conformance test (it is proved in F* and
  unit-tested), because the sled store is not behind the test's wrapper.

## Reproduction

```bash
cd serverVELA/vela-share-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh     # chains verify-fstar-share-executors.sh
cd .. && ~/.local/opt/vela-tools/bin/vela-heavy cargo test -p vela-server share::conformance
```
