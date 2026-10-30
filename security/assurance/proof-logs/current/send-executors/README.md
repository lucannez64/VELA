# One-off share-link executors against a store model (F-1)

## Claim

The send-link driver assumes its three executors (`CreateSendIo`,
`FetchSendIo`, `DeleteSendIo` in `serverVELA/vela-server/src/send.rs`) report
the truth about what their SQL did. That assumption is now proved against a
store model, for every starting `sends` table and every failing statement, and
checked against the real database. Verified on 60ebcf4.

Each executor method is now a thin loop (plan → render → run → stop at the
first failure → classify) over pure pieces in `vela-share-policy/src/store.rs`,
the same design as the [sharing pilot](../share-executors/README.md):

| Server method | Plan | Statement | Classifier |
|---|---|---|---|
| `CreateSendIo::insert_send` | `plan_send_create` | `InsertSend` | `classify_send_create` |
| `FetchSendIo::consume_view` | `plan_send_consume` | `ConsumeSendView` | `classify_send_consume` |
| `FetchSendIo::read_send` | `plan_send_read` | `SelectSend` | `classify_send_read` |
| `FetchSendIo::remove_fetched` | `plan_send_remove` | `DeleteSend` | `classify_send_remove` |
| `DeleteSendIo::delete_link` | `plan_send_delete` | `DeleteOwnedSend` | `classify_send_delete` |

`render_send` gives the exact SQL text and parameters used before, pinned byte
for byte by unit tests. None of these handlers holds a transaction, so every
statement autocommits. `run_send_auto` with fault `k` fails the k-th
statement, which for a one-statement plan means "the statement or nothing".

## Model

The pilot's `Vela_share_policy_store_model.fst` gained a `sends` table (a map
from id to row) and a `clock` parameter: the engine's comparison of the stored
expiry with the current time. The pilot's plans and theorems are unchanged and
still verify.

## Exact theorems

`Vela_share_policy_send_store_lemmas.fst`, for every starting state and fault
point:

- **Writes:** `send_create_is_honest`, `send_consume_is_honest`,
  `send_remove_is_honest` and `send_delete_is_honest`. Each proves success
  holds exactly when the SQL guard held and nothing failed. On success exactly
  the intended row changed:
  - create inserts the fresh row with `view_count = 0` and `revoked = 0`;
  - consume adds one view only while the link is unrevoked, unexpired and
    under its view cap;
  - delete removes only the owner's row and reports 1 or 0 rows exactly.

  Any failure, including a guard that matched no row, leaves the table
  unchanged.
- **Read:** `send_read_is_honest`. The payload equals the stored row, cell for
  cell; `Missing` holds exactly when the row is absent; `Unreadable` exactly
  when the query failed.
- **Facts the driver relies on:** `consumed_views_are_live`,
  `unavailable_links_are_not_live`, `delete_reports_only_owner_rows`,
  `create_writes_the_permit_bounds`, `fetch_read_delivers_the_stored_row` and
  `removal_is_final`.
- **Vectors:** 11 `vector_send_link_*` lemmas, proved from the theorems above
  and mirrored by `store_model.rs::tests::send_link_vectors`.

Every module is checked in its own process under 640 MB, `--z3rlimit 200`, no
admits: `Store` 40 s, `store_model` 37 s, `store_lemmas` 50 s,
`send_store_lemmas` 50 s.

## Mutations

`verify-fstar-send-executors-mutations.sh`; each mutant must fail the named
theorem:

| Mutant | Rejected at |
|---|---|
| `create-plan-swap`: the plan stores the id as the owner | `send_create_is_honest` |
| `consume-classify`: a zero-row consume reports `Consumed` | `send_consume_is_honest` |
| `remove-plan-drop`: cleanup plans no statement | `send_remove_is_honest` |
| `delete-rows`: delete reports 1 row for any run | `send_delete_is_honest` |
| `read-view-once`: the payload's view-once flag is forced true | `send_read_is_honest` |

The pilot's five mutants still reject.

## Real-database conformance

`vela-server/src/send/conformance.rs` runs the real executors on a real turso
database, through the same `Faulty` wrapper as the pilot:

- 12 `sends` states: absent, live, exhausted, uncapped, expired and revoked,
  each with a second slot absent or live;
- 456 cases (every executor × target × caller × fault point), 228 of them with
  an injected failure;
- each case compares the whole `sends` table, every observation cell and the
  error side channel with the Rust mirror;
- the schema check pins all 12 columns and rejects a duplicate id;
- one regression test pins an unparsable `expires_at` to `Unreadable`.

No executor was found dishonest.

## Rust changes

- The three `*SendIo` structs hold a `SendSql` instead of `&AppState`.
- SQL text, parameters, HTTP statuses, messages and error precedence are
  unchanged.
- `read_send` decodes through `SendRowView`. A valid expiry in a
  non-canonical format is re-serialized canonically; it is the same instant
  and the JSON is identical.

## Assumptions and limits

- Each statement is atomic and requests serialize.
- The expiry comparison is a model parameter, matched in conformance by the
  engine's stored-text order.
- Not covered yet:
  - `post_send`'s recipient share-key read, transaction begin and three quota
    reads (they need reads and aggregates inside the transaction model);
  - the `GET /sends` listing;
  - the expiry cleanup task;
  - the rate limiters.

## Reproduction

```bash
cd serverVELA/vela-share-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh     # chains both executor gates
cd .. && ~/.local/opt/vela-tools/bin/vela-heavy cargo test -p vela-server send::conformance
```
