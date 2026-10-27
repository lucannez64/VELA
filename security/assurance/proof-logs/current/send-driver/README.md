# One-off share links: create/fetch/delete driver

## Claim

`serverVELA/vela-share-policy/src/send_driver.rs` is the total per-request
decision relation for the anonymous one-off share-link endpoints
(`POST /send`, `GET /send/:id`, `DELETE /send/:id`). For **every** event list
(`begin_create`, `begin_fetch`, `begin_delete`, `step`, every `on_*_event`
wrapper), F* checks:

- `send_state_is_sound`/`send_effect_is_sound` are preserved; out-of-order
  events and every event after `Done` are `Idle`;
- **create**: the only insert permit is produced for an authenticated owner
  after the ciphertext/salt decode and every bound. The permit carries the
  clamped TTL (`5 min … 30 days`), the clamped view count (`1 … 1000`) and
  `view_once ⇒ max_views = 1` (`create_effect_is_bounded`). A request without
  an owner never reaches `InsertSend` (`create_requires_owner`);
- **fetch**: at most one delivery per request (`delivery_count ≤ 1`), a
  delivery is only behind a successful consume (`delivered ⇒ consumed`), and
  a failed consume can never deliver;
- **delete**: the only delete permit is owner-bound
  (`delete_effect_is_owner_bound`); a request without an owner never reaches
  `DeleteLink` (`delete_requires_owner`), and ends failed with
  `deleted = false`;
- success and failure exclude each other; reachability witnesses cover a
  successful create, a view-once fetch, an unavailable fetch, an owner delete,
  a non-owner delete and a create without an owner.

Extraction: 14 selected postconditions (3 begin decisions, 5 stage decisions
via `step`, 5 total per-effect wrappers, and the soundness predicates reached
through their preconditions).

## Composition (`send-driver-composition`)

A schedule is any list of `Create single_use views`, `Fetch` and `Delete owner`
actions over one shared link store; each action runs the extracted driver from
its begin transition. The invariant and schedule lemmas prove, for every
schedule:

- `single_use_at_most_one_fetch`: on a single-use link (and over any schedule
  that does not create a new link) the number of successful-fetch **driver
  decisions** is ≤ 1;
- `no_fetch_after_delete`: the counter of successful fetches after deletion is
  always 0;
- `only_owner_deletes`: the counter of non-owner delete decisions is always 0;
- witnesses evaluate concrete schedules: `[Fetch; Fetch; Delete false]` on a
  single-use link yields exactly one success and a deleted link,
  `[Create false 1; Fetch; Fetch; Fetch]` yields two successes, and
  `[Delete true; Fetch]` yields a delete with no fetch afterwards.

All counters increment on driver decisions (`f_succeeded`, `f_delivered`,
`f_deleted`), never on SQL statements.

## Read-only list

`GET /sends` has no state transition and therefore no driver. It authenticates
with `DeviceSession`, rate-limits per user, and selects only rows with
`owner_user_id = session.user_id` (unrevoked, unexpired, newest first, limit
200). The authorization predicate is that SQL scope; see the crate README.

## How the handlers are tied to the checked loop

- `src/send_interpreter.rs` defines `send_interpreter!` once; `run_send`
  expands it synchronously and hax extracts it.
- `serverVELA/vela-server/src/send.rs` expands the same macro with `await` in
  all three handlers over `CreateSendIo`, `FetchSendIo` and `DeleteSendIo`,
  each holding all I/O for its path. SQL text, statuses, messages and effect
  order are unchanged; request-dependent errors stay in an `error` slot.
- `security/formal/tests/test_handler_interpreters.py` requires the three
  `await` expansions and forbids direct driver transitions in the handler.

## Mutations (copies of the extraction, not committed)

All on `/tmp/vela-f2-account-b-mut/`; every one fails under the same F*
invocation.

| Mutation | Result |
|---|---|
| `mutation-create-without-owner.diff`: `begin_create` ignores `owner_present` | `create_requires_owner` fails |
| `mutation-delete-without-owner.diff`: `begin_delete` ignores `owner_present` | `delete_requires_owner` fails |
| `mutation-ttl-unbounded.diff`: `clamp_ttl` drops the 30-day ceiling | `begin_create` postcondition fails |
| `mutation-single-use-reusable.diff`: composition keeps a fetched single-use link live | `step_world_preserves` fails |
| `mutation-delete-keeps-link.diff`: composition delete leaves the link live | `delete_then_fetch_witness` fails |

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly. The three `sends` statements, the response fields and the
  error texts are reviewed and exercised by `integration.rs`.
- `Consumed` means the atomic `UPDATE … WHERE revoked = 0 AND expires_at > ?
  AND (max_views IS NULL OR view_count < max_views)` matched one row; this
  module does not model SQL or clocks.
- The composition is over one modelled link and atomic actions; SQL
  linearizability and multi-link schedules are outside it.
- The server's expansion differs from the checked one only by `.await`.

## Reproduction

```bash
cd serverVELA/vela-share-policy
./verify-fstar-send-driver.sh       # driver + per-request lemmas + composition
./verify-fstar-send-interpreter.sh  # interpreter extraction + lemmas
./verify-fstar.sh                   # full crate chain
python3 ../../security/formal/tests/test_handler_interpreters.py  # from repo root
```

`focused-verify.log` and `full-verify.log` are the local runs (F* 2025.10.06,
Z3 4.13.3, hax 0.3.7). No hosted run was recorded for this increment.
