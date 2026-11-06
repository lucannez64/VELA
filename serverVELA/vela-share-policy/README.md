# Verified sharing policy

This crate is the pure production policy for VELA's sharing surfaces. HTTP
parsing, signatures, clocks, SQL and the sled/Turso stores stay outside it; the
server converts its authenticated observations into facts, and can only act
from the private permits constructed here. hax extracts these decisions to F*
and checks their postconditions for every input.

| Surface | Production decision | Universally checked property |
|---|---|---|
| Cross-user sharing (M19/M21) | `driver.rs` | Capsule sends, linked-item update/revoke, inbox delete and share-EK registration follow the driver's guarded effects only; a non-sender never mutates a link. |
| `POST /send` | `send_driver::begin_create` | An insert is authorized only for an authenticated owner, after the ciphertext/salt decodes and inside the handler's bounds; the permit carries the clamped TTL (5 minutes … 30 days) and view count (1 … 1000, pinned to 1 by `view_once`). |
| `GET /send/:id` | `send_driver::begin_fetch` | A delivery is authorized only after the atomic view-consume matched a live, unexpired, unrevoked, unexhausted row. At most one delivery per request; a failed consume never delivers. |
| `DELETE /send/:id` | `send_driver::begin_delete` | The owner-scoped delete is reached only through an owner-bound permit; no effect is emitted without an authenticated owner. |
| `GET /sends` | *not a driver* | Read-only owner listing. The authorization check is the `DeviceSession` extractor plus the SQL predicate `WHERE owner_user_id = ?`; there is no state transition to plan, so it is deliberately outside the extracted drivers (see below). |

## `GET /sends` (read-only)

`GET /sends` carries no decision that changes state: it authenticates the
caller with the same `DeviceSession` middleware as the other owner endpoints,
rate-limits per user, and selects only rows whose `owner_user_id` equals the
session's user id (`AND revoked = 0 AND expires_at > ?`, newest first, limit
200). Because it performs no guarded write and has no permit-gated effect, it
is listed here rather than given a driver; the authorization predicate is the
SQL scope above and the handler is unchanged by the F-2 driver work.

## Send-link proofs

- `proofs/fstar/send-driver-lemmas/` quantifies over every observation list:
  create bounds, owner requirements, a delete permit is owner-bound, a fetch
  delivers at most once and only after a consume, plus reachability witnesses.
- `proofs/fstar/send-driver-composition/` composes any interleaving of
  create/fetch/delete over one shared link store: a single-use link yields at
  most one successful fetch, no successful fetch is ever counted after delete,
  and no non-owner delete commits. Counters increment on driver decisions
  (`f_succeeded`, `f_delivered`, `f_deleted`), not on SQL statements.
- `proofs/fstar/send-interpreter-lemmas/` proves the handler-visible loop
  `run_send` calls exactly the executor method for the driver's current effect,
  stops at the verdict within three turns, and ends in `run_from_create`,
  `run_from_fetch` or `run_from_delete` over the observations the executor
  actually returned.

## Run

Use the hax 0.3.7, Rust nightly 2025-11-08, F* 2025.10.06 and Z3 4.13.3
toolchain documented in
[`../vela-rekey-policy/README.md`](../vela-rekey-policy/README.md). Then:

```bash
./verify-fstar.sh
```

`verify-fstar.sh` checks the historical M19 selection, then the share driver,
the share interpreter, the one-off share-link driver (lemmas and composition)
and the share-link interpreter. The server handlers expand `send_interpreter!`
with `.await`; `security/formal/tests/test_handler_interpreters.py` enforces
that each handler uses that macro exactly once per request path and never calls
a driver transition directly.
