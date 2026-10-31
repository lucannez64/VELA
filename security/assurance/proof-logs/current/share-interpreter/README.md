# Sharing: handler-to-driver interpreter

## Claim

The five sharing HTTP requests (capsule send, linked-item update, linked-item
revoke, recipient inbox delete, share-EK registration) reach their driver only
through one loop, and that loop is checked. For every executor (any
implementation of `ShareIo`, any behaviour), the extracted `run_share`:

1. calls exactly the executor method for the effect the driver has just
   emitted, with that effect's permit argument (`SendInsertPermit`,
   `LinkUpdatePermit`, `InboxDeletePermit`, `EkRegistrationPermit`), one call
   per turn, and none once the driver reached a verdict
   (`run_share_is_run_ev`);
2. receives observations that each answer the effect they were returned for,
   and ends in the extracted driver's `run` over that list
   (`run_ev_follows_the_driver`);
3. reaches a verdict (`Complete`, `Fail`) within its 3-turn budget
   (`run_ev_reaches_a_verdict`);
4. therefore ends in a state where every per-request sharing theorem holds:
   `send_interpreter_theorem`, `update_interpreter_theorem`,
   `revoke_interpreter_theorem`, `inbox_interpreter_theorem` and
   `ek_interpreter_theorem`. Send and revoke invoke the driver's existing
   `share_trace_send_theorem` and `share_trace_revoke_theorem`; the update,
   inbox and EK corollaries state the same trace soundness and
   at-most-one-success facts.

## How the handlers are tied to the checked loop

- `serverVELA/vela-share-policy/src/interpreter.rs` defines the loop once as
  `share_interpreter!`. `run_share` expands it synchronously; hax extracts that
  function (`proofs/fstar/extraction-interpreter/`). The `start_*` entry points
  are the driver's own `begin_*` decisions, so a handler never names a driver
  transition.
- `serverVELA/vela-server/src/share/mod.rs` expands the macro with `await` over
  `SendIo`, `LinkUpdateIo`, `LinkRevokeIo`, `InboxDeleteIo` and `ShareEkIo`.
  Each executor struct holds all of the request's I/O and retains the original
  storage/decode error so the response keeps the historical status and message.
- `serverVELA/vela-server/src/share/executor.rs` gives the executor shape an
  async default per method; a handler overrides only the effects its request
  kind can reach.
- `security/formal/tests/test_handler_interpreters.py` requires the exact
  number of `await` expansions in the handler, forbids importing or calling
  driver transitions there, and requires the policy crate to define the macro
  once and expand it once.

## Mutations (copies of the extraction, not committed)

| Mutation | Result |
|---|---|
| `mutation-a.diff`: the `ObserveLink` turn calls `f_observe_device` and feeds `ShareEvent_EkObserved` | `run_share_is_run_ev` fails (`Assertion failed`, lemma line 176) |
| `mutation-b.diff`: a verdict still calls `f_observe_link` | `run_share_is_run_ev` fails (`Assertion failed`, lemma line 176) |

Both mutations type-check; the failures are proof failures, not syntax errors.

## Assumptions and non-claims

- Each executor method performs the SQL its name describes and reports the
  outcome honestly (the statements are reviewed and exercised by
  `share_channel_model.rs` and `integration.rs`, including the device-signed EK
  binding).
- The server's macro expansion differs from the checked one only by `.await`;
  that is a property of `macro_rules!`, not a proof.
- SQL isolation, linearizability of the guarded statements, clock behaviour and
  the cryptography itself.
- The revoke's cleanup result is deliberately ignored (both outcomes complete),
  exactly as the historical handler did.

## Reproduction

```bash
cd serverVELA/vela-share-policy
./verify-fstar-driver.sh      # regenerates the driver extraction
./verify-fstar-share-interpreter.sh # interpreter extraction + lemmas
python3 -m unittest discover -s security/formal/tests -p 'test_*.py'
```

`interpreter-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).
`mutation-a.log` and `mutation-b.log` are the mutation runs against copies under
`/tmp/vela-mut/`.

## Hosted reproduction

The [6be552c security workflow](https://github.com/lucannez64/VELA/actions/runs/40538488807) re-extracted and verified
this interpreter and its lemmas in its crate's chain; all fifteen PR checks
passed. `hosted-6be552c.log` holds the summary and hashes, which match the
local run.
