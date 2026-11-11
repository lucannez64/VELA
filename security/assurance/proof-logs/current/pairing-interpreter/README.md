# Device pairing: handler-to-driver interpreter

## Claim

The six device-pairing HTTP ceremonies (invitation package store, package
redemption, grant opening, claim, completion, result collection) reach their
driver only through one loop, and that loop is checked. For every executor (any
implementation of `PairingIo`, any behaviour), the extracted `run_pairing`:

1. calls exactly the executor method for the effect the driver has just
   emitted, with that effect's argument (the `CompletionAccountObservation` for
   the account preflight), one call per turn, and none once the driver reached
   a verdict (`run_pairing_is_run_ev`);
2. receives observations that each answer the effect they were returned for,
   and ends in the extracted driver's `run` over that list
   (`run_ev_follows_the_driver`);
3. reaches a verdict (`Complete`, `ReturnResult`, `Fail`, `RestoreAndFail`)
   within its 5-turn budget (`run_ev_reaches_a_verdict`);
4. therefore ends in a state where every per-request pairing theorem holds:
   `store_interpreter_theorem`, `invitation_interpreter_theorem`,
   `open_interpreter_theorem`, `claim_interpreter_theorem`,
   `completion_interpreter_theorem` and `result_interpreter_theorem`. The last
   four invoke the driver's existing `invitation_trace_theorem`,
   `claim_trace_theorem`, `completion_trace_theorem` and
   `result_trace_theorem`; the store and open corollaries state the same trace
   soundness and at-most-one-success/one-failure facts.

## How the handlers are tied to the checked loop

- `serverVELA/vela-enrollment-policy/src/pairing_interpreter.rs` defines the
  loop once as `pairing_interpreter!`. `run_pairing` expands it synchronously;
  hax extracts that function (`proofs/fstar/extraction-pairing-interpreter/`).
  The `start_*` entry points are the driver's own `begin_*` decisions, so a
  handler never names a driver transition.
- `serverVELA/vela-server/src/device/invitation.rs` expands the macro with
  `await` over `StorePackageIo` and `RedeemPackageIo`.
  `serverVELA/vela-server/src/device/rendezvous.rs` does the same over
  `OpenGrantIo`, `ClaimIo`, `CompleteIo` and `ResultIo`. Each executor struct
  holds all of the request's I/O and retains the original storage/decode error
  so the response keeps the historical status and message.
- `serverVELA/vela-server/src/device/pairing_executor.rs` gives the executor
  shape an async default per method; a handler overrides only the effects its
  ceremony can reach.
- `security/formal/tests/test_handler_interpreters.py` requires the exact
  number of `await` expansions in each handler, forbids importing or calling
  driver transitions there, and requires the policy crate to define the macro
  once and expand it once.
- The pairing driver's total `step` now also dispatches the account preflight
  (`PairingEvent::AccountChecked`), so every effect the handlers perform is an
  event in the extracted trace. This is a pure addition: `on_completion_account`
  is unchanged and the composition module still calls it directly.

## Mutations (copies of the extraction, not committed)

| Mutation | Result |
|---|---|
| `mutation-a.diff`: the `StorePackage` turn calls `f_store_grant` | `run_pairing_is_run_ev` fails (`Assertion failed`, lemma line 199) |
| `mutation-b.diff`: a verdict still calls `f_store_package` | `run_pairing_is_run_ev` fails (`Assertion failed`, lemma line 199) |

Both mutations type-check; the failures are proof failures, not syntax errors.

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly (the sled keys, SQL text and signature checks are reviewed,
  and exercised by `pairing_model.rs`, `enrollment_ceremony_model.rs` and
  `integration.rs`).
- The server's macro expansion differs from the checked one only by `.await`;
  that is a property of `macro_rules!`, not a proof.
- Sled/SQL linearizability, clock behaviour and the cryptography itself.
- The `CompleteIo` path deliberately does not restore the consumed ceremony
  after an ambiguous insert error (U-19); it does restore after a definite
  zero-row insert and after a changed take. The interpreter preserves that
  distinction by mapping the terminal effects unchanged.

## Reproduction

```bash
cd serverVELA/vela-enrollment-policy
./verify-fstar-pairing-driver.sh      # regenerates the driver extraction
./verify-fstar-pairing-interpreter.sh # interpreter extraction + lemmas
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
