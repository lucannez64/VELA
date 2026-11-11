# Account deletion: handler-to-driver interpreter

## Claim

`DELETE /account` reaches its driver only through one loop, and that loop is
checked. For every executor (any implementation of `DeletionIo`, any
behaviour), the extracted `run_deletion`:

1. calls exactly the executor method for the effect the driver has just
   emitted, with that effect's argument (the table for `DeleteTable`), one
   call per turn, and none once the driver reached a verdict
   (`run_deletion_is_run_ev`);
2. receives observations that each answer the effect they were returned for,
   and ends in `run_from_actor actor evs` for that list
   (`run_ev_follows_the_driver`);
3. reaches a verdict (`Complete`, `Fail`) within its 14-turn budget
   (`run_ev_reaches_a_verdict`);
4. therefore ends in a state where every per-request deletion theorem holds:
   a response implies a commit after the `users` row was deleted, a commit
   implies the transaction started, success and failure exclude each other
   (`run_deletion_theorem`).

## How the handler is tied to the checked loop

- `serverVELA/vela-session-policy/src/deletion_interpreter.rs` defines the loop
  once as `deletion_interpreter!`. `run_deletion` expands it synchronously;
  hax extracts that function (`proofs/fstar/extraction-deletion-interpreter/`).
- `serverVELA/vela-server/src/account/delete.rs` expands the same macro with
  `await` over `DeleteAccountIo`, which holds all of the request's I/O: one
  async method per effect, each returning only its observation type.
- `security/formal/tests/test_handler_interpreters.py` requires exactly one
  `await` expansion in the handler, forbids importing or calling driver
  transitions there, and requires the policy crate to define the macro once
  and expand it once.
- The executor trait is declared from one signature list (`executor_trait!`):
  under hax every method gets `requires(true)`, so the proof assumes nothing
  about the executor; ordinary builds get the same trait without attributes.

## Mutations (copies of the extraction, not committed)

| Mutation | Result |
|---|---|
| `mutation-a.diff`: `ScanDevices` calls the web-session scan | `run_deletion_is_run_ev` fails |
| `mutation-b.diff`: a verdict still calls `commit` | `run_deletion_is_run_ev` fails |

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly (the SQL text and store keys in `DeleteAccountIo` are
  reviewed, and exercised by `integration.rs` including the fault-injected
  rollback and by `account_deletion_model.rs`).
- The server's macro expansion differs from the checked one only by `.await`;
  that is a property of `macro_rules!`, not a proof.
- Store/SQL linearizability and the transaction's rollback on drop.

## Reproduction

```bash
cd serverVELA/vela-session-policy
./verify-fstar-deletion-driver.sh      # regenerates the driver extraction
./verify-fstar-deletion-interpreter.sh # interpreter extraction + lemmas
python3 -m unittest discover -s security/formal/tests -p 'test_*.py'
```

`interpreter-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).

## Hosted reproduction

The [f947ef7 security workflow](https://github.com/lucannez64/VELA/actions/runs/40488103343) re-extracted and verified the
interpreter and its lemmas in the session-policy chain; all fifteen PR checks
passed. `hosted-f947ef7.log` holds the summary and hashes, which match the
local run.
