# POST /account/register: handler-to-driver interpreter

## Claim

`POST /account/register` reaches its driver only through one loop, and that loop
is checked. For every executor (any implementation of `RegistrationIo`, any
behaviour), the extracted `run_registration`:

1. calls exactly the executor method for the effect the driver has just
   emitted, one call per turn, and none once the driver reached a verdict
   (`run_registration_is_run_ev`);
2. receives observations that each answer the effect they were returned for,
   and ends in `run_from_observation observation evs` for that list
   (`run_ev_follows_the_driver`);
3. reaches a verdict (`Complete`, `Fail`) within its eight-turn budget
   (`run_ev_reaches_a_verdict`);
4. therefore ends in a state where every per-request registration theorem holds:
   a response implies an account and first device inserted, a commit, an issued
   token and a tracked JTI; success and failure exclude each other
   (`run_registration_theorem`).

## How the handler is tied to the checked loop

- `serverVELA/vela-session-policy/src/registration_interpreter.rs` defines the
  loop once as `registration_interpreter!`. `run_registration` expands it
  synchronously; hax extracts that function
  (`proofs/fstar/extraction-registration-interpreter/`).
- `serverVELA/vela-server/src/account/mod.rs` expands the same macro with
  `await` over `RegisterIo`, which holds all of the request's I/O: one async
  method per effect, each returning only its observation type.
- `security/formal/tests/test_handler_interpreters.py` requires exactly one
  `await` expansion in the handler, forbids importing or calling driver
  transitions there, and requires the policy crate to define the macro once and
  expand it once.
- The executor trait is declared from one signature list (`executor_trait!`):
  under hax every method gets `requires(true)`, so the proof assumes nothing
  about the executor; ordinary builds get the same trait without attributes.

## Mutation

`mutation-1.diff` changes the extracted loop budget from eight turns to seven;
`run_registration_is_run_ev` cannot match the extracted `run_registration` and
fails. `mutation-1.log` records the rejected run. The mutant is a copy under
`/tmp/vela-f2-account-a-mut/`, never committed.

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly (the SQL text and store keys in `RegisterIo` are reviewed,
  and exercised by `integration.rs` including the new rollback test).
- Dropping an unfinished `TxGuard` rolls back the account row.
- The server's macro expansion differs from the checked one only by `.await`;
  that is a property of `macro_rules!`, not a proof.
- SQL/store linearizability and token-service behaviour.

## Reproduction

```bash
cd serverVELA/vela-session-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-registration-driver.sh
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-registration-interpreter.sh
python3 -m unittest discover -s security/formal/tests -p 'test_*.py'
```

`interpreter-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).
