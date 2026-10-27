# Enrollment redemption: handler-to-driver interpreter

## Claim

`POST /recovery/enroll-device` reaches its redemption driver only through one
loop, and that loop is checked. For every executor (any implementation of
`RedemptionIo`, any behaviour), the extracted `run_redemption`:

1. calls exactly the executor method for the effect the driver has just
   emitted, with that effect's argument (the insert permit), one call per turn,
   and none once the driver reached a verdict; a `RestoreAndFail` performs its
   one restoration and then stops (`run_redemption_is_run_ev`);
2. receives observations that each answer the effect they were returned for,
   and ends in `run_from_ready ready evs` for that list
   (`run_ev_follows_the_driver`);
3. reaches a verdict (`Complete`, `Fail`, `RestoreAndFail`) within its five-turn
   budget, or stops early because an effect (or the restoration) aborted, in
   which case the handler renders the recorded error unchanged
   (`run_ev_reaches_a_verdict`);
4. therefore ends in a state where every per-request redemption theorem holds:
   no success with a restoration, no restoration after a success, and at most
   one insert success (`run_redemption_theorem`).

## How the handler is tied to the checked loop

- `serverVELA/vela-recovery-policy/src/redemption_interpreter.rs` defines the
  loop once as `redemption_interpreter!`. `run_redemption` expands it
  synchronously; hax extracts that function
  (`proofs/fstar/extraction-redemption-interpreter/`).
- `serverVELA/vela-server/src/recovery/enroll_device.rs` expands the same macro
  with `await` over `EnrollDeviceIo`, which holds all of the request's I/O: one
  async method per effect, each returning only its observation type. A method
  that fails records the original error and returns `None`, which the loop
  reports as an abort.
- `security/formal/tests/test_handler_interpreters.py` requires exactly one
  `await` expansion in the handler, forbids importing or calling driver
  transitions there, and requires the policy crate to define the macro once and
  expand it once.
- The executor trait is declared from one signature list (`executor_trait!`):
  under hax every method gets `requires(true)`, so the proof assumes nothing
  about the executor; ordinary builds get the same trait without attributes.

## Mutations (copies of the extraction, not committed)

| Mutation | Result |
|---|---|
| `mutation-a.diff`: `Consume` calls the authority-recheck method | type error; `run_redemption` does not typecheck |
| `mutation-b.diff`: a verdict still calls `restore_grant` | `run_redemption_is_run_ev` fails |

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly (the SQL text, store keys and grant restoration in
  `EnrollDeviceIo` are reviewed, and exercised by `integration.rs` and
  `enrollment_ceremony_model.rs`).
- The server's macro expansion differs from the checked one only by `.await`;
  that is a property of `macro_rules!`, not a proof.
- Store/SQL linearizability and the single-use guarantee of `get_del`.

## Reproduction

```bash
cd serverVELA/vela-recovery-policy
./verify-fstar-driver.sh                 # regenerates the driver extraction
./verify-fstar-redemption-interpreter.sh # interpreter extraction + lemmas
python3 -m unittest discover -s security/formal/tests -p 'test_*.py'
```

`interpreter-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).
