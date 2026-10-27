# Device enrollment: handler-to-driver interpreter

## Claim

`POST /device/enroll` reaches its driver only through one loop, and that loop
is checked. For every executor (any implementation of `EnrollIo`, any
behaviour), the extracted `run_enroll`:

1. calls exactly the executor method for the effect the driver has just
   emitted, with that effect's argument, one call per turn, and none once the
   driver reached a verdict (`run_enroll_is_run_ev`);
2. receives observations that each answer the effect they were returned for,
   and ends in `run_from_enroll evs` for that list
   (`run_ev_follows_the_driver`);
3. reaches a verdict (`Complete`, `Fail`) within its 5-turn budget
   (`run_ev_reaches_a_verdict`);
4. therefore ends in a state where every per-request enrollment theorem holds:
   at most one insert decision per request, the insert behind the consumed
   enroll-purpose challenge and every approval, success implies the insert,
   failure never inserts, and success/failure exclude each other
   (`enroll_interpreter_theorem`).

The lemma module has 18 top-level definitions, 8 of them lemmas, including the
two-term SMT pattern `[SMTPat (fold_range …); SMTPat (iter_turn …)]`; the
`iter_turn_is_run_ev` equality is stated explicitly before the final
`run_enroll == …` assertion.

## How the handler is tied to the checked loop

- `serverVELA/vela-enrollment-policy/src/enroll_interpreter.rs` defines the
  loop once as `enroll_interpreter!`. `run_enroll` expands it synchronously;
  hax extracts that function (`proofs/fstar/extraction-enroll-interpreter/`).
- `serverVELA/vela-server/src/device/enroll.rs` expands the same macro with
  `await` over `EnrollIo`, which holds all of the request's I/O, and renders
  only the driver's verdict. The original error lives in one `error` slot.
- `security/formal/tests/test_handler_interpreters.py` requires exactly one
  `await` expansion, forbids importing or calling driver transitions there, and
  requires the policy crate to define the macro once and expand it once.
- The executor trait is declared from one signature list (`executor_trait!`):
  under hax every method gets `requires(true)`, so the proof assumes nothing
  about the executor; ordinary builds get the same trait without attributes.

## Mutations (copies of the extraction, not committed)

See `../enroll-driver/README.md`; the driver mutations also exercise this
module's final theorem (the retry mutation makes `insert_decisions <= 1` fail).

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly (SQL text and messages reviewed; `integration.rs`,
  `challenge_single_use_model.rs` and `enrollment_ceremony_model.rs` exercise
  the boundary).
- The server's macro expansion differs from the checked one only by `.await`;
  that is a property of `macro_rules!`, not a proof.
- SQL linearizability and signature unforgeability are outside this module.

## Reproduction

```bash
cd serverVELA/vela-enrollment-policy
./verify-fstar-enroll-driver.sh       # regenerates the driver extraction
./verify-fstar-enroll-interpreter.sh  # interpreter extraction + lemmas
python3 ../../security/formal/tests/test_handler_interpreters.py  # from repo root
```

`interpreter-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).
No hosted run was recorded for this increment.
