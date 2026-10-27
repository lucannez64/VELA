# Recovery-share lifecycle: handler-to-driver interpreter

## Claim

All four recovery-share handlers reach the pure lifecycle driver only through
one macro loop, and that loop is checked. For every executor (any
implementation of `RecoveryShareIo`, any behaviour), the extracted
`run_share_lifecycle`:

1. calls exactly the executor method for the effect the driver has just
   emitted, with that effect's permit, one call per turn, and none once the
   driver reached a verdict (`run_share_lifecycle_is_run_ev`);
2. receives observations that each answer the effect they were returned for,
   and ends in the driver's `run` over that list
   (`rs_run_ev_follows_the_driver`, `run_share_lifecycle_theorem`);
3. stops every later turn after an abort, so the handler renders the recorded
   error unchanged;
4. therefore ends in a state where every per-request lifecycle theorem from
   `recovery-share-driver-lemmas` holds.

## How the handlers are tied to the checked loop

- `serverVELA/vela-recovery-policy/src/recovery_share_interpreter.rs` defines
  the loop once as `recovery_share_interpreter!`. `run_share_lifecycle`
  expands it synchronously; hax extracts that function
  (`proofs/fstar/extraction-recovery-share-interpreter/`).
- `serverVELA/vela-server/src/recovery/mod.rs` expands the same macro with
  `await` over four async executor structs (`PutShareIo`, `FinalizeShareIo`,
  `GetShareIo`, `DeleteShareIo`), each holding all of the request's I/O: one
  async method per effect, each returning only its observation type. The
  unused methods refuse with `None` and an error slot rather than panicking.
- `security/formal/tests/test_handler_interpreters.py` requires four `await`
  expansions in the handler file, forbids importing or calling driver
  transitions there, and requires the policy crate to define the macro once
  and expand it once.
- The executor trait is declared from one signature list (`executor_trait!`):
  under hax every method gets `requires(true)`, so the proof assumes nothing
  about the executor; ordinary builds get the same trait without attributes.

## Mutation (copy under `/tmp/vela-f2-recshare-mut/`, not committed)

| Mutation | Result |
|---|---|
| `mutation-ignore-abort.diff`: the `StageShare` turn treats an executor `None` as `Staged` and steps anyway | `run_share_lifecycle_is_run_ev` fails (log: `mutation-ignore-abort.log`): the extracted loop no longer mirrors the aborting turn |

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly (the SQL text and the exact predicates are reviewed and
  exercised by `integration.rs` and the bounded model).
- The server's macro expansion differs from the checked one only by `.await`;
  that is a property of `macro_rules!`, not a proof.
- Store/SQL linearizability.

## Reproduction

```bash
cd serverVELA/vela-recovery-policy
./verify-fstar-recovery-share-driver.sh      # run first: driver + composition
./verify-fstar-recovery-share-interpreter.sh # interpreter extraction + lemmas
python3 -m unittest discover -s security/formal/tests -p 'test_*.py'
```

`interpreter-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).
