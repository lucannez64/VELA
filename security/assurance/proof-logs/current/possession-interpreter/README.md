# Possession-proof recovery: handler-to-driver interpreters

## Claim

The two possession-proof handlers reach their drivers only through one loop
each, and both loops are checked. For every executor implementation, the
extracted `run_possession_initiation` and `run_possession_recover`:

1. call exactly the executor method for the effect the driver has just emitted,
   in order, with that effect's argument (the grant permit), and nothing once
   the driver reached a verdict (`run_possession_*_is_run_ev`);
2. receive observations that each answer the effect they were returned for, and
   end in the driver's `run_*_from_begin evs` for that list
   (`*_run_ev_follows_the_driver`);
3. reach a verdict (`Complete`, `Fail`) within their budgets (3 and 6 turns),
   or stop early because an effect aborted, in which case the handler renders
   the recorded error unchanged (`*_run_ev_reaches_a_verdict`);
4. therefore end in a state where every per-request possession theorem holds:
   at most one stored challenge / issued grant, a grant carries a consumed,
   matched, verified, non-empty current-epoch proof, and no driver effect
   releases the server share (`run_possession_*_theorem`).

## How the handlers are tied to the checked loops

- `serverVELA/vela-recovery-policy/src/possession_interpreter.rs` defines both
  loops once (`possession_initiation_interpreter!` and
  `possession_recover_interpreter!`). `run_possession_initiation` and
  `run_possession_recover` expand them synchronously; hax extracts both
  (`proofs/fstar/extraction-possession-interpreter/`).
- `serverVELA/vela-server/src/recovery/possess.rs` expands the same macros with
  `await` over `InitiateProofIo` and `RecoverProofIo`, which hold all of the
  request's I/O: one async method per effect. A failing method records the
  original error and returns `None` (abort).
- `security/formal/tests/test_handler_interpreters.py` requires exactly one
  `await` expansion per macro, forbids importing or calling driver transitions
  in the handler, and pins the macro set per interpreter source.

## Mutations (copies of the extraction, not committed)

| Mutation | Result |
|---|---|
| `mutation-a.diff`: initiation `Observe` calls the challenge-store method | type error; the extracted loop does not typecheck |
| `mutation-b.diff`: a recover verdict still calls `issue_grant` | `run_possession_recover_is_run_ev` fails |

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly (reviewed; exercised by `integration.rs` including the
  stale-challenge race and by `recovery_possession_model.rs`).
- The server's macro expansions differ from the checked ones only by `.await`.
- The cryptographic proof verification is an observation; the checked policy
  decides what it authorizes.
- Store/SQL linearizability and the single-use guarantee of `get_del`.

## Reproduction

```bash
cd serverVELA/vela-recovery-policy
./verify-fstar-possession-driver.sh      # regenerates the driver extraction
./verify-fstar-possession-interpreter.sh # interpreter extraction + lemmas
python3 -m unittest discover -s security/formal/tests -p 'test_*.py'
```

`interpreter-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).

## Hosted reproduction

The [6be552c security workflow](https://github.com/lucannez64/VELA/actions/runs/40538488807) re-extracted and verified
this interpreter and its lemmas in its crate's chain; all fifteen PR checks
passed. `hosted-6be552c.log` holds the summary and hashes, which match the
local run.
