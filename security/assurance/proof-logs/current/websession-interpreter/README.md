# Web-session handler-to-driver interpreters

## Claim

Each of the four web-session handlers expands one `websession_*_interpreter!`
macro with `await`. The policy crate expands the same macro text into a
synchronous runner; hax extracts it and F* proves, for every executor:

1. the loop calls exactly the executor method for the effect the driver has
   just emitted, with that effect's argument, one call per turn, and nothing
   once the driver reached a verdict (`run_*_is_run_ev`);
2. the observations returned form a list in which each answers the effect it
   was returned for, and the final driver is the driver's own run over that
   list (`run_ev_follows_the_driver`);
3. the driver reaches a verdict within its budget (3 start, 3 grant, 7 token,
   3 delete turns) (`run_ev_reaches_a_verdict`);
4. hence every per-request theorem holds for the state the real handler ends in
   (`*_run_theorem`).

## How the handlers are tied to the checked loops

- `serverVELA/vela-session-policy/src/websession_interpreter.rs` defines the
  four macros once and expands each into `run_start`, `run_grant`, `run_token`,
  `run_delete`.
- `serverVELA/vela-server/src/web_session/mod.rs` expands each macro with
  `await` over an executor struct holding all of the request's I/O.
- `security/formal/tests/test_handler_interpreters.py` requires exactly one
  `await` expansion per handler/macro, forbids importing or calling driver
  transitions there, and requires the policy crate to define each macro once
  and expand it once.

## Notes

- The token driver models issue and JTI tracking as one effect, so the handler
  tracks before the driver may respond and a tracking failure is a failed
  exchange.
- The interpreter lemma modules are split one per loop and checked in separate
  `fstar.exe` invocations so the fold/iteration SMT patterns do not interact.

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly.
- The server's expansion differs from the checked one only by `.await`;
  that is a property of `macro_rules!`, not a proof.
- Store/SQL linearizability and request cancellation remain outside.

## Reproduction

```bash
cd serverVELA/vela-session-policy
./verify-fstar-websession-driver.sh
./verify-fstar-websession-interpreter.sh
```
