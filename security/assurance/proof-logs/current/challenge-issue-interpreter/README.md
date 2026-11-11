# GET /auth/challenge: handler-to-driver interpreter

## Claim

`GET /auth/challenge` reaches its driver only through one loop, and that loop is
checked. For every executor (any implementation of `ChallengeIssueIo`, any
behaviour), the extracted `run_issue`:

1. calls exactly the executor method for the effect the driver has just
   emitted, with the parsed purpose for the store, one call per turn, and none
   once the driver reached a verdict (`run_issue_is_run_ev`);
2. receives observations that each answer the effect they were returned for,
   and ends in `run_from_purpose purpose evs` for that list
   (`run_ev_follows_the_driver`);
3. reaches a verdict (`Issue`, `Fail`) within its three-turn budget
   (`run_ev_reaches_a_verdict`);
4. therefore ends in a state where every per-request issue theorem holds: an
   issue implies a parsed purpose, an allowed limiter, a 32-byte nonce and a
   fresh stored key; store and nonce effects occur at most once; success and
   failure exclude each other (`run_issue_theorem`).

## How the handler is tied to the checked loop

- `serverVELA/vela-session-policy/src/challenge_issue_interpreter.rs` defines the
  loop once as `challenge_issue_interpreter!`. `run_issue` expands it
  synchronously; hax extracts that function
  (`proofs/fstar/extraction-challenge-issue-interpreter/`).
- `serverVELA/vela-server/src/auth/challenge.rs` expands the same macro with
  `await` over `ChallengeIssueIo`, which holds the request's I/O: limiter,
  random source and first-writer-wins store.
- `security/formal/tests/test_handler_interpreters.py` requires exactly one
  `await` expansion in the handler, forbids importing or calling driver
  transitions there, and requires the policy crate to define the macro once and
  expand it once.
- The executor trait is declared from one signature list (`executor_trait!`):
  under hax every method gets `requires(true)`, so the proof assumes nothing
  about the executor; ordinary builds get the same trait without attributes.

## Mutation

`mutation-1.diff` changes the extracted loop budget from three turns to two;
`run_issue_is_run_ev` cannot match the extracted `run_issue` and fails.
`mutation-1.log` records the rejected run. The mutant is a copy under
`/tmp/vela-f2-account-a-mut/`, never committed.

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly (the limiter key, nonce length, store key and purpose tags in
  `ChallengeIssueIo` are reviewed and exercised by
  `challenge_single_use_model` and `integration.rs`).
- The server's macro expansion differs from the checked one only by `.await`;
  that is a property of `macro_rules!`, not a proof.
- Store/OS random/TTL semantics.

## Reproduction

```bash
cd serverVELA/vela-session-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-challenge-issue-driver.sh
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-challenge-issue-interpreter.sh
python3 -m unittest discover -s security/formal/tests -p 'test_*.py'
```

`interpreter-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).
