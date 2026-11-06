# `/auth/verify`: handler-to-driver interpreter

## Claim

`POST /auth/verify` reaches its driver only through one loop, and that loop is
checked. For every executor (any implementation of `LoginIo`, any behaviour),
the extracted `run_login`:

1. calls exactly the executor method for the effect the driver has just
   emitted, one call per turn, and none once the driver reached a verdict
   (`Respond`, `Fail`, `Idle`) (`run_login_is_run_ev`);
2. receives observations that each answer the effect they were returned for,
   and ends in `run_from_begin evs` for that list
   (`run_ev_follows_the_driver`);
3. reaches a verdict within its six-turn budget (`run_ev_reaches_a_verdict`);
4. therefore ends in a state where the per-request login theorem holds
   (`run_login_theorem`): the final driver is trace-sound, a response excludes a
   terminal failure, at most one response was authorized, and a response
   implies an accepted matching-purpose challenge, a present unrevoked device, a
   valid verifier result and a tracked JTI. The last lemma applies
   `login_trace_theorem` from `proofs/fstar/login-driver-lemmas` to the
   observation list the executor actually returned.

## Executor methods

| Effect | Method | Observation |
|---|---|---|
| `ConsumeChallenge` | `consume_challenge` | `ChallengeObservation` |
| `ObserveDevice` | `observe_device` | `DeviceObservation` |
| `VerifySignature` | `verify_signature` | `VerifierObservation` |
| `RecordVerificationFailure` | `record_verification_failure` | `FailureRecordObservation` |
| `ResetBackoff` | `reset_backoff` | `BackoffResetObservation` |
| `IssueToken` | `issue_token` | `TokenIssueObservation` |
| `TrackToken` | `track_token` | `TokenTrackObservation` |

`Respond`, `Fail` and `Idle` are terminal and perform nothing.

## How the handler is tied to the checked loop

- `serverVELA/vela-session-policy/src/login_interpreter.rs` defines the loop
  once as `login_interpreter!`. `run_login` expands it synchronously; hax
  extracts that function (`proofs/fstar/extraction-login-interpreter/`).
- `serverVELA/vela-server/src/auth/verify.rs` expands the same macro with
  `await` over `VerifyIo`, which holds all of the request's I/O and the errors
  the response needs: one async method per effect, each returning only its
  observation type.
- The executor trait is declared from one signature list (`executor_trait!` in
  `serverVELA/vela-session-policy/src/executor_trait.rs`, shared with the
  deletion and revocation interpreters): under hax every method gets
  `requires(true)`, so the proof assumes nothing about the executor.
- `security/formal/tests/test_handler_interpreters.py` requires exactly one
  `await` expansion in the handler, forbids importing or calling driver
  transitions there, and requires the policy crate to define the macro once and
  expand it once.

## What stays outside the macro

- The per-IP limiter and the backoff precheck. They run before the challenge
  take, i.e. before the driver begins, and are unchanged.
- The best-effort `last_active` update. It is performed by the executor's
  `reset_backoff` method on the success path only — the effect that precedes
  issuance — so the I/O order (`reset streak`, `UPDATE devices`, `issue`) and
  every observable are unchanged. A failed reset still skips the update and
  returns the store's own error, exactly as before.
- Response rendering. Statuses and messages are the historical ones; storage
  and verifier errors are kept in executor fields so the response carries the
  original text.
- `plan_admission` (the middleware's single pure admission decision) is exempt:
  it has no effect loop to interpret. It is listed in
  `../revocation-interpreter/README.md` with its reason.

## Mutations (copies of the extraction, not committed)

| Mutation | Result |
|---|---|
| `mutation-a.diff`: `ConsumeChallenge` also calls `f_observe_device` (an executor method the driver did not ask for) | `run_login_is_run_ev` fails |
| `mutation-b.diff`: a verdict still calls `f_track_token` | `run_login_is_run_ev` fails |

Both are well typed, so the failure is the theorem, not the type checker. The
logs are `mutation-a.log` and `mutation-b.log`.

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly (the SQL text, store keys and PASETO call in `VerifyIo` are
  reviewed and exercised by `login_driver_handler.rs` and `integration.rs`).
- The server's macro expansion differs from the checked one only by `.await`;
  that is a property of `macro_rules!`, not a proof.
- Single-use nonce linearization is proved separately in
  `proofs/fstar/login-driver-composition/` over the atomic take adapter; this
  module carries the observation kinds, not the store.
- Store/SQL linearizability, the clock, the hybrid verifier and PASETO
  cryptography remain trusted.

## Reproduction

```bash
cd serverVELA/vela-session-policy
./verify-fstar-login-driver.sh       # regenerates the driver extraction
./verify-fstar-login-interpreter.sh  # interpreter extraction + lemmas
python3 -m unittest discover -s security/formal/tests -p 'test_*.py'
```

`interpreter-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).

## Hosted reproduction

The [6be552c security workflow](https://github.com/lucannez64/VELA/actions/runs/40538488807) re-extracted and verified
this interpreter and its lemmas in its crate's chain; all fifteen PR checks
passed. `hosted-6be552c.log` holds the summary and hashes, which match the
local run.
