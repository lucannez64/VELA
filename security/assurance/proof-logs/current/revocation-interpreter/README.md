# `/device/revoke` and `/auth/logout`: handler-to-driver interpreters

## Claim

`POST /device/revoke` and `POST /auth/logout` reach their drivers only through
one loop each, and both loops are checked. For every executor (any
implementation of `RevocationIo` or `LogoutIo`, any behaviour), the extracted
`run_revocation` and `run_logout`:

1. call exactly the executor method for the effect the driver has just emitted,
   one call per turn, and none once the driver reached a verdict
   (`Complete`, `Fail`, `Idle`) (`run_revocation_is_run_ev`,
   `run_logout_is_run_ev`);
2. receive observations that each answer the effect they were returned for, and
   end in `run_from_actor actor evs` / `logout_run_from_begin observations` for
   that list (`run_ev_follows_the_driver`,
   `logout_run_ev_follows_the_driver`);
3. reach a verdict within their budgets — four revocation turns, one logout
   turn (`run_ev_reaches_a_verdict`,
   `logout_run_ev_reaches_a_verdict`);
4. therefore end in a state where the per-request theorems hold
   (`run_revocation_theorem`, `run_logout_theorem`): the final driver is
   trace-sound, at most one success and one failure effect occur, a recorded SQL
   row always has an applied lockout behind it, a completed cascade follows a
   successful or repeated revoke, success and failure exclude each other, the
   cascade/record order holds over the observation list, and a logout response
   implies the JTI marker was written. The last lemmas apply
   `revocation_trace_theorem` and `logout_success_implies_marker` from
   `proofs/fstar/revocation-driver-lemmas` to the observation lists the
   executors actually returned.

## Executor methods

Revocation (`RevocationIo`):

| Effect | Method | Observation |
|---|---|---|
| `LookupTarget` | `lookup_target` | `DeviceLookupObservation` |
| `LockoutDevice` | `lockout_device` | `LockoutObservation` |
| `RecordRevocation` | `record_revocation` | `RecordObservation` |
| `CascadeWebSessions` | `cascade_web_sessions` | `CascadeObservation` |

Logout (`LogoutIo`):

| Effect | Method | Observation |
|---|---|---|
| `RevokeJti` | `revoke_jti` | `LogoutObservation` |

`Complete`, `Fail` and `Idle` are terminal and perform nothing.

## How the handlers are tied to the checked loops

- `serverVELA/vela-session-policy/src/revocation_interpreter.rs` defines the
  loops once as `revocation_interpreter!` and `logout_interpreter!`.
  `run_revocation` and `run_logout` expand them synchronously; hax extracts both
  (`proofs/fstar/extraction-revocation-interpreter/`).
- `serverVELA/vela-server/src/device/revoke.rs` expands `revocation_interpreter!`
  with `await` over `RevokeDeviceIo`; `serverVELA/vela-server/src/auth/logout.rs`
  expands `logout_interpreter!` with `await` over `LogoutJtiIo`. Each executor
  holds all of its request's I/O and the original errors.
- The executor traits are declared from one signature list (`executor_trait!` in
  `serverVELA/vela-session-policy/src/executor_trait.rs`, shared with the
  deletion and login interpreters): under hax every method gets
  `requires(true)`, so the proof assumes nothing about the executor.
- `security/formal/tests/test_handler_interpreters.py` requires exactly one
  `await` expansion in each handler, forbids importing or calling driver
  transitions there, and requires the policy crate to define each macro once and
  expand it once.
- The two transition records in `revocation_driver` share the field names
  `driver` and `effect`. hax keeps record projections, and F* cannot infer the
  record from a bare `transition.effect` when two records declare that field, so
  the loops reach both through the pure accessors `revocation_driver_of`,
  `revocation_effect_of`, `logout_driver_of`, `logout_effect_of` in
  `revocation_interpreter.rs`. That is the only difference from the deletion and
  login macro text, and it changes no driver behaviour.

## What stays outside the macro

- `plan_admission` (in `revocation_driver.rs`, called from
  `vela-server/src/middleware.rs`) is exempt: it is one pure `observation ->
  decision` function with no effect loop, so there is nothing for an interpreter
  to sequentially interpret. Its F* contract
  (`admission_decision_matches_spec`) is checked by
  `verify-fstar-revocation-driver.sh`, and its composition with the deletion
  lockout is checked by `verify-fstar-deletion-driver.sh`.
- Response rendering. Statuses and messages are the historical ones; storage,
  query and parse errors are kept in executor fields so the responses carry the
  original text.

## Mutations (copies of the extraction, not committed)

| Mutation | Loop | Result |
|---|---|---|
| `mutation-c.diff`: `LockoutDevice` also calls `f_lookup_target` | revocation | `run_revocation_is_run_ev` fails |
| `mutation-d.diff`: a verdict still calls `f_cascade_web_sessions` | revocation | `run_revocation_is_run_ev` fails |
| `mutation-e.diff`: `RevokeJti` skips `f_revoke_jti` and fabricates `Applied` | logout | `run_logout_is_run_ev` fails |
| `mutation-f.diff`: `RevokeJti` calls `f_revoke_jti` twice | logout | `run_logout_is_run_ev` fails |

All four are well typed, so the failure is the theorem, not the type checker. The
logs are `mutation-c.log` … `mutation-f.log`.

Recorded finding: a *post-verdict* call in the logout loop's terminal arm cannot
be used as a mutant. The logout budget is one turn, so that arm is unreachable
inside the loop and F* (correctly) cannot distinguish it; the duplicate-call
mutation above covers the "the executor is asked for more I/O than the driver
emitted" property instead. For the revocation loop the post-verdict mutation is
reachable and fails as expected.

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly (the SQL text and store keys are reviewed and exercised by
  `device_revocation_model.rs` and `integration.rs`).
- The server's macro expansions differ from the checked ones only by `.await`;
  that is a property of `macro_rules!`, not a proof.
- Store/SQL linearizability, the sled TTL semantics and the clock remain
  trusted; the drivers are per-request values.

## Reproduction

```bash
cd serverVELA/vela-session-policy
./verify-fstar-revocation-driver.sh      # regenerates the driver extraction
./verify-fstar-revocation-interpreter.sh # interpreter extraction + lemmas
python3 -m unittest discover -s security/formal/tests -p 'test_*.py'
```

`interpreter-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).
