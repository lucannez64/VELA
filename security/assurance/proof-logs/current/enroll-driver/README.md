# Device enrollment: `POST /device/enroll` driver

## Claim

`serverVELA/vela-enrollment-policy/src/enroll_driver.rs` is the total
per-request decision relation for challenge-based device enrollment. The
handler performs exactly the effects the driver emits, and F* checks the
following for **every** event list (`begin_enroll`, `step`, every
`on_*_event` wrapper):

- `enroll_state_is_sound`/`enroll_effect_is_sound` are preserved by every
  transition, out-of-order events and every event after `Done` are `Idle`;
- `insert_decisions … <= 1`: **at most one device insert decision per request**
  (the insert event is the terminal decision, and a finished driver is inert);
- a final `inserted` state implies the enroll-purpose challenge was consumed,
  the enrolling device row was active, its authentication signature verified,
  the new key material and its enrollment signature verified, the rekey policy
  permitted the device-authority mutation and the guarded account epoch
  matched (`inserted_implies_approvals`);
- `succeeded ==> inserted`, `failed ==> !inserted`, and success/failure are
  mutually exclusive;
- an ambiguous insert error is terminal with no restoration: the `Failed`
  observation reaches `Done`/`Fail(InsertStorage)` and the driver has no
  restore effect (U-19), pinned by the `enroll-insert-error-retries` mutation;
- reachability witnesses: the happy five-event schedule inserts and succeeds;
  a rejected challenge and an ambiguous insert error both reach `Done` with
  `failed && !inserted`.

Extraction: 12 selected postconditions (1 begin, 5 stage decisions via `step`,
5 total per-effect wrappers, plus the two soundness predicates reached through
their preconditions).

## How the handler is tied to the checked loop

- `src/enroll_interpreter.rs` defines the loop once as
  `enroll_interpreter!`. `run_enroll` expands it synchronously; hax extracts it
  into `proofs/fstar/extraction-enroll-interpreter/`.
- `serverVELA/vela-server/src/device/enroll.rs` expands the same macro with
  `await` over `EnrollIo`, which holds all of the request's I/O: challenge
  consumption, device row read plus authentication signature, new-key decode
  and enrollment signature, the epoch/rekey permit, and the guarded insert.
  The original `AppError` is kept in one `error` slot so every failure keeps
  its exact status and text.
- `security/formal/tests/test_handler_interpreters.py` requires exactly one
  `await` expansion, forbids importing or calling driver transitions in the
  handler, and requires the policy crate to define the macro once and expand
  it once.

## Mutations (copies of the extraction, not committed)

All on `/tmp/vela-f2-account-b-mut/`, each a copy of the extracted driver and
the lemma module, checked with the same F* invocation; every one fails.

| Mutation | Result |
|---|---|
| `mutation-insert-without-approvals.diff`: `step` runs the insert event regardless of stage/flags | `step` postcondition fails |
| `mutation-insert-error-retries.diff`: `Failed` re-emits `InsertDevice` instead of ending | `insert_effect_is_done` fails |
| `mutation-rejected-challenge-continues.diff`: `Rejected` consumes the challenge and proceeds | `refused_challenge_reaches_failure` fails |

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly (SQL text and every message in `EnrollIo` are reviewed, and
  exercised by `integration.rs` and `challenge_single_use_model.rs`).
- `inserted` means the guarded `INSERT` reported one row; the row-level
  `users.key_epoch`/`rekey_state` guard is SQL, not modelled here. The
  "account epoch matches" fact is the guard's success observation.
- The hybrid signature checks are observed as booleans; signature
  unforgeability is outside this module.
- The server's expansion differs from the checked one only by `.await`.

## Reproduction

```bash
cd serverVELA/vela-enrollment-policy
./verify-fstar-enroll-driver.sh       # regenerates the driver extraction
./verify-fstar-enroll-interpreter.sh  # interpreter extraction + lemmas
./verify-fstar.sh                     # full crate chain
python3 ../../security/formal/tests/test_handler_interpreters.py  # from repo root
```

`focused-verify.log` and `full-verify.log` are the local runs (F* 2025.10.06,
Z3 4.13.3, hax 0.3.7). No hosted run was recorded for this increment.
