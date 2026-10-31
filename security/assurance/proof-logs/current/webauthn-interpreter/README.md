# WebAuthn recovery: handler-to-driver interpreters

## Claim

The four WebAuthn recovery handlers reach their drivers only through one loop
each, and all four loops are checked. For every executor implementation, the
extracted `run_registration_start`, `run_registration`, `run_auth_start` and
`run_auth_finish`:

1. call exactly the executor method for the effect the driver has just emitted,
   in order, with that effect's argument (the release permit), and nothing once
   the driver reached a verdict (`run_*_is_run_ev`);
2. receive observations that each answer the effect they were returned for, and
   end in the driver's `run_*` over that list
   (`*_run_ev_follows_the_driver`);
3. reach a verdict (`Complete`, `Fail`) within their budgets (3, 5, 3 and 8
   turns), or stop early because an effect aborted, in which case the handler
   renders the recorded error unchanged (`*_run_ev_reaches_a_verdict`);
4. therefore end in a state where every per-request WebAuthn theorem holds:

   | Loop | Budget | Per-request theorem |
   |---|---|---|
   | registration start | 3 | `registration_start_trace_theorem` |
   | registration finish | 5 | `registration_trace_theorem` |
   | authentication start | 3 | `auth_start_trace_theorem` |
   | authentication finish | 8 | `auth_finish_trace_theorem` |

## How the handlers are tied to the checked loops

- `serverVELA/vela-recovery-policy/src/webauthn_interpreter.rs` defines all four
  loops once (`registration_start_interpreter!`, `registration_interpreter!`,
  `auth_start_interpreter!`, `auth_finish_interpreter!`), along with the four
  executor traits. `run_registration_start`, `run_registration`,
  `run_auth_start` and `run_auth_finish` expand them synchronously; hax extracts
  all four (`proofs/fstar/extraction-webauthn-interpreter/`).
- `serverVELA/vela-server/src/recovery/webauthn.rs` expands
  `registration_start_interpreter!` and `registration_interpreter!` with
  `await`; `recovery/initiate.rs` expands `auth_start_interpreter!`;
  `recovery/recover.rs` expands `auth_finish_interpreter!`. Their executor
  structs (`RegisterStartIo`, `RegisterFinishIo`, `InitiateIo`, `RecoverIo`)
  hold all of the request's I/O: one async method per effect. A failing method
  records the original error and returns `None` (abort).
- `security/formal/tests/test_handler_interpreters.py` requires exactly one
  `await` expansion per macro, forbids importing or calling driver transitions
  in the handler, and pins the macro set per interpreter source.
- The proof structure is the one used by the checked redemption, possession and
  vault-upload interpreters: `fold_range_is_iter_turn` proves the extracted
  `fold_range` is the specification's `iter_turn`; `iter_turn_is_run_ev` and
  `run_*_is_run_ev` link it to the observation-collecting `run_ev`. The 8-arm
  authentication-finish loop additionally states the `iter_turn_is_run_ev`
  equality explicitly before the extracted-loop equality, so the two-term
  pattern `[SMTPat (fold_range ...); SMTPat (iter_turn ...)]` fires; relying on
  the solver to derive the `iter_turn` term by unfolding the large loop body is
  what defeated the earlier attempt.

## Mutations (copies of the extraction, not committed)

Each mutation is a copy of
`proofs/fstar/extraction-webauthn-interpreter/Vela_recovery_policy.Webauthn_interpreter.fst`
under `/tmp/vela-mut-webauthn/<id>/`, checked against the unchanged lemma
module.

| Mutation | Loop | Result |
|---|---|---|
| `mutation-rs-a.diff`: registration-start `Observe` calls the ceremony method | registration start | type error; the extracted loop does not typecheck |
| `mutation-rs-b.diff`: a registration-start verdict still calls `registration_start_store` | registration start | `run_registration_start_is_run_ev` fails |
| `mutation-reg-a.diff`: registration-finish `CountAttempt` calls the state-consumption method | registration finish | type error |
| `mutation-reg-b.diff`: a registration-finish verdict still calls `registration_persist` | registration finish | `run_registration_is_run_ev` fails |
| `mutation-as-a.diff`: authentication-start `Observe` calls the ceremony method | authentication start | type error |
| `mutation-as-b.diff`: an authentication-start verdict still calls `auth_start_store` | authentication start | `run_auth_start_is_run_ev` fails |
| `mutation-af-a.diff`: authentication-finish `CountAttempt` calls the context method | authentication finish | type error |
| `mutation-af-b.diff`: an authentication-finish verdict still calls `auth_finish_store_grant` | authentication finish | `run_auth_finish_is_run_ev` fails |

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly (reviewed; exercised by `integration.rs`,
  `recovery_lifecycle_model.rs` and `recovery_possession_model.rs`).
- The server's macro expansions differ from the checked ones only by `.await`.
- The WebAuthn ceremony/assertion checks and the SQL row queries are
  observations; the checked driver policy decides what they authorize.
- Store/SQL linearizability and the single-use guarantee of `get_del` remain
  outside these per-request theorems; cross-request composition is
  `webauthn-driver-composition`.

## Reproduction

```bash
cd serverVELA/vela-recovery-policy
./verify-fstar-webauthn-driver.sh      # regenerates the driver extraction
./verify-fstar-webauthn-interpreter.sh # interpreter extraction + lemmas
python3 -m unittest discover -s security/formal/tests -p 'test_*.py'
```

`interpreter-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).

## Hosted reproduction

The [36b877e security workflow](https://github.com/lucannez64/VELA/actions/runs/40550521146) re-extracted and verified the four
WebAuthn interpreters and their lemmas in the recovery-policy job (run on the
owner's self-hosted runner); all security checks passed. `hosted-36b877e.log`
holds the summary and hashes, which match the local run.
