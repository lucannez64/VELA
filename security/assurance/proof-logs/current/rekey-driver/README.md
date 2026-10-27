# Vault key-rotation driver (F-2 increment)

## Claim

`POST /vault/rekey/{start,capsules,commit,abort}` reach one extracted
per-request driver (`serverVELA/vela-rekey-policy/src/rekey_driver.rs`) through
the four interpreter loops in `src/rekey_interpreter.rs`. The driver owns every
post-validation decision and effect order:

- pacing, the lazy timeout rollback, the readiness probes, the freeze
  transaction, the inventory read, the freeze CAS, the cleanup and the
  transaction commit for `start`;
- the starter/rotation-id/attempt authority checks and the ordered per-capsule
  guarded update for `capsules`;
- the starter/rotation-id/attempt authority checks, both completeness probes,
  `plan_commit`, the commit CAS, the best-effort sweep and the epoch
  publication for `commit`;
- the abort authority check, `plan_abort` and the rollback CAS for `abort`;
- the lost-response commit replay (`authorize_commit_replay`).

Statuses, messages, SQL text, store keys and effect order are unchanged.

## Proof artifacts

- Focused extraction: `proofs/fstar/extraction-rekey-driver/`
  (`Vela_rekey_policy.Rekey_driver.fst`); the extracted policy root module is
  kept in the regenerated `extraction-rekey-driver-root/`.
- Per-request lemmas: `proofs/fstar/rekey-driver-lemmas/`.
- Concurrent composition: `proofs/fstar/rekey-driver-composition/`.
- Gate: `verify-fstar-rekey-driver.sh`, chained from `verify-fstar.sh`.

The intended headline theorem is `rekey_commit_trace_theorem`: a commit implies
the chunk-shadow and device-capsule completeness observations, the starting
device's live rotation id, and an epoch advance by exactly one; a
`CommitCas` effect occurs at most once; abort and timeout rollback restore the
active phase at the same epoch; a web session never starts or commits. The
composition counters are `w_two_rotations`, `w_second_commit` and
`w_commit_after_abort`.

## Current status (honest)

The Rust driver and interpreter are complete and their Rust conformance tests
pass. The focused F* gate is **not green yet**: F* still rejects the
`rekey_step` helper contracts (`on_replay_state` / dispatch branch). The
committed artifacts are the current attempt; `gate.log` holds the last run.
Because of that, the crate-level `verify-fstar.sh` also stops at this gate.

## Tests that do pass

- `cargo test -p vela-rekey-policy` (76 tests, including the driver/interpreter
  tests).
- `cargo test -p vela-server --test rekey_state_model`.
- `cargo test -p vela-server --test integration` (68 tests).
- `python3 -m unittest discover -s security/formal/tests -p 'test_*.py'`
  (after staging the new gate scripts executable; the handler-interpreter
  wiring test includes all new handlers).
- `python3 security/assurance/check-proof-boundary.py` (249 postconditions).

## Reproduction

```bash
cd serverVELA/vela-rekey-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-rekey-driver.sh
```

No mutation run was completed for this increment; nothing is claimed about
load-bearing mutations.
