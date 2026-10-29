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
- Concurrent composition: `proofs/fstar/rekey-driver-composition/`
  ([evidence](../rekey-composition/README.md)).
- Gate: `verify-fstar-rekey-driver.sh`, chained from `verify-fstar.sh`.

## Exact theorems

For every request and every finite event sequence the driver may observe:

- `rekey_start_trace_theorem`, `rekey_capsules_trace_theorem`,
  `rekey_abort_trace_theorem`: the final state is sound, nothing is committed,
  a request never both responds and fails, and at most one success and at most
  one failure is emitted. A capsules response implies every capsule write
  matched; a winning abort restores the ACTIVE phase at an epoch no lower than
  the initial one.
- `rekey_commit_trace_theorem`: a commit implies the account was ACTIVE at the
  start, the request is device-scoped, its device is the starter, the rotation
  id is present and matches, both completeness probes (chunk shadows, device
  capsules) returned empty, and the published epoch is exactly
  `next_epoch(from_epoch)`. A failed commit is never committed.
- `web_start_is_refused`, `web_commit_is_refused`, `web_abort_is_refused`: a
  web session gets `WebSessionForbidden` before any effect, and no later event
  changes that.

The lemmas are checked under `--z3rlimit 16000` set in the gate script (the
global budget; the proof files carry only the one `--fuel 4 --ifuel 2` pragma
the source-policy guard allows).

## Tests

- `cargo test -p vela-rekey-policy` (76 tests, including scripted
  driver/interpreter conformance tests).
- `cargo test -p vela-server`, all suites including `rekey_state_model`
  (`integration.log`, run on 8c46db3).

## Reproduction

```bash
cd serverVELA/vela-rekey-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-rekey-driver.sh
```

`gate.log` is the full `verify-fstar.sh` run on 8c46db3: every rotation module verifies; it ends at the vault-mutation driver failure described in [its README](../vault-mutation-driver/README.md), since unchained.
