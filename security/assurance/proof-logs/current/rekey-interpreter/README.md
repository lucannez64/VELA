# Vault key-rotation interpreter (F-2 increment)

`src/rekey_interpreter.rs` defines the four rotation loops once
(`rekey_start_interpreter!`, `rekey_capsules_interpreter!`,
`rekey_commit_interpreter!`, `rekey_abort_interpreter!`), with budgets of 12,
68, 10 and 4 executor calls. Each handler in
`serverVELA/vela-server/src/vault/rekey.rs` expands exactly one of them with
`.await`; `security/formal/tests/test_handler_interpreters.py` enforces that and
forbids importing or calling a driver transition in the handlers.

The synchronous expansions (`run_start`, `run_capsules`, `run_commit`,
`run_abort`) are extracted to `proofs/fstar/extraction-rekey-interpreter/` and
proved in `proofs/fstar/rekey-interpreter-lemmas/`: one shared module and one
module per loop, each checked in its own `fstar.exe` call.

## Exact theorems

`run_start_theorem`, `run_capsules_theorem`, `run_commit_theorem` and
`run_abort_theorem`: for every executor, the loop calls only the method for the
driver's current effect, performs nothing after the verdict, reaches a verdict
within its budget, and ends in exactly the driver state the per-request trace
theorem covers. They are built from `run_*_is_run_ev`, `iter_turn_is_run_ev`,
`run_ev_follows_the_driver` and `run_ev_reaches_a_verdict`.

No loop is unrolled: reaching a verdict is an induction over a one-turn
progress lemma (`step_progress`) with one helper per effect. The capsule loop's
measure is `65 - index`, with the side invariant `capsules_written >= 0` proved
in the lemma module. Global budget: fuel 1, ifuel 1, `--z3rlimit 100`,
`--split_queries always`; the largest rlimit any query used was about 18.

`rekey_{start,capsules,commit,abort}_cancellation`: every prefix of turns, for
every executor, leaves a sound driver state
([cancellation](../cancellation/README.md)).

## Reproduction

```bash
cd serverVELA/vela-rekey-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-rekey-interpreter.sh
```

This gate loads the driver and its lemmas without re-checking them; the driver
gate checks those. The run is in [`../rekey-driver/gate.log`](../rekey-driver/gate.log).
