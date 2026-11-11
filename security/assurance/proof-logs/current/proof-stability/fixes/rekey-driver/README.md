# Rekey-driver proof: seed-stable witnesses (plan step T8 follow-up)

Base commit: `f3e27569`. Files changed:
`serverVELA/vela-rekey-policy/proofs/fstar/rekey-driver-lemmas/Vela_rekey_policy_rekey_driver_lemmas.fst`
and the `--z3rlimit` of the driver/lemma call in
`serverVELA/vela-rekey-policy/verify-fstar-rekey-driver.sh`.

## Finding

Hosted proof-stability run 41925059881: job "vela-rekey-policy, seed 1"
(`serverVELA/vela-rekey-policy/verify-fstar.sh core`) was killed (exit 143)
after 71 min in the rekey-driver F* call. Seeds 2 and 3 finished the whole job
in 17 and 38 min. (Hosted numbers are from the task brief; this directory has
the local evidence.)

The driver/lemma F* call checks the extracted
`Vela_rekey_policy.Rekey_driver` and the hand-written lemma module together.
The extracted module sets its own `#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"`,
so the gate's command-line `--z3rlimit 16000` only reached the lemma module.

The cost was in the five concrete reachability witnesses at the end of the
lemma module (`start_reaches_freeze`, `start_witness_completes`,
`commit_witness_completes`, `abort_witness_restores`,
`timeout_witness_restores`). Their proof was `()`: Z3 had to unroll the
recursive `run` over 3 to 10 concrete events. That fails at the default fuel
(2) and F* retries at fuel 2/ifuel 2, fuel 4 and finally fuel 8, each try with
rlimit 16000. Even at seed 0 (`before-seed0.log`):

| Query | Tries | Last try | Total time | Used rlimit (last try) |
|---|---|---|---|---|
| `start_witness_completes` | 4 | fuel 8, ifuel 2 | 912 s | 385.4 |
| `commit_witness_completes` | 4 | fuel 8, ifuel 2 | 201 s | 109.4 |
| `start_reaches_freeze` | 4 | fuel 8, ifuel 2 | 73 s | 41.1 |
| `abort_witness_restores` | 3 | fuel 4, ifuel 2 | 15 s | 19.1 |
| `timeout_rollback_restores_active` | 1 | fuel 2 | 6.3 s | 11.4 |

The other queries of the module took at most 1.7 s (`step_after_done`, used
3.0). The whole gate took 1504 s at seed 0, of which the driver/lemma F* call
was 1328 s (`TOTAL TIME` line). With a fuel-8 query that needs 385 rlimit units
at seed 0, a different seed can need far more, and the 16000 ceiling allows
hours. That matches the seed-1 timeout.

Seed-1 reproduction (`before-seed1-lemmas-timeout.log`): the original lemma
module alone, with the original `--z3rlimit 16000`, checked under `--z3seed 1`
with a 2700 s cap. This is the lemma call only, against the same extraction
(`lemmas-only-helper.sh` here, run against a scratch copy of the base
files; not a gate). Seed 0 vs seed 1:

| Query | Seed 0 (time / used rlimit) | Seed 1 (time / used rlimit) |
|---|---|---|
| `timeout_rollback_restores_active` | 6.3 s / 11.4 | 12.2 s / 14.9 |
| `start_reaches_freeze` (4 tries, passes at fuel 8) | 73 s / 41.1 | 80 s / 44.2 |
| `start_witness_completes` | 4 tries, fuel 8 passes after 857 s / 385.4 | first 3 tries fail in 51.6 s; the fuel-8 try was still running when the cap killed the run, more than 41 min later (the log shows no result line for it) |

So within the cap, the seed-1 run never reaches `commit_witness_completes` (201 s at
seed 0). That is consistent with the hosted job dying after 71 min.

## Change

No statement was changed or weakened, and nothing is admitted or assumed. The
source policy (`security/formal/check-driver-proof-sources.py`) allows only
`#push-options "--fuel 4 --ifuel 2"` in proof modules, so no per-lemma
rlimit scope is possible. Instead, every query was made small enough for one
small command-line limit:

- `run_cons` / `run_nil`: unroll `run` exactly once.
- `begin_device_{start,commit,abort}`: a device-scoped request starts from
  `fresh op r`.
- One `step_*` lemma per transition the witnesses take (rate limit, load for
  start/commit/abort/expired, ORAM, capable, acknowledged, begin-tx,
  inventory, freeze CAS, cleanup, tx-commit, chunks, devices, commit CAS,
  sweep, publish, rollback). Each one unfolds a single `rekey_step` on an
  arbitrary driver whose stage fixes the branch. It is stated as an equation
  with the resulting driver (`{ d with ... }`, or `loaded d s stage` for the
  record `after_state` builds), so the chain composes by rewriting.
- `epochs_valid`, `next_epoch_two`: the machine-integer facts, each in its own
  query.
- Each witness proof is now the explicit chain of those lemmas. The concrete
  `commit_prefix @ [...]` is flattened with `assert_norm`.
- `timeout_rollback_restores_active` is split into one lemma per entry point
  (`timeout_restored_{start,capsules,commit,abort}`), so each query unfolds
  only one branch of `dispatch_after_timeout`.
- Gate: `--z3rlimit 16000` -> `--z3rlimit 100` for the driver/lemma call
  (comment in the script). The extracted module keeps its own 500. The
  composition call was already 100 and is unchanged.

## After: driver gate under seeds 0-3 (cold, build box, via vela-heavy)

| Seed | Gate result | Gate time | Driver/lemma F* call | Failed query attempts (lemma module) | Max used rlimit (lemma module, limit 100) |
|---|---|---|---|---|---|
| 0 | PASS | 284 s | 132 s | 0 | 2.997 (`step_after_done`) |
| 1 | PASS | 326 s | 145 s | 0 | 2.995 (`step_after_done`) |
| 2 | PASS | 341 s | 162 s | 0 | 2.998 (`step_after_done`) |
| 3 | PASS | 259 s | 93 s | 0 | 2.995 (`step_after_done`) |

Every lemma-module query now succeeds on the first try at fuel 2/ifuel 1. Per
query (time / used rlimit), seed 0 before, then seeds 0, 1, 2, 3 after:

| Query | Before, seed 0 | After s0 | After s1 | After s2 | After s3 |
|---|---|---|---|---|---|
| `start_witness_completes` | 912 s / 385.4 | 0.7 s / 1.551 | 1.0 s / 1.551 | 1.0 s / 1.551 | 1.0 s / 1.551 |
| `commit_witness_completes` | 201 s / 109.4 | 0.7 s / 1.255 | 1.1 s / 1.230 | 1.2 s / 1.230 | 1.0 s / 1.230 |
| `start_reaches_freeze` | 73 s / 41.1 | 0.5 s / 0.965 | 0.6 s / 0.965 | 0.7 s / 0.965 | 0.6 s / 0.965 |
| `abort_witness_restores` | 15 s / 19.1 | 0.3 s / 0.623 | 0.5 s / 0.621 | 0.5 s / 0.621 | 0.4 s / 0.621 |
| `timeout_witness_restores` | 0.8 s / 1.786 | 0.2 s / 0.381 | 0.2 s / 0.380 | 0.2 s / 0.382 | 0.2 s / 0.382 |
| `timeout_rollback_restores_active` | 6.3 s / 11.4 | 0.1 s / 0.187 | 0.1 s / 0.187 | 0.1 s / 0.187 | 0.1 s / 0.187 |
| `step_after_done` (unchanged) | 1.7 s / 2.997 | 1.8 s / 2.997 | 2.8 s / 2.995 | 2.4 s / 2.998 | 2.3 s / 2.995 |

The composition module (same gate, rlimit 100, not changed here) also passed
under every seed. Its largest query is `local_event_inv` #4: used 18.4 / 19.3
/ 30.3 / 29.9 at seeds 0-3. The largest extracted-driver query is `on_capsule`
(limit 500 from the extraction header): used 76.5 / 76.6 / 76.6 / 10.3, 6-68 s.
Neither is in this step's files. See follow-ups.

## After: `verify-fstar.sh core` under seed 1

`serverVELA/vela-rekey-policy/verify-fstar.sh core` ran end to end under seed 1
(cold, without `--query_stats`): **PASS, exit 0, 3414 s** (`core-seed1.log`,
23 `Verified module` lines). Its rekey-driver gate checked lemma module
`f58f23b2...` and printed the three result lines, and the rekey interpreter
gate, which loads this module, passed after it.

The longest part of that run was not the rekey driver. The log has no
timestamps, but a process listing during the run showed the
`vault-upload-driver-composition` F* call running from before 03:30 to after
03:51 (one Z3 process at 15 CPU-minutes), and the chain had moved past it by
04:01. That gate is outside this step's files (see follow-ups). Per-query
numbers for it are unverified because the run had no `--query_stats`.

## Logs

- `before-seed0.log`: original module, seed 0, `--query_stats` (gate 1504 s).
- `after-seed{0,1,2,3}.log`: new module, `--query_stats`, each a full
  `verify-fstar-rekey-driver.sh` run (cargo test, hax extraction, source
  policy, driver/lemma call, composition call, hash lines).
- `before-seed1-lemmas-timeout.log`: original lemma module only, seed 1,
  `--query_stats`. The 2700 s cap killed it (`vela-heavy` exited 124), so
  the log ends without the shim's final `seconds=... exit=...` line.
- `lemmas-only-helper.sh`: the helper that run used (`VELA_WT` set to the
  scratch copy, `RLIMIT=16000`).
- `core-seed1.log`: `serverVELA/vela-rekey-policy/verify-fstar.sh core` under seed 1.
- `query-stats-wrapper.sh`: the seed shim's pass-through path (seed 0) does
  not add `--query_stats`. The seed-0 logs therefore put this wrapper behind
  the shim on `PATH` (`bash -c 'PATH=<dir>:$PATH exec security/assurance/z3-seed/verify-fstar-seeded.sh --query-stats 0 <gate>'`).
  It adds `--query_stats` to module checks and execs the pinned F*.
  Seeds 1-3 use the shim's own `--query-stats`.

In each log, the gate's last `sha256sum` line identifies the lemma module that
was checked: `2ba3396d...` is the original (base), `f58f23b2...` is this change.

## Follow-ups (not done here)

- `Vela_rekey_policy_rekey_driver_composition.local_event_inv` #4 used up to
  30.3 of its 100 limit (seed 2). That is a 3.3x margin and the closest to its
  limit in this gate.
- `vault-upload-driver-composition` took on the order of 20-30 min of the
  seed-1 core run (process listing, not measured per query). It is worth a
  `--query-stats 1` run of `verify-fstar-vault-upload-driver.sh`.
- The extracted `on_capsule` postcondition takes 50-68 s at seeds 0-2 (used
  76.6 of 500) but 6 s at seed 3. It is seed-sensitive, but generated from
  Rust, so outside this step's files.
