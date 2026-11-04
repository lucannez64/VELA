# Proof stability under three Z3 seeds (plan step T8)

Generated evidence for the rule that every F* module of the corpus verifies
with the pinned Z3 (4.13.3, [04-reproducibility.md](../../../04-reproducibility.md))
under three different Z3 random seeds. Seed 0 is the default the normal CI
already checks; this gate replays every gate with seeds 1, 2 and 3.

Produced by: `security/assurance/z3-seed/fstar.exe` (seed shim),
`security/formal/list-rlimits.py` (rlimit inventory),
`.github/workflows/proof-stability.yml` (CI) and
`security/formal/collect-stability.py` (hosted table). Do not edit the
generated tables by hand. The evidence was produced from base commit
`f680ed71c18fb9d0bd2f327a08585c736ad10fb0`; the hosted-run block is filled
from a later CI run.

## How a seed reaches Z3

`security/assurance/z3-seed/fstar.exe` is a small Python shim placed first on
`PATH`. With `VELA_Z3_SEED=<n>` set it execs the next real `fstar.exe` as

    fstar.exe --z3seed <n> <original arguments>

for calls that check modules; `--dep`, `--version`, `--print`, ... pass through
unchanged, and a caller that already passes `--z3seed` keeps its value. Without
`VELA_Z3_SEED` the shim is a pure pass-through. `VELA_Z3_SEED_LOG=1` prints the
exact argv of every exec, which is the per-call evidence in the logs here.

F* 2025.10.06 resolves Z3 from its own release tree: a logging `z3-4.13.3`
wrapper placed first on `PATH` saw no calls, and the release bundles
`lib/fstar/z3-4.13.3` (the run reports "Z3 version (according to F*): 4.13.3").
The seed therefore appears in the SMT query dump as
`(set-option :smt.random-seed <n>)`. The probe
(`security/assurance/z3-seed/verify-fstar-seed-probe.sh`, log
[local/seed-shim-probe.log](local/seed-shim-probe.log)) shows:

- pass-through: `(set-option :smt.random-seed 0)`;
- seed 1 and seed 2: the same one-lemma module checks, and the dumps contain
  seeds 1 and 2 respectively; the dumps differ across seeds and two seed-1
  runs are byte-identical;
- with the shared F* cache shim on `PATH`, both orders compose: cache first
  runs the cache and then the seed shim (seed 3 appears in the query dump),
  seed first injects the seed and bypasses the cache by design.

The shim skips its own directory and the sibling `fstar-cache` directory in
its `PATH` lookup because both shims are named `fstar.exe`; without that they
would exec each other in a loop. A cached seeded run therefore puts the cache
shim first. Evidence runs are cold anyway (`VELA_FSTAR_CACHE=0`).

No tracked F* module sets `--z3seed` in `#set-options`/`#push-options` (0 rows
in [rlimits.json](rlimits.json), section `z3seed_in_fstar`), so the shim's flag
is never overridden by a module.

A tracked executable cache shim is required for the cache to work through
`PATH`: `git ls-files -s security/assurance/fstar-cache/fstar.exe` reports
mode `100644` in this tree, so a `PATH`-based activation (security.yml's
"Use the shared F* cache" step appends its directory) does not take effect.
That is a pre-existing observation outside this step's files; the composition
probe above used an executable copy to exercise the code. Unverified: whether
the same mode is present in the commit CI runs.

## Z3 resource limits

[rlimits.md](rlimits.md) and [rlimits.json](rlimits.json) list every setting:

- 128 command-line `--z3rlimit` occurrences across 66 tracked shell scripts
  (the 64 `verify-fstar*.sh` gates plus `verify-share-facts-fstar.sh`,
  `cross-driver/verify.sh` and helpers);
- 85 `#set-options` occurrences in tracked F* modules (module copies under
  `security/assurance/proof-logs/` excluded); no `#push-options` line sets a
  limit in this tree;
- no `--z3rlimit_factor` anywhere;
- largest configured limit **32000**, in
  `security/formal/cross-driver/verify-fstar-cross-driver-mutations.sh:52`
  and `security/formal/cross-driver/verify.sh:121`.

The `--query_stats` section of `rlimits.md` records what the modules checked
locally actually used: 0.078 of a 500 limit at most, so the configured ceilings
were not close to binding for those modules.

## Local validation (cold, on the build box)

One small gate, `libVELA/vela-sync-policy/verify-fstar-epoch.sh` (one
extraction module, 4 extracted postconditions, 1 lemma module with 6
handwritten lemmas), run through `security/assurance/z3-seed/verify-fstar-seeded.sh`
via `vela-heavy`, cold (`VELA_FSTAR_CACHE=0`, no verdict cache, no shared
checked modules), one run after another:

| Gate | Seed | Result | Time |
|---|---|---|---|
| `libVELA/vela-sync-policy/verify-fstar-epoch.sh` | 0 (pass-through) | PASS | 24 s |
| `libVELA/vela-sync-policy/verify-fstar-epoch.sh` | 1 | PASS | 26 s |
| `libVELA/vela-sync-policy/verify-fstar-epoch.sh` | 2 | PASS | 28 s |
| `libVELA/vela-sync-policy/verify-fstar-epoch.sh` | 3 | PASS | 27 s |

Logs: [local/epoch-gate-seed0.log](local/epoch-gate-seed0.log),
[seed 1](local/epoch-gate-seed1.log) (with `--query_stats`),
[seed 2](local/epoch-gate-seed2.log), [seed 3](local/epoch-gate-seed3.log).
Each log shows the shim's `exec ... --z3seed <n> ...` line, both modules
verified and the gate's own hash checks of the regenerated extraction.

This proves the shim and the cold seeded path on one gate; it is not the full
corpus evidence. No module failed under any seed, so no proof was split and no
limit was raised.

## Hosted run

`.github/workflows/proof-stability.yml` reruns `security.yml`'s 18 refinement
entries plus the M28 trace-equivalence gate (`security/formal/m28-trace-equivalence/verify.sh`,
which `formal-rekey` checks outside the refinement matrix) with seeds 1, 2 and 3
(57 jobs, `fail-fast: false`) on GitHub-hosted
`ubuntu-24.04` runners only, cold, with the seed shim first on `PATH`. Each job
uploads `.stability-out/` (gate log plus `result.json`); the summary job runs
`security/formal/check-stability-matrix.py` and fails unless every pair is
PASS. `security/formal/check-stability-matrix.py` also enforces that this
matrix stays identical to `security.yml`'s refinement matrix plus its listed
extra gates.

Scope: these 19 gates check every tracked F* module the proofs rely on. Not
covered: the copies under `proof-logs/current/*/extractions` (archived evidence
of earlier runs, regenerated by the gates), and
`proof-logs/current/std-model-review/format-collapse/Fmt_collapse.fst`, which is
not a proof the corpus relies on but a demonstration of a model defect (T4).

To fill this section from a run:

    gh run download <run-id> -D /tmp/stability-artifacts
    python3 security/formal/collect-stability.py \
      --artifacts /tmp/stability-artifacts \
      --readme security/assurance/proof-logs/current/proof-stability/README.md \
      --require-all-pass

<!-- hosted-run:start -->
_No hosted run collected yet._
<!-- hosted-run:end -->

## What this does not prove

- Three seeds are a sample of Z3's search, not all of it: Z3 version, machine
  load, timeouts and F*'s own scheduling still differ per run.
- A green seeded run shows the proofs do not depend on those particular seeds.
  It is evidence of stability, not a proof of it, and it must be re-established
  when F*, Z3, hax or the gates change.
- The shim sits on `PATH` and could pass any arguments to the real F*; it only
  adds `--z3seed` (and `--query_stats` when asked), and the logs record every
  exec line so the added flags are auditable. It adds no admitted query and
  changes no proof obligation.
- The local run covers one gate only. The full 57-job evidence is the hosted
  run above.
