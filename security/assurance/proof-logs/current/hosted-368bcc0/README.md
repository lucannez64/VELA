# Hosted evidence: 368bcc0

The [security workflow](https://github.com/lucannez64/VELA/actions/runs/40095461376)
passed on `368bcc0` (all five jobs). `workflow.json` records the head SHA,
conclusion and every job.

Files (copied from the run's uploaded `assurance-symbolic-logs` artifact or
selected from `gh run view --log`; not edited):

- `security-excerpt.log`: 13 checked module artifacts, **231 selected
  postconditions**, zero local `assume val`; the six positive CryptoVerif
  verdicts, the explicit legacy non-proof and the hybrid-signature games; the
  static scan pass.
- `run-all-summary.txt`: all nineteen `run-all.sh` steps, including the
  credential-release ladder (M1–M10), the journal gate and the network
  boundary models.
- `credential-release.log`: exactly 83 verified and the five named intended
  falsifications.
- `m28-trace-equivalence.log`: the handwritten F★ journal encoding module,
  verified with caching disabled, pinned Z3 4.13.3, recorded argv and module
  hash.

This reproduces the 231-postcondition corpus, the enrollment preflight and
independent-ordering increments, and the journal encoding check that earlier
documents listed as awaiting hosted reproduction. Passing these gates
establishes the documented scoped results only, not whole-system correctness
or an external audit.

Full console output: `gh run view 40095461376 --repo lucannez64/VELA --log`.
