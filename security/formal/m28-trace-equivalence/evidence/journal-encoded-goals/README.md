# Journal-encoded-goals evidence

Fresh evidence for the M28 encoded all-pairs proof, the concrete unary
free-term order instance, and the two-commit reachability witness.

- `verify.log` is the complete output of the repository's shared gate:
  `vela-heavy security/formal/m28-trace-equivalence/verify.sh` with
  `VELA_FSTAR_BIN=/tmp/vela-fstar-prebuilt/fstar/bin/fstar.exe`.
  The gate runs `check-m28-semantic-proof.py`, prints the pinned F* version,
  module SHA-256 and arguments, then runs F* with
  `--cache_off --z3rlimit 100 --z3version 4.13.3` under
  `security/assurance/bounded.sh` / `security/formal/fstar-bounded.sh`.
- `metadata.txt` records the worktree, base/cherry-pick commits, module hash,
  source line count, tool versions, flags, guard result and counts.

The source guard is a drift check, not a soundness certificate. The log shows
one verified module, no warnings, and no local proof escapes. The F* module
adds zero Rust postconditions; the extracted corpus remains 245 explicit
postconditions / 252 selected functions.

The unchanged Tamarin models, rules and guards were not rerun here. Their ten
M28 / eleven M29 verdicts remain separate from this F* kernel.
