#!/usr/bin/env bash
# T8 iteration helper (not a gate): check only the rekey-driver lemma module
# against the extraction the real gate left in the worktree, with the same
# F* flags as verify-fstar-rekey-driver.sh. RLIMIT overrides --z3rlimit.
set -euo pipefail
root=${VELA_WT:-/home/hirew/.t3/worktrees/VELA/t3-3abe79e1}
cd "$root/serverVELA/vela-rekey-policy"
hax=/home/hirew/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/hax-lib-0.3.7
start=$SECONDS
fstar.exe --cmi --cache_off --warn_error -331 --z3rlimit "${RLIMIT:-500}" --z3version 4.13.3 \
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
  --include "$hax/proof-libs/fstar/core" --include "$hax/proof-libs/fstar/rust_primitives" \
  --include "$hax/proofs/fstar/extraction" \
  --include proofs/fstar/extraction-rekey-driver-root \
  --include proofs/fstar/extraction-rekey-driver \
  --include proofs/fstar/rekey-driver-lemmas \
  proofs/fstar/rekey-driver-lemmas/Vela_rekey_policy_rekey_driver_lemmas.fst
echo "lemmas-only: seconds=$((SECONDS - start))"
