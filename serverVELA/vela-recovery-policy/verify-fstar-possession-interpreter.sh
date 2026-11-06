#!/usr/bin/env bash
set -euo pipefail

# Handler-to-driver link for the two possession-proof handlers.
#
# `src/possession_interpreter.rs` defines the two macros once. The server's
# handlers expand them with `.await`; this crate expands them into the
# synchronous `run_possession_initiation` and `run_possession_recover`, which
# hax extracts here. The lemma module proves, for every executor, that each
# loop calls exactly the executor method for the effect the driver just
# emitted, stops at the verdict (or at the effect that aborted) within its
# budget, and ends in the driver's `run_*_from_begin` over the observations
# returned, so the per-request possession theorems hold for the handlers.
#
# The driver module is taken from `extraction-possession-driver` (regenerated
# by verify-fstar-possession-driver.sh, which runs first).

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"

for command_name in cargo cargo-hax driver-hax-frontend-exporter hax-engine fstar.exe z3-4.13.3 jq; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is missing; follow README.md" >&2
    exit 1
  }
done

[[ $(fstar.exe --version | head -n1) == 'F* 2025.10.06' ]] || {
  echo 'unexpected F* version' >&2
  exit 2
}
[[ -f proofs/fstar/extraction-possession-driver/Vela_recovery_policy.Possession_driver.fst ]] || {
  echo 'run verify-fstar-possession-driver.sh first' >&2
  exit 1
}

cargo test --lib possession_interpreter

rm -rf proofs/fstar/extraction-possession-interpreter
cargo hax into \
  --output-dir proofs/fstar/extraction-possession-interpreter \
  -i '-** +vela_recovery_policy::possession_interpreter::** +vela_recovery_policy::possession_driver::begin_initiation +vela_recovery_policy::possession_driver::step_initiation +vela_recovery_policy::possession_driver::begin_proof_recover +vela_recovery_policy::possession_driver::step_proof_recover' \
  fstar --z3rlimit 500
# The partial root and driver modules hax writes alongside are superseded by
# the full extraction-possession-driver artifact.
rm -f proofs/fstar/extraction-possession-interpreter/Vela_recovery_policy.fst
rm -f proofs/fstar/extraction-possession-interpreter/Vela_recovery_policy.Possession_driver.fst

generated=(proofs/fstar/extraction-possession-interpreter/Vela_recovery_policy.Possession_interpreter.fst)
driver=(proofs/fstar/extraction-possession-driver/*.fst)
driver_lemmas=(proofs/fstar/possession-driver-lemmas/Vela_recovery_policy_possession_driver_lemmas.fst)
lemmas=(proofs/fstar/possession-interpreter-lemmas/Vela_recovery_policy_possession_interpreter_lemmas.fst)
for f in "${generated[@]}" "${lemmas[@]}"; do
  [[ -f $f ]] || { echo "missing $f" >&2; exit 1; }
done

python3 "$proof_root/../../security/formal/check-driver-proof-sources.py" \
  --generated "${generated[@]}" "${driver[@]}" \
  --proof "${driver_lemmas[@]}" "${lemmas[@]}" \
  --include-dir "$proof_root"

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)
[[ -n $hax_lib_root && -d $hax_lib_root ]] || {
  echo "could not locate hax-lib proof libraries" >&2
  exit 1
}

fstar_args=(
  --cmi
  --cache_off
  --warn_error -331
  --z3rlimit 8000
  --z3version 4.13.3
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib'
  --include "$hax_lib_root/proof-libs/fstar/core"
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives"
  --include "$hax_lib_root/proofs/fstar/extraction"
  --include proofs/fstar/extraction-possession-driver
  --include proofs/fstar/possession-driver-lemmas
  --include proofs/fstar/extraction-possession-interpreter
  --include proofs/fstar/possession-interpreter-lemmas
  "${generated[@]}" "${lemmas[@]}"
)
fstar.exe "${fstar_args[@]}"

echo "possession interpreter: both handlers' loops call only the executor method for the driver's current effect, stop at a verdict (or abort) within their budgets, and end in the driver state the per-request theorems cover"
sha256sum "${generated[@]}" "${lemmas[@]}" src/possession_interpreter.rs
