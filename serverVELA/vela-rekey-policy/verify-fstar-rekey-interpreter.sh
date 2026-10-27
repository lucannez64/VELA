#!/usr/bin/env bash
set -euo pipefail

# Handler-to-driver link for the four vault key-rotation endpoints.
#
# `src/rekey_interpreter.rs` defines the four loops once
# (`rekey_start_interpreter!` etc.). The server's handlers expand them with
# `.await`; this crate expands them into the synchronous `run_start`,
# `run_capsules`, `run_commit` and `run_abort`, which hax extracts here. The
# lemma module proves, for every executor, that each loop calls exactly the
# executor method for the effect the driver just emitted, stops at the verdict,
# reaches a verdict within its budget, and ends in `run_from_* request evs` for
# the observations returned, so the per-request rotation theorems hold for the
# handler.
#
# The driver module itself is taken from `extraction-rekey-driver` (regenerated
# by verify-fstar-rekey-driver.sh, which runs first); this extraction keeps only
# the interpreter module.

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
driver_module=proofs/fstar/extraction-rekey-driver/Vela_rekey_policy.Rekey_driver.fst
[[ -f $driver_module ]] || {
  echo 'run verify-fstar-rekey-driver.sh first' >&2
  exit 1
}

cargo test --lib rekey_interpreter

rm -rf proofs/fstar/extraction-rekey-interpreter
cargo hax into \
  --output-dir proofs/fstar/extraction-rekey-interpreter \
  -i '-** +vela_rekey_policy::rekey_interpreter::** +vela_rekey_policy::rekey_driver::begin_start +vela_rekey_policy::rekey_driver::begin_capsules +vela_rekey_policy::rekey_driver::begin_commit +vela_rekey_policy::rekey_driver::begin_abort +vela_rekey_policy::rekey_driver::rekey_step' \
  fstar --z3rlimit 500
# The partial driver module hax writes alongside is superseded by the full one.
rm -f proofs/fstar/extraction-rekey-interpreter/Vela_rekey_policy.Rekey_driver.fst
rm -f proofs/fstar/extraction-rekey-interpreter/Vela_rekey_policy.fst
python3 "$proof_root/strip-hax-instances.py" proofs/fstar/extraction-rekey-interpreter/*.fst
generated=(proofs/fstar/extraction-rekey-interpreter/Vela_rekey_policy.Rekey_interpreter.fst)
driver=("$driver_module")
driver_lemmas=(proofs/fstar/rekey-driver-lemmas/Vela_rekey_policy_rekey_driver_lemmas.fst)
lemmas=(proofs/fstar/rekey-interpreter-lemmas/Vela_rekey_policy_rekey_interpreter_lemmas.fst)
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
  --z3rlimit 16000
  --z3version 4.13.3
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib'
  --include "$hax_lib_root/proof-libs/fstar/core"
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives"
  --include "$hax_lib_root/proofs/fstar/extraction"
  --include proofs/fstar/extraction-rekey-driver-root
  --include proofs/fstar/extraction-rekey-driver
  --include proofs/fstar/rekey-driver-lemmas
  --include proofs/fstar/extraction-rekey-interpreter
  --include proofs/fstar/rekey-interpreter-lemmas
  "${driver[@]}" "${generated[@]}" "${driver_lemmas[@]}" "${lemmas[@]}"
)
printf 'F* rekey-interpreter argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "rekey interpreter: the four handlers' loops call only the executor method for the driver's current effect, stop at the verdict within 67 turns, and end in the driver state the per-request theorems cover"
sha256sum "${generated[@]}" "${driver[@]}" "${lemmas[@]}" src/rekey_interpreter.rs
