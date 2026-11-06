#!/usr/bin/env bash
set -euo pipefail

# Handler-to-driver link for the four web-session transitions.
#
# `src/websession_interpreter.rs` defines the loops once. The server handlers
# expand the same macros with `.await`; this crate expands them into the
# synchronous `run_start`, `run_grant`, `run_token` and `run_delete`, which hax
# extracts here. The lemma module proves, for every executor, that each loop
# calls exactly the executor method for the effect the driver just emitted,
# stops at the verdict, reaches a verdict within its budget, and ends in the
# driver state the per-request theorems cover.
#
# The driver modules are taken from `extraction-websession-driver` (regenerated
# by verify-fstar-websession-driver.sh, which runs first).

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
[[ -f proofs/fstar/extraction-websession-driver/Vela_session_policy.Websession_driver.fst ]] || {
  echo 'run verify-fstar-websession-driver.sh first' >&2
  exit 1
}

cargo test --lib websession_interpreter

rm -rf proofs/fstar/extraction-websession-interpreter
cargo hax into \
  --output-dir proofs/fstar/extraction-websession-interpreter \
  -i '-** +vela_session_policy::websession_interpreter::** +vela_session_policy::websession_driver::begin_start +vela_session_policy::websession_driver::start_step +vela_session_policy::websession_driver::begin_grant +vela_session_policy::websession_driver::grant_step +vela_session_policy::websession_driver::begin_token +vela_session_policy::websession_driver::token_step +vela_session_policy::websession_driver::begin_delete +vela_session_policy::websession_driver::delete_step' \
  fstar --z3rlimit 500
# The partial driver module and the shared policy/challenge modules hax writes
# alongside are superseded by the full driver extraction (on the include path).
rm -f proofs/fstar/extraction-websession-interpreter/Vela_session_policy.Websession_driver.fst \
      proofs/fstar/extraction-websession-interpreter/Vela_session_policy.fst \
      proofs/fstar/extraction-websession-interpreter/Vela_session_policy.Challenge.fst

generated=(proofs/fstar/extraction-websession-interpreter/Vela_session_policy.Websession_interpreter.fst)
driver=(proofs/fstar/extraction-websession-driver/*.fst)
driver_lemmas=(proofs/fstar/websession-driver-lemmas/Vela_session_policy_websession_driver_lemmas.fst)
mapfile -t lemmas < <(find proofs/fstar/websession-interpreter-lemmas -maxdepth 1 -type f -name 'Vela_session_policy_websession_*_interpreter_lemmas.fst' -print | sort)
if (( ${#lemmas[@]} != 4 )); then
  echo "expected four reviewed web-session interpreter lemma modules" >&2
  exit 1
fi
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
  --include proofs/fstar/extraction-websession-driver
  --include proofs/fstar/websession-driver-lemmas
  --include proofs/fstar/extraction-websession-interpreter
  --include proofs/fstar/websession-interpreter-lemmas
  "${generated[@]}"
)
for lemma in "${lemmas[@]}"; do
  printf 'F* web-session-interpreter module %s:\n' "$lemma"
  fstar.exe "${fstar_args[@]}" "$lemma"
done

echo "web-session interpreters: each handler loop calls only the executor method for the driver's current effect, stops at the verdict within 3/3/7/3 turns, and ends in the driver state the per-request theorems cover"
sha256sum "${generated[@]}" "${lemmas[@]}" src/websession_interpreter.rs
