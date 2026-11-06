#!/usr/bin/env bash
set -euo pipefail

# Handler-to-driver link for the five remaining vault/device mutations.
#
# `src/vault_mutation_interpreter.rs` defines the five loops once. The server's
# handlers expand them with `.await`; this crate expands them into the
# synchronous `run_*` functions, which hax extracts here. The lemma module
# proves, for every executor, that each loop calls exactly the executor method
# for the effect the driver just emitted, stops at the verdict, reaches it
# within its budget, and ends in the state the per-request driver theorems
# cover.

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
driver_module=proofs/fstar/extraction-vault-mutation-driver/Vela_rekey_policy.Vault_mutation_driver.fst
[[ -f $driver_module ]] || {
  echo 'run verify-fstar-vault-mutation-driver.sh first' >&2
  exit 1
}

cargo test --lib vault_mutation_interpreter

rm -rf proofs/fstar/extraction-vault-mutation-interpreter
cargo hax into \
  --output-dir proofs/fstar/extraction-vault-mutation-interpreter \
  -i '-** +vela_rekey_policy::vault_mutation_interpreter::** +vela_rekey_policy::vault_mutation_driver::begin_chunk_delete +vela_rekey_policy::vault_mutation_driver::chunk_delete_step +vela_rekey_policy::vault_mutation_driver::begin_oram +vela_rekey_policy::vault_mutation_driver::oram_step +vela_rekey_policy::vault_mutation_driver::begin_schema +vela_rekey_policy::vault_mutation_driver::schema_step +vela_rekey_policy::vault_mutation_driver::begin_capsule_ack +vela_rekey_policy::vault_mutation_driver::capsule_ack_step +vela_rekey_policy::vault_mutation_driver::begin_rekey_capable +vela_rekey_policy::vault_mutation_driver::rekey_capable_step' \
  fstar --z3rlimit 500
rm -f proofs/fstar/extraction-vault-mutation-interpreter/Vela_rekey_policy.Vault_mutation_driver.fst
rm -f proofs/fstar/extraction-vault-mutation-interpreter/Vela_rekey_policy.fst
python3 "$proof_root/strip-hax-instances.py" proofs/fstar/extraction-vault-mutation-interpreter/*.fst

generated=(proofs/fstar/extraction-vault-mutation-interpreter/Vela_rekey_policy.Vault_mutation_interpreter.fst)
driver=("$driver_module")
driver_lemmas=(proofs/fstar/vault-mutation-driver-lemmas/Vela_rekey_policy_vault_mutation_driver_lemmas.fst)
lemmas=(proofs/fstar/vault-mutation-interpreter-lemmas/Vela_rekey_policy_vault_mutation_interpreter_lemmas.fst)
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

# Every step is split into one contracted helper per event, so the budget is
# small: the extracted modules keep hax's reviewed rlimit-500 header and the
# hand-written lemmas run at rlimit 100.
fstar_args=(
  --cmi
  --cache_off
  --warn_error -331
  --z3rlimit 100
  --z3version 4.13.3
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib'
  --include "$hax_lib_root/proof-libs/fstar/core"
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives"
  --include "$hax_lib_root/proofs/fstar/extraction"
  --include proofs/fstar/extraction-vault-mutation-driver-root
  --include proofs/fstar/extraction-vault-mutation-driver
  --include proofs/fstar/vault-mutation-driver-lemmas
  --include proofs/fstar/extraction-vault-mutation-interpreter
  --include proofs/fstar/vault-mutation-interpreter-lemmas
  "${driver[@]}" "${generated[@]}" "${driver_lemmas[@]}" "${lemmas[@]}"
)
printf 'F* vault-mutation-interpreter argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "vault mutation interpreters: each handler's loop calls only the executor method for the driver's current effect, stops at the verdict within its budget, ends in the driver state the per-request theorems cover, and every prefix of turns (a dropped handler future) leaves a sound driver state"
sha256sum "${generated[@]}" "${driver[@]}" "${lemmas[@]}" src/vault_mutation_interpreter.rs
