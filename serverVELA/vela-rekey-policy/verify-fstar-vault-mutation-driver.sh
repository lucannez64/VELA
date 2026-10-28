#!/usr/bin/env bash
set -euo pipefail

# Focused F-2 increment: the remaining vault and device mutation drivers
# (`DELETE /vault/chunk/:id`, `PUT /vault/oram/:tree_id/path/:leaf`,
# `POST /vault/schema`, `POST /device/capsule/ack`,
# `POST /device/rekey-capable`).
#
# The module reuses the F* module name `Vela_rekey_policy`, so it is regenerated
# into `proofs/fstar/extraction-vault-mutation-driver/` and checked in its own
# fstar.exe invocation.

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"

for command_name in cargo cargo-hax driver-hax-frontend-exporter hax-engine fstar.exe z3-4.13.3 jq; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is missing; follow README.md" >&2
    exit 1
  }
done

version=$(fstar.exe --version)
printf '%s\n' "$version"
[[ ${version%%$'\n'*} == 'F* 2025.10.06' ]] || {
  echo 'unexpected F* version' >&2
  exit 2
}

cargo test

rm -rf proofs/fstar/extraction-vault-mutation-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-vault-mutation-driver \
  -i '-** +vela_rekey_policy::vault_mutation_driver::begin_chunk_delete +vela_rekey_policy::vault_mutation_driver::chunk_delete_step +vela_rekey_policy::vault_mutation_driver::begin_oram +vela_rekey_policy::vault_mutation_driver::oram_step +vela_rekey_policy::vault_mutation_driver::begin_schema +vela_rekey_policy::vault_mutation_driver::schema_step +vela_rekey_policy::vault_mutation_driver::begin_capsule_ack +vela_rekey_policy::vault_mutation_driver::capsule_ack_step +vela_rekey_policy::vault_mutation_driver::begin_rekey_capable +vela_rekey_policy::vault_mutation_driver::rekey_capable_step +vela_rekey_policy::plan_active_mutation +vela_rekey_policy::next_epoch' \
  fstar --z3rlimit 500

mkdir -p proofs/fstar/extraction-vault-mutation-driver-root
rm -f proofs/fstar/extraction-vault-mutation-driver-root/*.fst
mv proofs/fstar/extraction-vault-mutation-driver/Vela_rekey_policy.fst \
  proofs/fstar/extraction-vault-mutation-driver-root/
python3 "$proof_root/strip-hax-instances.py" proofs/fstar/extraction-vault-mutation-driver/*.fst

mapfile -t proof_files < <(
  find proofs/fstar/extraction-vault-mutation-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t lemma_files < <(
  find proofs/fstar/vault-mutation-driver-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused vault-mutation-driver modules" >&2
  exit 1
fi
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed vault-mutation-driver lemma module" >&2
  exit 1
fi

python3 "$proof_root/../../security/formal/check-driver-proof-sources.py" \
  --generated "${proof_files[@]}" \
  --proof "${lemma_files[@]}" \
  --include-dir "$proof_root"

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)
if [[ -z $hax_lib_root || ! -d $hax_lib_root ]]; then
  echo "could not locate hax-lib proof libraries" >&2
  exit 1
fi

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
  --include proofs/fstar/extraction-vault-mutation-driver-root
  --include proofs/fstar/extraction-vault-mutation-driver
  --include proofs/fstar/vault-mutation-driver-lemmas
  "${proof_files[@]}" "${lemma_files[@]}"
)
printf 'F* vault-mutation-driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "vault mutation drivers: chunk delete, ORAM path write, schema activation, capsule ack and capability attestation each reach a verdict through the extracted transitions"
echo "per-request trace: at most one success/failure, the chunk delete publishes only after its guarded delete, ORAM writes and rechecks each bucket once in order, schema/capability effects are device-scoped single writes, and a capsule ack clears or reports a replay without clearing a different pending epoch"
sha256sum "${proof_files[@]}" "${lemma_files[@]}" src/vault_mutation_driver.rs
