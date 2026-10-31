#!/usr/bin/env bash
set -euo pipefail

# F-1 for the vault, rekey, capsule, ORAM and schema executors: each executor
# method's observation is the truth about the database and the store.
#
# `src/executor.rs` splits every executor method in `vela-server/src/vault/*.rs`
# and `vela-server/src/device/{capsule,list}.rs` into a typed statement plan
# (`plan_*`), the SQL/store rendering (pinned byte for byte by its unit tests)
# and an observation classifier (`classify_*`). hax extracts the plans and
# classifiers here. `Vela_rekey_policy_executor_model` models the tables and
# store keys they touch, statement, transaction and CAS semantics and a failure
# at any statement; `Vela_rekey_policy_executor_lemmas` proves, for every
# starting database and every fault point, that each observation reports
# exactly what the run did, and the store facts the drivers rely on.
#
# Usage: ./verify-fstar-vault-executors.sh [all|model]
#   all    extract, check the proofs, then run the mutation checks (default)
#   model  reuse the checked-in extraction and check only the proof modules

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"
want=${1:-all}

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

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)
[[ -n $hax_lib_root && -d $hax_lib_root ]] || {
  echo "could not locate hax-lib proof libraries" >&2
  exit 1
}

generated=(
  proofs/fstar/extraction-executor/Vela_rekey_policy.Executor.fst
  proofs/fstar/extraction-executor/Vela_rekey_policy.Rekey_driver.fst
  proofs/fstar/extraction-executor/Vela_rekey_policy.Vault_mutation_driver.fst
  proofs/fstar/extraction-executor/Vela_rekey_policy.Vault_upload_driver.fst
)
model=(proofs/fstar/executor-lemmas/Vela_rekey_policy_executor_model.fst)
lemmas=(proofs/fstar/executor-lemmas/Vela_rekey_policy_executor_lemmas.fst)

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
  --include proofs/fstar/extraction-executor
  --include proofs/fstar/executor-lemmas
)

if [[ $want == all ]]; then
  # Rendering pins and the Rust mirror's shared vectors.
  cargo test --lib executor

  items=(
    plan_delete_chunk plan_read_version plan_reread_version plan_read_chunk
    plan_chunk_exists plan_chunk_create plan_chunk_shadow plan_chunk_update
    plan_read_inventory plan_freeze_cas plan_freeze_cleanup plan_commit_transaction plan_commit_cas
    plan_sweep_old_chunks plan_rollback_cas plan_rollback_cleanup
    plan_shadow_activity plan_probe_oram plan_probe_capable
    plan_probe_acknowledged plan_probe_chunk_shadows plan_probe_device_capsules
    plan_write_capsule plan_ack_capsule plan_pending_capsule plan_attest_capable
    plan_schema_floor plan_oram_exists plan_oram_insert plan_oram_update
    classify_version classify_reread classify_delete classify_chunk_read
    classify_chunk_create classify_chunk_shadow classify_chunk_update
    classify_inventory classify_probe classify_freeze_cas classify_transaction
    classify_cleanup classify_sweep classify_rollback
    classify_shadow_activity classify_capsule_write classify_pending
    classify_ack classify_attest classify_schema_write classify_oram_create
    classify_oram_update
  )
  include='-**'
  for item in "${items[@]}"; do
    include+=" +vela_rekey_policy::executor::$item"
  done

  rm -rf proofs/fstar/extraction-executor
  cargo hax into \
    --output-dir proofs/fstar/extraction-executor \
    -i "$include" \
    fstar --z3rlimit 500
fi

for f in "${generated[@]}" "${model[@]}" "${lemmas[@]}"; do
  [[ -f $f ]] || { echo "missing $f (run with 'all')" >&2; exit 1; }
done

python3 "$proof_root/../../security/formal/check-driver-proof-sources.py" \
  --generated "${generated[@]}" \
  --proof "${model[@]}" "${lemmas[@]}" \
  --include-dir "$proof_root"

# One module at a time, each in its own process, so each stays within its
# memory budget.
for module in "${generated[@]}" "${model[@]}" "${lemmas[@]}"; do
  echo "checking $module"
  if [[ -x /usr/bin/time ]]; then
    /usr/bin/time -f "$module: %M KB peak, %e s" fstar.exe "${fstar_args[@]}" "$module"
  else
    fstar.exe "${fstar_args[@]}" "$module"
  fi
done

if [[ $want == all ]]; then
  # Each mutant of the plans and classifiers must break the proof.
  "$proof_root/verify-fstar-vault-executors-mutations.sh"
fi

echo "vault executors: for every starting database and every failing statement, each proved executor's observation reports exactly what its statements did to vault_chunks, users, devices, oram_buckets and the schema key, and a failed run leaves them unchanged"
sha256sum "${generated[@]}" "${model[@]}" "${lemmas[@]}" src/executor.rs src/executor_model.rs
