#!/usr/bin/env bash
set -euo pipefail

# F-1 for the device-enrollment executors: each executor method's observation
# is the truth about the turso tables and the sled store.
#
# `src/executor.rs` splits every executor method in
# `vela-server/src/device/{enroll,invitation,rendezvous}.rs` into a typed
# statement plan (`plan_*`), the rendering (pinned byte for byte by its unit
# tests) and an observation classifier (`classify_*`). hax extracts the plans
# and classifiers here. `Vela_enrollment_policy_executor_model` models the
# tables, the store keys, statement semantics and a failure at any statement;
# `Vela_enrollment_policy_executor_lemmas` proves, for every starting database
# and store and every fault point, that each observation reports exactly what
# the run did, plus the facts the pairing and enrollment drivers rely on.
#
# The driver modules come from `verify-fstar-pairing-driver.sh` and
# `verify-fstar-enroll-driver.sh`, which run earlier in verify-fstar.sh; this
# extraction keeps only the executor module.

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
for f in \
  proofs/fstar/extraction/Vela_enrollment_policy.fst \
  proofs/fstar/extraction-pairing-driver/Vela_enrollment_policy.Pairing_driver.fst \
  proofs/fstar/extraction-enroll-driver/Vela_enrollment_policy.Enroll_driver.fst; do
  [[ -f $f ]] || {
    echo "missing $f; run verify-fstar-pairing-driver.sh and verify-fstar-enroll-driver.sh first" >&2
    exit 1
  }
done

# Rendering pins and the Rust mirror's shared vectors.
cargo test --lib executor

items=(
  plan_store_package plan_redeem_package plan_store_grant plan_claim_check
  plan_claim_write plan_account_read plan_completion_preflight plan_take_ceremony
  plan_completion_insert plan_result_write plan_result_read plan_claim_read
  plan_device_by_grant plan_active_device_read plan_enroll_insert plan_challenge_take
  classify_store classify_redeem classify_challenge_take classify_claim_check
  classify_claim_write classify_account account_fields classify_completion_preflight
  classify_take_ceremony classify_insert_completion classify_insert_enroll
  classify_result_read classify_claim_read classify_enrolled_device
  classify_device_check
)
include='-**'
for item in "${items[@]}"; do
  include+=" +vela_enrollment_policy::executor::$item"
done

rm -rf proofs/fstar/extraction-executor
cargo hax into \
  --output-dir proofs/fstar/extraction-executor \
  -i "$include" \
  fstar --z3rlimit 500
# The partial driver and root modules hax writes alongside are superseded by
# the full driver extractions.
rm -f proofs/fstar/extraction-executor/Vela_enrollment_policy.fst
rm -f proofs/fstar/extraction-executor/Vela_enrollment_policy.Pairing_driver.fst
rm -f proofs/fstar/extraction-executor/Vela_enrollment_policy.Enroll_driver.fst

generated=(proofs/fstar/extraction-executor/Vela_enrollment_policy.Executor.fst)
# The checked-in historical root module carries its own (older) budget
# header, so the source policy is applied to the driver extractions this gate
# depends on, not to that artifact.
driver=(
  proofs/fstar/extraction-pairing-driver/*.fst
  proofs/fstar/extraction-enroll-driver/*.fst
)
model=(proofs/fstar/executor-lemmas/Vela_enrollment_policy_executor_model.fst)
lemmas=(proofs/fstar/executor-lemmas/Vela_enrollment_policy_executor_lemmas.fst)
for f in "${generated[@]}" "${model[@]}" "${lemmas[@]}"; do
  [[ -f $f ]] || { echo "missing $f" >&2; exit 1; }
done

python3 "$proof_root/../../security/formal/check-driver-proof-sources.py" \
  --generated "${generated[@]}" "${driver[@]}" \
  --proof "${model[@]}" "${lemmas[@]}" \
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
  --z3rlimit 100
  --z3version 4.13.3
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib'
  --include "$hax_lib_root/proof-libs/fstar/core"
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives"
  --include "$hax_lib_root/proofs/fstar/extraction"
  --include proofs/fstar/extraction
  --include proofs/fstar/extraction-pairing-driver
  --include proofs/fstar/extraction-enroll-driver
  --include proofs/fstar/extraction-executor
  --include proofs/fstar/executor-lemmas
)
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

# Each mutant of the plans and classifiers must break the proof.
"$proof_root/verify-fstar-enrollment-executors-mutations.sh"

echo "enrollment executors: for every starting database and store and every failing statement, each enrollment executor's observation reports exactly what its statements did to users, devices and the enrollment keys, and a failed run changes nothing"
sha256sum "${generated[@]}" "${model[@]}" "${lemmas[@]}" src/executor.rs src/executor_model.rs
