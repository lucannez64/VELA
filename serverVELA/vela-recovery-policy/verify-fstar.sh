#!/usr/bin/env bash
set -euo pipefail

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"

for command_name in cargo-hax driver-hax-frontend-exporter hax-engine fstar.exe z3-4.13.3; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is missing; follow README.md" >&2
    exit 1
  }
done

cargo test

cargo hax into \
  -i '-** +vela_recovery_policy::plan_publication_stage +vela_recovery_policy::plan_publication_finalize +vela_recovery_policy::competing_split_can_finalize +vela_recovery_policy::retired_epoch_publication_can_finalize +vela_recovery_policy::already_finalized_epoch_can_finalize +vela_recovery_policy::plan_initiation +vela_recovery_policy::plan_registration +vela_recovery_policy::plan_recovery +vela_recovery_policy::plan_credential_update +vela_recovery_policy::plan_enrollment +vela_recovery_policy::replaced_credential_can_recover +vela_recovery_policy::consumed_challenge_can_recover_again +vela_recovery_policy::cross_user_grant_can_enroll +vela_recovery_policy::revoked_credential_grant_can_enroll +vela_recovery_policy::rotated_grant_can_enroll +vela_recovery_policy::consumed_grant_can_enroll_again +vela_recovery_policy::plan_proof_initiation +vela_recovery_policy::plan_possession_recovery +vela_recovery_policy::unproven_possession_claim_can_recover +vela_recovery_policy::stale_commitment_can_recover +vela_recovery_policy::commitmentless_possession_grant_can_enroll' \
  fstar --z3rlimit 100

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)
if [[ -z "$hax_lib_root" || ! -d "$hax_lib_root" ]]; then
  echo "could not locate hax-lib proof libraries" >&2
  exit 1
fi

mapfile -t proof_files < <(
  find proofs/fstar/extraction -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no F* modules" >&2
  exit 1
fi

fstar.exe \
  --cmi \
  --warn_error -331 \
  --z3rlimit 100 \
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
  --include "$hax_lib_root/proof-libs/fstar/core" \
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives" \
  --include "$hax_lib_root/proofs/fstar/extraction" \
  --include proofs/fstar/extraction \
  "${proof_files[@]}"
