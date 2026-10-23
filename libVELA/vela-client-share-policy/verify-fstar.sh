#!/usr/bin/env bash
set -euo pipefail

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"

for command_name in cargo-hax driver-hax-frontend-exporter hax-engine fstar.exe z3-4.13.3 jq; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is missing; follow README.md" >&2
    exit 1
  }
done

cargo test

cargo hax into \
  -i '-** +vela_client_share_policy::plan_share_admission +vela_client_share_policy::unauthenticated_share_can_be_admitted +vela_client_share_policy::misaddressed_share_can_be_admitted +vela_client_share_policy::misattributed_share_can_be_admitted +vela_client_share_policy::foreign_signer_update_can_be_applied +vela_client_share_policy::cross_lineage_update_can_be_applied +vela_client_share_policy::stale_revision_update_can_be_applied +vela_client_share_policy::pinned_share_can_restart_as_first_contact +vela_client_share_policy::initial_acceptance_is_authorized +vela_client_share_policy::next_store_generation +vela_client_share_policy::stale_snapshot_can_commit +vela_client_share_policy::pending_commit_can_be_overwritten +vela_client_share_policy::exhausted_generation_can_commit +vela_client_share_policy::recovery_should_apply +vela_client_share_policy::local_edit_can_be_overwritten +vela_client_share_policy::deleted_item_can_be_restored +vela_client_share_policy::existing_pin_can_restart_acceptance +vela_client_share_policy::missing_payload_can_be_accepted +vela_client_share_policy::share_permit_revision' \
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
