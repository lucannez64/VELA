#!/usr/bin/env bash
set -euo pipefail

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"

for command_name in cargo-hax driver-hax-frontend-exporter hax-engine fstar.exe z3-4.13.3; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is missing; follow ../vela-client-recovery-policy/README.md" >&2
    exit 1
  }
done

cargo test

cargo hax into \
  -i '-** +vela_sync_policy::plan_epoch_adoption +vela_sync_policy::rolled_back_server_epoch_can_adopt +vela_sync_policy::skipped_transition_can_adopt +vela_sync_policy::freezing_rotation_can_adopt +vela_sync_policy::foreign_capsule_can_adopt +vela_sync_policy::plan_chunk_download +vela_sync_policy::rolled_back_chunk_can_be_accepted +vela_sync_policy::unbound_aad_chunk_can_be_accepted +vela_sync_policy::classify_merge_action +vela_sync_policy::tombstoned_item_can_be_resurrected +vela_sync_policy::conflicted_local_edit_can_be_overwritten' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no F* modules" >&2
  exit 1
fi

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)

fstar.exe \
  --cmi \
  --warn_error -331 \
  --z3rlimit 500 \
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
  --include "$hax_lib_root/proof-libs/fstar/core" \
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives" \
  --include "$hax_lib_root/proofs/fstar/extraction" \
  --include proofs/fstar/extraction \
  "${proof_files[@]}"
