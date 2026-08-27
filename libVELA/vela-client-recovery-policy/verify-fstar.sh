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
  -i '-** +vela_client_recovery_policy::plan_reconstruction +vela_client_recovery_policy::plan_adoption +vela_client_recovery_policy::plan_publication_resume +vela_client_recovery_policy::rotated_journal_can_write_external +vela_client_recovery_policy::finalized_publication_can_abort +vela_client_recovery_policy::malformed_journal_can_complete +vela_client_recovery_policy::cross_account_shares_can_reconstruct +vela_client_recovery_policy::mixed_epoch_shares_can_reconstruct +vela_client_recovery_policy::mismatched_split_ids_can_reconstruct +vela_client_recovery_policy::untagged_shares_can_reconstruct +vela_client_recovery_policy::same_channel_shares_can_reconstruct +vela_client_recovery_policy::duplicate_coordinates_can_reconstruct +vela_client_recovery_policy::unbound_contact_share_can_reconstruct +vela_client_recovery_policy::plan_contact_delivery +vela_client_recovery_policy::rotated_contact_journal_can_seal +vela_client_recovery_policy::keyless_contact_delivery_can_seal +vela_client_recovery_policy::unauthenticated_secret_can_be_adopted +vela_client_recovery_policy::wrong_epoch_secret_can_be_adopted' \
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
