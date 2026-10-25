#!/usr/bin/env bash
set -euo pipefail

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"

for command_name in cargo-hax driver-hax-frontend-exporter hax-engine fstar.exe z3-4.13.3; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is missing; follow ../vela-rekey-policy/README.md" >&2
    exit 1
  }
done

cargo test

cargo hax into \
  -i '-** +vela_share_policy::ek_registration_facts +vela_share_policy::plan_ek_registration +vela_share_policy::forged_ek_binding_can_register +vela_share_policy::replayed_ek_binding_can_register +vela_share_policy::foreign_device_ek_can_register +vela_share_policy::revoked_device_ek_can_register +vela_share_policy::send_facts +vela_share_policy::plan_send +vela_share_policy::timestamp_format_plausible +vela_share_policy::link_mutation_facts +vela_share_policy::plan_link_mutation +vela_share_policy::non_sender_can_mutate_link +vela_share_policy::revoked_link_can_mutate +vela_share_policy::unauthenticated_sender_can_send_observed +vela_share_policy::unregistered_recipient_can_receive_observed +vela_share_policy::empty_capsule_can_be_sent_observed +vela_share_policy::full_inbox_can_receive_observed +vela_share_policy::unverified_signature_can_register_observed +vela_share_policy::foreign_device_ek_can_register_observed +vela_share_policy::revoked_device_ek_can_register_observed +vela_share_policy::replayed_ek_binding_can_register_observed +vela_share_policy::non_sender_can_mutate_observed_link +vela_share_policy::revoked_link_can_mutate_observed +vela_share_policy::missing_link_can_mutate_observed' \
  fstar --z3rlimit 100

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
  --z3rlimit 100 \
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
  --include "$hax_lib_root/proof-libs/fstar/core" \
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives" \
  --include "$hax_lib_root/proofs/fstar/extraction" \
  --include proofs/fstar/extraction \
  "${proof_files[@]}"

# F-2 focused sharing-driver trace proof. It regenerates a partial extraction
# with the same F* module name into proofs/fstar/extraction-driver, so it must
# run in its own fstar.exe invocation and never share an include directory with
# the historical artifact checked above.
"$proof_root/verify-fstar-driver.sh"
