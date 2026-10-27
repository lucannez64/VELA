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
  -i '-** +vela_enrollment_policy::open_facts +vela_enrollment_policy::plan_open +vela_enrollment_policy::claim_facts +vela_enrollment_policy::plan_claim +vela_enrollment_policy::inspect_facts +vela_enrollment_policy::authorize_inspection +vela_enrollment_policy::completion_facts +vela_enrollment_policy::plan_completion +vela_enrollment_policy::result_facts +vela_enrollment_policy::authorize_result +vela_enrollment_policy::completed_ceremony_can_complete_again +vela_enrollment_policy::other_device_can_inspect +vela_enrollment_policy::substituted_claim_can_complete +vela_enrollment_policy::result_without_claimed_key_proof +vela_enrollment_policy::web_session_can_open_enrollment_grant +vela_enrollment_policy::expired_grant_can_open +vela_enrollment_policy::missing_grant_can_be_claimed +vela_enrollment_policy::invalid_public_key_length_can_be_claimed +vela_enrollment_policy::missing_claim_can_be_inspected +vela_enrollment_policy::other_device_can_inspect_observed_claim +vela_enrollment_policy::revoked_opener_can_complete +vela_enrollment_policy::foreign_device_can_complete_observed_ceremony +vela_enrollment_policy::unverified_signature_can_complete +vela_enrollment_policy::missing_claim_can_complete_observed_ceremony +vela_enrollment_policy::request_supplied_claim_can_complete +vela_enrollment_policy::stale_epoch_can_complete +vela_enrollment_policy::invalid_result_signature_can_return_result +vela_enrollment_policy::missing_claimed_key_can_return_result +vela_enrollment_policy::unclaimed_ceremony_can_return_result' \
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

# F-2 focused pairing-driver trace proof. It regenerates a partial extraction
# with the same F* module name into proofs/fstar/extraction-pairing-driver, so
# it must run in its own fstar.exe invocation and never share an include
# directory with the historical artifact checked above.
"$proof_root/verify-fstar-pairing-driver.sh"

# Handler-to-driver link for the device-pairing ceremonies: the interpreter
# loop the handlers expand, proved to perform exactly the driver's effects.
# Needs the pairing driver extraction above.
"$proof_root/verify-fstar-pairing-interpreter.sh"

# F-2 focused `POST /device/enroll` driver: the single-use challenge, the two
# signature checks and the guarded account-epoch insert.
"$proof_root/verify-fstar-enroll-driver.sh"

# Handler-to-driver link for `POST /device/enroll`; needs the driver
# extraction above.
"$proof_root/verify-fstar-enroll-interpreter.sh"
