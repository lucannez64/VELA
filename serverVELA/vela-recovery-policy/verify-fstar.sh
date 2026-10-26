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
  -i '-** +vela_recovery_policy::plan_publication_stage +vela_recovery_policy::plan_publication_finalize +vela_recovery_policy::competing_split_can_finalize +vela_recovery_policy::retired_epoch_publication_can_finalize +vela_recovery_policy::already_finalized_epoch_can_finalize +vela_recovery_policy::plan_initiation +vela_recovery_policy::plan_registration +vela_recovery_policy::plan_recovery +vela_recovery_policy::plan_credential_update +vela_recovery_policy::plan_enrollment +vela_recovery_policy::plan_enrollment_preflight +vela_recovery_policy::enrollment_preflight_ordering_is_checked +vela_recovery_policy::ready_preflight_implies_guards_and_fields +vela_recovery_policy::all_applicable_guards_imply_ready +vela_recovery_policy::ready_preflight_matches_independent_readiness +vela_recovery_policy::epoch_mismatch_precedes_rotation_paused +vela_recovery_policy::epoch_mismatch_precedes_commitment_missing +vela_recovery_policy::epoch_mismatch_precedes_credential_replaced +vela_recovery_policy::rotation_paused_precedes_commitment_missing +vela_recovery_policy::rotation_paused_precedes_credential_replaced +vela_recovery_policy::commitment_missing_and_credential_replaced_are_disjoint +vela_recovery_policy::missing_grant_precedes_account_rejection +vela_recovery_policy::missing_preflight_grant_can_be_ready +vela_recovery_policy::unqueried_preflight_account_can_be_ready +vela_recovery_policy::absent_preflight_account_can_be_ready +vela_recovery_policy::epoch_mismatched_preflight_account_can_be_ready +vela_recovery_policy::rekeying_preflight_account_can_be_ready +vela_recovery_policy::replaced_preflight_credential_can_be_ready +vela_recovery_policy::commitmentless_preflight_possession_can_be_ready +vela_recovery_policy::replaced_credential_can_recover +vela_recovery_policy::consumed_challenge_can_recover_again +vela_recovery_policy::cross_user_grant_can_enroll +vela_recovery_policy::revoked_credential_grant_can_enroll +vela_recovery_policy::rotated_grant_can_enroll +vela_recovery_policy::consumed_grant_can_enroll_again +vela_recovery_policy::plan_proof_initiation +vela_recovery_policy::plan_possession_recovery +vela_recovery_policy::unproven_possession_claim_can_recover +vela_recovery_policy::stale_commitment_can_recover +vela_recovery_policy::commitmentless_possession_grant_can_enroll +vela_recovery_policy::initiate_facts +vela_recovery_policy::initiate_facts_authorize +vela_recovery_policy::missing_recovery_share_can_initiate +vela_recovery_policy::credentialless_account_can_initiate +vela_recovery_policy::colliding_attempt_id_can_initiate +vela_recovery_policy::expired_initiate_ttl_can_start +vela_recovery_policy::credential_update_facts +vela_recovery_policy::unverified_assertion_can_update_credential +vela_recovery_policy::stale_assertion_credential_can_update +vela_recovery_policy::observed_recovery_epoch +vela_recovery_policy::observed_recovery_epoch_is_active +vela_recovery_policy::recover_facts +vela_recovery_policy::recover_facts_authorize +vela_recovery_policy::missing_attempt_can_release +vela_recovery_policy::cross_user_recover_observation_can_release +vela_recovery_policy::mismatched_attempt_observation_can_release +vela_recovery_policy::replaced_observed_credential_can_release +vela_recovery_policy::unverified_observed_assertion_can_release +vela_recovery_policy::unverified_observation_user_can_release +vela_recovery_policy::missing_observed_share_can_release +vela_recovery_policy::rekeying_observed_account_can_release +vela_recovery_policy::proof_initiate_facts +vela_recovery_policy::proof_initiate_facts_authorize +vela_recovery_policy::absent_account_can_start_possession_proof +vela_recovery_policy::missing_share_can_start_possession_proof +vela_recovery_policy::commitmentless_account_can_start_possession_proof +vela_recovery_policy::rotating_account_can_start_possession_proof +vela_recovery_policy::colliding_possession_attempt_id_can_start +vela_recovery_policy::expired_possession_initiate_ttl_can_start +vela_recovery_policy::possession_recover_facts +vela_recovery_policy::possession_recover_facts_authorize +vela_recovery_policy::missing_possession_attempt_can_recover +vela_recovery_policy::absent_possession_account_can_recover +vela_recovery_policy::cross_user_possession_observation_can_recover +vela_recovery_policy::mismatched_possession_attempt_observation_can_recover +vela_recovery_policy::unverified_possession_observation_can_recover +vela_recovery_policy::rekeying_possession_observation_can_recover +vela_recovery_policy::missing_possession_commitment_can_recover +vela_recovery_policy::rotated_commitment_observation_can_recover +vela_recovery_policy::enrollment_facts +vela_recovery_policy::enrollment_facts_authorize +vela_recovery_policy::missing_enrollment_grant_observation_can_enroll +vela_recovery_policy::unconsumed_enrollment_grant_observation_can_enroll +vela_recovery_policy::replaced_enrollment_grant_observation_can_enroll +vela_recovery_policy::absent_enrollment_account_can_enroll +vela_recovery_policy::rekeying_enrollment_observation_can_enroll +vela_recovery_policy::replaced_credential_observation_can_enroll +vela_recovery_policy::commitmentless_possession_observation_can_enroll +vela_recovery_policy::rotated_enrollment_observation_can_enroll +vela_recovery_policy::invalid_public_keys_observation_can_enroll' \
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

# F-2 focused redemption-driver trace proof. It regenerates a partial extraction
# with the same F* module name into proofs/fstar/extraction-driver, so it must
# run in its own fstar.exe invocation and never share an include directory with
# the historical artifact checked above.
"$proof_root/verify-fstar-driver.sh"

# F-2 possession-proof recovery drivers. This regenerates its own partial
# extraction into proofs/fstar/extraction-possession-driver, so it must also run
# in its own fstar.exe invocation.
"$proof_root/verify-fstar-possession-driver.sh"

# F-2 WebAuthn recovery drivers. This regenerates its own partial extraction
# into proofs/fstar/extraction-webauthn-driver, so it must also run in its own
# fstar.exe invocation.
"$proof_root/verify-fstar-webauthn-driver.sh"
