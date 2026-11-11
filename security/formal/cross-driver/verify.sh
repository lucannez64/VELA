#!/usr/bin/env bash
set -euo pipefail

# F-2 cross-driver concurrent composition gate.
#
# Regenerates the focused extractions of the four decision-driver crates the
# composition uses (session: login, revocation/admission, deletion; enrollment:
# pairing completion; recovery: enrollment redemption), then checks one F*
# module over the shared account/device/token/grant world.
#
# Each crate's root F* module is named after the crate. Different crates have
# distinct names, so all three focused extractions can share one fstar.exe
# invocation. Within one crate, only one partial root module is ever passed.

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$proof_root/../../.." && pwd)
server_root=$repo_root/serverVELA

session_crate=$server_root/vela-session-policy
enrollment_crate=$server_root/vela-enrollment-policy
recovery_crate=$server_root/vela-recovery-policy

session_gen=$session_crate/proofs/fstar/extraction-f2-cross
enrollment_gen=$enrollment_crate/proofs/fstar/extraction-f2-cross
recovery_gen=$recovery_crate/proofs/fstar/extraction-f2-cross

composition=$proof_root/Vela_cross_driver_composition.fst

for command_name in cargo cargo-hax driver-hax-frontend-exporter hax-engine fstar.exe z3-4.13.3 jq; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is missing; follow the crate README.md" >&2
    exit 1
  }
done

version=$(fstar.exe --version)
printf '%s\n' "$version"
[[ ${version%%$'\n'*} == 'F* 2025.10.06' ]] || {
  echo 'unexpected F* version' >&2
  exit 2
}

# ── Focused extractions ────────────────────────────────────────────────────

rm -rf "$session_gen"
(
  cd "$session_crate"
  cargo hax into \
    --output-dir proofs/fstar/extraction-f2-cross \
    -i '-** +vela_session_policy::login_driver::begin_login +vela_session_policy::login_driver::step +vela_session_policy::login_driver::on_challenge_taken +vela_session_policy::login_driver::on_device_looked_up +vela_session_policy::login_driver::on_verifier_finished +vela_session_policy::login_driver::on_failure_record_observed +vela_session_policy::login_driver::on_backoff_reset_observed_event +vela_session_policy::login_driver::on_token_issue_observed +vela_session_policy::login_driver::on_token_track_observed +vela_session_policy::revocation_driver::begin_revocation +vela_session_policy::revocation_driver::step +vela_session_policy::revocation_driver::on_target_looked_up +vela_session_policy::revocation_driver::on_lockout_completed +vela_session_policy::revocation_driver::on_record_completed +vela_session_policy::revocation_driver::on_cascade_completed +vela_session_policy::revocation_driver::begin_logout +vela_session_policy::revocation_driver::logout_step +vela_session_policy::revocation_driver::on_logout_completed +vela_session_policy::revocation_driver::plan_admission +vela_session_policy::deletion_driver::begin_deletion +vela_session_policy::deletion_driver::step +vela_session_policy::deletion_driver::on_devices_scanned_event +vela_session_policy::deletion_driver::on_device_lockout_event +vela_session_policy::deletion_driver::on_web_sessions_scanned_event +vela_session_policy::deletion_driver::on_web_session_lockout_event +vela_session_policy::deletion_driver::on_transaction_observed_event +vela_session_policy::deletion_driver::on_table_deleted_event +vela_session_policy::deletion_driver::on_users_deleted_event +vela_session_policy::deletion_driver::on_commit_event' \
    fstar --z3rlimit 500
)

rm -rf "$enrollment_gen"
(
  cd "$enrollment_crate"
  cargo hax into \
    --output-dir proofs/fstar/extraction-f2-cross \
    -i '-** +vela_enrollment_policy::pairing_driver::begin_completion +vela_enrollment_policy::pairing_driver::on_completion_account +vela_enrollment_policy::pairing_driver::on_completion_ready_event +vela_enrollment_policy::pairing_driver::on_ceremony_taken_event +vela_enrollment_policy::pairing_driver::on_device_inserted_event +vela_enrollment_policy::pairing_driver::on_result_written_event +vela_enrollment_policy::pairing_driver::step' \
    fstar --z3rlimit 500
)

rm -rf "$recovery_gen"
(
  cd "$recovery_crate"
  cargo hax into \
    --output-dir proofs/fstar/extraction-f2-cross \
    -i '-** +vela_recovery_policy::driver::begin_redemption +vela_recovery_policy::driver::step +vela_recovery_policy::driver::on_grant_consumed +vela_recovery_policy::driver::on_final_policy_observed +vela_recovery_policy::driver::on_insert_completed +vela_recovery_policy::driver::on_authority_rechecked' \
    fstar --z3rlimit 500
)

mapfile -t session_files < <(
  find "$session_gen" -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t enrollment_files < <(
  find "$enrollment_gen" -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t recovery_files < <(
  find "$recovery_gen" -maxdepth 1 -type f -name '*.fst' -print | sort
)
for files in session_files enrollment_files recovery_files; do
  eval "count=\${#${files}[@]}"
  if (( count == 0 )); then
    echo "hax generated no focused modules for $files" >&2
    exit 1
  fi
done
[[ -f $composition ]] || {
  echo "missing reviewed cross-driver composition module" >&2
  exit 1
}

printf 'session modules:\n'
printf '  %s\n' "${session_files[@]}"
printf 'enrollment modules:\n'
printf '  %s\n' "${enrollment_files[@]}"
printf 'recovery modules:\n'
printf '  %s\n' "${recovery_files[@]}"

# Enforce the reviewed source policy, including nested comments and exact
# budget-only pragmas. This is a source guard; fstar.exe remains the checker.
python3 "$repo_root/security/formal/check-driver-proof-sources.py" \
  --generated "${session_files[@]}" "${enrollment_files[@]}" "${recovery_files[@]}" \
  --proof "$composition" \
  --include-dir "$proof_root"

hax_lib_root=$(
  cd "$session_crate"
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
  --z3rlimit 32000
  --z3version 4.13.3
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib'
  --include "$hax_lib_root/proof-libs/fstar/core"
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives"
  --include "$hax_lib_root/proofs/fstar/extraction"
  --include "$session_gen"
  --include "$enrollment_gen"
  --include "$recovery_gen"
  --include "$proof_root"
  "${session_files[@]}" "${enrollment_files[@]}" "${recovery_files[@]}" "$composition"
)
printf 'F* cross-driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "cross-driver composition: extracted login, revocation/admission, deletion, pairing-completion and recovery-redemption drivers over one shared world"
sha256sum "${session_files[@]}" "${enrollment_files[@]}" "${recovery_files[@]}" "$composition"
