#!/usr/bin/env bash
set -euo pipefail

# Focused F-2 increment: WebAuthn recovery transition drivers.
#
# `proofs/fstar/extraction/` is the historical 90-contract artifact for this
# crate, `proofs/fstar/extraction-driver/` is the enrollment-redemption driver
# artifact and `proofs/fstar/extraction-possession-driver/` is the
# possession-proof driver artifact. All three reuse the F* module name
# `Vela_recovery_policy`, so this focused extraction is regenerated into
# `proofs/fstar/extraction-webauthn-driver/` and checked in a separate
# fstar.exe invocation. Never pass more than one of those include directories
# to the same invocation.
#
# The hand-written trace lemmas quantify over every event list and call the
# extracted `Vela_recovery_policy.Webauthn_driver.step_*` transition functions;
# they do not restate the transition logic.

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"

for command_name in cargo cargo-hax driver-hax-frontend-exporter hax-engine fstar.exe z3-4.13.3 jq; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is missing; follow README.md" >&2
    exit 1
  }
done

version=$(fstar.exe --version)
printf '%s\n' "$version"
[[ ${version%%$'\n'*} == 'F* 2025.10.06' ]] || {
  echo 'unexpected F* version' >&2
  exit 2
}

rm -rf proofs/fstar/extraction-webauthn-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-webauthn-driver \
  -i '-** +vela_recovery_policy::webauthn_driver::begin_registration_start +vela_recovery_policy::webauthn_driver::step_registration_start +vela_recovery_policy::webauthn_driver::on_registration_start_observed +vela_recovery_policy::webauthn_driver::on_registration_ceremony_started +vela_recovery_policy::webauthn_driver::on_registration_start_stored +vela_recovery_policy::webauthn_driver::begin_registration +vela_recovery_policy::webauthn_driver::step_registration +vela_recovery_policy::webauthn_driver::on_registration_attempt_counted +vela_recovery_policy::webauthn_driver::on_registration_state_consumed +vela_recovery_policy::webauthn_driver::on_registration_verified +vela_recovery_policy::webauthn_driver::on_credential_looked_up +vela_recovery_policy::webauthn_driver::on_credential_persisted +vela_recovery_policy::webauthn_driver::begin_auth_start +vela_recovery_policy::webauthn_driver::step_auth_start +vela_recovery_policy::webauthn_driver::on_auth_start_observed +vela_recovery_policy::webauthn_driver::on_auth_ceremony_started +vela_recovery_policy::webauthn_driver::on_auth_start_stored +vela_recovery_policy::webauthn_driver::begin_auth_finish +vela_recovery_policy::webauthn_driver::step_auth_finish +vela_recovery_policy::webauthn_driver::on_auth_finish_attempt_counted +vela_recovery_policy::webauthn_driver::on_auth_finish_context_observed +vela_recovery_policy::webauthn_driver::on_auth_attempt_consumed +vela_recovery_policy::webauthn_driver::on_auth_assertion_observed +vela_recovery_policy::webauthn_driver::on_auth_credential_updated +vela_recovery_policy::webauthn_driver::on_auth_account_observed +vela_recovery_policy::webauthn_driver::on_auth_share_observed +vela_recovery_policy::webauthn_driver::on_auth_grant_stored' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction-webauthn-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t lemma_files < <(
  find proofs/fstar/webauthn-driver-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused webauthn-driver modules" >&2
  exit 1
fi
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed webauthn-driver lemma module" >&2
  exit 1
fi
composition_files=(proofs/fstar/webauthn-driver-composition/Vela_recovery_policy_webauthn_driver_composition.fst)
[[ -f ${composition_files[0]} ]] || {
  echo "missing reviewed webauthn-driver composition module" >&2
  exit 1
}

# Enforce the reviewed source policy, including nested comments and exact
# budget-only pragmas. This is a source guard; fstar.exe remains the checker.
python3 "$proof_root/../../security/formal/check-driver-proof-sources.py" \
  --generated "${proof_files[@]}" \
  --proof "${lemma_files[@]}" "${composition_files[@]}" \
  --include-dir "$proof_root"

hax_lib_root=$(
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
  --z3rlimit 4000
  --z3version 4.13.3
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib'
  --include "$hax_lib_root/proof-libs/fstar/core"
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives"
  --include "$hax_lib_root/proofs/fstar/extraction"
  --include proofs/fstar/extraction-webauthn-driver
  --include proofs/fstar/webauthn-driver-lemmas
  --include proofs/fstar/webauthn-driver-composition
  "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}"
)
printf 'F* webauthn-driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "webauthn driver proof: 27 focused Rust contracts checked"
echo "webauthn driver composition: any number of interleaved requests issue at most one grant per challenge"
sha256sum "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}" src/webauthn_driver.rs
