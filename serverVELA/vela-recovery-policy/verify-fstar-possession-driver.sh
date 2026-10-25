#!/usr/bin/env bash
set -euo pipefail

# Focused F-2 increment: possession-proof recovery transition drivers.
#
# `proofs/fstar/extraction/` is the historical 90-contract artifact for this
# crate and `proofs/fstar/extraction-driver/` is the enrollment-redemption
# driver artifact. Both reuse the F* module name `Vela_recovery_policy`, so
# this focused extraction is regenerated into
# `proofs/fstar/extraction-possession-driver/` and checked in a separate
# fstar.exe invocation. Never pass more than one of those include directories
# to the same invocation.
#
# The hand-written trace lemmas quantify over every event list and call the
# extracted `Vela_recovery_policy.PossessionDriver.*` transition functions;
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

rm -rf proofs/fstar/extraction-possession-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-possession-driver \
  -i '-** +vela_recovery_policy::possession_driver::begin_initiation +vela_recovery_policy::possession_driver::step_initiation +vela_recovery_policy::possession_driver::on_initiation_observed +vela_recovery_policy::possession_driver::on_challenge_stored +vela_recovery_policy::possession_driver::begin_proof_recover +vela_recovery_policy::possession_driver::step_proof_recover +vela_recovery_policy::possession_driver::on_attempt_counted +vela_recovery_policy::possession_driver::on_attempt_consumed +vela_recovery_policy::possession_driver::on_account_observed +vela_recovery_policy::possession_driver::on_proof_observed +vela_recovery_policy::possession_driver::on_grant_stored +vela_recovery_policy::possession_driver::proof_recover_effect_releases_share' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction-possession-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t lemma_files < <(
  find proofs/fstar/possession-driver-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused possession-driver modules" >&2
  exit 1
fi
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed possession-driver lemma module" >&2
  exit 1
fi
composition_files=(proofs/fstar/possession-driver-composition/Vela_recovery_policy_possession_driver_composition.fst)
[[ -f ${composition_files[0]} ]] || {
  echo "missing reviewed possession-driver composition module" >&2
  exit 1
}

# Enforce the reviewed source policy, including nested comments and exact
# budget-only pragmas. This is a source guard; fstar.exe remains the checker.
python3 "$proof_root/../../security/formal/check-driver-proof-sources.py" \
  --generated "${proof_files[@]}" \
  --proof "${lemma_files[@]}" "${composition_files[@]}"

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
  --include proofs/fstar/extraction-possession-driver
  --include proofs/fstar/possession-driver-lemmas
  --include proofs/fstar/possession-driver-composition
  "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}"
)
printf 'F* possession-driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "possession driver proof: 11 focused Rust contracts checked"
echo "possession driver composition: any number of interleaved attempts issue at most one grant per proof state"
sha256sum "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}" src/possession_driver.rs
