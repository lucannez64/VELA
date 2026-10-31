#!/usr/bin/env bash
set -euo pipefail

# Focused F-2 increment: the `POST /device/enroll` decision driver.
#
# `proofs/fstar/extraction/` is the historical selection artifact for this
# crate. The enrollment driver reuses nothing from it, but it does reuse the F*
# module name `Vela_enrollment_policy`, so it is regenerated into
# `proofs/fstar/extraction-enroll-driver/` and checked in a separate fstar.exe
# invocation. Never pass both partial root modules: one would shadow the other.
#
# The hand-written per-request lemmas quantify over every event list and call
# the extracted `step`/`begin_enroll`; they do not restate the transition logic.

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
printf 'rustc: '
rustc --version
printf 'cargo hax: '
cargo hax --version | tr '\n' ' '
printf '\n'

cargo test

rm -rf proofs/fstar/extraction-enroll-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-enroll-driver \
  -i '-** +vela_enrollment_policy::enroll_driver::begin_enroll +vela_enrollment_policy::enroll_driver::step +vela_enrollment_policy::enroll_driver::on_challenge_consumed_event +vela_enrollment_policy::enroll_driver::on_device_checked_event +vela_enrollment_policy::enroll_driver::on_enrollment_prepared_event +vela_enrollment_policy::enroll_driver::on_account_checked_event +vela_enrollment_policy::enroll_driver::on_device_inserted_event' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction-enroll-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t lemma_files < <(
  find proofs/fstar/enroll-driver-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused enrollment-driver modules" >&2
  exit 1
fi
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed enrollment-driver lemma module" >&2
  exit 1
fi

# Enforce the reviewed source policy, including nested comments and exact
# budget-only pragmas. This is a source guard; fstar.exe remains the checker.
python3 "$proof_root/../../security/formal/check-driver-proof-sources.py" \
  --generated "${proof_files[@]}" \
  --proof "${lemma_files[@]}" \
  --include-dir "$proof_root"

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)
if [[ -z $hax_lib_root || ! -d $hax_lib_root ]]; then
  echo "could not locate hax-lib proof libraries" >&2
  exit 1
fi

common_args=(
  --cmi
  --cache_off
  --warn_error -331
  --z3version 4.13.3
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib'
  --include "$hax_lib_root/proof-libs/fstar/core"
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives"
  --include "$hax_lib_root/proofs/fstar/extraction"
  --include proofs/fstar/extraction-enroll-driver
)

lemma_args=(
  "${common_args[@]}"
  --z3rlimit 16000
  --include proofs/fstar/enroll-driver-lemmas
  "${proof_files[@]}" "${lemma_files[@]}"
)
printf 'F* enrollment-driver lemma argv:'
printf ' %q' "${lemma_args[@]}"
printf '\n'
fstar.exe "${lemma_args[@]}"

echo "enrollment driver: one consumed enroll-purpose challenge, approving device checks, verified new-key signature, active rekey permit and guarded insert per request"
echo "enrollment trace: at most one insert effect per challenge; success implies the insert; an ambiguous insert error is terminal and restores nothing"
sha256sum "${proof_files[@]}" "${lemma_files[@]}" src/enroll_driver.rs
