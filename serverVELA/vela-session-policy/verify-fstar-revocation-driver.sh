#!/usr/bin/env bash
set -euo pipefail

# Focused F-2/F-3 increment: the device-revocation, logout and admission
# decision drivers.
#
# `proofs/fstar/extraction/` is the historical 21-selection artifact for this
# crate and `proofs/fstar/extraction-login-driver/` is the focused login
# artifact. The revocation driver reuses the F* module name
# `Vela_session_policy`, so it is regenerated into
# `proofs/fstar/extraction-revocation-driver/` and checked in a separate
# fstar.exe invocation. Never pass both partial root modules: one would shadow
# the other.
#
# The hand-written per-request lemmas quantify over every event list and call
# the extracted `step`/`logout_step`; they do not restate the transition logic.
# The composition module is self-contained over the extracted driver (it does
# not import the lemma module) so the mutation checks fail in the composition
# theorem, not in an unrelated lemma.

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

rm -rf proofs/fstar/extraction-revocation-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-revocation-driver \
  -i '-** +vela_session_policy::revocation_driver::begin_revocation +vela_session_policy::revocation_driver::step +vela_session_policy::revocation_driver::on_target_looked_up +vela_session_policy::revocation_driver::on_lockout_completed +vela_session_policy::revocation_driver::on_record_completed +vela_session_policy::revocation_driver::on_cascade_completed +vela_session_policy::revocation_driver::begin_logout +vela_session_policy::revocation_driver::logout_step +vela_session_policy::revocation_driver::on_logout_completed +vela_session_policy::revocation_driver::plan_admission +vela_session_policy::revocation_driver::revoked_jti_can_be_admitted +vela_session_policy::revocation_driver::revoked_device_can_be_admitted +vela_session_policy::revocation_driver::revoked_device_row_can_be_admitted' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction-revocation-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t lemma_files < <(
  find proofs/fstar/revocation-driver-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
composition_files=(proofs/fstar/revocation-driver-composition/Vela_session_policy_revocation_driver_composition.fst)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused revocation-driver modules" >&2
  exit 1
fi
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed revocation-driver lemma module" >&2
  exit 1
fi
[[ -f ${composition_files[0]} ]] || {
  echo "missing reviewed revocation-driver composition module" >&2
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
  --z3rlimit 16000
  --z3version 4.13.3
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib'
  --include "$hax_lib_root/proof-libs/fstar/core"
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives"
  --include "$hax_lib_root/proofs/fstar/extraction"
  --include proofs/fstar/extraction-revocation-driver
  --include proofs/fstar/revocation-driver-lemmas
  --include proofs/fstar/revocation-driver-composition
  "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}"
)
printf 'F* revocation-driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "revocation driver: 13 focused Rust functions, 13 soundness postconditions (7 preconditions)"
echo "per-request trace: lockout before SQL record, cascade only after a successful or repeated revoke, at most one success/failure"
echo "logout trace: one JTI write, success implies the marker, storage failure terminal"
echo "revocation composition: arbitrary interleavings never authorize a cross-account or revoked-actor revoke and never admit a revoked device's token"
sha256sum "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}" src/revocation_driver.rs
