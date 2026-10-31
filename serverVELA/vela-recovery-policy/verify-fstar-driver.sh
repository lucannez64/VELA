#!/usr/bin/env bash
set -euo pipefail

# Focused F-2 increment: actual enrollment-redemption transition driver.
#
# `proofs/fstar/extraction/` is the historical 90-contract artifact for this
# crate. The driver extraction reuses the F* module name `Vela_recovery_policy`,
# so it is regenerated into `proofs/fstar/extraction-driver/` and checked in a
# separate fstar.exe invocation. Never pass both include directories: the
# focused (partial) root module would shadow the historical one, or vice versa.
#
# The hand-written trace lemmas quantify over every event list and call the
# extracted `Vela_recovery_policy.Driver.step`; they do not restate its
# transition logic.

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

rm -rf proofs/fstar/extraction-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-driver \
  -i '-** +vela_recovery_policy::driver::begin_redemption +vela_recovery_policy::driver::step +vela_recovery_policy::driver::on_grant_consumed +vela_recovery_policy::driver::on_final_policy_observed +vela_recovery_policy::driver::on_insert_completed +vela_recovery_policy::driver::on_authority_rechecked' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t lemma_files < <(
  find proofs/fstar/driver-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused driver modules" >&2
  exit 1
fi
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed driver lemma module" >&2
  exit 1
fi
composition_files=(proofs/fstar/driver-composition/Vela_recovery_policy_driver_composition.fst)
[[ -f ${composition_files[0]} ]] || {
  echo "missing reviewed driver composition module" >&2
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
  --include proofs/fstar/extraction-driver
  --include proofs/fstar/driver-lemmas
  --include proofs/fstar/driver-composition
  "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}"
)
printf 'F* driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "driver proof: 6 focused Rust contracts, 23 hand-written trace lemmas/witnesses checked"
echo "driver composition: any number of interleaved requests write at most one device row per grant"
sha256sum "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}" src/driver.rs
