#!/usr/bin/env bash
set -euo pipefail

# Focused F-2/F-3 increment: the device-pairing decision driver.
#
# `proofs/fstar/extraction/` is the historical 29-selection artifact for this
# crate. The pairing driver reuses the F* module name
# `Vela_enrollment_policy`, so it is regenerated into
# `proofs/fstar/extraction-pairing-driver/` and checked in a separate
# fstar.exe invocation. Never pass both partial root modules: one would shadow
# the other.
#
# The hand-written per-request lemmas quantify over every event list and call
# the extracted `step`/`begin_*`; they do not restate the transition logic.
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

rm -rf proofs/fstar/extraction-pairing-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-pairing-driver \
  -i '-** +vela_enrollment_policy::pairing_driver::begin_store_package +vela_enrollment_policy::pairing_driver::begin_redeem_package +vela_enrollment_policy::pairing_driver::begin_open_grant +vela_enrollment_policy::pairing_driver::begin_claim +vela_enrollment_policy::pairing_driver::begin_completion +vela_enrollment_policy::pairing_driver::begin_result +vela_enrollment_policy::pairing_driver::step +vela_enrollment_policy::pairing_driver::on_package_written_event +vela_enrollment_policy::pairing_driver::on_package_redeemed_event +vela_enrollment_policy::pairing_driver::on_grant_written_event +vela_enrollment_policy::pairing_driver::on_claim_checked_event +vela_enrollment_policy::pairing_driver::on_claim_written_event +vela_enrollment_policy::pairing_driver::on_completion_account +vela_enrollment_policy::pairing_driver::on_completion_ready_event +vela_enrollment_policy::pairing_driver::on_ceremony_taken_event +vela_enrollment_policy::pairing_driver::on_device_inserted_event +vela_enrollment_policy::pairing_driver::on_result_written_event +vela_enrollment_policy::pairing_driver::on_result_read_event +vela_enrollment_policy::pairing_driver::on_claim_read_event' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction-pairing-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t lemma_files < <(
  find proofs/fstar/pairing-driver-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
composition_files=(proofs/fstar/pairing-driver-composition/Vela_enrollment_policy_pairing_driver_composition.fst)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused pairing-driver modules" >&2
  exit 1
fi
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed pairing-driver lemma module" >&2
  exit 1
fi
[[ -f ${composition_files[0]} ]] || {
  echo "missing reviewed pairing-driver composition module" >&2
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

common_args=(
  --cmi
  --cache_off
  --warn_error -331
  --z3version 4.13.3
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib'
  --include "$hax_lib_root/proof-libs/fstar/core"
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives"
  --include "$hax_lib_root/proofs/fstar/extraction"
  --include proofs/fstar/extraction-pairing-driver
)

# The per-request trace lemmas are one invocation. The composition is checked
# on its own with a low solver budget: its non-vacuity witnesses evaluate long
# concrete schedules, and a larger budget only makes Z3 search longer, not find
# a different proof.
lemma_args=(
  "${common_args[@]}"
  --z3rlimit 16000
  --include proofs/fstar/pairing-driver-lemmas
  "${proof_files[@]}" "${lemma_files[@]}"
)
composition_args=(
  "${common_args[@]}"
  --z3rlimit 500
  --include proofs/fstar/pairing-driver-composition
  "${proof_files[@]}" "${composition_files[@]}"
)
printf 'F* pairing-driver lemma argv:'
printf ' %q' "${lemma_args[@]}"
printf '\n'
fstar.exe "${lemma_args[@]}"
printf 'F* pairing-driver composition argv:'
printf ' %q' "${composition_args[@]}"
printf '\n'
fstar.exe "${composition_args[@]}"

echo "pairing driver: 30 extracted Rust functions (19 selected + 11 private decisions), 30 effect/state postconditions, 24 preconditions"
echo "invitation trace: one destructive redemption per request, a refused/replayed token never completes"
echo "claim trace: at most one guarded claim write, only on a live unclaimed grant with exact key lengths"
echo "completion trace: at most one take and one insert, inserted implies stored claim + active opener + verified signature + matching bindings"
echo "result trace: a returned device is only after the verified result policy accepted a proof under the claimed key"
echo "pairing composition: arbitrary interleavings authorize at most one claim, one take, one insert and one redemption per stored version, never a cross-account, unsigned or already-enrolled completion"
sha256sum "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}" src/pairing_driver.rs
