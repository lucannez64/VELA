#!/usr/bin/env bash
set -euo pipefail

# Focused F-2 increment: the one-off share-link decision driver.
#
# `proofs/fstar/extraction/` is the historical M19 selection artifact for this
# crate. The send driver reuses the F* module name `Vela_share_policy`, so it is
# regenerated into `proofs/fstar/extraction-send-driver/` and checked in a
# separate fstar.exe invocation. Never pass both partial root modules: one
# would shadow the other.
#
# The hand-written per-request lemmas quantify over every event list and call
# the extracted `step`/`begin_*`; they do not restate the transition logic. The
# composition module is self-contained over the extracted driver (it does not
# import the lemma module), so the mutation checks fail in the composition
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

rm -rf proofs/fstar/extraction-send-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-send-driver \
  -i '-** +vela_share_policy::send_driver::begin_create +vela_share_policy::send_driver::begin_fetch +vela_share_policy::send_driver::begin_delete +vela_share_policy::send_driver::step +vela_share_policy::send_driver::on_send_inserted_event +vela_share_policy::send_driver::on_view_consumed_event +vela_share_policy::send_driver::on_send_read_event +vela_share_policy::send_driver::on_send_removed_event +vela_share_policy::send_driver::on_send_deleted_event' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction-send-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t lemma_files < <(
  find proofs/fstar/send-driver-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
composition_files=(proofs/fstar/send-driver-composition/Vela_share_policy_send_driver_composition.fst)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused send-driver modules" >&2
  exit 1
fi
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed send-driver lemma module" >&2
  exit 1
fi
[[ -f ${composition_files[0]} ]] || {
  echo "missing reviewed send-driver composition module" >&2
  exit 1
}

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
  --include proofs/fstar/extraction-send-driver
)

lemma_args=(
  "${common_args[@]}"
  --z3rlimit 16000
  --include proofs/fstar/send-driver-lemmas
  "${proof_files[@]}" "${lemma_files[@]}"
)
composition_args=(
  "${common_args[@]}"
  --z3rlimit 8000
  --include proofs/fstar/send-driver-composition
  "${proof_files[@]}" "${composition_files[@]}"
)
printf 'F* send-driver lemma argv:'
printf ' %q' "${lemma_args[@]}"
printf '\n'
fstar.exe "${lemma_args[@]}"
printf 'F* send-driver composition argv:'
printf ' %q' "${composition_args[@]}"
printf '\n'
fstar.exe "${composition_args[@]}"

echo "share-link driver: create carries only the clamped TTL/view bounds and an owner scope; a fetch delivers at most once and only after a consume; a delete is owner-bound"
echo "share-link composition: arbitrary create/fetch/delete interleavings keep one successful fetch per single-use link, never fetch after delete, and never delete for a non-owner"
sha256sum "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}" src/send_driver.rs
