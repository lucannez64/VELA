#!/usr/bin/env bash
set -euo pipefail

# Focused F-2 increment: the vault key-rotation decision drivers.
#
# `proofs/fstar/extraction/` is the historical 12-contract artifact for this
# crate and `extraction-vault-upload-driver/` the chunk upload/read increment.
# The rotation driver reuses the F* module name `Vela_rekey_policy`, so it is
# regenerated into `proofs/fstar/extraction-rekey-driver/` and checked in its
# own fstar.exe invocation. Never pass two partial root modules: one would
# shadow the other.
#
# The hand-written per-request lemmas quantify over every event list and call
# the extracted `rekey_step`; they do not restate the transition logic. The
# composition module is self-contained over the extracted driver so the
# mutation checks fail in the composition theorem, not in an unrelated lemma.

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

rm -rf proofs/fstar/extraction-rekey-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-rekey-driver \
  -i '-** +vela_rekey_policy::rekey_driver::begin_start +vela_rekey_policy::rekey_driver::begin_capsules +vela_rekey_policy::rekey_driver::begin_commit +vela_rekey_policy::rekey_driver::begin_abort +vela_rekey_policy::rekey_driver::rekey_step +vela_rekey_policy::rekey_driver::commit_replay +vela_rekey_policy::plan_start +vela_rekey_policy::plan_commit +vela_rekey_policy::plan_abort +vela_rekey_policy::plan_timeout +vela_rekey_policy::authorize_attempt +vela_rekey_policy::authorize_commit_replay +vela_rekey_policy::next_epoch' \
  fstar --z3rlimit 500

# The root module carries the extracted policy decisions this driver calls.
# Keep it in a separate include directory; the source guard checks only the new
# driver module and the hand-written proofs.
mkdir -p proofs/fstar/extraction-rekey-driver-root
rm -f proofs/fstar/extraction-rekey-driver-root/*.fst
mv proofs/fstar/extraction-rekey-driver/Vela_rekey_policy.fst \
  proofs/fstar/extraction-rekey-driver-root/
# Newer hax emits unused derived-trait instance assumptions for the focused
# types; the checked-in upload extraction predates them. Strip only those
# reviewed generated blocks before the source guard.
python3 "$proof_root/strip-hax-instances.py" proofs/fstar/extraction-rekey-driver/*.fst

mapfile -t proof_files < <(
  find proofs/fstar/extraction-rekey-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t lemma_files < <(
  find proofs/fstar/rekey-driver-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t composition_files < <(
  find proofs/fstar/rekey-driver-composition -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused rekey-driver modules" >&2
  exit 1
fi
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed rekey-driver lemma module" >&2
  exit 1
fi
if (( ${#composition_files[@]} != 1 )); then
  echo "expected exactly one reviewed rekey-driver composition module" >&2
  exit 1
fi

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
  --include proofs/fstar/extraction-rekey-driver-root
  --include proofs/fstar/extraction-rekey-driver
  --include proofs/fstar/rekey-driver-lemmas
  --include proofs/fstar/rekey-driver-composition
  "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}"
)
printf 'F* rekey-driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "rekey driver: focused Rust decision functions with soundness postconditions (four entry points, one transition relation)"
echo "per-request trace: at most one commit, commit only after both completeness observations and starter/rotation authority, abort/timeout restore the active state at the same epoch, web sessions never start or commit"
echo "rekey composition: arbitrary interleavings never commit two rotations for one rotation id, never commit after an abort, and never run two rotations at once"
sha256sum "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}" src/rekey_driver.rs
