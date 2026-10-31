#!/usr/bin/env bash
set -euo pipefail

# Focused F-2 increment: recovery-share lifecycle transition driver.
#
# `proofs/fstar/extraction/` is the historical 90-contract artifact for this
# crate; the other focused driver gates reuse the F* module name
# `Vela_recovery_policy`, so this extraction is regenerated into
# `proofs/fstar/extraction-recovery-share-driver/` and checked in its own
# fstar.exe invocation. This focused extraction also pulls in the extracted
# WebAuthn authentication-finish driver and possession-proof driver because the
# composition module below reuses their release decisions directly.
#
# The hand-written per-request and composition lemmas quantify over every event
# list and call the extracted transition functions; they do not restate the
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

rm -rf proofs/fstar/extraction-recovery-share-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-recovery-share-driver \
  -i '-** +vela_recovery_policy::recovery_share_driver::begin_share_lifecycle +vela_recovery_policy::recovery_share_driver::step_share_lifecycle +vela_recovery_policy::recovery_share_driver::share_lifecycle_state_is_sound +vela_recovery_policy::recovery_share_driver::share_lifecycle_effect_is_sound +vela_recovery_policy::webauthn_driver::begin_auth_finish +vela_recovery_policy::webauthn_driver::step_auth_finish +vela_recovery_policy::webauthn_driver::auth_finish_state_is_sound +vela_recovery_policy::possession_driver::begin_proof_recover +vela_recovery_policy::possession_driver::step_proof_recover +vela_recovery_policy::possession_driver::proof_recover_state_is_sound +vela_recovery_policy::possession_driver::proof_recover_effect_releases_share' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction-recovery-share-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t lemma_files < <(
  find proofs/fstar/recovery-share-driver-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t composition_files < <(
  find proofs/fstar/recovery-share-driver-composition -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused recovery-share-driver modules" >&2
  exit 1
fi
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed recovery-share-driver lemma module" >&2
  exit 1
fi
if (( ${#composition_files[@]} != 1 )); then
  echo "expected exactly one reviewed recovery-share-driver composition module" >&2
  exit 1
fi

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
  --z3rlimit 8000
  --z3version 4.13.3
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib'
  --include "$hax_lib_root/proof-libs/fstar/core"
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives"
  --include "$hax_lib_root/proofs/fstar/extraction"
  --include proofs/fstar/extraction-recovery-share-driver
  --include proofs/fstar/recovery-share-driver-lemmas
  --include proofs/fstar/recovery-share-driver-composition
  "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}"
)
printf 'F* recovery-share-driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "recovery-share driver proof: per-request stage/finalize/delete/read theorems over every event list"
echo "recovery-share driver composition: any interleaving of stage, finalize, delete, WebAuthn release and possession keeps one current split and never releases a deleted or superseded share"
sha256sum "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}" src/recovery_share_driver.rs
