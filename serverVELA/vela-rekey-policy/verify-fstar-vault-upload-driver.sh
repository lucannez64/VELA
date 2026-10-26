#!/usr/bin/env bash
set -euo pipefail

# Focused F-2/F-3 increment: the vault chunk upload and read decision drivers.
#
# `proofs/fstar/extraction/` is the historical 12-contract artifact for this
# crate. The upload driver reuses the F* module name `Vela_rekey_policy`, so it
# is regenerated into `proofs/fstar/extraction-vault-upload-driver/` and checked
# in a separate fstar.exe invocation. Never pass both partial root modules: one
# would shadow the other.
#
# The hand-written per-request lemmas quantify over every event list and call
# the extracted `upload_step`/`read_step`; they do not restate the transition
# logic. The composition module is self-contained over the extracted driver and
# the extracted epoch guards, so the mutation checks fail in the composition
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

rm -rf proofs/fstar/extraction-vault-upload-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-vault-upload-driver \
  -i '-** +vela_rekey_policy::vault_upload_driver::begin_upload +vela_rekey_policy::vault_upload_driver::upload_step +vela_rekey_policy::vault_upload_driver::on_rekey_observed +vela_rekey_policy::vault_upload_driver::on_attempt_observed +vela_rekey_policy::vault_upload_driver::on_quota_observed +vela_rekey_policy::vault_upload_driver::on_write_observed +vela_rekey_policy::vault_upload_driver::on_recheck_observed +vela_rekey_policy::vault_upload_driver::on_reread_observed +vela_rekey_policy::vault_upload_driver::on_activity_observed +vela_rekey_policy::vault_upload_driver::on_published_observed +vela_rekey_policy::vault_upload_driver::begin_read +vela_rekey_policy::vault_upload_driver::read_step +vela_rekey_policy::vault_upload_driver::on_read_epoch +vela_rekey_policy::vault_upload_driver::on_read_lookup +vela_rekey_policy::resolve_write_epoch +vela_rekey_policy::authorize_shadow +vela_rekey_policy::plan_active_mutation +vela_rekey_policy::authorize_active_mutation +vela_rekey_policy::next_epoch' \
  fstar --z3rlimit 500

# The root module is the historical policy artifact, regenerated as a
# dependency. It carries hax's `PartialEq` instance assumption for `Phase`,
# which the focused source guard intentionally rejects. Keep it in a separate
# include directory; its contracts are covered by
# security/assurance/check-proof-boundary.py, while the guard below checks only
# the new driver module and the hand-written proofs.
# Keep the directory's .gitignore; replace only the generated module.
mkdir -p proofs/fstar/extraction-vault-upload-driver-root
rm -f proofs/fstar/extraction-vault-upload-driver-root/*.fst
mv proofs/fstar/extraction-vault-upload-driver/Vela_rekey_policy.fst \
  proofs/fstar/extraction-vault-upload-driver-root/

mapfile -t proof_files < <(
  find proofs/fstar/extraction-vault-upload-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t lemma_files < <(
  find proofs/fstar/vault-upload-driver-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t composition_files < <(
  find proofs/fstar/vault-upload-driver-composition -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused vault-upload-driver modules" >&2
  exit 1
fi
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed vault-upload-driver lemma module" >&2
  exit 1
fi
if (( ${#composition_files[@]} != 1 )); then
  echo "expected exactly one reviewed vault-upload-driver composition module" >&2
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
  --z3rlimit 16000
  --z3version 4.13.3
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib'
  --include "$hax_lib_root/proof-libs/fstar/core"
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives"
  --include "$hax_lib_root/proofs/fstar/extraction"
  --include proofs/fstar/extraction-vault-upload-driver-root
  --include proofs/fstar/extraction-vault-upload-driver
  --include proofs/fstar/vault-upload-driver-lemmas
  --include proofs/fstar/vault-upload-driver-composition
  "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}"
)
printf 'F* vault-upload-driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "vault upload driver: 14 focused Rust functions, 2 soundness postconditions"
echo "per-request trace: every active write follows an ACTIVE non-rotation route; shadow writes require the starting device; success implies a matched guarded write; at most one success/failure"
echo "read trace: only a current-epoch, same-account row is served"
echo "upload composition: arbitrary interleavings never authorize a stale active write or a web-session shadow write, and the extracted epoch guards reject stale commits and non-device shadow writers"
sha256sum proofs/fstar/extraction-vault-upload-driver-root/Vela_rekey_policy.fst \
  "${proof_files[@]}" "${lemma_files[@]}" "${composition_files[@]}" src/vault_upload_driver.rs
