#!/usr/bin/env bash
set -euo pipefail

# Focused F-2 increment: the `POST /account/register` registration driver.
#
# The driver reuses the crate's `Vela_session_policy.*` F* module namespace, so
# it is regenerated into `proofs/fstar/extraction-registration-driver/` and
# checked in its own fstar.exe invocation. Never pass two partial root modules:
# one would shadow the other.
#
# The hand-written lemma module quantifies over every event list and calls the
# extracted `step`; it does not restate the transition logic.

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

rm -rf proofs/fstar/extraction-registration-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-registration-driver \
  -i '-** +vela_session_policy::registration_driver::begin_registration +vela_session_policy::registration_driver::step +vela_session_policy::registration_driver::on_rate_limit +vela_session_policy::registration_driver::on_budget +vela_session_policy::registration_driver::on_transaction +vela_session_policy::registration_driver::on_account_insert +vela_session_policy::registration_driver::on_device_insert +vela_session_policy::registration_driver::on_commit +vela_session_policy::registration_driver::on_token +vela_session_policy::registration_driver::on_track +vela_session_policy::registration_driver::on_rate_limit_event +vela_session_policy::registration_driver::on_budget_event +vela_session_policy::registration_driver::on_transaction_event +vela_session_policy::registration_driver::on_account_insert_event +vela_session_policy::registration_driver::on_device_insert_event +vela_session_policy::registration_driver::on_commit_event +vela_session_policy::registration_driver::on_token_event +vela_session_policy::registration_driver::on_track_event' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction-registration-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
lemma_file=proofs/fstar/registration-driver-lemmas/Vela_session_policy_registration_driver_lemmas.fst
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused registration modules" >&2
  exit 1
fi
[[ -f $lemma_file ]] || {
  echo "missing reviewed registration lemma module" >&2
  exit 1
}

python3 "$proof_root/../../security/formal/check-driver-proof-sources.py" \
  --generated "${proof_files[@]}" \
  --proof "$lemma_file" \
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
  --include proofs/fstar/extraction-registration-driver
  --include proofs/fstar/registration-driver-lemmas
  "${proof_files[@]}" "$lemma_file"
)
printf 'F* registration-driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "registration driver: one account and one first device, or nothing; success needs a started transaction, both inserts observed, a commit, an issued token and a tracked JTI; every failure is terminal and never responds"
sha256sum "${proof_files[@]}" "$lemma_file" src/registration_driver.rs
