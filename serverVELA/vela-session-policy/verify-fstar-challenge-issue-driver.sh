#!/usr/bin/env bash
set -euo pipefail

# Focused F-2 increment: the `GET /auth/challenge` issue driver.
#
# The driver reuses the crate's `Vela_session_policy.*` F* module namespace, so
# it is regenerated into `proofs/fstar/extraction-challenge-issue-driver/` and
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

rm -rf proofs/fstar/extraction-challenge-issue-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-challenge-issue-driver \
  -i '-** +vela_session_policy::challenge::byte_or_zero +vela_session_policy::challenge::stored_tag_copies_prefix +vela_session_policy::challenge::stored_tag_from_bytes +vela_session_policy::challenge::purpose_tag_bytes +vela_session_policy::challenge::purpose_stored_tag +vela_session_policy::challenge::classify_stored_tag +vela_session_policy::challenge::classify_consumption +vela_session_policy::challenge::classify_taken_challenge +vela_session_policy::challenge_issue_driver::begin_issue +vela_session_policy::challenge_issue_driver::step +vela_session_policy::challenge_issue_driver::issue_stage_index +vela_session_policy::challenge_issue_driver::on_rate_limit +vela_session_policy::challenge_issue_driver::on_nonce +vela_session_policy::challenge_issue_driver::on_store +vela_session_policy::challenge_issue_driver::on_rate_limit_event +vela_session_policy::challenge_issue_driver::on_nonce_event +vela_session_policy::challenge_issue_driver::on_store_event' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction-challenge-issue-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
lemma_file=proofs/fstar/challenge-issue-driver-lemmas/Vela_session_policy_challenge_issue_driver_lemmas.fst
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused challenge-issue modules" >&2
  exit 1
fi
[[ -f $lemma_file ]] || {
  echo "missing reviewed challenge-issue lemma module" >&2
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
  --include proofs/fstar/extraction-challenge-issue-driver
  --include proofs/fstar/challenge-issue-driver-lemmas
  "${proof_files[@]}" "$lemma_file"
)
printf 'F* challenge-issue-driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "challenge issue driver: exactly one store, for the parsed purpose, only after the limiter and a 32-byte nonce, only when the key was absent; no store after any failure"
sha256sum "${proof_files[@]}" "$lemma_file" src/challenge_issue_driver.rs src/challenge_issue_interpreter.rs
