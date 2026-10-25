#!/usr/bin/env bash
set -euo pipefail

# Focused F-1/F-2 increment: exact challenge-purpose recognition and the
# `/auth/verify` login decision driver.
#
# The historical `proofs/fstar/extraction/` artifact keeps the original 21
# session-policy contracts. The new `challenge` and `login_driver` modules are
# extracted into `proofs/fstar/extraction-login-driver/` in their own
# `cargo hax` run and checked in their own `fstar.exe` invocation. Never pass
# the historical extraction directory to this invocation: the focused partial
# root module would shadow it (or vice versa).
#
# The hand-written challenge lemma module restates exact recognition as literal
# bytes and proves the extracted classifier equals that raw-byte specification.
# The login lemma module quantifies over every event list and calls the actual
# extracted `Vela_session_policy.Login_driver.step`; it does not restate the
# transition logic. No `assume`, `admit`, `axiom`, `--lax` or proof-goal-as-
# hypothesis is used.

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

rm -rf proofs/fstar/extraction-login-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-login-driver \
  -i '-** +vela_session_policy::challenge::purpose_stored_tag +vela_session_policy::challenge::classify_stored_tag +vela_session_policy::challenge::classify_consumption +vela_session_policy::login_driver::begin_login +vela_session_policy::login_driver::step +vela_session_policy::login_driver::on_challenge_taken +vela_session_policy::login_driver::on_device_looked_up +vela_session_policy::login_driver::on_verifier_finished +vela_session_policy::login_driver::on_failure_record_observed +vela_session_policy::login_driver::on_backoff_reset_observed_event +vela_session_policy::login_driver::on_token_issue_observed +vela_session_policy::login_driver::on_token_track_observed' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction-login-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t challenge_lemma_files < <(
  find proofs/fstar/challenge-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t login_lemma_files < <(
  find proofs/fstar/login-driver-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused challenge/login modules" >&2
  exit 1
fi
if (( ${#challenge_lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed challenge lemma module" >&2
  exit 1
fi
if (( ${#login_lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed login-driver lemma module" >&2
  exit 1
fi

# Fail closed on proof escapes in the generated artifact and the lemmas. This
# is a textual guard, not the proof: fstar.exe below is the checker.
escapes=$(grep -nE '(^|[^[:alnum:]_])(assume|admit|axiom)([^[:alnum:]_]|$)|--lax' \
  "${proof_files[@]}" "${challenge_lemma_files[@]}" "${login_lemma_files[@]}" || true)
if [[ -n $escapes ]]; then
  printf '%s\n' "$escapes" >&2
  echo 'proof escape detected in focused challenge/login artifact' >&2
  exit 3
fi

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
  --include proofs/fstar/extraction-login-driver
  --include proofs/fstar/challenge-lemmas
  --include proofs/fstar/login-driver-lemmas
  "${proof_files[@]}" "${challenge_lemma_files[@]}" "${login_lemma_files[@]}"
)
printf 'F* login-driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "login driver proof: 11 focused production entry points checked (3 challenge + 8 login)"
echo "challenge refinement: exact literal-byte recognition for every bounded stored tag"
echo "login trace: one response at most, response implies accepted login + valid verifier + tracked token, failure terminal"
sha256sum "${proof_files[@]}" "${challenge_lemma_files[@]}" "${login_lemma_files[@]}" \
  src/challenge.rs src/login_driver.rs
