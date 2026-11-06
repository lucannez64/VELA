#!/usr/bin/env bash
set -euo pipefail

# Focused F-1/F-2 increment: exact challenge-purpose recognition and the
# `/auth/verify` login decision driver.
#
# The historical `proofs/fstar/extraction/` artifact keeps the original 21 selections / 19
# session-policy postconditions. The new `challenge` and `login_driver` modules are
# extracted into `proofs/fstar/extraction-login-driver/` in their own
# `cargo hax` run and checked in their own `fstar.exe` invocation. Never pass
# the historical extraction directory to this invocation: the focused partial
# root module would shadow it (or vice versa).
#
# The hand-written challenge lemma modules restate exact recognition as literal
# bytes and prove the extracted classifier equals that raw-byte specification.
# The tag-producer module states the raw-slice conversion obligations (length
# preservation, exact copied prefix, composed classifier acceptance) over an
# arbitrary `&[u8]` and proves them against the extracted
# `stored_tag_from_bytes` body. The take-adapter module states the independent
# literal-byte decision over the actual `Option<Vec<u8>>` store value and proves
# the extracted `classify_taken_challenge` adapter equals it, including the
# retained-length and missing-present cases. The login lemma module quantifies
# over every event list and calls the actual extracted
# `Vela_session_policy.Login_driver.step`; it does not restate the transition
# logic. No `assume`, `admit`, `axiom`, `--lax` or proof-goal-as-hypothesis is
# used.

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
  -i '-** +vela_session_policy::challenge::byte_or_zero +vela_session_policy::challenge::stored_tag_copies_prefix +vela_session_policy::challenge::stored_tag_from_bytes +vela_session_policy::challenge::purpose_tag_bytes +vela_session_policy::challenge::purpose_stored_tag +vela_session_policy::challenge::classify_stored_tag +vela_session_policy::challenge::classify_consumption +vela_session_policy::challenge::classify_taken_challenge +vela_session_policy::login_driver::begin_login +vela_session_policy::login_driver::step +vela_session_policy::login_driver::on_challenge_taken +vela_session_policy::login_driver::on_device_looked_up +vela_session_policy::login_driver::on_verifier_finished +vela_session_policy::login_driver::on_failure_record_observed +vela_session_policy::login_driver::on_backoff_reset_observed_event +vela_session_policy::login_driver::on_token_issue_observed +vela_session_policy::login_driver::on_token_track_observed' \
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
mapfile -t take_adapter_lemma_files < <(
  find proofs/fstar/challenge-take-adapter-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
composition_file=proofs/fstar/login-driver-composition/Vela_session_policy_login_driver_composition.fst
[[ -f $composition_file ]] || {
  echo "missing reviewed login composition module" >&2
  exit 1
}

raw_nonce_file=proofs/fstar/login-raw-nonce-lemmas/Vela_session_policy_login_raw_nonce.fst
[[ -f $raw_nonce_file ]] || {
  echo "missing reviewed raw-byte nonce bridge module" >&2
  exit 1
}

store_world_file=proofs/fstar/challenge-store-world-lemmas/Vela_session_policy_challenge_store_world.fst
[[ -f $store_world_file ]] || {
  echo "missing reviewed challenge store-world module" >&2
  exit 1
}

if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused challenge/login modules" >&2
  exit 1
fi
if (( ${#challenge_lemma_files[@]} != 2 )); then
  echo "expected exactly two reviewed challenge lemma modules" >&2
  exit 1
fi
if (( ${#login_lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed login-driver lemma module" >&2
  exit 1
fi
if (( ${#take_adapter_lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed take-adapter lemma module" >&2
  exit 1
fi

# Enforce the same reviewed source policy as the other focused drivers.
# Imported hax libraries remain trusted; fstar.exe is the proof checker.
python3 "$proof_root/../../security/formal/check-driver-proof-sources.py" \
  --generated "${proof_files[@]}" \
  --proof "${challenge_lemma_files[@]}" "${login_lemma_files[@]}" "$composition_file" "$raw_nonce_file" "${take_adapter_lemma_files[@]}" "$store_world_file" \
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
  --include proofs/fstar/extraction-login-driver
  --include proofs/fstar/challenge-lemmas
  --include proofs/fstar/login-driver-lemmas
  --include proofs/fstar/login-driver-composition
  --include proofs/fstar/login-raw-nonce-lemmas
  --include proofs/fstar/challenge-take-adapter-lemmas
  --include proofs/fstar/challenge-store-world-lemmas
  "${proof_files[@]}" "${challenge_lemma_files[@]}" "${login_lemma_files[@]}" "$composition_file" "$raw_nonce_file" "${take_adapter_lemma_files[@]}" "$store_world_file"
)
printf 'F* login-driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "focused proof: 17 selected functions checked (8 challenge/producer/adapter + 9 login), 12 explicit Rust postconditions"
echo "challenge refinement: exact literal-byte recognition for every bounded stored tag"
echo "tag producer: length preserved, min(len,9) prefix exact, acceptance iff raw literal, for every slice"
echo "issued path: purpose_tag_bytes classifies as its own purpose and no other"
echo "login trace: one response at most, response implies accepted login + valid verifier + tracked token, failure terminal"
echo "raw-byte bridge: projection commutes with every action and schedule; modeled takes use the extracted converter and classifier"
echo "take adapter: actual Option<Vec> result yields Missing for None and Accepted iff the exact expected literal, else WrongPurpose; length retained"
echo "store world: the login bounds hold over the store's actual Option<Vec<u8>> value, every take decided by the extracted adapter"
echo "login composition: one nonce admits at most one request, Respond effect and successful issuance observation under the atomic-take interface"
sha256sum "${proof_files[@]}" "${challenge_lemma_files[@]}" "${login_lemma_files[@]}" "$composition_file" "$raw_nonce_file" "${take_adapter_lemma_files[@]}" "$store_world_file" \
  src/challenge.rs src/login_driver.rs ../vela-server/src/auth/challenge.rs
