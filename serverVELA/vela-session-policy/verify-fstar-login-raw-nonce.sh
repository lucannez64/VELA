#!/usr/bin/env bash
set -euo pipefail

# Standalone F* check for the raw-byte nonce bridge.
#
# This script does NOT regenerate any extraction.  It reuses the reviewed
# focused extraction (`proofs/fstar/extraction-login-driver/`), the reviewed
# challenge/producer lemma modules, the reviewed login-driver lemma module, and
# the reviewed abstract composition module, and checks the new hand-written raw
# nonce module against the *actual* extracted
# `Vela_session_policy.Login_driver.step`, `stored_tag_from_bytes` and
# `classify_consumption`.
#
# The new module keeps the stored nonce as `option (t_Slice u8)`, computes the
# take decision with the actual extracted conversion/classifier, projects the
# raw world to the existing abstract composition world, proves that projection
# commutes with every action and every schedule, and transports the
# at-most-one-admission/response/issuance bounds and the non-login refusal
# across the projection.  It adds zero Rust postconditions and does not edit
# the existing extracted or proof modules.
#
# The shared source policy is enforced with security/formal/
# check-driver-proof-sources.py.  Every local F* source directory used here,
# including the verifier cwd, is enumerated, and only the reviewed budget
# pragmas are accepted.  No `assume`, `admit`, `axiom`, `--lax`, `opaque`,
# local `val`, or proof-goal-as-hypothesis is used.
#
# All heavy execution must go through ~/.local/opt/vela-tools/bin/vela-heavy
# (3 GiB / no swap / one job / global lock).  Invoke this script as:
#
#   ~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-login-raw-nonce.sh

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"

# Prefer the pinned prebuilt F*, falling back to the persistent installation
# with the same version if /tmp was cleaned.
if ! command -v fstar.exe >/dev/null 2>&1; then
  persistent_fstar=$HOME/.local/opt/vela-formal-fstar-2025.10.06/fstar/bin
  if [[ -x $persistent_fstar/fstar.exe ]]; then
    export PATH=$persistent_fstar:$PATH
  fi
fi

for command_name in fstar.exe z3-4.13.3 jq python3 cargo cargo-hax; do
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
z3_version=$(z3-4.13.3 --version)
printf '%s\n' "$z3_version"
[[ $z3_version == *'Z3 version 4.13.3'* ]] || {
  echo 'unexpected Z3 version' >&2
  exit 2
}
printf 'rustc: '
rustc --version
printf 'cargo hax: '
cargo hax --version | tr '\n' ' '
printf '\n'
hax_version=$(cargo hax --version)
[[ $hax_version == *'version=0.3.7'* ]] || {
  echo 'unexpected hax version' >&2
  exit 2
}

# Inputs, not outputs.  Refuse to move either extraction or any reviewed proof
# module one byte.
input_files=(
  proofs/fstar/extraction/Vela_session_policy.fst
  proofs/fstar/extraction-login-driver/Vela_session_policy.Challenge.fst
  proofs/fstar/extraction-login-driver/Vela_session_policy.Login_driver.fst
  proofs/fstar/challenge-lemmas/Vela_session_policy_challenge_lemmas.fst
  proofs/fstar/challenge-lemmas/Vela_session_policy_tag_producer_lemmas.fst
  proofs/fstar/login-driver-lemmas/Vela_session_policy_login_driver_lemmas.fst
  proofs/fstar/login-driver-composition/Vela_session_policy_login_driver_composition.fst
  proofs/fstar/login-raw-nonce-lemmas/Vela_session_policy_login_raw_nonce.fst
)
for input_file in "${input_files[@]}"; do
  [[ -f $input_file ]] || {
    echo "missing proof input: $input_file" >&2
    exit 1
  }
done
before_hashes=$(sha256sum "${input_files[@]}")
printf 'proof inputs before:\n%s\n' "$before_hashes"

# Every local F* directory that participates in source resolution, including
# the verifier cwd, is enumerated by the shared source guard below.  The
# historical extraction (`proofs/fstar/extraction`) has unreviewed generated
# budget options that the shared guard intentionally rejects, and it does not
# participate in this F* resolution path (the focused partial root modules
# would shadow it), so it is hash-guarded above and below instead.  Every
# directory that *is* in the resolution path is enumerated.
mapfile -t generated_files < <(
  find proofs/fstar/extraction-login-driver -maxdepth 1 -type f \
    \( -name '*.fst' -o -name '*.fsti' \) -print | sort
)
mapfile -t challenge_lemma_files < <(
  find proofs/fstar/challenge-lemmas -maxdepth 1 -type f \
    \( -name '*.fst' -o -name '*.fsti' \) -print | sort
)
mapfile -t login_lemma_files < <(
  find proofs/fstar/login-driver-lemmas -maxdepth 1 -type f \
    \( -name '*.fst' -o -name '*.fsti' \) -print | sort
)
mapfile -t composition_files < <(
  find proofs/fstar/login-driver-composition -maxdepth 1 -type f \
    \( -name '*.fst' -o -name '*.fsti' \) -print | sort
)
mapfile -t raw_nonce_files < <(
  find proofs/fstar/login-raw-nonce-lemmas -maxdepth 1 -type f \
    \( -name '*.fst' -o -name '*.fsti' \) -print | sort
)
if (( ${#generated_files[@]} != 2 )); then
  echo "expected the two focused challenge/login extraction modules" >&2
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
if (( ${#composition_files[@]} != 1 )); then
  echo "expected exactly one reviewed login-composition module" >&2
  exit 1
fi
if (( ${#raw_nonce_files[@]} != 1 )); then
  echo "expected exactly one reviewed raw-nonce module" >&2
  exit 1
fi

# Enforce the reviewed source policy, including nested comments and exact
# budget-only pragmas.  This is a source guard; fstar.exe remains the checker.
python3 "$proof_root/../../security/formal/check-driver-proof-sources.py" \
  --generated "${generated_files[@]}" \
  --proof "${challenge_lemma_files[@]}" "${login_lemma_files[@]}" \
          "${composition_files[@]}" "${raw_nonce_files[@]}" \
  --include-dir "$proof_root" \
  --include-dir proofs/fstar/extraction-login-driver \
  --include-dir proofs/fstar/challenge-lemmas \
  --include-dir proofs/fstar/login-driver-lemmas \
  --include-dir proofs/fstar/login-driver-composition \
  --include-dir proofs/fstar/login-raw-nonce-lemmas

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
  "${generated_files[@]}" "${challenge_lemma_files[@]}" \
  "${login_lemma_files[@]}" "${composition_files[@]}" \
  "${raw_nonce_files[@]}"
)
printf 'F* login-raw-nonce argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

after_hashes=$(sha256sum "${input_files[@]}")
[[ $before_hashes == "$after_hashes" ]] || {
  echo 'a proof input changed during the raw-nonce run' >&2
  exit 1
}
printf 'proof inputs after:\n%s\n' "$after_hashes"

echo "login raw nonce: 0 new Rust postconditions; all extraction and proof modules are inputs and byte-identical"
echo "login raw nonce: the actual stored_tag_from_bytes/classify_consumption decision drives Take"
echo "login raw nonce: projection to the abstract composition commutes with every action and schedule"
echo "login raw nonce: one raw nonce admits at most one request, one Respond effect and one successful token issuance"
echo "login raw nonce: a raw value the actual classifier does not accept for login never admits, responds or issues"
sha256sum "${generated_files[@]}" "${challenge_lemma_files[@]}" \
  "${login_lemma_files[@]}" "${composition_files[@]}" \
  "${raw_nonce_files[@]}" src/challenge.rs src/login_driver.rs
