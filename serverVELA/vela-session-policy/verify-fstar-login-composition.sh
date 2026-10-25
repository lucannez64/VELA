#!/usr/bin/env bash
set -euo pipefail

# Focused F-1/F-2 increment: concurrent one-challenge login composition.
#
# This script does NOT regenerate either extraction. It reuses the reviewed
# focused extraction (`proofs/fstar/extraction-login-driver/`) and the original
# historical extraction (`proofs/fstar/extraction/Vela_session_policy.fst`),
# and checks the hand-written composition module against the *actual*
# `Vela_session_policy.Login_driver.step`. The historical extraction is never
# passed to fstar.exe here: the focused partial root module would shadow it (or
# vice versa). Its bytes are hashed before and after the run and must not move.
#
# The composition is one nonce shared by an arbitrary number of requests. It
# models the atomic `get_del` take as an interface. It proves at most one
# admitted request, at most one `Respond` effect and at most one successful
# token issuance per nonce, plus purpose isolation for a non-login nonce.
# Sled/SQL/crypto/OS refinement is explicitly outside the module.
#
# The shared source policy is enforced with security/formal/
# check-driver-proof-sources.py. Every local F* source directory used here,
# including the verifier cwd, is enumerated, and only the reviewed budget
# pragmas are accepted. No `assume`, `admit`, `axiom`, `--lax` or proof-goal-
# as-hypothesis is used.

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

# Historical and focused extraction are inputs, not outputs. Refuse to move
# either one byte.
historical_before=$(sha256sum proofs/fstar/extraction/Vela_session_policy.fst)
focused_before=$(sha256sum proofs/fstar/extraction-login-driver/*.fst)
printf 'historical extraction before: %s\n' "$historical_before"

# Every local F* directory that participates in source resolution, including
# the verifier cwd. `proofs/fstar/extraction` is deliberately absent from the
# fstar invocation (the focused partial root would shadow the historical
# module) and is only hash-guarded above.
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
if (( ${#generated_files[@]} != 2 )); then
  echo "expected the two focused challenge/login extraction modules" >&2
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
if (( ${#composition_files[@]} != 1 )); then
  echo "expected exactly one reviewed login-composition module" >&2
  exit 1
fi

# Enforce the reviewed source policy, including nested comments and exact
# budget-only pragmas. This is a source guard; fstar.exe remains the checker.
python3 "$proof_root/../../security/formal/check-driver-proof-sources.py" \
  --generated "${generated_files[@]}" \
  --proof "${challenge_lemma_files[@]}" "${login_lemma_files[@]}" "${composition_files[@]}" \
  --include-dir "$proof_root" \
  --include-dir proofs/fstar/extraction-login-driver \
  --include-dir proofs/fstar/challenge-lemmas \
  --include-dir proofs/fstar/login-driver-lemmas \
  --include-dir proofs/fstar/login-driver-composition

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
  "${generated_files[@]}" "${challenge_lemma_files[@]}" "${login_lemma_files[@]}" "${composition_files[@]}"
)
printf 'F* login-composition argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

historical_after=$(sha256sum proofs/fstar/extraction/Vela_session_policy.fst)
focused_after=$(sha256sum proofs/fstar/extraction-login-driver/*.fst)
[[ $historical_before == "$historical_after" ]] || {
  echo 'historical extraction changed during the proof run' >&2
  exit 1
}
[[ $focused_before == "$focused_after" ]] || {
  echo 'focused extraction changed during the proof run' >&2
  exit 1
}
printf 'historical extraction after:  %s\n' "$historical_after"

echo "login composition: 0 new Rust postconditions; the two extracted modules are inputs and are byte-identical"
echo "login composition: one nonce admits at most one request, one Respond effect and one successful token issuance"
echo "login composition: an absent or non-login nonce never admits a request, responds or issues a token"
sha256sum "${generated_files[@]}" "${challenge_lemma_files[@]}" "${login_lemma_files[@]}" "${composition_files[@]}" \
  src/challenge.rs src/login_driver.rs
