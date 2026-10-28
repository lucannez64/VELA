#!/usr/bin/env bash
set -euo pipefail

# F-2 web-session decision drivers: start, grant, token exchange and delete.
#
# The four drivers reuse the `Vela_session_policy.*` module names, so this gate
# regenerates them into `proofs/fstar/extraction-websession-driver/` and checks
# them in their own fstar.exe invocation. The driver lemmas quantify over every
# event list and call the extracted `*_step`; they do not restate the transition
# logic. Concurrent composition over the shared store is the remaining F-2 obligation
# for this increment; see the evidence README.
#
# The drivers call the verified policy functions `plan_observed_grant`,
# `plan_observed_web_token` and `clamp_web_ttl`; hax extracts them as
# dependencies, so the per-request statements are about the real policy.

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

cargo test --lib websession

rm -rf proofs/fstar/extraction-websession-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-websession-driver \
  -i '-** +vela_session_policy::websession_driver::begin_start +vela_session_policy::websession_driver::start_step +vela_session_policy::websession_driver::begin_grant +vela_session_policy::websession_driver::grant_step +vela_session_policy::websession_driver::begin_token +vela_session_policy::websession_driver::token_step +vela_session_policy::websession_driver::begin_delete +vela_session_policy::websession_driver::delete_step' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction-websession-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t lemma_files < <(
  find proofs/fstar/websession-driver-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused web-session driver modules" >&2
  exit 1
fi
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed web-session driver lemma module" >&2
  exit 1
fi

python3 "$proof_root/../../security/formal/check-driver-proof-sources.py" \
  --generated "${proof_files[@]}" \
  --proof "${lemma_files[@]}" \
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
  --include proofs/fstar/extraction-websession-driver
  --include proofs/fstar/websession-driver-lemmas
  "${proof_files[@]}" "${lemma_files[@]}"
)
printf 'F* web-session-driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "web-session drivers: start, grant, token exchange and delete"
echo "per-request: pending-only start, checked grant plan + clamped TTL, checked token plan after a purpose-bound single-use challenge and one claim, owner-only delete"
echo "traces: soundness over every event list, at most one success/failure (and one token issue) per request"
sha256sum "${proof_files[@]}" "${lemma_files[@]}" src/websession_driver.rs
