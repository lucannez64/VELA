#!/usr/bin/env bash
set -euo pipefail

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"

command -v cargo-hax >/dev/null || {
  echo "cargo-hax is missing; follow README.md" >&2
  exit 1
}
command -v driver-hax-frontend-exporter >/dev/null || {
  echo "driver-hax-frontend-exporter is missing; install hax-driver 0.3.7" >&2
  exit 1
}
command -v hax-engine >/dev/null || {
  echo "hax-engine is missing; evaluate opam env and follow README.md" >&2
  exit 1
}
command -v fstar.exe >/dev/null || {
  echo "fstar.exe is missing; evaluate opam env and follow README.md" >&2
  exit 1
}
command -v z3-4.13.3 >/dev/null || {
  echo "z3-4.13.3 is missing; install the F* solver pinned in README.md" >&2
  exit 1
}

cargo test

cargo hax into \
  -i '-** +vela_rekey_policy::next_epoch +vela_rekey_policy::resolve_write_epoch +vela_rekey_policy::plan_start +vela_rekey_policy::authorize_attempt +vela_rekey_policy::authorize_shadow +vela_rekey_policy::plan_commit +vela_rekey_policy::plan_abort +vela_rekey_policy::plan_timeout +vela_rekey_policy::authorize_commit_replay +vela_rekey_policy::plan_active_mutation +vela_rekey_policy::authorize_active_mutation +vela_rekey_policy::stale_permit_authorizes_successor' \
  fstar --z3rlimit 100

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)
if [[ -z "$hax_lib_root" || ! -d "$hax_lib_root" ]]; then
  echo "could not locate hax-lib proof libraries" >&2
  exit 1
fi

mapfile -t proof_files < <(
  find proofs/fstar/extraction -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no F* modules" >&2
  exit 1
fi

fstar.exe \
  --cmi \
  --warn_error -331 \
  --z3rlimit 100 \
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
  --include "$hax_lib_root/proof-libs/fstar/core" \
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives" \
  --include "$hax_lib_root/proofs/fstar/extraction" \
  --include proofs/fstar/extraction \
  "${proof_files[@]}"
