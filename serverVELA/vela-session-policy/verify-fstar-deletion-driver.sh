#!/usr/bin/env bash
set -euo pipefail

# Focused F-2/F-3 increment: the account-deletion decision driver.
#
# `proofs/fstar/extraction/` is the historical 21-selection artifact for this
# crate, `proofs/fstar/extraction-login-driver/` the focused login artifact and
# `proofs/fstar/extraction-revocation-driver/` the focused revocation artifact.
# The deletion driver reuses the F* module names `Vela_session_policy.*`, so it
# is regenerated into `proofs/fstar/extraction-deletion-driver/` and checked in
# its own fstar.exe invocation. Never pass two partial root modules: one would
# shadow the other.
#
# The composition also calls the *extracted* middleware admission decision
# (`plan_admission`, `Vela_session_policy.Revocation_driver`) so "a deleted
# account's tokens are never admitted after its lockout" is a statement about
# the real admission driver, not a modelled guard. Only that function is
# selected from the revocation module; the rest of it is owned by
# `verify-fstar-revocation-driver.sh`.
#
# The hand-written per-request lemmas quantify over every event list and call
# the extracted `step`; they do not restate the transition logic. The
# composition module is self-contained over the extracted driver (it does not
# import the lemma module) so the mutation checks fail in the composition
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

rm -rf proofs/fstar/extraction-deletion-driver
cargo hax into \
  --output-dir proofs/fstar/extraction-deletion-driver \
  -i '-** +vela_session_policy::deletion_driver::begin_deletion +vela_session_policy::deletion_driver::step +vela_session_policy::deletion_driver::on_devices_scanned_event +vela_session_policy::deletion_driver::on_device_lockout_event +vela_session_policy::deletion_driver::on_web_sessions_scanned_event +vela_session_policy::deletion_driver::on_web_session_lockout_event +vela_session_policy::deletion_driver::on_transaction_observed_event +vela_session_policy::deletion_driver::on_table_deleted_event +vela_session_policy::deletion_driver::on_users_deleted_event +vela_session_policy::deletion_driver::on_commit_event +vela_session_policy::revocation_driver::plan_admission' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction-deletion-driver -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t lemma_files < <(
  find proofs/fstar/deletion-driver-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t bridge_files < <(
  find proofs/fstar/deletion-driver-bridge -maxdepth 1 -type f -name '*.fst' -print | sort
)
composition_files=(proofs/fstar/deletion-driver-composition/Vela_session_policy_deletion_driver_composition.fst)
if (( ${#bridge_files[@]} != 1 )); then
  echo "expected exactly one reviewed deletion-driver bridge module" >&2
  exit 1
fi
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no focused deletion-driver modules" >&2
  exit 1
fi
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed deletion-driver lemma module" >&2
  exit 1
fi
[[ -f ${composition_files[0]} ]] || {
  echo "missing reviewed deletion-driver composition module" >&2
  exit 1
}

# Enforce the reviewed source policy, including nested comments and exact
# budget-only pragmas. This is a source guard; fstar.exe remains the checker.
python3 "$proof_root/../../security/formal/check-driver-proof-sources.py" \
  --generated "${proof_files[@]}" \
  --proof "${lemma_files[@]}" "${bridge_files[@]}" "${composition_files[@]}" \
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
  --include proofs/fstar/extraction-deletion-driver
  --include proofs/fstar/deletion-driver-lemmas
  --include proofs/fstar/deletion-driver-bridge
  --include proofs/fstar/deletion-driver-composition
  "${proof_files[@]}" "${lemma_files[@]}" "${bridge_files[@]}" "${composition_files[@]}"
)
printf 'F* deletion-driver argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "deletion driver: 11 focused Rust functions, 10 soundness postconditions (9 preconditions)"
echo "per-request trace: device and web-session lockouts before the transaction, all-or-nothing table order, commit only after the users row was deleted, no commit on any failure or absent account"
echo "deletion composition: arbitrary interleavings never authorize a cross-account effect, never commit a second deletion, and never admit a locked-out account's token"
sha256sum "${proof_files[@]}" "${lemma_files[@]}" "${bridge_files[@]}" "${composition_files[@]}" src/deletion_driver.rs
