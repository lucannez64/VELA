#!/usr/bin/env bash
set -euo pipefail

# Mutation checks for proofs/fstar/rekey-driver-composition. Run through
# `vela-heavy ./verify-fstar-rekey-driver-composition-mutations.sh [name]`
# after verify-fstar-rekey-driver.sh (it reuses that gate's extraction).
#
# Each mutant is a copy of the extracted driver under /tmp, with one decision
# removed; the checked-in extraction is never modified. For each mutant:
#   1. the checked-in composition must FAIL to verify against it (the removed
#      decision is load-bearing);
#   2. a small witness module must PASS and show the matching counter becomes
#      positive (the counter is not vacuous).
#
#   starter       the abort/commit starter checks are removed: a non-starter's
#                 abort wins (`w_non_starter_abort`), since `rollback_rekey`
#                 does not check the starter
#   commit-skip   the driver commits on a lost commit CAS: a commit is decided
#                 for an aborted rotation (`w_commit_after_abort`)
#   completeness  a failed device-capsule probe is treated as complete: a
#                 commit is decided without the check passing
#                 (`w_unchecked_commit`)
#   web           the web-session refusal (and the matching clause of the
#                 driver's effect contract) is removed: an executor call is
#                 performed for a web session (`w_web_step`)

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"
want=${1:-all}
should_run() { [[ $want == all || $want == "$1" ]]; }

driver_dir=$proof_root/proofs/fstar/extraction-rekey-driver
root_dir=$proof_root/proofs/fstar/extraction-rekey-driver-root
lemma_dir=$proof_root/proofs/fstar/rekey-driver-lemmas
composition_dir=$proof_root/proofs/fstar/rekey-driver-composition
composition=$composition_dir/Vela_rekey_policy_rekey_driver_composition.fst
mut=/tmp/vela-rekey-composition-mut
summary=$mut/summary.txt

for command_name in fstar.exe z3-4.13.3 jq cargo; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is missing" >&2
    exit 1
  }
done
for f in "$driver_dir/Vela_rekey_policy.Rekey_driver.fst" "$root_dir/Vela_rekey_policy.fst" "$composition"; do
  [[ -f $f ]] || { echo "missing $f (run verify-fstar-rekey-driver.sh first)" >&2; exit 1; }
done

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)
[[ -n $hax_lib_root && -d $hax_lib_root ]] || {
  echo "could not locate hax-lib proof libraries" >&2
  exit 1
}

base_args=(
  --cmi
  --cache_off
  --warn_error -331
  --z3rlimit 100
  --fuel 1
  --ifuel 1
  --split_queries always
  --z3version 4.13.3
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib'
  --include "$hax_lib_root/proof-libs/fstar/core"
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives"
  --include "$hax_lib_root/proofs/fstar/extraction"
  --include "$root_dir"
  --include "$lemma_dir"
  --include "$composition_dir"
)

mkdir -p "$mut"
if [[ $want == all ]]; then : > "$summary"; fi

prepare () {
  local name=$1
  local d=$mut/$name
  rm -rf "$d"
  mkdir -p "$d/driver" "$d/witness"
  cp "$driver_dir"/*.fst "$d/driver/"
  python3 - "$name" "$d/driver/Vela_rekey_policy.Rekey_driver.fst" <<'PY'
import sys, pathlib
name, path = sys.argv[1], pathlib.Path(sys.argv[2])
text = path.read_text()

def patch(old, new, count=1):
    global text
    assert text.count(old) == count, (name, old[:70], text.count(old))
    text = text.replace(old, new)

if name == 'starter':
    patch('''    if ~.driver.f_starter_matches
    then terminal driver (RekeyFailure_StarterRequired <: t_RekeyFailure)''',
          '''    if false
    then terminal driver (RekeyFailure_StarterRequired <: t_RekeyFailure)''')
    patch('Vela_rekey_policy.f_starter_matches = driver.f_starter_matches;',
          'Vela_rekey_policy.f_starter_matches = true;', count=3)
elif name == 'commit-skip':
    patch('''  | CasObservation_Skipped  -> terminal driver (RekeyFailure_ConcurrentCommit <: t_RekeyFailure)''',
          '''  | CasObservation_Skipped  ->
    transition ({
          driver with
          f_stage = RekeyStage_Sweep <: t_RekeyStage;
          f_committed = true;
          f_epoch = driver.f_to_epoch;
          f_active = true
        }
        <:
        t_RekeyDriver)
      (RekeyEffect_SweepOldChunks <: t_RekeyEffect)''')
elif name == 'completeness':
    patch('''  | ProbeObservation_Found  ->
    let decided:t_RekeyDriver = { driver with f_capsules_complete = false } <: t_RekeyDriver in
    terminal decided (RekeyFailure_DeviceCapsulesIncomplete <: t_RekeyFailure)''',
          '''  | ProbeObservation_Found  ->
    commit_plan ({ driver with f_capsules_complete = true } <: t_RekeyDriver)''')
elif name == 'web':
    patch('''    if ~.request.f_device_scope
    then terminal driver (RekeyFailure_WebSessionForbidden <: t_RekeyFailure)''',
          '''    if false
    then terminal driver (RekeyFailure_WebSessionForbidden <: t_RekeyFailure)''')
    # The driver's own contract also forbids pacing a web session; drop that
    # clause too, or the composition still follows from the (now false)
    # postcondition of `begin_*`.
    patch('''      | RekeyStage_RateLimit  -> true
      | _ -> false) &&
    d.f_authenticated &&
    d.f_device_scope
''',
          '''      | RekeyStage_RateLimit  -> true
      | _ -> false) &&
    d.f_authenticated
''')
else:
    raise SystemExit('unknown mutant ' + name)
path.write_text(text)
PY
}

run_fail () {
  local name=$1
  local log=$mut/$name/theorem.log
  if fstar.exe "${base_args[@]}" --include "$mut/$name/driver" "$composition" >"$log" 2>&1; then
    echo "MUTANT $name: composition unexpectedly verified" >&2
    return 1
  fi
  local line
  line=$(grep -m1 -E '^\* Error [0-9]+ at' "$log" || true)
  [[ -n $line ]] || { echo "MUTANT $name: no F* error reported" >&2; tail -20 "$log" >&2; return 1; }
  echo "$name|composition|fails|$line" >> "$summary"
  printf 'MUTANT %s: composition failed as expected: %s\n' "$name" "$line"
}

run_pass () {
  local name=$1
  local witness=$2
  local log=$mut/$name/witness.log
  if ! fstar.exe "${base_args[@]}" --include "$mut/$name/driver" --include "$mut/$name/witness" \
      "$witness" >"$log" 2>&1; then
    echo "MUTANT $name: witness failed to verify" >&2
    tail -20 "$log" >&2
    return 1
  fi
  echo "$name|witness|verified|counter reachable" >> "$summary"
  printf 'MUTANT %s: witness verified, counter reachable\n' "$name"
}

# The witnesses reuse the composition's definitions (`initial`, `steps`,
# `ok_choice`); device 7 starts rotation 0 with ten executor calls.
witness_head () {
  cat <<EOF
module $1
open Core_models
open Vela_rekey_policy.Rekey_driver
open Vela_rekey_policy_rekey_driver_composition
#push-options "--fuel 4 --ifuel 2"

let start0 : list action =
  [Spawn RekeyOp_Start 7 false None None (mk_i64 0)] @ steps 0 10
EOF
}

if should_run starter; then
  prepare starter
  { witness_head Vela_rekey_composition_starter_witness
    cat <<'EOF'
/// Device 8 aborts device 7's rotation.
let w = run_world initial
  (start0 @ [Spawn RekeyOp_Abort 8 false (Some 0) None (mk_i64 0)] @ steps 1 4)

let witness () : Lemma (w.w_non_starter_abort > 0) = assert_norm (w.w_non_starter_abort > 0)
#pop-options
EOF
  } > "$mut/starter/witness/Vela_rekey_composition_starter_witness.fst"
  run_fail starter
  run_pass starter "$mut/starter/witness/Vela_rekey_composition_starter_witness.fst"
fi

if should_run commit-skip; then
  prepare commit-skip
  { witness_head Vela_rekey_composition_commit_skip_witness
    cat <<'EOF'
/// Device 7's commit reaches its CAS (four calls), its abort then wins, and
/// the commit CAS is lost.
let w = run_world initial
  (start0 @
   [Spawn RekeyOp_Commit 7 false (Some 0) None (mk_i64 0)] @ steps 1 4 @
   [Spawn RekeyOp_Abort 7 false (Some 0) None (mk_i64 0)] @ steps 2 3 @
   steps 1 1)

let witness () : Lemma (w.w_commit_after_abort > 0) = assert_norm (w.w_commit_after_abort > 0)
#pop-options
EOF
  } > "$mut/commit-skip/witness/Vela_rekey_composition_commit_skip_witness.fst"
  run_fail commit-skip
  run_pass commit-skip "$mut/commit-skip/witness/Vela_rekey_composition_commit_skip_witness.fst"
fi

if should_run completeness; then
  prepare completeness
  { witness_head Vela_rekey_composition_completeness_witness
    cat <<'EOF'
/// The device-capsule probe reports an incomplete device.
let found : choice = { ok_choice with c_probe = ProbeObservation_Found }

let w = run_world initial
  (start0 @
   [Spawn RekeyOp_Commit 7 false (Some 0) None (mk_i64 0)] @ steps 1 3 @
   [Step 1 found] @ steps 1 1)

let witness () : Lemma (w.w_unchecked_commit > 0) = assert_norm (w.w_unchecked_commit > 0)
#pop-options
EOF
  } > "$mut/completeness/witness/Vela_rekey_composition_completeness_witness.fst"
  run_fail completeness
  run_pass completeness "$mut/completeness/witness/Vela_rekey_composition_completeness_witness.fst"
fi

if should_run web; then
  prepare web
  { witness_head Vela_rekey_composition_web_witness
    cat <<'EOF'
let w = run_world initial
  ([Spawn RekeyOp_Start 9 true None None (mk_i64 0)] @ steps 0 1)

let witness () : Lemma (w.w_web_step > 0) = assert_norm (w.w_web_step > 0)
#pop-options
EOF
  } > "$mut/web/witness/Vela_rekey_composition_web_witness.fst"
  run_fail web
  run_pass web "$mut/web/witness/Vela_rekey_composition_web_witness.fst"
fi

echo "rekey composition mutation summary:"
cat "$summary"
