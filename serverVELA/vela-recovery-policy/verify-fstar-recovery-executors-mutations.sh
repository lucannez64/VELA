#!/usr/bin/env bash
set -euo pipefail

# Mutation checks for the F-1 recovered-device-enrollment proofs. Run after
# verify-fstar-recovery-executors.sh (it reuses that gate's extraction); that
# gate calls this script last.
#
# Each mutant is a copy of the extracted `Vela_recovery_policy.Redemption_store`
# under /tmp with one change, equal to a one-line change in
# `src/redemption_store.rs`; the checked-in extraction is never modified. The
# checked-in lemma module must FAIL against every mutant, and the named theorem
# must be among those that fail.
#
#   classify-match     classify_take reports a match for any consumed grant
#   classify-error     classify_insert maps a failed insert to Inserted
#   classify-rows      classify_insert maps a zero-row insert to Inserted
#   classify-authority classify_authority maps a missing commitment to StillRotating
#   plan-guard         plan_insert_device always uses the commitment guard
#   plan-epoch         plan_insert_device writes a fixed epoch

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"
want=${1:-all}

store=$proof_root/proofs/fstar/extraction-redemption/Vela_recovery_policy.Redemption_store.fst
model_dir=$proof_root/proofs/fstar/redemption-lemmas
lemmas=$model_dir/Vela_recovery_policy_redemption_lemmas.fst
mut=/tmp/vela-recovery-executor-mut
[[ -f $store && -f $lemmas ]] || { echo "run verify-fstar-recovery-executors.sh first" >&2; exit 1; }

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)

mutants=(classify-match classify-error classify-rows classify-authority plan-guard plan-epoch)
declare -A expect=(
  [classify-match]=take_grant_is_honest
  [classify-error]=insert_device_is_honest
  [classify-rows]=insert_device_is_honest
  [classify-authority]=authority_observation_is_honest
  [plan-guard]=insert_device_is_honest
  [plan-epoch]=insert_device_is_honest
)

rm -rf "$mut"
failures=0
for name in "${mutants[@]}"; do
  [[ $want == all || $want == "$name" ]] || continue
  d=$mut/$name
  mkdir -p "$d/store" "$d/lemmas"
  cp "$store" "$d/store/"
  cp "$model_dir"/*.fst "$d/lemmas/"
  python3 - "$name" "$d/store/Vela_recovery_policy.Redemption_store.fst" <<'PY'
import sys, pathlib
name, path = sys.argv[1], pathlib.Path(sys.argv[2])
text = path.read_text()
def once(old, new):
    global text
    if text.count(old) != 1:
        sys.exit(f'{name}: expected exactly one match for {old!r}, found {text.count(old)}')
    text = text.replace(old, new)
if name == 'classify-match':
    once('''        grant.f_key_epoch =. preflight.f_key_epoch && grant.f_possession =. preflight.f_possession &&
        grant.f_credential_id =. preflight.f_credential_id''',
         '''        true''')
elif name == 'classify-error':
    once('''    | WriteOutcome_Failed  ->
      Vela_recovery_policy.Driver.InsertObservation_Failed''',
         '''    | WriteOutcome_Failed  ->
      Vela_recovery_policy.Driver.InsertObservation_Inserted''')
elif name == 'classify-rows':
    start = text.index('let classify_insert')
    end = text.index('/// The live authority recheck')
    body = text[start:end]
    old = '''      if rows >. mk_u64 0
      then
        Vela_recovery_policy.Driver.InsertObservation_Inserted
        <:
        Vela_recovery_policy.Driver.t_InsertObservation
      else
        Vela_recovery_policy.Driver.InsertObservation_Skipped
        <:
        Vela_recovery_policy.Driver.t_InsertObservation'''
    if body.count(old) != 1:
        sys.exit(f'{name}: classify_insert shape changed')
    body2 = body.replace(old, '''      Vela_recovery_policy.Driver.InsertObservation_Inserted
      <:
      Vela_recovery_policy.Driver.t_InsertObservation''')
    text = text[:start] + body2 + text[end:]
elif name == 'classify-authority':
    once('''      | Core_models.Option.Option_None  ->
        Vela_recovery_policy.Driver.AuthorityRecheckObservation_CommitmentRevoked''',
         '''      | Core_models.Option.Option_None  ->
        Vela_recovery_policy.Driver.AuthorityRecheckObservation_StillRotating''')
elif name == 'plan-guard':
    start = text.index('let plan_insert_device')
    end = text.index('/// `recheck_authority`')
    body = text[start:end]
    old = 'f_guard = guard'
    if body.count(old) != 1:
        sys.exit(f'{name}: guard field not found')
    text = text[:start] + body.replace(old, 'f_guard = GrantGuard_Commitment') + text[end:]
elif name == 'plan-epoch':
    start = text.index('let plan_insert_device')
    end = text.index('/// `recheck_authority`')
    body = text[start:end]
    old = 'f_epoch = epoch'
    if body.count(old) != 1:
        sys.exit(f'{name}: epoch field not found')
    text = text[:start] + body.replace(old, 'f_epoch = mk_i64 1') + text[end:]
path.write_text(text)
PY
  set +e
  out=$(fstar.exe --cmi --cache_off --warn_error -331 --z3rlimit 200 --z3version 4.13.3 \
    --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
    --include "$hax_lib_root/proof-libs/fstar/core" \
    --include "$hax_lib_root/proof-libs/fstar/rust_primitives" \
    --include "$hax_lib_root/proofs/fstar/extraction" \
    --include "$proof_root/proofs/fstar/extraction-driver" \
    --include "$d/store" --include "$d/lemmas" \
    "$d/lemmas/Vela_recovery_policy_redemption_lemmas.fst" 2>&1)
  status=$?
  set -e
  if (( status == 0 )); then
    echo "mutant $name: VERIFIED (the proof does not depend on it)" >&2
    failures=$((failures + 1))
    continue
  fi
  # Every theorem with an error; the expected one must be among them.
  rejected=$(grep -oE 'Vela_recovery_policy_redemption_lemmas\.fst\(([0-9]+),' <<<"$out" | grep -oE '[0-9]+' | sort -un |
    while read -r line; do head -n "$line" "$lemmas" | grep -oE '^let [a-z_0-9]+' | tail -n1 | cut -d' ' -f2; done | sort -u | tr '\n' ' ')
  if [[ " $rejected " != *" ${expect[$name]} "* ]]; then
    echo "mutant $name: rejected at [${rejected% }], expected ${expect[$name]}:" >&2
    grep -m5 -E 'Error' <<<"$out" >&2 || true
    failures=$((failures + 1))
    continue
  fi
  echo "mutant $name: rejected at ${rejected% }"
done
(( failures == 0 )) || { echo "$failures mutation check(s) failed" >&2; exit 1; }
echo "recovery executor mutations: every mutant rejected at its theorem"
