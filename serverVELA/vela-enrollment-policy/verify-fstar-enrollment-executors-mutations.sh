#!/usr/bin/env bash
set -euo pipefail

# Mutation checks for the F-1 enrollment-executor proofs. Run after
# verify-fstar-enrollment-executors.sh (it reuses that gate's extraction); that
# gate calls this script last.
#
# Each mutant is a copy of the extracted `Vela_enrollment_policy.Executor`
# under /tmp with one change, equal to a one-line change in `src/executor.rs`;
# the checked-in extraction is never modified. The checked-in lemma module must
# FAIL against every mutant, and the named theorem must be among those that
# fail.
#
#   classify-error       classify_store maps a failed write to Stored
#   classify-claim-write a guard-missing claim write is classified Inserted
#   classify-skip        a zero-row completion insert is classified Inserted
#   classify-take        a present ceremony take is classified Missing
#   classify-device      a missing enrollment device is classified Verified
#   plan-drop            the completion preflight drops the opener read
#   plan-swap            store_grant swaps the user and opener in the record
#   account-classify     the account preflight always reports a successful query
#   grant-exists         a missing grant is reported live
#   grant-read-binding   the grant read compares the device id with the user
#   claim-inspect        a stored claim is reported absent
#   restore-classify     a failed ceremony restore is reported Stored
#   rate-classify        a limited counter is reported Admitted
#   rate-plan-key        the counter is incremented at the empty key

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"
want=${1:-all}

executor=$proof_root/proofs/fstar/extraction-executor/Vela_enrollment_policy.Executor.fst
lemmas_dir=$proof_root/proofs/fstar/executor-lemmas
lemmas=$lemmas_dir/Vela_enrollment_policy_executor_lemmas.fst
mut=$(mktemp -d "${TMPDIR:-/tmp}/vela-enroll-executor-mut.XXXXXX")
# A fresh directory per run: CI runners and local runs share the build box.
trap 'rm -rf "$mut"' EXIT
[[ -f $executor && -f $lemmas ]] || {
  echo "run verify-fstar-enrollment-executors.sh first" >&2
  exit 1
}

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)

mutants=(
  classify-error classify-claim-write classify-skip classify-take
  classify-device plan-drop plan-swap account-classify
  grant-exists grant-read-binding claim-inspect restore-classify
  rate-classify rate-plan-key
)
declare -A expect=(
  [classify-error]=store_package_is_honest
  [classify-claim-write]=claim_write_is_honest
  [classify-skip]=completion_insert_is_honest
  [classify-take]=take_ceremony_is_honest
  [classify-device]=active_device_is_honest
  [plan-drop]=completion_preflight_is_honest
  [plan-swap]=store_grant_is_honest
  [account-classify]=account_read_is_honest
  [grant-exists]=grant_exists_is_honest
  [grant-read-binding]=grant_read_is_honest
  [claim-inspect]=claim_inspection_is_honest
  [restore-classify]=ceremony_restore_is_honest
  [rate-classify]=rate_limit_is_honest
  [rate-plan-key]=rate_limit_is_honest
)

failures=0
for name in "${mutants[@]}"; do
  [[ $want == all || $want == "$name" ]] || continue
  d=$mut/$name
  mkdir -p "$d/executor" "$d/lemmas"
  cp "$executor" "$d/executor/"
  cp "$lemmas_dir"/*.fst "$d/lemmas/"
  python3 - "$name" "$d/executor/Vela_enrollment_policy.Executor.fst" <<'PY'
import sys, pathlib, re
name, path = sys.argv[1], pathlib.Path(sys.argv[2])
text = path.read_text()

def once(old, new):
    global text
    if text.count(old) != 1:
        sys.exit(f'{name}: expected exactly one match for {old!r}, found {text.count(old)}')
    text = text.replace(old, new)

def body(start_marker, end_marker):
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    return start, end

if name == 'classify-error':
    start, end = body('let classify_store', '/// The destructive package read')
    segment = text[start:end]
    old = 'Vela_enrollment_policy.Pairing_driver.StoreObservation_Failed'
    if segment.count(old) < 1:
        sys.exit(f'{name}: classify_store shape changed')
    text = text[:start] + segment.replace(
        old, 'Vela_enrollment_policy.Pairing_driver.StoreObservation_Stored') + text[end:]
elif name == 'classify-claim-write':
    start, end = body('let classify_claim_write', '/// The account preflight')
    segment = text[start:end]
    old = 'Vela_enrollment_policy.Pairing_driver.ClaimWriteObservation_GuardMissing'
    if segment.count(old) < 1:
        sys.exit(f'{name}: classify_claim_write shape changed')
    text = text[:start] + segment.replace(
        old, 'Vela_enrollment_policy.Pairing_driver.ClaimWriteObservation_Inserted') + text[end:]
elif name == 'classify-skip':
    start, end = body('let classify_insert_completion', '/// The enrollment insert.')
    segment = text[start:end]
    old = 'Vela_enrollment_policy.Pairing_driver.DeviceInsertObservation_Skipped'
    if segment.count(old) < 1:
        sys.exit(f'{name}: classify_insert_completion shape changed')
    text = text[:start] + segment.replace(
        old, 'Vela_enrollment_policy.Pairing_driver.DeviceInsertObservation_Inserted') + text[end:]
elif name == 'classify-take':
    start, end = body('let classify_take_ceremony', '/// The completion insert.')
    segment = text[start:end]
    pattern = re.compile(
        r'\| TakeOutcome_Present  ->.*?\n    \| _ ->', re.S)
    replaced, count = pattern.subn(
        '| TakeOutcome_Present  ->\n'
        '      Vela_enrollment_policy.Pairing_driver.TakeObservation_Missing\n'
        '      <:\n'
        '      Vela_enrollment_policy.Pairing_driver.t_TakeObservation\n'
        '    | _ ->', segment)
    if count != 1:
        sys.exit(f'{name}: TakeOutcome_Present arm not found')
    text = text[:start] + replaced + text[end:]
elif name == 'classify-device':
    start = text.index('let classify_device_check')
    end = len(text)
    segment = text[start:end]
    old = 'Vela_enrollment_policy.Enroll_driver.DeviceObservation_Unavailable'
    if segment.count(old) < 1:
        sys.exit(f'{name}: classify_device_check shape changed')
    text = text[:start] + segment.replace(
        old, 'Vela_enrollment_policy.Enroll_driver.DeviceObservation_Verified') + text[end:]
elif name == 'plan-drop':
    start, end = body('let plan_completion_preflight', '/// `CompleteIo::take_ceremony`')
    segment = text[start:end]
    old = ('PairingStmt_ReadClaim ({ f_grant_id = grant_id }) <: t_PairingStmt;\n'
           '            PairingStmt_SelectOpener ({ f_device_id = device_id; f_user_id = user_id })\n'
           '            <:\n'
           '            t_PairingStmt')
    new = 'PairingStmt_ReadClaim ({ f_grant_id = grant_id }) <: t_PairingStmt'
    if segment.count(old) != 1:
        sys.exit(f'{name}: preflight plan shape changed')
    segment = segment.replace(old, new)
    segment = segment.replace('(List.Tot.length list) 2', '(List.Tot.length list) 1')
    segment = segment.replace('array_of_list 2 list', 'array_of_list 1 list')
    text = text[:start] + segment + text[end:]
elif name == 'plan-swap':
    start, end = body('let plan_store_grant', '/// `ClaimIo::check_claim`')
    segment = text[start:end]
    old = 'f_user_id = user_id; f_device_id = device_id'
    if segment.count(old) != 1:
        sys.exit(f'{name}: grant plan shape changed')
    text = text[:start] + segment.replace(
        old, 'f_user_id = device_id; f_device_id = user_id') + text[end:]
elif name == 'account-classify':
    start, end = body('let classify_account', "/// The account row's truth")
    segment = text[start:end]
    pattern = re.compile(r'let ok:bool =\n.*?\n  in\n', re.S)
    replaced, count = pattern.subn('let ok:bool = true in\n', segment)
    if count != 1:
        sys.exit(f'{name}: classify_account shape changed')
    text = text[:start] + replaced + text[end:]
elif name == 'grant-exists':
    start, end = body('let classify_grant_exists', "/// `get_claim`\'s payload read")
    segment = text[start:end]
    old = '| ReadOutcome_GrantExists true -> true'
    if segment.count(old) != 1:
        sys.exit(f'{name}: grant-exists classifier shape changed')
    text = text[:start] + segment.replace(old, '| ReadOutcome_GrantExists _ -> true') + text[end:]
elif name == 'grant-read-binding':
    start, end = body('let classify_grant_read', "/// `post_claim`\'s pre-driver liveness bit")
    segment = text[start:end]
    old = 'f_opener_matches = row.f_device_id =. session_device'
    if segment.count(old) != 1:
        sys.exit(f'{name}: grant read bindings shape changed')
    text = text[:start] + segment.replace(
        old, 'f_opener_matches = row.f_user_id =. session_device') + text[end:]
elif name == 'claim-inspect':
    start, end = body('let classify_claim_inspection', "/// The completion\'s ceremony restore")
    segment = text[start:end]
    old = 'f_claim_present = true;'
    if segment.count(old) != 1:
        sys.exit(f'{name}: claim inspection shape changed')
    text = text[:start] + segment.replace(old, 'f_claim_present = false;') + text[end:]
elif name == 'restore-classify':
    start, end = body('let classify_ceremony_restore', '/// Whether a counter value is within')
    segment = text[start:end]
    old = ('    | _ ->\n'
           '      Vela_enrollment_policy.Pairing_driver.StoreObservation_Failed')
    if segment.count(old) != 1:
        sys.exit(f'{name}: ceremony restore shape changed')
    text = text[:start] + segment.replace(
        old,
        '    | _ ->\n'
        '      Vela_enrollment_policy.Pairing_driver.StoreObservation_Stored') + text[end:]
elif name == 'rate-classify':
    # classify_rate_limit is last in the generated module; run to the end.
    start = text.index('let classify_rate_limit')
    segment = text[start:]
    old = ('      if under_limit count limit\n'
           '      then RateObservation_Admitted <: t_RateObservation\n'
           '      else RateObservation_Limited <: t_RateObservation')
    if segment.count(old) != 1:
        sys.exit(f'{name}: rate classifier shape changed')
    text = text[:start] + segment.replace(
        old, '      RateObservation_Admitted <: t_RateObservation')
elif name == 'rate-plan-key':
    start, end = body('let plan_rate_limit', '/// A single unconditional store write')
    segment = text[start:end]
    old = 'f_key = key'
    if segment.count(old) != 1:
        sys.exit(f'{name}: rate plan key shape changed')
    text = text[:start] + segment.replace(old, 'f_key = Alloc.String.String ""') + text[end:]
else:
    sys.exit(f'unknown mutant {name}')

path.write_text(text)
PY
  set +e
  out=$(fstar.exe --cmi --cache_off --warn_error -331 --z3rlimit 100 --z3version 4.13.3 \
    --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
    --include "$hax_lib_root/proof-libs/fstar/core" \
    --include "$hax_lib_root/proof-libs/fstar/rust_primitives" \
    --include "$hax_lib_root/proofs/fstar/extraction" \
    --include "$proof_root/proofs/fstar/extraction" \
    --include "$proof_root/proofs/fstar/extraction-pairing-driver" \
    --include "$proof_root/proofs/fstar/extraction-enroll-driver" \
    --include "$d/executor" --include "$d/lemmas" \
    "$d/lemmas/Vela_enrollment_policy_executor_lemmas.fst" 2>&1)
  status=$?
  set -e
  if (( status == 0 )); then
    echo "mutant $name: VERIFIED (the proof does not depend on it)" >&2
    failures=$((failures + 1))
    continue
  fi
  # Every theorem with an error; the expected one must be among them.
  rejected=$(grep -oE 'Vela_enrollment_policy_executor_lemmas\.fst\(([0-9]+),' <<<"$out" | grep -oE '[0-9]+' | sort -un |
    while read -r line; do head -n "$line" "$lemmas" | grep -oE '^let [a-z_0-9]+' | tail -n1 | cut -d' ' -f2; done | sort -u | tr '\n' ' ') || true
  if [[ -z ${rejected// /} ]]; then
    # No lemma error: F* was killed or failed elsewhere. Say so instead of exiting silently.
    echo "mutant $name: F* exited $status without an error in the lemma module; last output:" >&2
    tail -n 20 <<<"$out" >&2
    failures=$((failures + 1))
    continue
  fi
  if [[ " $rejected " != *" ${expect[$name]} "* ]]; then
    echo "mutant $name: rejected at [${rejected% }], expected ${expect[$name]}:" >&2
    grep -m5 -E 'Error' <<<"$out" >&2 || true
    failures=$((failures + 1))
    continue
  fi
  echo "mutant $name: rejected at ${rejected% }"
done
(( failures == 0 )) || { echo "$failures mutation check(s) failed" >&2; exit 1; }
echo "enrollment executor mutations: every mutant rejected at its theorem"
