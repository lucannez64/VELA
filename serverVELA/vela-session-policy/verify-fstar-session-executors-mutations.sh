#!/usr/bin/env bash
set -euo pipefail

# Mutation checks for the F-1 session-executor proofs. Run after
# verify-fstar-session-executors.sh (it reuses that gate's extraction); that
# gate calls this script last.
#
# Each mutant is a copy of the extracted `Vela_session_policy.Store` under /tmp
# with one change, equal to a one-line change in `src/store.rs`; the
# checked-in extraction is never modified. The checked-in lemma module must
# FAIL against every mutant, and the named theorem must be among those that
# fail.
#
#   classify-logout-error   classify_logout maps a failed write to Applied
#   classify-record-error   classify_record maps a failed update to Updated
#   classify-delete-failed  classify_table_delete maps a failure to Deleted
#   classify-users-absent   classify_users_delete maps zero rows to Deleted
#   classify-target-owner   classify_target ignores the caller
#   classify-commit-error   classify_commit maps a failed commit to Committed
#   plan-table-swap         the web-sessions delete runs the inbox delete
#   plan-users-swap         the users delete runs the devices delete
#   plan-logout-ttl         the logout marker outlives its token lifetime
#   plan-sentinel-ttl       the device sentinel outlives its token lifetime

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"
want=${1:-all}

store=$proof_root/proofs/fstar/extraction-store/Vela_session_policy.Store.fst
model_dir=$proof_root/proofs/fstar/store-lemmas
lemmas=$model_dir/Vela_session_policy_store_lemmas.fst
mut=/tmp/vela-session-executor-mut
[[ -f $store && -f $lemmas ]] || { echo "run verify-fstar-session-executors.sh first" >&2; exit 1; }

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)

mutants=(
  classify-logout-error classify-record-error classify-delete-failed
  classify-users-absent classify-target-owner classify-commit-error
  plan-table-swap plan-users-swap plan-logout-ttl plan-sentinel-ttl
)
declare -A expect=(
  [classify-logout-error]=logout_is_honest
  [classify-record-error]=revoke_record_is_honest
  [classify-delete-failed]=delete_table_is_honest
  [classify-users-absent]=delete_users_is_honest
  [classify-target-owner]=revoke_observe_is_honest
  [classify-commit-error]=commit_is_honest
  [plan-table-swap]=plan_delete_table_shape
  [plan-users-swap]=plan_delete_users_shape
  [plan-logout-ttl]=plan_logout_shape
  [plan-sentinel-ttl]=plan_lockout_device_shape
)

rm -rf "$mut"
failures=0
for name in "${mutants[@]}"; do
  [[ $want == all || $want == "$name" ]] || continue
  d=$mut/$name
  mkdir -p "$d/store" "$d/lemmas"
  cp "$store" "$d/store/"
  cp "$model_dir"/*.fst "$d/lemmas/"
  python3 - "$name" "$d/store/Vela_session_policy.Store.fst" <<'PY'
import sys, pathlib
name, path = sys.argv[1], pathlib.Path(sys.argv[2])
text = path.read_text()

def once(old, new):
    global text
    if text.count(old) != 1:
        sys.exit(f'{name}: expected exactly one match for {old!r}, found {text.count(old)}')
    text = text.replace(old, new)

def in_body(start_marker, end_marker, old, new):
    global text
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    body = text[start:end]
    if body.count(old) != 1:
        sys.exit(f'{name}: expected exactly one {old!r} in the body, found {body.count(old)}')
    text = text[:start] + body.replace(old, new) + text[end:]

if name == 'classify-logout-error':
    once('''    | StoreOutcome_Applied  ->
      Vela_session_policy.Revocation_driver.LogoutObservation_Applied''',
         '''    | StoreOutcome_Applied  ->
      Vela_session_policy.Revocation_driver.LogoutObservation_StorageFailed''')
elif name == 'classify-record-error':
    once('''  | WriteOutcome_Applied _ ->
    Vela_session_policy.Revocation_driver.RecordObservation_Updated''',
         '''  | WriteOutcome_Applied _ ->
    Vela_session_policy.Revocation_driver.RecordObservation_Failed''')
elif name == 'classify-delete-failed':
    once('''  | WriteOutcome_Failed  ->
    Vela_session_policy.Deletion_driver.TableDeleteObservation_Failed''',
         '''  | WriteOutcome_Failed  ->
    Vela_session_policy.Deletion_driver.TableDeleteObservation_Deleted''')
elif name == 'classify-users-absent':
    once('''  | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 0) ->
    Vela_session_policy.Deletion_driver.UsersDeleteObservation_Absent''',
         '''  | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 0) ->
    Vela_session_policy.Deletion_driver.UsersDeleteObservation_Deleted''')
elif name == 'classify-target-owner':
    once('| Core_models.Option.Option_Some owner -> owner =. caller',
         '| Core_models.Option.Option_Some owner -> true')
elif name == 'classify-commit-error':
    once('''  | WriteOutcome_Failed  ->
    Vela_session_policy.Deletion_driver.CommitObservation_Failed''',
         '''  | WriteOutcome_Failed  ->
    Vela_session_policy.Deletion_driver.CommitObservation_Committed''')
elif name == 'plan-table-swap':
    in_body('let plan_delete_table', 'let plan_delete_users',
            'SqlStmt_DeleteWebSessionsByUser ({ f_user = user })',
            'SqlStmt_DeleteShareInboxByUser ({ f_user = user })')
elif name == 'plan-users-swap':
    in_body('let plan_delete_users', 'let plan_commit',
            'SqlStmt_DeleteUserById ({ f_user = user })',
            'SqlStmt_DeleteDevicesByUser ({ f_user = user })')
elif name == 'plan-logout-ttl':
    in_body('let plan_logout', 'let plan_sentinel',
            'f_ttl = v_TOKEN_MAX_LIFETIME_SECS',
            'f_ttl = mk_u64 901')
elif name == 'plan-sentinel-ttl':
    start = text.index('let plan_lockout_device')
    end = text.index('let plan_lockout_web_session', start)
    body = text[start:end]
    old = 'f_ttl = v_TOKEN_MAX_LIFETIME_SECS'
    if body.count(old) != 1:
        sys.exit(f'{name}: expected one sentinel TTL, found {body.count(old)}')
    text = text[:start] + body.replace(old, 'f_ttl = mk_u64 901') + text[end:]
path.write_text(text)
PY
  set +e
  out=$(fstar.exe --cmi --cache_off --warn_error -331 --z3rlimit 200 --z3version 4.13.3 \
    --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
    --include "$hax_lib_root/proof-libs/fstar/core" \
    --include "$hax_lib_root/proof-libs/fstar/rust_primitives" \
    --include "$hax_lib_root/proofs/fstar/extraction" \
    --include "$proof_root/proofs/fstar/extraction" \
    --include "$proof_root/proofs/fstar/extraction-deletion-driver" \
    --include "$proof_root/proofs/fstar/extraction-revocation-driver" \
    --include "$d/store" --include "$d/lemmas" \
    "$d/lemmas/Vela_session_policy_store_lemmas.fst" 2>&1)
  status=$?
  set -e
  if (( status == 0 )); then
    echo "mutant $name: VERIFIED (the proof does not depend on it)" >&2
    failures=$((failures + 1))
    continue
  fi
  # Every theorem with an error; the expected one must be among them.
  rejected=$(grep -oE 'Vela_session_policy_store_lemmas\.fst\(([0-9]+),' <<<"$out" | grep -oE '[0-9]+' | sort -un |
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
echo "session executor mutations: every mutant rejected at its theorem"
