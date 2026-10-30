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
#   classify-login-challenge-failed  a failed challenge take reports accepted
#   classify-login-device-failed     a failed device query reports present
#   classify-failure-counter-error   a refused failure counter reports okay
#   classify-reset-error             a failed streak reset reports Reset
#   classify-track-error             a failed JTI track reports Tracked
#   plan-counter-limit               the failed-proof counter allows one more
#   plan-jti-ttl                     the JTI set outlives the session cap
#   classify-store-nonce-failed      a failed challenge write reports Inserted
#   plan-store-nonce-ttl             the challenge outlives its TTL
#   classify-insert-error            a failed INSERT reports Inserted
#   classify-budget-failed           a failed count query reports zero accounts
#   plan-registration-limit          the registration window allows one more
#   plan-insert-account-swap         the account insert swaps its two key columns
#   classify-start-insert-error      a failed pending insert reports Inserted
#   plan-insert-pending-swap         the pending insert swaps its approver and hash
#   classify-grant-conflict          a zero-row grant CAS reports Updated
#   classify-grant-error             a failed grant CAS reports Updated
#   plan-grant-swap                  the grant CAS swaps its mode and capsule
#   classify-claim-error             a failed token claim reports Claimed
#   plan-claim-ttl                   the token claim outlives its session ceiling
#   classify-issue-track             a failed JTI track still issues
#   classify-lockout-session-error   a failed session lockout reports Applied
#   plan-revoke-session-key          the audit update targets another session
#   classify-revoke-session-error    a failed audit update reports Updated

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
  classify-login-challenge-failed classify-login-device-failed
  classify-failure-counter-error classify-reset-error classify-track-error
  plan-counter-limit plan-jti-ttl
  classify-store-nonce-failed plan-store-nonce-ttl classify-insert-error
  classify-budget-failed plan-registration-limit plan-insert-account-swap
  classify-start-insert-error plan-insert-pending-swap
  classify-grant-conflict classify-grant-error plan-grant-swap
  classify-claim-error plan-claim-ttl classify-issue-track
  classify-lockout-session-error plan-revoke-session-key
  classify-revoke-session-error
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
  [classify-login-challenge-failed]=login_challenge_storage_failed
  [classify-login-device-failed]=login_device_is_honest
  [classify-failure-counter-error]=login_failure_counter_reports_its_run
  [classify-reset-error]=login_reset_is_honest
  [classify-track-error]=login_track_is_honest
  [plan-counter-limit]=plan_failure_counter_shape
  [plan-jti-ttl]=plan_track_jti_shape
  [classify-store-nonce-failed]=challenge_nonce_is_honest
  [plan-store-nonce-ttl]=plan_store_nonce_shape
  [classify-insert-error]=insert_account_is_honest
  [classify-budget-failed]=account_count_is_honest
  [plan-registration-limit]=plan_registration_rate_limit_shape
  [plan-insert-account-swap]=plan_insert_account_shape
  [classify-start-insert-error]=insert_pending_is_honest
  [plan-insert-pending-swap]=plan_insert_pending_shape
  [classify-grant-conflict]=grant_update_is_honest
  [classify-grant-error]=grant_update_is_honest
  [plan-grant-swap]=plan_grant_update_shape
  [classify-claim-error]=token_claim_is_honest
  [plan-claim-ttl]=plan_token_claim_shape
  [classify-issue-track]=token_issue_is_honest
  [classify-lockout-session-error]=lockout_session_is_honest
  [plan-revoke-session-key]=plan_revoke_session_shape
  [classify-revoke-session-error]=revoke_session_observes_its_run
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
elif name == 'classify-login-challenge-failed':
    once('''  | TakeOutcome_Failed  ->
    Vela_session_policy.Login_driver.ChallengeObservation_StorageFailed''',
         '''  | TakeOutcome_Failed  ->
    Vela_session_policy.Login_driver.ChallengeObservation_Observed
      (Vela_session_policy.Challenge.ChallengeConsumption_Accepted)''')
elif name == 'classify-login-device-failed':
    once('''  | DeviceReadOutcome_Failed  ->
    Vela_session_policy.Login_driver.DeviceObservation_QueryFailed''',
         '''  | DeviceReadOutcome_Failed  ->
    Vela_session_policy.Login_driver.DeviceObservation_Present''')
elif name == 'classify-failure-counter-error':
    once('''    (match outcomes.[ mk_usize 0 ] <: t_StoreOutcome with
      | StoreOutcome_Applied  -> true''',
         '''    (match outcomes.[ mk_usize 0 ] <: t_StoreOutcome with
      | StoreOutcome_Applied  -> false''')
elif name == 'classify-reset-error':
    once('''  | StoreOutcome_Failed  ->
    Vela_session_policy.Login_driver.BackoffResetObservation_StorageFailed''',
         '''  | StoreOutcome_Failed  ->
    Vela_session_policy.Login_driver.BackoffResetObservation_Reset''')
elif name == 'classify-track-error':
    once('''  | StoreOutcome_Failed  ->
    Vela_session_policy.Login_driver.TokenTrackObservation_Failed''',
         '''  | StoreOutcome_Failed  ->
    Vela_session_policy.Login_driver.TokenTrackObservation_Tracked''')
elif name == 'plan-counter-limit':
    once('f_limit = v_VERIFY_FAIL_LIMIT', 'f_limit = mk_u64 4')
elif name == 'plan-jti-ttl':
    once('f_ttl = v_JTI_SET_TTL_SECS', 'f_ttl = mk_u64 1')
elif name == 'classify-store-nonce-failed':
    once('''  | NxOutcome_Failed  ->
    Vela_session_policy.Challenge_issue_driver.StoreObservation_Failed''',
         '''  | NxOutcome_Failed  ->
    Vela_session_policy.Challenge_issue_driver.StoreObservation_Inserted''')
elif name == 'plan-store-nonce-ttl':
    once('f_ttl = v_CHALLENGE_TTL_SECS', 'f_ttl = mk_u64 61')
elif name == 'classify-insert-error':
    once('''  | WriteOutcome_Failed  ->
    Vela_session_policy.Registration_driver.InsertObservation_Failed''',
         '''  | WriteOutcome_Failed  ->
    Vela_session_policy.Registration_driver.InsertObservation_Inserted''')
elif name == 'classify-budget-failed':
    once('''  | CountOutcome_Failed  ->
    Vela_session_policy.Registration_driver.BudgetObservation_QueryFailed''',
         '''  | CountOutcome_Failed  ->
    Vela_session_policy.Registration_driver.BudgetObservation_Counted
    ({ Vela_session_policy.Registration_driver.f_count = mk_i64 0 })''')
elif name == 'plan-registration-limit':
    once('f_limit = v_REGISTER_RATE_LIMIT', 'f_limit = mk_u64 6')
elif name == 'plan-insert-account-swap':
    in_body('let plan_insert_account', 'let plan_insert_device',
            'f_share_ek = share_ek; f_share_ek_since = share_ek_since',
            'f_share_ek = share_ek_since; f_share_ek_since = share_ek')
elif name == 'classify-start-insert-error':
    once('''  | WriteOutcome_Failed  ->
    Vela_session_policy.Websession_driver.StartInsertObservation_Failed''',
         '''  | WriteOutcome_Failed  ->
    Vela_session_policy.Websession_driver.StartInsertObservation_Inserted''')
elif name == 'plan-insert-pending-swap':
    in_body('let plan_insert_pending', 'let plan_grant_update',
            'f_approver = approver;', 'f_approver = poll_secret_hash;')
    in_body('let plan_insert_pending', 'let plan_grant_update',
            'f_poll_secret_hash = poll_secret_hash;',
            'f_poll_secret_hash = approver;')
elif name == 'classify-grant-conflict':
    once('''  | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 0) ->
    Vela_session_policy.Websession_driver.GrantUpdateObservation_Conflict''',
         '''  | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 0) ->
    Vela_session_policy.Websession_driver.GrantUpdateObservation_Updated''')
elif name == 'classify-grant-error':
    once('''  | WriteOutcome_Failed  ->
    Vela_session_policy.Websession_driver.GrantUpdateObservation_Failed''',
         '''  | WriteOutcome_Failed  ->
    Vela_session_policy.Websession_driver.GrantUpdateObservation_Updated''')
elif name == 'plan-grant-swap':
    in_body('let plan_grant_update', 'let plan_revoke_session',
            'f_mode = mode;', 'f_mode = capsule;')
    in_body('let plan_grant_update', 'let plan_revoke_session',
            'f_capsule = capsule;', 'f_capsule = mode;')
elif name == 'classify-claim-error':
    once('''  | NxOutcome_Failed  ->
    Vela_session_policy.Websession_driver.TokenClaimObservation_StorageFailed''',
         '''  | NxOutcome_Failed  ->
    Vela_session_policy.Websession_driver.TokenClaimObservation_Claimed''')
elif name == 'plan-claim-ttl':
    in_body('let plan_token_claim', 'let plan_token_sentinel',
            'f_ttl = v_WEB_SESSION_MAX_TTL_SECS', 'f_ttl = mk_u64 86401')
elif name == 'classify-issue-track':
    once('''    (match tracked <: t_StoreOutcome with
      | StoreOutcome_Applied  -> true
      | _ -> false)''',
         '''    true''')
elif name == 'classify-lockout-session-error':
    once('''  | StoreOutcome_Failed  ->
    Vela_session_policy.Websession_driver.DeleteSentinelObservation_StorageFailed''',
         '''  | StoreOutcome_Failed  ->
    Vela_session_policy.Websession_driver.DeleteSentinelObservation_Applied''')
elif name == 'plan-revoke-session-key':
    once('SqlStmt_RevokeSessionById ({ f_session = session })',
         'SqlStmt_RevokeSessionById ({ f_session = Alloc.String.String "" })')
elif name == 'classify-revoke-session-error':
    once('''  | WriteOutcome_Failed  ->
    Vela_session_policy.Websession_driver.DeleteRecordObservation_Failed''',
         '''  | WriteOutcome_Failed  ->
    Vela_session_policy.Websession_driver.DeleteRecordObservation_Updated''')
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
    --include "$proof_root/proofs/fstar/extraction-websession-driver" \
    --include "$proof_root/proofs/fstar/extraction-login-driver" \
    --include "$proof_root/proofs/fstar/extraction-registration-driver" \
    --include "$proof_root/proofs/fstar/extraction-challenge-issue-driver" \
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
