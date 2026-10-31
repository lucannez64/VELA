#!/usr/bin/env bash
set -euo pipefail

# Mutation checks for the F-1 recovery executor proofs. Run after
# verify-fstar-recovery-executors.sh (it reuses that gate's extraction); that
# gate calls this script last.
#
# Each mutant is a copy of one extracted store module
# (`Vela_recovery_policy.Redemption_store` or
# `Vela_recovery_policy.Share_store`) under /tmp with one change, equal to a
# one-line change in its Rust source; the checked-in extraction is never
# modified. The checked-in lemma module must FAIL against every mutant, and the
# named theorem must be among those that fail.
#
#   redemption family (`src/redemption_store.rs`)
#   classify-match     classify_take reports a match for any consumed grant
#   classify-error     classify_insert maps a failed insert to Inserted
#   classify-rows      classify_insert maps a zero-row insert to Inserted
#   classify-authority classify_authority maps a missing commitment to StillRotating
#   plan-guard         plan_insert_device always uses the commitment guard
#   plan-epoch         plan_insert_device writes a fixed epoch
#
#   recovery-share family (`src/share_store.rs`)
#   share-classify-stage-rows  a zero-row stage update reports Staged
#   share-classify-account     a non-matching active share reports a match
#   share-classify-read        a missing share reports present
#   share-classify-delete-rows a zero-row delete reports Deleted
#   share-plan-epoch           the stage update writes a fixed epoch
#   share-plan-split           the promote update uses the user id as split id
#
#   possession family (`src/possession_store.rs`)
#   possession-classify-store   a lost challenge race reports Stored
#   possession-classify-attempt a corrupt attempt reports Missing
#   possession-classify-grant   a failed grant store reports Stored
#   possession-plan-key         the challenge is stored under the value, not its key

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"
want=${1:-all}

redemption_store=$proof_root/proofs/fstar/extraction-redemption/Vela_recovery_policy.Redemption_store.fst
redemption_lemmas=$proof_root/proofs/fstar/redemption-lemmas/Vela_recovery_policy_redemption_lemmas.fst
share_store=$proof_root/proofs/fstar/extraction-share/Vela_recovery_policy.Share_store.fst
share_lemmas=$proof_root/proofs/fstar/share-lemmas/Vela_recovery_policy_share_lemmas.fst
possession_store=$proof_root/proofs/fstar/extraction-possession/Vela_recovery_policy.Possession_store.fst
possession_lemmas=$proof_root/proofs/fstar/possession-lemmas/Vela_recovery_policy_possession_lemmas.fst
webauthn_store=$proof_root/proofs/fstar/extraction-webauthn/Vela_recovery_policy.Webauthn_store.fst
webauthn_lemmas=$proof_root/proofs/fstar/webauthn-lemmas/Vela_recovery_policy_webauthn_lemmas.fst
[[ -f $redemption_store && -f $redemption_lemmas ]] || {
  echo "run verify-fstar-recovery-executors.sh first" >&2; exit 1
}
[[ -f $share_store && -f $share_lemmas ]] || {
  echo "run verify-fstar-recovery-executors.sh first" >&2; exit 1
}
[[ -f $possession_store && -f $possession_lemmas ]] || {
  echo "run verify-fstar-recovery-executors.sh first" >&2; exit 1
}
[[ -f $webauthn_store && -f $webauthn_lemmas ]] || {
  echo "run verify-fstar-recovery-executors.sh first" >&2; exit 1
}
mut=$(mktemp -d "${TMPDIR:-/tmp}/vela-recovery-executor-mut.XXXXXX")
# A fresh directory per run: CI runners and local runs share the build box.
trap 'rm -rf "$mut"' EXIT

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)

mutants=(
  classify-match classify-error classify-rows classify-authority plan-guard plan-epoch
  share-classify-stage-rows share-classify-account share-classify-read
  share-classify-delete-rows share-plan-epoch share-plan-split
  possession-classify-store possession-classify-attempt
  possession-classify-grant possession-plan-key
  webauthn-classify-start-share webauthn-classify-start-credential
  webauthn-classify-store-lost webauthn-classify-consume
  webauthn-classify-update webauthn-classify-account
  webauthn-classify-persist webauthn-classify-uniqueness
  webauthn-classify-release webauthn-plan-select-share
  webauthn-plan-grant-key webauthn-plan-persist-user
)
declare -A expect=(
  [classify-match]=take_grant_is_honest
  [classify-error]=insert_device_is_honest
  [classify-rows]=insert_device_is_honest
  [classify-authority]=authority_observation_is_honest
  [plan-guard]=insert_device_is_honest
  [plan-epoch]=insert_device_is_honest
  [share-classify-stage-rows]=stage_share_is_honest
  [share-classify-account]=stage_account_is_honest
  [share-classify-read]=read_share_is_honest
  [share-classify-delete-rows]=delete_share_is_honest
  [share-plan-epoch]=stage_share_is_honest
  [share-plan-split]=promote_staged_split_is_honest
  [possession-classify-store]=store_challenge_is_honest
  [possession-classify-attempt]=attempt_consumption_is_honest
  [possession-classify-grant]=grant_store_is_honest
  [possession-plan-key]=store_challenge_is_honest
  [webauthn-classify-start-share]=auth_start_observation_is_honest
  [webauthn-classify-start-credential]=auth_start_observation_is_honest
  [webauthn-classify-store-lost]=auth_start_store_is_honest
  [webauthn-classify-consume]=attempt_consumption_is_honest
  [webauthn-classify-update]=credential_update_guard_is_honest
  [webauthn-classify-account]=finish_account_is_honest
  [webauthn-classify-persist]=credential_persist_is_honest
  [webauthn-classify-uniqueness]=uniqueness_is_honest
  [webauthn-classify-release]=share_release_is_honest
  [webauthn-plan-select-share]=auth_start_observation_is_honest
  [webauthn-plan-grant-key]=grant_store_is_honest
  [webauthn-plan-persist-user]=credential_persist_is_honest
)

failures=0
for name in "${mutants[@]}"; do
  [[ $want == all || $want == "$name" ]] || continue
  case $name in
    share-*)
      store=$share_store
      lemmas=$share_lemmas
      lemma_dir=$proof_root/proofs/fstar/share-lemmas
      store_module=Vela_recovery_policy.Share_store.fst
      includes=(
        --include "$proof_root/proofs/fstar/extraction-recovery-share-driver"
        --include "$proof_root/proofs/fstar/extraction-share"
      )
      ;;
    possession-*)
      store=$possession_store
      lemmas=$possession_lemmas
      lemma_dir=$proof_root/proofs/fstar/possession-lemmas
      store_module=Vela_recovery_policy.Possession_store.fst
      includes=(
        --include "$proof_root/proofs/fstar/extraction-possession-driver"
      )
      ;;
    webauthn-*)
      store=$webauthn_store
      lemmas=$webauthn_lemmas
      lemma_dir=$proof_root/proofs/fstar/webauthn-lemmas
      store_module=Vela_recovery_policy.Webauthn_store.fst
      includes=(
        --include "$proof_root/proofs/fstar/extraction-webauthn-driver"
        --include "$proof_root/proofs/fstar/extraction-webauthn"
      )
      ;;
    *)
      store=$redemption_store
      lemmas=$redemption_lemmas
      lemma_dir=$proof_root/proofs/fstar/redemption-lemmas
      store_module=Vela_recovery_policy.Redemption_store.fst
      includes=(
        --include "$proof_root/proofs/fstar/extraction-driver"
        --include "$proof_root/proofs/fstar/extraction-redemption"
      )
      ;;
  esac
  d=$mut/$name
  mkdir -p "$d/store" "$d/lemmas"
  cp "$store" "$d/store/$store_module"
  cp "$lemma_dir"/*.fst "$d/lemmas/"
  python3 - "$name" "$d/store/$store_module" <<'PY'
import sys, pathlib
name, path = sys.argv[1], pathlib.Path(sys.argv[2])
text = path.read_text()
def once(old, new):
    global text
    if text.count(old) != 1:
        sys.exit(f'{name}: expected exactly one match for {old!r}, found {text.count(old)}')
    text = text.replace(old, new)
def region(start_marker, end_marker):
    start = text.index(start_marker)
    end = text.index(end_marker)
    return start, text[start:end], end
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
    start, body, end = region('let classify_insert', '/// The live authority recheck')
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
    text = text[:start] + body.replace(old, '''      Vela_recovery_policy.Driver.InsertObservation_Inserted
      <:
      Vela_recovery_policy.Driver.t_InsertObservation''') + text[end:]
elif name == 'classify-authority':
    once('''      | Core_models.Option.Option_None  ->
        Vela_recovery_policy.Driver.AuthorityRecheckObservation_CommitmentRevoked''',
         '''      | Core_models.Option.Option_None  ->
        Vela_recovery_policy.Driver.AuthorityRecheckObservation_StillRotating''')
elif name == 'plan-guard':
    start, body, end = region('let plan_insert_device', '/// `recheck_authority`')
    if body.count('f_guard = guard') != 1:
        sys.exit(f'{name}: guard field not found')
    text = text[:start] + body.replace('f_guard = guard', 'f_guard = GrantGuard_Commitment') + text[end:]
elif name == 'plan-epoch':
    start, body, end = region('let plan_insert_device', '/// `recheck_authority`')
    if body.count('f_epoch = epoch') != 1:
        sys.exit(f'{name}: epoch field not found')
    text = text[:start] + body.replace('f_epoch = epoch', 'f_epoch = mk_i64 1') + text[end:]
elif name == 'share-classify-stage-rows':
    start, body, end = region('let classify_stage_update', '/// `stage_query_account`')
    if body.count('if rows =. mk_u64 1') != 1:
        sys.exit(f'{name}: stage row check not found')
    text = text[:start] + body.replace('if rows =. mk_u64 1', 'if true') + text[end:]
elif name == 'share-classify-account':
    start, body, end = region('let classify_stage_account', '/// `promote_staged_split`')
    start_at = body.index('      Vela_recovery_policy.Recovery_share_driver.f_active_share_matches')
    stop_at = body.index('      Vela_recovery_policy.Recovery_share_driver.f_active_split_matches')
    replacement = '      Vela_recovery_policy.Recovery_share_driver.f_active_share_matches = true;\n'
    text = text[:start] + body[:start_at] + replacement + body[stop_at:] + text[end:]
elif name == 'share-classify-read':
    start = text.index('let classify_read_share')
    body = text[start:]
    old = 'Core_models.Option.impl__is_some #Alloc.String.t_String row.f_share'
    if body.count(old) != 1:
        sys.exit(f'{name}: share presence check not found')
    text = text[:start] + body.replace(old, 'true')
elif name == 'share-classify-delete-rows':
    start, body, end = region('let classify_delete_update', '/// `read_share`')
    if body.count('if rows =. mk_u64 1') != 1:
        sys.exit(f'{name}: delete row check not found')
    text = text[:start] + body.replace('if rows =. mk_u64 1', 'if true') + text[end:]
elif name == 'share-plan-epoch':
    start, body, end = region('let plan_stage_share', '/// `FinalizeShareIo::promote_staged_split`')
    if body.count('f_epoch = epoch') != 1:
        sys.exit(f'{name}: stage epoch field not found')
    text = text[:start] + body.replace('f_epoch = epoch', 'f_epoch = mk_i64 1') + text[end:]
elif name == 'share-plan-split':
    start, body, end = region('let plan_promote_staged_split', '/// `DeleteShareIo::delete_share`')
    if body.count('f_split_id = split_id') != 1:
        sys.exit(f'{name}: promote split field not found')
    text = text[:start] + body.replace('f_split_id = split_id', 'f_split_id = user') + text[end:]
elif name == 'possession-classify-store':
    start, body, end = region('let classify_store_challenge', '/// `RecoverProofIo::consume_attempt`: the removed state')
    if body.count('ChallengeStoreObservation_Stored') != 1 or body.count('ChallengeStoreObservation_Lost') != 1:
        sys.exit(f'{name}: challenge classifier shape changed')
    mutated = body.replace('ChallengeStoreObservation_Stored', 'ChallengeStoreObservation_TMP')
    mutated = mutated.replace('ChallengeStoreObservation_Lost', 'ChallengeStoreObservation_Stored')
    mutated = mutated.replace('ChallengeStoreObservation_TMP', 'ChallengeStoreObservation_Lost')
    text = text[:start] + mutated + text[end:]
elif name == 'possession-classify-attempt':
    start, body, end = region('let classify_attempt', '/// `RecoverProofIo::query_account`: every field is the live row')
    old = '''  | ProofAttemptTake_Corrupt  ->
    Vela_recovery_policy.Possession_driver.AttemptConsumptionObservation_Corrupt'''
    if body.count(old) != 1:
        sys.exit(f'{name}: corrupt branch not found')
    text = text[:start] + body.replace(old, '''  | ProofAttemptTake_Corrupt  ->
    Vela_recovery_policy.Possession_driver.AttemptConsumptionObservation_Missing''') + text[end:]
elif name == 'possession-classify-grant':
    start = text.index('let classify_grant_store')
    body = text[start:]
    end = len(text)
    old = '''  if stored
  then
    Vela_recovery_policy.Possession_driver.GrantStoreObservation_Stored
    <:
    Vela_recovery_policy.Possession_driver.t_GrantStoreObservation
  else
    Vela_recovery_policy.Possession_driver.GrantStoreObservation_Failed'''
    if body.count(old) != 1:
        sys.exit(f'{name}: grant classifier shape changed')
    text = text[:start] + body.replace(old, '''  if stored
  then
    Vela_recovery_policy.Possession_driver.GrantStoreObservation_Stored
    <:
    Vela_recovery_policy.Possession_driver.t_GrantStoreObservation
  else
    Vela_recovery_policy.Possession_driver.GrantStoreObservation_Stored''') + text[end:]
elif name == 'possession-plan-key':
    start, body, end = region('let plan_store_challenge', '/// `RecoverProofIo::consume_attempt`: the atomic single-use take')
    if body.count('f_key = key') != 1:
        sys.exit(f'{name}: challenge key field not found')
    text = text[:start] + body.replace('f_key = key', 'f_key = value') + text[end:]
elif name == 'webauthn-classify-start-share':
    start, body, end = region('let classify_auth_start', '/// `RecoverIo::auth_finish_context`')
    if body.count('f_share_present = share.f_share_present') != 1:
        sys.exit(f'{name}: share field not found')
    text = text[:start] + body.replace('f_share_present = share.f_share_present', 'f_share_present = true') + text[end:]
elif name == 'webauthn-classify-start-credential':
    start, body, end = region('let classify_auth_start', '/// `RecoverIo::auth_finish_context`')
    old_cred = 'f_credential = credential.f_credential'
    if body.count(old_cred) != 1:
        sys.exit(f'{name}: credential field not found')
    text = text[:start] + body.replace(old_cred,
        'f_credential = Vela_recovery_policy.Webauthn_driver.StoredCredentialObservation_Present') + text[end:]
elif name == 'webauthn-classify-store-lost':
    start, body, end = region('let classify_store_auth_state', 'let classify_store_registration_state')
    if body.count('ChallengeStoreObservation_Stored') != 1 or body.count('ChallengeStoreObservation_Lost') != 1:
        sys.exit(f'{name}: challenge classifier shape changed')
    mutated = body.replace('ChallengeStoreObservation_Stored', 'ChallengeStoreObservation_TMP')
    mutated = mutated.replace('ChallengeStoreObservation_Lost', 'ChallengeStoreObservation_Stored')
    mutated = mutated.replace('ChallengeStoreObservation_TMP', 'ChallengeStoreObservation_Lost')
    text = text[:start] + mutated + text[end:]
elif name == 'webauthn-classify-consume':
    start, body, end = region('let classify_take_auth_state', 'let classify_credential_update')
    old = '''  | AuthStateTake_Corrupt  ->
    Vela_recovery_policy.Webauthn_driver.AuthAttemptConsumptionObservation_Corrupt'''
    if body.count(old) != 1:
        sys.exit(f'{name}: corrupt branch not found')
    text = text[:start] + body.replace(old, '''  | AuthStateTake_Corrupt  ->
    Vela_recovery_policy.Webauthn_driver.AuthAttemptConsumptionObservation_Missing''') + text[end:]
elif name == 'webauthn-classify-update':
    start, body, end = region('let classify_credential_update', 'let classify_finish_account')
    if body.count('if rows >. mk_u64 0') != 1:
        sys.exit(f'{name}: row check not found')
    text = text[:start] + body.replace('if rows >. mk_u64 0', 'if true') + text[end:]
elif name == 'webauthn-classify-account':
    start, body, end = region('let classify_finish_account', '/// `RecoverIo::auth_finish_account`\'s split-id side channel')
    old = 'f_account_epoch_active = ~.row.f_rotation_active'
    if body.count(old) != 1:
        sys.exit(f'{name}: rotation field not found')
    text = text[:start] + body.replace(old, 'f_account_epoch_active = true') + text[end:]
elif name == 'webauthn-classify-persist':
    start = text.index('let classify_persist_credential')
    body = text[start:]
    old = '''        if rows >. mk_u64 0
        then
          Vela_recovery_policy.Webauthn_driver.CredentialPersistObservation_Persisted
          <:
          Vela_recovery_policy.Webauthn_driver.t_CredentialPersistObservation
        else
          Vela_recovery_policy.Webauthn_driver.CredentialPersistObservation_AccountGone
          <:
          Vela_recovery_policy.Webauthn_driver.t_CredentialPersistObservation'''
    if body.count(old) != 1:
        sys.exit(f'{name}: persist row check not found')
    text = text[:start] + body.replace(old, '''        Vela_recovery_policy.Webauthn_driver.CredentialPersistObservation_Persisted
        <:
        Vela_recovery_policy.Webauthn_driver.t_CredentialPersistObservation''')
elif name == 'webauthn-classify-uniqueness':
    start, body, end = region('let classify_uniqueness', 'let classify_persist_credential')
    old = '''  | CredentialHolderView_Unreadable  ->
    Vela_recovery_policy.Webauthn_driver.CredentialUniquenessObservation_LookupFailed'''
    if body.count(old) != 1:
        sys.exit(f'{name}: unreadable branch not found')
    text = text[:start] + body.replace(old, '''  | CredentialHolderView_Unreadable  ->
    Vela_recovery_policy.Webauthn_driver.CredentialUniquenessObservation_Unique''') + text[end:]
elif name == 'webauthn-classify-release':
    start, body, end = region('let classify_share_release', 'let classify_grant_store')
    if body.count('ShareDecodeObservation_Decoded') != 1 or body.count('ShareDecodeObservation_Corrupt') != 1:
        sys.exit(f'{name}: release classifier shape changed')
    mutated = body.replace('ShareDecodeObservation_Decoded', 'ShareDecodeObservation_TMP')
    mutated = mutated.replace('ShareDecodeObservation_Corrupt', 'ShareDecodeObservation_Decoded')
    mutated = mutated.replace('ShareDecodeObservation_TMP', 'ShareDecodeObservation_Corrupt')
    text = text[:start] + mutated + text[end:]
elif name == 'webauthn-plan-select-share':
    start, body, end = region('let plan_select_share', '/// `InitiateIo::auth_start_observe` / `RecoverIo::auth_finish_context` /')
    if body.count('f_user = user') != 1:
        sys.exit(f'{name}: share user field not found')
    text = text[:start] + body.replace('f_user = user', 'f_user = Alloc.String.String ""') + text[end:]
elif name == 'webauthn-plan-grant-key':
    start, body, end = region('let plan_store_credential_grant', '/// `InitiateIo::auth_start_observe`: every field')
    if body.count('f_key = key') != 1:
        sys.exit(f'{name}: grant key field not found')
    text = text[:start] + body.replace('f_key = key', 'f_key = value') + text[end:]
elif name == 'webauthn-plan-persist-user':
    start, body, end = region('let plan_persist_credential', 'let plan_store_registration_state')
    if body.count('f_user = user') != 1:
        sys.exit(f'{name}: persist user field not found')
    text = text[:start] + body.replace('f_user = user', 'f_user = credential') + text[end:]
else:
    sys.exit(f'{name}: unknown mutant')
path.write_text(text)
PY
  set +e
  out=$(fstar.exe --cmi --cache_off --warn_error -331 --z3rlimit 200 --z3version 4.13.3 \
    --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
    --include "$hax_lib_root/proof-libs/fstar/core" \
    --include "$hax_lib_root/proof-libs/fstar/rust_primitives" \
    --include "$hax_lib_root/proofs/fstar/extraction" \
    "${includes[@]}" \
    --include "$d/store" --include "$d/lemmas" \
    "$d/lemmas/$(basename "$lemmas")" 2>&1)
  status=$?
  set -e
  if (( status == 0 )); then
    echo "mutant $name: VERIFIED (the proof does not depend on it)" >&2
    failures=$((failures + 1))
    continue
  fi
  # Every theorem with an error; the expected one must be among them.
  rejected=$(grep -oE "$(basename "$lemmas" | sed 's/\./\\./g')\(([0-9]+)," <<<"$out" | grep -oE '[0-9]+' | sort -un |
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
echo "recovery executor mutations: every mutant rejected at its theorem"
