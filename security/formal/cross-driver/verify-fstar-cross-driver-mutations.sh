#!/usr/bin/env bash
set -euo pipefail

# F-2 cross-driver mutation checks. Run through
# `~/.local/opt/vela-tools/bin/vela-heavy security/formal/cross-driver/verify-fstar-cross-driver-mutations.sh`.
#
# Each mutant is a copy of the focused extraction under /tmp/vela-f2-cross-mut.
# The original extraction is never modified. For each mutant:
#   1. the checked-in composition theorem must FAIL (the removed check is
#      load-bearing);
#   2. a small witness module over the definitions must PASS and show the
#      corresponding counter becomes positive (the counter is not vacuous).
#
# A merged extraction directory per crate is used so the mutant module shadows
# the committed one without relying on include-path ordering.

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
want=${1:-all}
should_run() { [[ $want == all || $want == "$1" ]]; }
proof_root=$root/security/formal/cross-driver
composition=$proof_root/Vela_cross_driver_composition.fst
session=$root/serverVELA/vela-session-policy/proofs/fstar/extraction-f2-cross
enrollment=$root/serverVELA/vela-enrollment-policy/proofs/fstar/extraction-f2-cross
recovery=$root/serverVELA/vela-recovery-policy/proofs/fstar/extraction-f2-cross
mut=/tmp/vela-f2-cross-mut
logdir=$root/serverVELA/vela-session-policy/proofs/fstar/f2-cross-mutation-logs
if [[ $want == all ]]; then rm -rf "$logdir"; fi
mkdir -p "$logdir"

for command_name in fstar.exe z3-4.13.3 jq cargo; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is missing" >&2
    exit 1
  }
done

hax_lib_root=$(
  cd "$root/serverVELA/vela-session-policy"
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)
if [[ -z $hax_lib_root || ! -d $hax_lib_root ]]; then
  echo "could not locate hax-lib proof libraries" >&2
  exit 1
fi

base_args=(
  --cmi
  --cache_off
  --warn_error -331
  --z3rlimit 32000
  --z3version 4.13.3
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib'
  --include "$hax_lib_root/proof-libs/fstar/core"
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives"
  --include "$hax_lib_root/proofs/fstar/extraction"
)

prepare () {
  local name=$1
  local d=$mut/$name
  rm -rf "$d"
  mkdir -p "$d/session" "$d/enrollment" "$d/recovery" "$d/defs" "$d/witness"
  cp "$session"/*.fst "$d/session/"
  cp "$enrollment"/*.fst "$d/enrollment/"
  cp "$recovery"/*.fst "$d/recovery/"
  python3 - "$name" "$d" "$composition" <<'PY'
import sys, pathlib
name, d, composition = sys.argv[1], pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])

def patch(path, old, new):
    text = path.read_text()
    assert old in text, (path, old[:60])
    path.write_text(text.replace(old, new, 1))

if name == 'admission':
    patch(d/'session'/'Vela_session_policy.Revocation_driver.fst',
          '''let admission_is_authorized (o: t_AdmissionObservation) : bool =
  ~.o.f_jti_revoked && ~.o.f_device_revoked && o.f_account_present &&
  (~.o.f_device_scoped || o.f_device_row_active)''',
          '''let admission_is_authorized (o: t_AdmissionObservation) : bool = true''')
    text = (d/'session'/'Vela_session_policy.Revocation_driver.fst').read_text()
    start = text.index('let plan_admission (observation: t_AdmissionObservation)')
    end = text.index('// ── Rust conformance tests', start) if '// ── Rust conformance tests' in text[start:] else len(text)
    new = '''let plan_admission (observation: t_AdmissionObservation)
    : Prims.Pure t_AdmissionDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_AdmissionDecision = decision in
          admission_decision_matches_spec observation decision) =
  AdmissionDecision_Admit <: t_AdmissionDecision

'''
    (d/'session'/'Vela_session_policy.Revocation_driver.fst').write_text(text[:start]+new+text[end:])

if name == 'pair-opener':
    patch(d/'enrollment'/'Vela_enrollment_policy.Pairing_driver.fst',
          '''  let opener_active:bool =
    match observation.f_opener <: t_OpenerObservation with
    | OpenerObservation_Active  -> true
    | _ -> false
  in''',
          '''  let opener_active:bool = true in''')

if name == 'revoke-delete':
    patch(d/'session'/'Vela_session_policy.Revocation_driver.fst',
          '''    if ~.target.f_same_account
    then terminal driver (RevocationFailure_CrossAccount <: t_RevocationFailure)
    else''',
          '''    if false
    then terminal driver (RevocationFailure_CrossAccount <: t_RevocationFailure)
    else''')
    patch(d/'session'/'Vela_session_policy.Revocation_driver.fst',
          '  if actor.f_authenticated && actor.f_device_active\n',
          '  if true\n')
    patch(d/'session'/'Vela_session_policy.Deletion_driver.fst',
          '  if actor_active && actor.f_scoped_to_session_account\n',
          '  if actor_active\n')

if name == 'missing':
    patch(d/'session'/'Vela_session_policy.Login_driver.fst',
          '''  | ChallengeObservation_Observed (Vela_session_policy.Challenge.ChallengeConsumption_Missing ) ->
    terminal driver (LoginFailure_ChallengeMissing <: t_LoginFailure)''',
          '''  | ChallengeObservation_Observed (Vela_session_policy.Challenge.ChallengeConsumption_Missing ) ->
    transition ({
          driver with
          f_stage = LoginStage_Device <: t_LoginStage;
          f_challenge_accepted = true
        }
        <:
        t_LoginDriver)
      (LoginEffect_ObserveDevice <: t_LoginEffect)''')
    patch(d/'enrollment'/'Vela_enrollment_policy.Pairing_driver.fst',
          '''  | TakeObservation_Missing  -> terminal d (PairingFailure_CeremonyConsumed <: t_PairingFailure)''',
          '''  | TakeObservation_Missing  ->
    transition ({ d with f_stage = PairingStage_InFlight <: t_PairingStage; f_consumed = true }
        <:
        t_PairingDriver)
      (PairingEffect_InsertDevice <: t_PairingEffect)''')
    patch(d/'recovery'/'Vela_recovery_policy.Driver.fst',
          '''  | ConsumptionObservation_Missing  ->
    terminal driver (RedemptionFailure_GrantUnavailable <: t_RedemptionFailure)''',
          '''  | ConsumptionObservation_Missing  ->
    transition ({
          driver with
          f_stage = RedemptionStage_FinalPolicy <: t_RedemptionStage;
          f_consumed_matched = true
        }
        <:
        t_RedemptionDriver)
      (RedemptionEffect_FinalPolicy <: t_RedemptionEffect)''')

text = composition.read_text()
if name == 'guard':
    old = '''let insert_guard (w: world) (acct: nat) (epoch: i64) : bool =
  account_present w acct && account_active w acct && account_epoch w acct =. epoch'''
    new = '''let insert_guard (w: world) (acct: nat) (epoch: i64) : bool =
  account_active w acct && account_epoch w acct =. epoch'''
    assert old in text
    text = text.replace(old, new, 1)
    (d/'Vela_cross_driver_composition.fst').write_text(text)
marker = '// ── Driver-side facts used by the composition'
i = text.index(marker)
(d/'defs'/'Vela_cross_driver_composition.fst').write_text(text[:i])
PY
}

theorem_args () {
  local d=$mut/$1
  local comp=$composition
  if [[ $1 == guard ]]; then comp=$d/Vela_cross_driver_composition.fst; fi
  printf '%s\0' "${base_args[@]}" \
    --cache_dir "$d/cache-theorem" \
    --include "$d/session" --include "$d/enrollment" --include "$d/recovery" \
    "$comp"
}

witness_args () {
  local d=$mut/$1
  shift
  printf '%s\0' "${base_args[@]}" \
    --cache_dir "$d/cache-witness" \
    --include "$d/session" --include "$d/enrollment" --include "$d/recovery" \
    --include "$d/defs" --include "$d/witness" "$@"
}

run_fail () {
  local name=$1
  local log=$logdir/$name-theorem.log
  local -a args
  mapfile -d '' args < <(theorem_args "$name")
  if fstar.exe "${args[@]}" >"$log" 2>&1; then
    echo "MUTANT $name: composition unexpectedly verified" >&2
    return 1
  fi
  local line
  line=$(grep -m1 -E '^\* Error [0-9]+ at' "$log" || true)
  echo "$name|theorem|exit 1|$line" >> "$logdir/summary.txt"
  printf 'MUTANT %s: composition failed as expected: %s\n' "$name" "$line"
}

run_pass () {
  local name=$1
  local witness=$2
  local log=$logdir/$name-$(basename "$witness" .fst).log
  local -a args
  mapfile -d '' args < <(witness_args "$name" "$witness")
  if ! fstar.exe "${args[@]}" >"$log" 2>&1; then
    echo "MUTANT $name: witness $witness failed to verify" >&2
    tail -20 "$log" >&2
    return 1
  fi
  echo "$name|witness $(basename "$witness")|exit 0|counter reachable" >> "$logdir/summary.txt"
  printf 'MUTANT %s: witness %s verified\n' "$name" "$witness"
}

# ── admission ──────────────────────────────────────────────────────────────

if should_run admission; then
prepare admission
cat > "$mut/admission/witness/Vela_cross_admission_witness.fst" <<'EOF'
module Vela_cross_admission_witness
open Vela_session_policy.Revocation_driver
open Vela_cross_driver_composition
#set-options "--fuel 8 --ifuel 4"

let revoked_world : world =
  { initial with
    w_tokens = [{ tk_device = 0; tk_live = true; tk_jti = false }];
    w_devices = mark_revoked (mark_sentinel initial.w_devices 0) 0 }

let deleted_world : world =
  { initial with
    w_tokens = [{ tk_device = 0; tk_live = true; tk_jti = false }];
    w_devices = mark_account_deleted initial.w_devices 0;
    w_accounts = set_account_absent initial.w_accounts 0 }

let revoked_use = deliver_use revoked_world 0
let deleted_use = deliver_use deleted_world 0

let witness () : Lemma (
  revoked_use.w_admit_revoked > 0 /\
  deleted_use.w_admit_deleted > 0) = ()
EOF
run_fail admission
run_pass admission "$mut/admission/witness/Vela_cross_admission_witness.fst"
fi

# ── pair-opener ────────────────────────────────────────────────────────────

if should_run pair-opener; then
prepare pair-opener
cat > "$mut/pair-opener/witness/Vela_cross_pair_opener_witness.fst" <<'EOF'
module Vela_cross_pair_opener_witness
open Core_models
open Vela_enrollment_policy
open Vela_enrollment_policy.Pairing_driver
open Vela_cross_driver_composition
#set-options "--fuel 8 --ifuel 4"

let ctx : pair_ctx =
  { pc_session_account = 0; pc_session_device = 1;
    pc_declared = mk_i64 1; pc_signature_ok = true }

let start =
  begin_completion
    (GrantObservation_Present
       ({ f_user_matches = true; f_opener_matches = true }))

let opener_revoked_world : world =
  { initial with
    w_devices = mark_revoked initial.w_devices 1;
    w_reqs = [PairReq start.f_driver ctx false] }

let after = deliver_pair_preflight opener_revoked_world 0

let witness () : Lemma (after.w_pair_revoked_approver > 0) = ()
EOF
run_fail pair-opener
run_pass pair-opener "$mut/pair-opener/witness/Vela_cross_pair_opener_witness.fst"
fi

# ── guard ──────────────────────────────────────────────────────────────────

if should_run guard; then
prepare guard
cat > "$mut/guard/witness/Vela_cross_guard_witness.fst" <<'EOF'
module Vela_cross_guard_witness
open Core_models
open Vela_enrollment_policy
open Vela_enrollment_policy.Pairing_driver
open Vela_recovery_policy
open Vela_recovery_policy.Driver
open Vela_cross_driver_composition
#set-options "--fuel 8 --ifuel 4"

let pair_ctx0 : pair_ctx =
  { pc_session_account = 0; pc_session_device = 1;
    pc_declared = mk_i64 1; pc_signature_ok = true }

let inflight : t_PairingDriver =
  { f_ceremony = PairingCeremony_CompleteGrant;
    f_stage = PairingStage_InFlight;
    f_authorized = true; f_wrote = true; f_consumed = true;
    f_inserted = false; f_recorded = false; f_restored = false;
    f_succeeded = false; f_failed = false; f_grant_present = true;
    f_user_matches = true; f_opener_matches = true; f_claim_present = true;
    f_opener_active = true; f_signature_verified = true }

let rec_insert : t_RedemptionDriver =
  { f_stage = RedemptionStage_Insert;
    f_epoch = mk_i64 1; f_possession = true;
    f_consumed_matched = true; f_permit_issued = true;
    f_insert_attempted = true; f_insert_succeeded = false;
    f_restored = false }

let deleted_pair_world : world =
  { initial with
    w_accounts = set_account_absent initial.w_accounts 0;
    w_devices = mark_account_deleted initial.w_devices 0;
    w_pair = { initial.w_pair with pg_present = false };
    w_reqs = [PairReq inflight pair_ctx0 true] }

let deleted_rec_world : world =
  { initial with
    w_accounts = set_account_absent initial.w_accounts 0;
    w_devices = mark_account_deleted initial.w_devices 0;
    w_rec = { initial.w_rec with rg_present = false };
    w_reqs = [RecReq rec_insert] }

let pair_after = deliver_pair_insert deleted_pair_world 0
let rec_after = deliver_rec_insert deleted_rec_world 0

let witness () : Lemma (
  pair_after.w_pair_insert_deleted > 0 /\
  rec_after.w_rec_insert_deleted > 0) = ()
EOF
run_fail guard
run_pass guard "$mut/guard/witness/Vela_cross_guard_witness.fst"
fi

# ── revoke-delete ──────────────────────────────────────────────────────────

if should_run revoke-delete; then
prepare revoke-delete
cat > "$mut/revoke-delete/witness/Vela_cross_revoke_delete_witness.fst" <<'EOF'
module Vela_cross_revoke_delete_witness
open Core_models
open Vela_session_policy.Revocation_driver
open Vela_session_policy.Deletion_driver
open Vela_cross_driver_composition
#set-options "--fuel 8 --ifuel 4"

let revoke_ctx : actor_ctx =
  { ac_owner = 0; ac_active = true; ac_target_owner = 1 }

let observe_driver : t_RevocationDriver =
  (begin_revocation ({ f_authenticated = true; f_device_active = true })).f_driver

let cross_world : world =
  { initial with w_reqs = [RevokeReq observe_driver revoke_ctx 2] }

let cross_after =
  deliver_revoke cross_world 0
    (RevocationEvent_TargetObserved
       (DeviceLookupObservation_Present
          ({ f_same_account = false; f_already_revoked = false })))

let inactive_ctx : actor_ctx =
  { ac_owner = 0; ac_active = false; ac_target_owner = 0 }

let inactive_driver : t_RevocationDriver =
  (begin_revocation ({ f_authenticated = true; f_device_active = false })).f_driver

let inactive_world : world =
  { initial with w_reqs = [RevokeReq inactive_driver inactive_ctx 0] }

let inactive_after =
  deliver_revoke inactive_world 0
    (RevocationEvent_TargetObserved
       (DeviceLookupObservation_Present
          ({ f_same_account = true; f_already_revoked = false })))

let delete_ctx : del_ctx = { dc_session = 0; dc_target = 1 }
let delete_driver : t_DeletionDriver =
  { f_stage = DeletionStage_DeleteUsers;
    f_actor_active = true; f_same_account = true;
    f_devices_locked = true; f_devices_lockout_done = true;
    f_web_sessions_locked = true; f_web_sessions_lockout_done = true;
    f_transaction_open = true; f_transaction_started = true;
    f_users_deleted = false; f_committed = false;
    f_responded = false; f_failed = false }

let delete_world : world =
  { initial with w_reqs = [DeleteReq delete_driver delete_ctx] }

let delete_after = deliver_delete delete_world 0

let witness () : Lemma (
  cross_after.w_cross_account > 0 /\
  inactive_after.w_revoked_actor > 0 /\
  delete_after.w_cross_delete > 0) = ()
EOF
run_fail revoke-delete
run_pass revoke-delete "$mut/revoke-delete/witness/Vela_cross_revoke_delete_witness.fst"
fi

# ── missing ────────────────────────────────────────────────────────────────

if should_run missing; then
prepare missing
cat > "$mut/missing/witness/Vela_cross_missing_witness.fst" <<'EOF'
module Vela_cross_missing_witness
open Core_models
open Vela_session_policy.Challenge
open Vela_session_policy.Login_driver
open Vela_enrollment_policy
open Vela_enrollment_policy.Pairing_driver
open Vela_recovery_policy
open Vela_recovery_policy.Driver
open Vela_cross_driver_composition
#set-options "--fuel 8 --ifuel 4"

let login_l1 : t_LoginDriver =
  (Vela_session_policy.Login_driver.step (begin_login ()).f_driver
     (LoginEvent_ChallengeObserved
        (ChallengeObservation_Observed ChallengeConsumption_Missing))).f_driver
let login_l2 : t_LoginDriver =
  (Vela_session_policy.Login_driver.step login_l1
     (LoginEvent_DeviceObserved DeviceObservation_Present)).f_driver
let login_l3 : t_LoginDriver =
  (Vela_session_policy.Login_driver.step login_l2
     (LoginEvent_VerifierObserved VerifierObservation_Valid)).f_driver
let login_issue : t_LoginDriver =
  (Vela_session_policy.Login_driver.step login_l3
     (LoginEvent_BackoffResetObserved BackoffResetObservation_Reset)).f_driver

let login_world : world =
  { initial with w_reqs = [LoginReq login_issue 0 false 0] }

let login_after = deliver_login login_world 0

let pair_ctx0 : pair_ctx =
  { pc_session_account = 0; pc_session_device = 1;
    pc_declared = mk_i64 1; pc_signature_ok = true }

let preflight : t_CompletionPreflightObservation =
  { f_claim = ClaimMaterialObservation_Usable;
    f_capsule_valid = true; f_signature_field_valid = true;
    f_opener = OpenerObservation_Active;
    f_signature = SignatureObservation_Verified;
    f_account_epoch = mk_i64 1; f_declared_epoch = mk_i64 1;
    f_rotation_in_progress = false; f_account_epoch_active = true }

let pair_start =
  (begin_completion
     (GrantObservation_Present
        ({ f_user_matches = true; f_opener_matches = true }))).f_driver
let pair_account =
  (on_completion_account pair_start
     ({ f_account_query_ok = true; f_declared_epoch_positive = true;
        f_rekey_permitted = true })).f_driver
let pair_applied =
  (on_completion_ready_event pair_account preflight).f_driver
let pair_inflight =
  (on_ceremony_taken_event pair_applied TakeObservation_Missing).f_driver

let pair_world : world =
  { initial with
    w_pair = { initial.w_pair with pg_present = false; pg_devices = 1 };
    w_reqs = [PairReq pair_inflight pair_ctx0 true] }

let pair_after = deliver_pair_insert pair_world 0

let ready : Vela_recovery_policy.t_ReadyToConsume =
  { f_epoch = mk_i64 1; f_possession = true }
let rec_start = (begin_redemption ready).f_driver
let rec_policy =
  (on_grant_consumed rec_start ConsumptionObservation_Missing).f_driver
let rec_insert_drv =
  (on_final_policy_observed rec_policy
     (rec_policy_observation
        { initial with
          w_rec = { initial.w_rec with rg_present = false; rg_devices = 1 } }
        rec_policy)).f_driver

let rec_world : world =
  { initial with
    w_rec = { initial.w_rec with rg_present = false; rg_devices = 1 };
    w_reqs = [RecReq rec_insert_drv] }

let rec_after = deliver_rec_insert rec_world 0

let witness () : Lemma (
  login_after.w_double_login > 0 /\
  pair_after.w_double_pair > 0 /\
  rec_after.w_double_rec > 0) = ()
EOF
run_fail missing
run_pass missing "$mut/missing/witness/Vela_cross_missing_witness.fst"
fi

echo "mutation summary:"
cat "$logdir/summary.txt"
