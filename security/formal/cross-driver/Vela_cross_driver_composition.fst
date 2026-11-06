module Vela_cross_driver_composition

/// Concurrent composition of the *extracted* decision drivers that share one
/// account/device/token/grant world:
///
/// - `/auth/verify`            `Vela_session_policy.Login_driver`
/// - token use / middleware    `Vela_session_policy.Revocation_driver.plan_admission`
/// - `/device/revoke`          `Vela_session_policy.Revocation_driver`
/// - `/auth/logout`            `Vela_session_policy.Revocation_driver` (logout)
/// - `DELETE /account`         `Vela_session_policy.Deletion_driver`
/// - pairing completion        `Vela_enrollment_policy.Pairing_driver`
/// - recovery redemption       `Vela_recovery_policy.Driver`
///
/// A schedule is an arbitrary list of actions. Each request keeps its own
/// extracted driver value; every observation that is a fact about the shared
/// state (account existence/epoch/phase, device row/revoked/sentinel, challenge
/// consumption, grant availability, JTI marker) is computed from the *live*
/// world at the step where the handler observes it. Effects are applied in the
/// same step: the guarded SQL statements and the store's atomic take/get_del
/// are one step each.
///
/// Theorem (`cross_driver_composition_theorem`): for every schedule,
/// 1. no token is admitted for a device revoked (sentinel or durable row) or an
///    account absent at the admission step;
/// 2. no device is inserted by a pairing/recovery completion for an account
///    absent at the insert step, and no pairing insert follows a decision taken
///    while the approving device was revoked;
/// 3. no revoke effect is authorized by a spawn-time inactive actor or for a
///    cross-account target, and no deletion commits for an account other than
///    the session's;
/// 4. one token per login challenge, one device per pairing grant, one device
///    per recovery grant.
///
/// Assumptions (not proved here): SQL statements are linearizable and the
/// deletion's eight deletes + `users` delete commit atomically; sled `get_del`,
/// `set_ex` and `take_live_pair` are linearizable; the handler performs exactly
/// the effect the driver returns in the same step as its observation; devices
/// are not transferred between accounts; the middleware's admission decision
/// linearizes its four observations into one step (the read-then-decide gap
/// left before that point is the in-flight window); hybrid signatures, PASETO,
/// TTLs and multi-node visibility are trusted/outside.

open FStar.Mul
open Core_models
open Vela_session_policy.Challenge
open Vela_session_policy.Login_driver
open Vela_session_policy.Revocation_driver
open Vela_session_policy.Deletion_driver
open Vela_enrollment_policy
open Vela_enrollment_policy.Pairing_driver
open Vela_recovery_policy
open Vela_recovery_policy.Driver

let b2n (b: bool) : nat = if b then 1 else 0

// ── List helpers ───────────────────────────────────────────────────────────

let rec update (#a: Type) (l: list a) (i: nat) (x: a) : Tot (list a) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update t (i - 1) x

let rec update_length (#a: Type) (l: list a) (i: nat) (x: a)
  : Lemma (ensures (FStar.List.Tot.length (update l i x) = FStar.List.Tot.length l))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else update_length t (i - 1) x

let rec snoc (#a: Type) (l: list a) (x: a) : Tot (list a) (decreases l) =
  match l with
  | [] -> [x]
  | h :: t -> h :: snoc t x

let rec snoc_length (#a: Type) (l: list a) (x: a)
  : Lemma (ensures (FStar.List.Tot.length (snoc l x) = FStar.List.Tot.length l + 1))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> snoc_length t x

// ── Shared world ───────────────────────────────────────────────────────────

/// One `users` row. `ac_epoch` is `key_epoch`; `ac_active` is
/// `rekey_state IS NULL` (the phase is active, not freezing).
noeq type account = {
  ac_present: bool;
  ac_epoch: i64;
  ac_active: bool;
}

/// One `devices` row. `dv_present` is false once the deletion transaction
/// committed (the row is gone); `dv_revoked` is the durable `revoked = 1`;
/// `dv_sentinel` is the sled `device:revoked:` marker.
noeq type device = {
  dv_account: nat;
  dv_present: bool;
  dv_revoked: bool;
  dv_sentinel: bool;
}

/// One issued device token. `tk_live` becomes true only at the extracted
/// login driver's `TrackToken` effect; `tk_jti` is the `jti:revoked:` marker.
noeq type token = {
  tk_device: nat;
  tk_live: bool;
  tk_jti: bool;
}

/// The one login challenge (`get_del` key). `ch_consumed` is the destructive
/// take; a `WrongPurpose` take also consumes the key.
noeq type challenge = {
  ch_present: bool;
  ch_purpose_ok: bool;
  ch_consumed: bool;
}

/// The one pairing grant+claim pair (`take_live_pair` clears `pg_present`).
noeq type pair_grant = {
  pg_present: bool;
  pg_devices: nat;
  pg_account: nat;
  pg_opener: nat;
}

/// The one recovery enrollment grant (`get_del` clears `rg_present`).
noeq type rec_grant = {
  rg_present: bool;
  rg_devices: nat;
  rg_account: nat;
  rg_epoch: i64;
  rg_possession: bool;
}

noeq type actor_ctx = {
  ac_owner: nat;
  ac_active: bool;
  ac_target_owner: nat;
}

noeq type del_ctx = {
  dc_session: nat;
  dc_target: nat;
}

noeq type pair_ctx = {
  pc_session_account: nat;
  pc_session_device: nat;
  pc_declared: i64;
  pc_signature_ok: bool;
}

noeq type request =
  /// `dev`, whether a token slot was reserved at the accepted take, and its
  /// index in `w_tokens` (stable because tokens are only appended).
  | LoginReq : t_LoginDriver -> nat -> bool -> nat -> request
  | RevokeReq : t_RevocationDriver -> actor_ctx -> nat -> request
  | LogoutReq : t_LogoutDriver -> nat -> request
  | DeleteReq : t_DeletionDriver -> del_ctx -> request
  /// The last bool is the *live* opener activity observed when the completion
  /// preflight made its decision.
  | PairReq : t_PairingDriver -> pair_ctx -> bool -> request
  | RecReq : t_RedemptionDriver -> request

noeq type world = {
  w_accounts: list account;
  w_devices: list device;
  w_tokens: list token;
  w_challenge: challenge;
  w_pair: pair_grant;
  w_rec: rec_grant;
  w_reqs: list request;
  /// Accepted atomic challenge takes. At most one (the key is single-use).
  w_login_accepts: nat;
  /// A token was issued by a login whose take was not accepted.
  w_double_login: nat;
  /// A second device was inserted for the pairing grant.
  w_double_pair: nat;
  /// A second device was inserted for the recovery grant.
  w_double_rec: nat;
  /// A revoke effect was authorized for a cross-account target.
  w_cross_account: nat;
  /// A revoke effect was authorized by a spawn-time inactive actor.
  w_revoked_actor: nat;
  /// A deletion committed for an account other than the session's.
  w_cross_delete: nat;
  /// A token was admitted while its device was revoked.
  w_admit_revoked: nat;
  /// A token was admitted while its account was absent.
  w_admit_deleted: nat;
  /// A pairing insert landed for an absent account.
  w_pair_insert_deleted: nat;
  /// A recovery insert landed for an absent account.
  w_rec_insert_deleted: nat;
  /// A pairing insert followed a decision with a revoked opener.
  w_pair_revoked_approver: nat;
}

// ── Live accessors ─────────────────────────────────────────────────────────

let account_at (w: world) (i: nat) : account =
  if i < FStar.List.Tot.length w.w_accounts
  then FStar.List.Tot.index w.w_accounts i
  else { ac_present = false; ac_epoch = mk_i64 0; ac_active = false }

let device_at (w: world) (i: nat) : device =
  if i < FStar.List.Tot.length w.w_devices
  then FStar.List.Tot.index w.w_devices i
  else { dv_account = 0; dv_present = false; dv_revoked = false; dv_sentinel = false }

let token_at (w: world) (i: nat) : token =
  if i < FStar.List.Tot.length w.w_tokens
  then FStar.List.Tot.index w.w_tokens i
  else { tk_device = 0; tk_live = false; tk_jti = false }

let device_account (w: world) (i: nat) : nat = (device_at w i).dv_account
let device_present (w: world) (i: nat) : bool = (device_at w i).dv_present
let device_revoked (w: world) (i: nat) : bool = (device_at w i).dv_revoked
let device_sentinel (w: world) (i: nat) : bool = (device_at w i).dv_sentinel
let device_active (w: world) (i: nat) : bool =
  (device_at w i).dv_present && not (device_at w i).dv_revoked

let account_present (w: world) (i: nat) : bool = (account_at w i).ac_present
let account_active (w: world) (i: nat) : bool = (account_at w i).ac_active
let account_epoch (w: world) (i: nat) : i64 = (account_at w i).ac_epoch

let insert_guard (w: world) (acct: nat) (epoch: i64) : bool =
  account_present w acct && account_active w acct && account_epoch w acct =. epoch

// ── World mutations ────────────────────────────────────────────────────────

let mark_sentinel (devs: list device) (i: nat) : list device =
  if i < FStar.List.Tot.length devs
  then update devs i ({ FStar.List.Tot.index devs i with dv_sentinel = true })
  else devs

let mark_revoked (devs: list device) (i: nat) : list device =
  if i < FStar.List.Tot.length devs
  then update devs i ({ FStar.List.Tot.index devs i with dv_revoked = true })
  else devs

let rec mark_device_jtis (tokens: list token) (dev: nat) : Tot (list token) (decreases tokens) =
  match tokens with
  | [] -> []
  | tk :: rest ->
      (if tk.tk_device = dev then { tk with tk_jti = true } else tk)
      :: mark_device_jtis rest dev

let rec mark_account_sentinels (devs: list device) (acct: nat) : Tot (list device) (decreases devs) =
  match devs with
  | [] -> []
  | dv :: rest ->
      (if dv.dv_account = acct then { dv with dv_sentinel = true } else dv)
      :: mark_account_sentinels rest acct

let rec mark_account_revoked (devs: list device) (acct: nat) : Tot (list device) (decreases devs) =
  match devs with
  | [] -> []
  | dv :: rest ->
      (if dv.dv_account = acct then { dv with dv_revoked = true } else dv)
      :: mark_account_revoked rest acct

let rec mark_account_deleted (devs: list device) (acct: nat) : Tot (list device) (decreases devs) =
  match devs with
  | [] -> []
  | dv :: rest ->
      (if dv.dv_account = acct then { dv with dv_present = false } else dv)
      :: mark_account_deleted rest acct

let device_account_aux (devs: list device) (i: nat) : nat =
  if i < FStar.List.Tot.length devs
  then (FStar.List.Tot.index devs i).dv_account
  else 0

let rec mark_account_jtis (tokens: list token) (devs: list device) (acct: nat)
  : Tot (list token) (decreases tokens) =
  match tokens with
  | [] -> []
  | tk :: rest ->
      (if device_account_aux devs tk.tk_device = acct
       then { tk with tk_jti = true }
       else tk)
      :: mark_account_jtis rest devs acct

let mark_token_live (tokens: list token) (i: nat) : list token =
  if i < FStar.List.Tot.length tokens
  then update tokens i ({ FStar.List.Tot.index tokens i with tk_live = true })
  else tokens

let mark_token_jti (tokens: list token) (i: nat) : list token =
  if i < FStar.List.Tot.length tokens
  then update tokens i ({ FStar.List.Tot.index tokens i with tk_jti = true })
  else tokens

let set_account_absent (accts: list account) (i: nat) : list account =
  if i < FStar.List.Tot.length accts
  then update accts i ({ FStar.List.Tot.index accts i with ac_present = false })
  else accts

// ── Per-request invariant ──────────────────────────────────────────────────

let request_ok (r: request) : prop =
  match r with
  | LoginReq d _dev has _idx ->
      login_state_is_sound d /\
      (d.f_challenge_accepted ==> has)
  | RevokeReq d actor _target ->
      revocation_state_is_sound d /\
      (d.f_same_account ==> actor.ac_owner = actor.ac_target_owner) /\
      (d.f_actor_active = actor.ac_active)
  | LogoutReq d _ -> logout_state_is_sound d
  | DeleteReq d ctx ->
      deletion_state_is_sound d /\
      (d.f_same_account ==> ctx.dc_session = ctx.dc_target)
  | PairReq d _ctx opener_live ->
      pairing_state_is_sound d /\
      d.f_ceremony = PairingCeremony_CompleteGrant /\
      ((match d.f_stage <: t_PairingStage with
        | PairingStage_Applied -> true
        | PairingStage_InFlight -> true
        | PairingStage_WroteResult -> true
        | _ -> false) ==> opener_live)
  | RecReq d -> redemption_state_is_sound d

let rec all_requests_ok (l: list request) : Tot prop (decreases l) =
  match l with
  | [] -> True
  | r :: rest -> request_ok r /\ all_requests_ok rest

let rec all_requests_ok_index (l: list request) (i: nat)
  : Lemma
    (requires (all_requests_ok l /\ i < FStar.List.Tot.length l))
    (ensures (request_ok (FStar.List.Tot.index l i)))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else all_requests_ok_index t (i - 1)

let rec all_requests_ok_update (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (all_requests_ok l /\ request_ok r))
    (ensures (all_requests_ok (update l i r)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else all_requests_ok_update t (i - 1) r

let all_requests_ok_cons (r: request) (l: list request)
  : Lemma
    (requires (request_ok r /\ all_requests_ok l))
    (ensures (all_requests_ok (r :: l))) = ()

let rec all_requests_ok_update2 (l: list request) (i: nat) (x: request) (y: request)
  : Lemma
    (requires (all_requests_ok l /\ request_ok y))
    (ensures (all_requests_ok (update (update l i x) i y)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else all_requests_ok_update2 t (i - 1) x y

// ── In-flight / held counts ────────────────────────────────────────────────

let pair_inflight (r: request) : bool =
  match r with
  | PairReq d _ _ ->
      (match d.f_stage <: t_PairingStage with
       | PairingStage_InFlight -> true
       | _ -> false)
  | _ -> false

let rec count_pair_inflight (l: list request) : Tot nat (decreases l) =
  match l with
  | [] -> 0
  | r :: rest -> b2n (pair_inflight r) + count_pair_inflight rest

let rec count_pair_inflight_update (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (i < FStar.List.Tot.length l))
    (ensures (
      count_pair_inflight (update l i r) + b2n (pair_inflight (FStar.List.Tot.index l i))
      = count_pair_inflight l + b2n (pair_inflight r)))
    (decreases l) =
  match l with
  | [] -> ()
  | h :: t -> if i = 0 then () else count_pair_inflight_update t (i - 1) r

let rec count_pair_inflight_update_le (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (i < FStar.List.Tot.length l /\ b2n (pair_inflight r) <= b2n (pair_inflight (FStar.List.Tot.index l i))))
    (ensures (count_pair_inflight (update l i r) <= count_pair_inflight l))
    (decreases l) =
  match l with
  | [] -> ()
  | h :: t -> if i = 0 then () else count_pair_inflight_update_le t (i - 1) r

let rec count_pair_inflight_update_one (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (
      i < FStar.List.Tot.length l /\
      not (pair_inflight (FStar.List.Tot.index l i)) /\
      pair_inflight r))
    (ensures (count_pair_inflight (update l i r) = count_pair_inflight l + 1))
    (decreases l) =
  match l with
  | [] -> ()
  | h :: t ->
      if i = 0
      then ()
      else count_pair_inflight_update_one t (i - 1) r

let rec count_pair_inflight_update_zero (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (
      i < FStar.List.Tot.length l /\
      pair_inflight (FStar.List.Tot.index l i) /\
      not (pair_inflight r)))
    (ensures (count_pair_inflight (update l i r) + 1 = count_pair_inflight l))
    (decreases l) =
  match l with
  | [] -> ()
  | h :: t ->
      if i = 0
      then ()
      else count_pair_inflight_update_zero t (i - 1) r

let rec_held (r: request) : bool =
  match r with
  | RecReq d ->
      (match d.f_stage <: t_RedemptionStage with
       | RedemptionStage_FinalPolicy -> true
       | RedemptionStage_Insert -> true
       | RedemptionStage_Recheck -> true
       | _ -> false)
  | _ -> false

let rec count_rec_held (l: list request) : Tot nat (decreases l) =
  match l with
  | [] -> 0
  | r :: rest -> b2n (rec_held r) + count_rec_held rest

let rec count_rec_held_update (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (i < FStar.List.Tot.length l))
    (ensures (
      count_rec_held (update l i r) + b2n (rec_held (FStar.List.Tot.index l i))
      = count_rec_held l + b2n (rec_held r)))
    (decreases l) =
  match l with
  | [] -> ()
  | h :: t -> if i = 0 then () else count_rec_held_update t (i - 1) r

// ── The shared invariant ───────────────────────────────────────────────────

let inv (w: world) : prop =
  all_requests_ok w.w_reqs /\
  w.w_login_accepts <= b2n w.w_challenge.ch_consumed /\
  FStar.List.Tot.length w.w_tokens <= w.w_login_accepts + w.w_double_login /\
  w.w_double_login = 0 /\
  w.w_cross_account = 0 /\
  w.w_revoked_actor = 0 /\
  w.w_cross_delete = 0 /\
  w.w_admit_revoked = 0 /\
  w.w_admit_deleted = 0 /\
  b2n w.w_pair.pg_present + w.w_pair.pg_devices + count_pair_inflight w.w_reqs <= 1 /\
  w.w_double_pair = 0 /\
  w.w_pair_insert_deleted = 0 /\
  w.w_pair_revoked_approver = 0 /\
  b2n w.w_rec.rg_present + w.w_rec.rg_devices + count_rec_held w.w_reqs <= 1 /\
  w.w_double_rec = 0 /\
  w.w_rec_insert_deleted = 0

// ── Observations derived from the live world ───────────────────────────────

let challenge_observation (w: world) : t_ChallengeObservation =
  if w.w_challenge.ch_present && not w.w_challenge.ch_consumed
  then
    (if w.w_challenge.ch_purpose_ok
     then ChallengeObservation_Observed ChallengeConsumption_Accepted
     else ChallengeObservation_Observed ChallengeConsumption_WrongPurpose)
  else ChallengeObservation_Observed ChallengeConsumption_Missing

let device_observation (w: world) (dev: nat) : t_DeviceObservation =
  if device_active w dev then DeviceObservation_Present else DeviceObservation_Absent

let login_event (w: world) (d: t_LoginDriver) (dev: nat) : t_LoginEvent =
  match d.f_stage <: t_LoginStage with
  | LoginStage_Challenge -> LoginEvent_ChallengeObserved (challenge_observation w)
  | LoginStage_Device -> LoginEvent_DeviceObserved (device_observation w dev)
  | LoginStage_Verify -> LoginEvent_VerifierObserved VerifierObservation_Valid
  | LoginStage_Reset -> LoginEvent_BackoffResetObserved BackoffResetObservation_Reset
  | LoginStage_Issue -> LoginEvent_TokenIssued TokenIssueObservation_Issued
  | LoginStage_Track -> LoginEvent_TokenTracked TokenTrackObservation_Tracked
  | _ -> LoginEvent_ChallengeObserved (ChallengeObservation_Observed ChallengeConsumption_Missing)

let target_observation (w: world) (actor: actor_ctx) (target: nat)
  : t_DeviceLookupObservation =
  if target < FStar.List.Tot.length w.w_devices && device_present w target
  then
    DeviceLookupObservation_Present
      ({ f_same_account = (actor.ac_owner = actor.ac_target_owner);
         f_already_revoked = device_revoked w target })
  else DeviceLookupObservation_Absent

// ── Login delivery ─────────────────────────────────────────────────────────

let deliver_login (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | LoginReq d dev has idx ->
        if login_state_is_sound d
        then
          let e = login_event w d dev in
          let t = Vela_session_policy.Login_driver.step d e in
          (match d.f_stage <: t_LoginStage with
           | LoginStage_Challenge ->
               let ch = w.w_challenge in
               let taken = ch.ch_present && not ch.ch_consumed in
               let accepted = taken && ch.ch_purpose_ok in
               let nr =
                 (if accepted
                  then LoginReq t.f_driver dev true
                         (FStar.List.Tot.length w.w_tokens)
                  else LoginReq t.f_driver dev has idx) in
               { w with
                 w_challenge = (if taken then { ch with ch_consumed = true } else ch);
                 w_login_accepts = w.w_login_accepts + b2n accepted;
                 w_tokens =
                   (if accepted
                    then
                      snoc w.w_tokens
                        ({ tk_device = dev; tk_live = false; tk_jti = false })
                    else w.w_tokens);
                 w_reqs = update w.w_reqs i nr }
           | LoginStage_Issue ->
               if has
               then
                 { w with
                   w_tokens = mark_token_live w.w_tokens idx;
                   w_reqs = update w.w_reqs i (LoginReq t.f_driver dev has idx) }
               else
                 { w with
                   w_tokens =
                     snoc w.w_tokens
                       ({ tk_device = dev; tk_live = true; tk_jti = false });
                   w_double_login = w.w_double_login + 1;
                   w_reqs =
                     update w.w_reqs i
                       (LoginReq t.f_driver dev true
                          (FStar.List.Tot.length w.w_tokens)) }
           | _ ->
               { w with
                 w_reqs = update w.w_reqs i (LoginReq t.f_driver dev has idx) })
        else w
    | _ -> w
  else w

// ── Revocation / logout delivery ───────────────────────────────────────────

let is_revoke_effect (e: t_RevocationEffect) : bool =
  match e <: t_RevocationEffect with
  | RevocationEffect_LockoutDevice -> true
  | RevocationEffect_RecordRevocation -> true
  | _ -> false

let apply_revoke_effect (w: world) (target: nat) (e: t_RevocationEffect) : world =
  match e <: t_RevocationEffect with
  | RevocationEffect_LockoutDevice ->
      { w with
        w_devices = mark_sentinel w.w_devices target;
        w_tokens = mark_device_jtis w.w_tokens target }
  | RevocationEffect_RecordRevocation ->
      { w with w_devices = mark_revoked w.w_devices target }
  | _ -> w

let count_revoke_authorization (w: world) (actor: actor_ctx) (e: t_RevocationEffect) : world =
  if is_revoke_effect e
  then
    { w with
      w_cross_account =
        w.w_cross_account + (if actor.ac_owner <> actor.ac_target_owner then 1 else 0);
      w_revoked_actor = w.w_revoked_actor + (if actor.ac_active then 0 else 1) }
  else w

let deliver_revoke (w: world) (i: nat) (e: t_RevocationEvent) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d actor target ->
        if revocation_state_is_sound d
        then
          let t = Vela_session_policy.Revocation_driver.step d e in
          let w1 =
            { w with w_reqs = update w.w_reqs i (RevokeReq t.f_driver actor target) } in
          count_revoke_authorization
            (apply_revoke_effect w1 target t.f_effect) actor t.f_effect
        else w
    | _ -> w
  else w

let deliver_logout (w: world) (i: nat) (obs: t_LogoutObservation) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | LogoutReq d token_index ->
        if logout_state_is_sound d
        then
          let t = logout_step d obs in
          let w1 =
            { w with w_reqs = update w.w_reqs i (LogoutReq t.f_driver token_index) } in
          (match t.f_effect <: t_LogoutEffect with
           | LogoutEffect_Complete ->
               { w1 with w_tokens = mark_token_jti w1.w_tokens token_index }
           | _ -> w1)
        else w
    | _ -> w
  else w

// ── Deletion delivery ──────────────────────────────────────────────────────

let commit_deletion (w: world) (ctx: del_ctx) : world =
  { w with
    w_accounts = set_account_absent w.w_accounts ctx.dc_target;
    w_devices = mark_account_deleted w.w_devices ctx.dc_target;
    w_tokens = mark_account_jtis w.w_tokens w.w_devices ctx.dc_target }

let is_commit_effect (e: t_DeletionEffect) : bool =
  match e <: t_DeletionEffect with
  | DeletionEffect_CommitTransaction -> true
  | _ -> false

let apply_delete_effect (w: world) (ctx: del_ctx) (e: t_DeletionEffect) : world =
  match e <: t_DeletionEffect with
  | DeletionEffect_LockoutDevices | DeletionEffect_LockoutWebSessions ->
      { w with
        w_devices = mark_account_sentinels w.w_devices ctx.dc_target;
        w_tokens = mark_account_jtis w.w_tokens w.w_devices ctx.dc_target }
  | DeletionEffect_CommitTransaction -> commit_deletion w ctx
  | _ -> w

let count_delete_authorization (w: world) (ctx: del_ctx) (e: t_DeletionEffect) : world =
  if is_commit_effect e
  then
    { w with
      w_cross_delete =
        w.w_cross_delete + (if ctx.dc_session <> ctx.dc_target then 1 else 0) }
  else w

let delete_event (w: world) (d: t_DeletionDriver) (ctx: del_ctx) : t_DeletionEvent =
  match d.f_stage <: t_DeletionStage with
  | DeletionStage_ObserveDevices -> DeletionEvent_DevicesScanned ScanObservation_Rows
  | DeletionStage_LockoutDevices -> DeletionEvent_DeviceLockout
      Vela_session_policy.Deletion_driver.LockoutObservation_Applied
  | DeletionStage_ObserveWebSessions ->
      DeletionEvent_WebSessionsScanned ScanObservation_Rows
  | DeletionStage_LockoutWebSessions ->
      DeletionEvent_WebSessionLockout
        Vela_session_policy.Deletion_driver.LockoutObservation_Applied
  | DeletionStage_BeginTransaction ->
      DeletionEvent_Transaction TransactionObservation_Begun
  | DeletionStage_DeleteTable _ -> DeletionEvent_TableDeleted TableDeleteObservation_Deleted
  | DeletionStage_DeleteUsers ->
      DeletionEvent_UsersDeleted
        (if account_present w ctx.dc_target
         then UsersDeleteObservation_Deleted
         else UsersDeleteObservation_Absent)
  | DeletionStage_Commit -> DeletionEvent_Commit CommitObservation_Committed
  | DeletionStage_Done -> DeletionEvent_DevicesScanned ScanObservation_Rows

let deliver_delete (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | DeleteReq d ctx ->
        if deletion_state_is_sound d
        then
          (match d.f_stage <: t_DeletionStage with
           | DeletionStage_Done -> w
           | _ ->
               let e = delete_event w d ctx in
               let t = Vela_session_policy.Deletion_driver.step d e in
               let w1 =
                 { w with w_reqs = update w.w_reqs i (DeleteReq t.f_driver ctx) } in
               count_delete_authorization
                 (apply_delete_effect w1 ctx t.f_effect) ctx t.f_effect)
        else w
    | _ -> w
  else w

// ── Pairing completion delivery ────────────────────────────────────────────

let grant_observation (w: world) (ctx: pair_ctx) : t_GrantObservation =
  if w.w_pair.pg_present
  then
    GrantObservation_Present
      ({ f_user_matches = (ctx.pc_session_account = w.w_pair.pg_account);
         f_opener_matches = (ctx.pc_session_device = w.w_pair.pg_opener) })
  else GrantObservation_Absent

let pair_account_observation (w: world) (ctx: pair_ctx)
  : t_CompletionAccountObservation =
  ({ f_account_query_ok = account_present w w.w_pair.pg_account;
     f_declared_epoch_positive = (ctx.pc_declared >=. mk_i64 1);
     f_rekey_permitted = account_active w w.w_pair.pg_account })

let pair_opener_active (w: world) (ctx: pair_ctx) : bool =
  device_active w ctx.pc_session_device

let pair_preflight_observation (w: world) (ctx: pair_ctx)
  : t_CompletionPreflightObservation =
  let a = account_at w w.w_pair.pg_account in
  let opener_active = pair_opener_active w ctx in
  ({ f_claim =
       (if w.w_pair.pg_present
        then ClaimMaterialObservation_Usable
        else ClaimMaterialObservation_Missing);
     f_capsule_valid = true;
     f_signature_field_valid = true;
     f_opener =
       (if opener_active then OpenerObservation_Active
        else OpenerObservation_Inactive);
     f_signature =
       (if ctx.pc_signature_ok then SignatureObservation_Verified
        else SignatureObservation_Failed);
     f_account_epoch = (if a.ac_present then a.ac_epoch else mk_i64 0);
     f_declared_epoch = ctx.pc_declared;
     f_rotation_in_progress = not a.ac_active;
     f_account_epoch_active =
       (a.ac_present && a.ac_active && a.ac_epoch =. ctx.pc_declared &&
        ctx.pc_declared >=. mk_i64 1) })

let take_observation (w: world) : t_TakeObservation =
  if w.w_pair.pg_present
  then TakeObservation_Taken
    ({ f_grant_matches = true; f_claim_matches = true })
  else TakeObservation_Missing

let deliver_pair_account (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | PairReq d ctx opener_live ->
        if pairing_state_is_sound d
        then
          let t = on_completion_account d (pair_account_observation w ctx) in
          { w with w_reqs = update w.w_reqs i (PairReq t.f_driver ctx opener_live) }
        else w
    | _ -> w
  else w

let deliver_pair_preflight (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | PairReq d ctx opener_live ->
        if pairing_state_is_sound d
        then
          let live = pair_opener_active w ctx in
          let t = on_completion_ready_event d (pair_preflight_observation w ctx) in
          let take =
            (match t.f_effect <: t_PairingEffect with
             | PairingEffect_TakeCeremony -> true
             | _ -> false) in
          let new_opener = if take then live else opener_live in
          let revoked_approver = take && not live in
          let w1 =
            { w with
              w_reqs = update w.w_reqs i (PairReq t.f_driver ctx new_opener);
              w_pair_revoked_approver =
                w.w_pair_revoked_approver + b2n revoked_approver } in
          w1
        else w
    | _ -> w
  else w

let deliver_pair_take (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | PairReq d ctx opener_live ->
        if pairing_state_is_sound d
        then
          (match d.f_stage <: t_PairingStage with
           | PairingStage_Applied ->
               let obs = take_observation w in
               let t = on_ceremony_taken_event d obs in
               let taken =
                 (match t.f_effect <: t_PairingEffect with
                  | PairingEffect_InsertDevice -> true
                  | _ -> false) in
               { w with
                 w_reqs = update w.w_reqs i (PairReq t.f_driver ctx opener_live);
                 w_pair = ({ w.w_pair with pg_present = (w.w_pair.pg_present && not taken) }) }
           | _ -> w)
        else w
    | _ -> w
  else w

let deliver_pair_insert (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | PairReq d ctx opener_live ->
        if pairing_state_is_sound d
        then
          (match d.f_stage <: t_PairingStage with
           | PairingStage_InFlight ->
               let ok =
                 insert_guard w w.w_pair.pg_account ctx.pc_declared in
               let obs =
                 (if ok then DeviceInsertObservation_Inserted
                  else DeviceInsertObservation_Skipped) in
               let t = on_device_inserted_event d obs in
               let inserted =
                 (match t.f_effect <: t_PairingEffect with
                  | PairingEffect_WriteResult -> true
                  | _ -> false) in
               let w1 =
                 { w with
                   w_reqs = update w.w_reqs i (PairReq t.f_driver ctx opener_live);
                   w_pair =
                     ({ w.w_pair with
                        pg_present =
                          (if inserted then false else true);
                        pg_devices =
                          w.w_pair.pg_devices + b2n inserted });
                   w_double_pair =
                     w.w_double_pair + (if inserted && w.w_pair.pg_devices > 0 then 1 else 0);
                   w_pair_insert_deleted =
                     w.w_pair_insert_deleted +
                       (if inserted && not (account_present w w.w_pair.pg_account) then 1 else 0);
                   w_pair_revoked_approver =
                     w.w_pair_revoked_approver +
                       (if inserted && not opener_live then 1 else 0) } in
               w1
           | _ -> w)
        else w
    | _ -> w
  else w

// ── Recovery redemption delivery ───────────────────────────────────────────

let consume_observation (w: world) : t_ConsumptionObservation =
  if w.w_rec.rg_present
  then
    ConsumptionObservation_Present
      ({ f_key_epoch = w.w_rec.rg_epoch;
         f_possession = w.w_rec.rg_possession;
         f_matches_observed_grant = true })
  else ConsumptionObservation_Missing

let rec_policy_observation (w: world) (d: t_RedemptionDriver)
  : t_FinalPolicyObservation =
  let a = account_at w w.w_rec.rg_account in
  let enrollment =
    ({ f_grant_present = true;
       f_grant_consumed = true;
       f_consumed_matches_observed = true;
       f_account_present = a.ac_present;
       f_grant_possession = d.f_possession;
       f_grant_epoch = d.f_epoch;
       f_stored_epoch = Core_models.Option.Option_Some d.f_epoch;
       f_account_epoch_active =
         (a.ac_present && a.ac_active && a.ac_epoch =. d.f_epoch);
       f_credential_id_matches = true;
       f_commitment_len = mk_usize 1;
       f_hybrid_ek_len = v_HYBRID_EK_LEN;
       f_hybrid_vk_len = v_HYBRID_VK_LEN }) in
  let rekey =
    (if a.ac_present && a.ac_active && a.ac_epoch =. d.f_epoch
     then RekeyObservation_Permit ({ f_epoch = a.ac_epoch })
     else RekeyObservation_Reject) in
  ({ f_enrollment = enrollment; f_rekey = rekey })

let deliver_rec_consume (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RecReq d ->
        if redemption_state_is_sound d
        then
          (match d.f_stage <: t_RedemptionStage with
           | RedemptionStage_Consume ->
               let t = on_grant_consumed d (consume_observation w) in
               let restore =
                 (match t.f_effect <: t_RedemptionEffect with
                  | RedemptionEffect_RestoreAndFail _ -> true
                  | _ -> false) in
               { w with
                 w_reqs = update w.w_reqs i (RecReq t.f_driver);
                 w_rec = ({ w.w_rec with rg_present = restore }) }
           | _ -> w)
        else w
    | _ -> w
  else w

let deliver_rec_policy (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RecReq d ->
        if redemption_state_is_sound d
        then
          (match d.f_stage <: t_RedemptionStage with
           | RedemptionStage_FinalPolicy ->
               let t = on_final_policy_observed d (rec_policy_observation w d) in
               let restore =
                 (match t.f_effect <: t_RedemptionEffect with
                  | RedemptionEffect_RestoreAndFail _ -> true
                  | _ -> false) in
               { w with
                 w_reqs = update w.w_reqs i (RecReq t.f_driver);
                 w_rec = ({ w.w_rec with rg_present = restore }) }
           | _ -> w)
        else w
    | _ -> w
  else w

let deliver_rec_insert (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RecReq d ->
        if redemption_state_is_sound d
        then
          (match d.f_stage <: t_RedemptionStage with
           | RedemptionStage_Insert ->
               let ok = insert_guard w w.w_rec.rg_account d.f_epoch in
               let obs =
                 (if ok then InsertObservation_Inserted
                  else InsertObservation_Skipped) in
               let t = on_insert_completed d obs in
               let inserted =
                 (match t.f_effect <: t_RedemptionEffect with
                  | RedemptionEffect_Complete -> true
                  | _ -> false) in
               { w with
                 w_reqs = update w.w_reqs i (RecReq t.f_driver);
                 w_rec =
                   ({ w.w_rec with
                      rg_devices = w.w_rec.rg_devices + b2n inserted });
                 w_double_rec =
                   w.w_double_rec +
                     (if inserted && w.w_rec.rg_devices > 0 then 1 else 0);
                 w_rec_insert_deleted =
                   w.w_rec_insert_deleted +
                     (if inserted && not (account_present w w.w_rec.rg_account)
                      then 1 else 0) }
           | _ -> w)
        else w
    | _ -> w
  else w

let rec_recheck_observation (w: world) (d: t_RedemptionDriver)
  : t_AuthorityRecheckObservation =
  if not (account_present w w.w_rec.rg_account)
  then AuthorityRecheckObservation_AccountAbsent
  else if account_active w w.w_rec.rg_account && account_epoch w w.w_rec.rg_account =. d.f_epoch
  then AuthorityRecheckObservation_CommitmentRevoked
  else AuthorityRecheckObservation_StillRotating

let deliver_rec_recheck (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RecReq d ->
        if redemption_state_is_sound d
        then
          (match d.f_stage <: t_RedemptionStage with
           | RedemptionStage_Recheck ->
               let t = on_authority_rechecked d (rec_recheck_observation w d) in
               let restore =
                 (match t.f_effect <: t_RedemptionEffect with
                  | RedemptionEffect_RestoreAndFail _ -> true
                  | _ -> false) in
               { w with
                 w_reqs = update w.w_reqs i (RecReq t.f_driver);
                 w_rec = ({ w.w_rec with rg_present = restore }) }
           | _ -> w)
        else w
    | _ -> w
  else w

// ── Admission ──────────────────────────────────────────────────────────────

let admission_observation (w: world) (tk: token) : t_AdmissionObservation =
  ({ f_jti_revoked = tk.tk_jti;
     f_device_revoked = device_sentinel w tk.tk_device;
     f_account_present =
       account_present w (device_account w tk.tk_device);
     f_device_row_active = device_active w tk.tk_device;
     f_device_scoped = true })

let deliver_use (w: world) (token_index: nat) : world =
  if token_index < FStar.List.Tot.length w.w_tokens
  then
    let tk = FStar.List.Tot.index w.w_tokens token_index in
    if not tk.tk_live then w
    else
      let observation = admission_observation w tk in
      match plan_admission observation <: t_AdmissionDecision with
      | AdmissionDecision_Admit ->
          let sent = device_sentinel w tk.tk_device in
          let row_active = device_active w tk.tk_device in
          let acct_present =
            account_present w (device_account w tk.tk_device) in
          { w with
            w_admit_revoked =
              w.w_admit_revoked + (if sent || not row_active then 1 else 0);
            w_admit_deleted =
              w.w_admit_deleted + (if not acct_present then 1 else 0) }
      | AdmissionDecision_Reject _ -> w
  else w

// ── Arbitrary schedules ────────────────────────────────────────────────────

type action =
  | SpawnLogin : nat -> action
  | LoginStep : nat -> action
  | SpawnRevoke : nat -> nat -> action
  | LookupRevoke : nat -> action
  | LockoutRevoke : nat -> action
  | RecordRevoke : nat -> action
  | CascadeRevoke : nat -> action
  | SpawnLogout : nat -> action
  | LogoutStep : nat -> action
  | SpawnDelete : nat -> nat -> action
  | DeleteStep : nat -> action
  | SpawnPair : nat -> nat -> i64 -> bool -> action
  | PairAccount : nat -> action
  | PairPreflight : nat -> action
  | PairTake : nat -> action
  | PairInsert : nat -> action
  | SpawnRec : action
  | RecConsume : nat -> action
  | RecPolicy : nat -> action
  | RecInsert : nat -> action
  | RecRecheck : nat -> action
  | Use : nat -> action

let spawn_login (w: world) (dev: nat) : world =
  { w with
    w_reqs =
      LoginReq (begin_login ()).f_driver dev false 0 :: w.w_reqs }

let spawn_revoke (w: world) (actor: nat) (target: nat) : world =
  if actor < FStar.List.Tot.length w.w_devices &&
     target < FStar.List.Tot.length w.w_devices
  then
    let active = device_active w actor in
    let start =
      begin_revocation
        ({ f_authenticated = true; f_device_active = active }) in
    { w with
      w_reqs =
        RevokeReq start.f_driver
          ({ ac_owner = device_account w actor;
             ac_active = active;
             ac_target_owner = device_account w target }) target
        :: w.w_reqs }
  else w

let spawn_logout (w: world) (token_index: nat) : world =
  if token_index < FStar.List.Tot.length w.w_tokens
  then
    { w with w_reqs = LogoutReq (begin_logout ()).f_driver token_index :: w.w_reqs }
  else w

let spawn_delete (w: world) (actor: nat) (target: nat) : world =
  if actor < FStar.List.Tot.length w.w_devices
  then
    let session = device_account w actor in
    let active = device_active w actor in
    let start =
      begin_deletion
        ({ f_authenticated = true;
           f_device_active = active;
           f_scoped_to_session_account = (session = target) }) in
    { w with
      w_reqs =
        DeleteReq start.f_driver
          ({ dc_session = session; dc_target = target }) :: w.w_reqs }
  else w

let spawn_pair (w: world) (sacc: nat) (sdev: nat) (declared: i64) (sig_ok: bool)
  : world =
  let ctx =
    ({ pc_session_account = sacc; pc_session_device = sdev;
       pc_declared = declared; pc_signature_ok = sig_ok }) in
  let start = begin_completion (grant_observation w ctx) in
  { w with w_reqs = PairReq start.f_driver ctx false :: w.w_reqs }

let spawn_rec (w: world) : world =
  let ready : Vela_recovery_policy.t_ReadyToConsume =
    { f_epoch = w.w_rec.rg_epoch; f_possession = w.w_rec.rg_possession } in
  { w with w_reqs = RecReq (begin_redemption ready).f_driver :: w.w_reqs }

let world_step (w: world) (a: action) : world =
  match a with
  | SpawnLogin dev -> spawn_login w dev
  | LoginStep i -> deliver_login w i
  | SpawnRevoke actor target -> spawn_revoke w actor target
  | LookupRevoke i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        (match FStar.List.Tot.index w.w_reqs i with
         | RevokeReq _ actor target ->
             deliver_revoke w i
               (RevocationEvent_TargetObserved (target_observation w actor target))
         | _ -> w)
      else w
  | LockoutRevoke i ->
      deliver_revoke w i
        (RevocationEvent_LockoutObserved
           Vela_session_policy.Revocation_driver.LockoutObservation_Applied)
  | RecordRevoke i ->
      deliver_revoke w i
        (RevocationEvent_RecordObserved RecordObservation_Updated)
  | CascadeRevoke i ->
      deliver_revoke w i
        (RevocationEvent_CascadeObserved CascadeObservation_Completed)
  | SpawnLogout token_index -> spawn_logout w token_index
  | LogoutStep i -> deliver_logout w i LogoutObservation_Applied
  | SpawnDelete actor target -> spawn_delete w actor target
  | DeleteStep i -> deliver_delete w i
  | SpawnPair sacc sdev declared sig_ok -> spawn_pair w sacc sdev declared sig_ok
  | PairAccount i -> deliver_pair_account w i
  | PairPreflight i -> deliver_pair_preflight w i
  | PairTake i -> deliver_pair_take w i
  | PairInsert i -> deliver_pair_insert w i
  | SpawnRec -> spawn_rec w
  | RecConsume i -> deliver_rec_consume w i
  | RecPolicy i -> deliver_rec_policy w i
  | RecInsert i -> deliver_rec_insert w i
  | RecRecheck i -> deliver_rec_recheck w i
  | Use token_index -> deliver_use w token_index

let rec run_world (w: world) (schedule: list action) : Tot world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

let initial : world =
  {
    w_accounts =
      [ { ac_present = true; ac_epoch = mk_i64 1; ac_active = true };
        { ac_present = true; ac_epoch = mk_i64 1; ac_active = true } ];
    w_devices =
      [ { dv_account = 0; dv_present = true; dv_revoked = false; dv_sentinel = false };
        { dv_account = 0; dv_present = true; dv_revoked = false; dv_sentinel = false };
        { dv_account = 1; dv_present = true; dv_revoked = false; dv_sentinel = false } ];
    w_tokens = [];
    w_challenge =
      { ch_present = true; ch_purpose_ok = true; ch_consumed = false };
    w_pair =
      { pg_present = true; pg_devices = 0; pg_account = 0; pg_opener = 1 };
    w_rec =
      { rg_present = true; rg_devices = 0; rg_account = 0;
        rg_epoch = mk_i64 1; rg_possession = true };
    w_reqs = [];
    w_login_accepts = 0;
    w_double_login = 0;
    w_double_pair = 0;
    w_double_rec = 0;
    w_cross_account = 0;
    w_revoked_actor = 0;
    w_cross_delete = 0;
    w_admit_revoked = 0;
    w_admit_deleted = 0;
    w_pair_insert_deleted = 0;
    w_rec_insert_deleted = 0;
    w_pair_revoked_approver = 0;
  }

// ── Driver-side facts used by the composition ──────────────────────────────

/// A revoke-authorizing effect from the extracted driver carries an active
/// actor and a same-account target (read off `revocation_effect_is_sound`).
let revoke_effect_authority (d: t_RevocationDriver) (e: t_RevocationEvent)
  : Lemma
    (requires (revocation_state_is_sound d))
    (ensures (
      let t = Vela_session_policy.Revocation_driver.step d e in
      match t.f_effect <: t_RevocationEffect with
      | RevocationEffect_LockoutDevice ->
          t.f_driver.f_actor_active && t.f_driver.f_same_account
      | RevocationEffect_RecordRevocation ->
          t.f_driver.f_actor_active && t.f_driver.f_same_account
      | _ -> True)) =
  let t = Vela_session_policy.Revocation_driver.step d e in
  assert (revocation_effect_is_sound t.f_driver t.f_effect);
  match t.f_effect <: t_RevocationEffect with
  | RevocationEffect_LockoutDevice -> ()
  | RevocationEffect_RecordRevocation -> ()
  | _ -> ()

let revocation_step_keeps_actor_active (d: t_RevocationDriver) (e: t_RevocationEvent)
  : Lemma
    (requires (revocation_state_is_sound d))
    (ensures (
      (Vela_session_policy.Revocation_driver.step d e).f_driver.f_actor_active =
      d.f_actor_active)) =
  match e <: t_RevocationEvent with
  | RevocationEvent_TargetObserved obs ->
      (match obs <: t_DeviceLookupObservation with
       | DeviceLookupObservation_Present t ->
           (match t.f_same_account <: bool with
            | true -> ()
            | false -> ())
       | _ -> ())
  | RevocationEvent_LockoutObserved _ -> ()
  | RevocationEvent_RecordObserved _ -> ()
  | RevocationEvent_CascadeObserved _ -> ()

/// A login step can only set `challenge_accepted` from false to true on an
/// accepted challenge observation; no other event introduces it.
let login_step_accepted_origin (d: t_LoginDriver) (e: t_LoginEvent)
  : Lemma
    (requires (login_state_is_sound d))
    (ensures (
      (Vela_session_policy.Login_driver.step d e).f_driver.f_challenge_accepted = true ==>
      (d.f_challenge_accepted = true \/
       (match e <: t_LoginEvent with
        | LoginEvent_ChallengeObserved
            (ChallengeObservation_Observed ChallengeConsumption_Accepted) -> true
        | _ -> false)))) =
  match e <: t_LoginEvent with
  | LoginEvent_ChallengeObserved obs ->
      (match obs <: t_ChallengeObservation with
       | ChallengeObservation_Observed c ->
           (match c <: t_ChallengeConsumption with
            | ChallengeConsumption_Accepted ->
                (match d.f_stage <: t_LoginStage with
                 | LoginStage_Challenge -> ()
                 | _ -> ())
            | ChallengeConsumption_Missing -> ()
            | ChallengeConsumption_WrongPurpose -> ())
       | ChallengeObservation_StorageFailed -> ())
  | LoginEvent_DeviceObserved _ -> ()
  | LoginEvent_VerifierObserved _ -> ()
  | LoginEvent_FailureRecorded _ -> ()
  | LoginEvent_BackoffResetObserved _ -> ()
  | LoginEvent_TokenIssued _ -> ()
  | LoginEvent_TokenTracked _ -> ()

let login_step_accepted_implies_has
      (d: t_LoginDriver) (e: t_LoginEvent) (has: bool)
  : Lemma
    (requires (
      login_state_is_sound d /\
      (d.f_challenge_accepted ==> has) /\
      (match e <: t_LoginEvent with
       | LoginEvent_ChallengeObserved
           (ChallengeObservation_Observed ChallengeConsumption_Accepted) -> False
       | _ -> True)))
    (ensures (
      (Vela_session_policy.Login_driver.step d e).f_driver.f_challenge_accepted ==> has)) =
  login_step_accepted_origin d e

/// A successful completion preflight that authorizes `TakeCeremony` observed
/// an active opener. In the shipped driver this is the verified completion
/// policy's `opener_active` conjunct; the composition uses it to tie the
/// decision to the *live* approving device.
let pair_preflight_take_opener
      (d: t_PairingDriver)
      (obs: t_CompletionPreflightObservation)
  : Lemma
    (requires (
      pairing_state_is_sound d /\
      (match d.f_stage <: t_PairingStage with
       | PairingStage_Start -> true
       | _ -> false) /\
      (match d.f_ceremony <: t_PairingCeremony with
       | PairingCeremony_CompleteGrant -> true
       | _ -> false) /\
      not d.f_wrote))
    (ensures (
      (match (on_completion_ready_event d obs).f_effect <: t_PairingEffect with
       | PairingEffect_TakeCeremony -> true
       | _ -> false) ==>
      (match obs.f_opener <: t_OpenerObservation with
       | OpenerObservation_Active -> true
       | _ -> false))) =
  let t = on_completion_ready_event d obs in
  match t.f_effect <: t_PairingEffect with
  | PairingEffect_TakeCeremony ->
      (match obs.f_opener <: t_OpenerObservation with
       | OpenerObservation_Active -> ()
       | OpenerObservation_Inactive -> ()
       | OpenerObservation_Error -> ())
  | _ -> ()

// ── Counting helpers ───────────────────────────────────────────────────────

let rec count_pair_inflight_ge_one (l: list request) (i: nat)
  : Lemma
    (requires (i < FStar.List.Tot.length l /\ pair_inflight (FStar.List.Tot.index l i)))
    (ensures (count_pair_inflight l >= 1))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else count_pair_inflight_ge_one t (i - 1)

let rec count_rec_held_ge_one (l: list request) (i: nat)
  : Lemma
    (requires (i < FStar.List.Tot.length l /\ rec_held (FStar.List.Tot.index l i)))
    (ensures (count_rec_held l >= 1))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else count_rec_held_ge_one t (i - 1)

let rec count_pair_inflight_update_eq (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (
      i < FStar.List.Tot.length l /\
      b2n (pair_inflight r) = b2n (pair_inflight (FStar.List.Tot.index l i))))
    (ensures (count_pair_inflight (update l i r) = count_pair_inflight l))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else count_pair_inflight_update_eq t (i - 1) r

let rec count_rec_held_update_eq (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (
      i < FStar.List.Tot.length l /\
      b2n (rec_held r) = b2n (rec_held (FStar.List.Tot.index l i))))
    (ensures (count_rec_held (update l i r) = count_rec_held l))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else count_rec_held_update_eq t (i - 1) r

let count_pair_inflight_cons_false (r: request) (l: list request)
  : Lemma
    (requires (not (pair_inflight r)))
    (ensures (count_pair_inflight (r :: l) = count_pair_inflight l)) = ()

let count_rec_held_cons_false (r: request) (l: list request)
  : Lemma
    (requires (not (rec_held r)))
    (ensures (count_rec_held (r :: l) = count_rec_held l)) = ()

// ── Invariant preservation: login ──────────────────────────────────────────

let spawn_login_inv (w: world) (dev: nat)
  : Lemma (requires (inv w)) (ensures (inv (spawn_login w dev))) =
  let t0 = begin_login () in
  assert (login_state_is_sound t0.f_driver);
  let r = LoginReq t0.f_driver dev false 0 in
  assert (request_ok r);
  all_requests_ok_cons r w.w_reqs;
  count_pair_inflight_cons_false r w.w_reqs;
  count_rec_held_cons_false r w.w_reqs

let deliver_login_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_login w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | LoginReq d dev has idx ->
        if login_state_is_sound d
        then begin
          all_requests_ok_index w.w_reqs i;
          let e = login_event w d dev in
          let t = Vela_session_policy.Login_driver.step d e in
          assert (login_state_is_sound t.f_driver);
          assert (login_effect_is_sound t.f_driver t.f_effect);
          login_step_accepted_origin d e;
          assert (not (pair_inflight (FStar.List.Tot.index w.w_reqs i)));
          assert (not (rec_held (FStar.List.Tot.index w.w_reqs i)));
          (match d.f_stage <: t_LoginStage with
           | LoginStage_Challenge ->
               let ch = w.w_challenge in
               let taken = ch.ch_present && not ch.ch_consumed in
               let accepted = taken && ch.ch_purpose_ok in
               if accepted
               then begin
                 let nr =
                   LoginReq t.f_driver dev true
                     (FStar.List.Tot.length w.w_tokens) in
                 assert (request_ok nr);
                 all_requests_ok_update w.w_reqs i nr;
                 count_pair_inflight_update_eq w.w_reqs i nr;
                 count_rec_held_update_eq w.w_reqs i nr;
                 assert (taken = true);
                 assert (not ch.ch_consumed);
                 assert (w.w_login_accepts = 0)
               end
               else begin
                 let nr = LoginReq t.f_driver dev has idx in
                 assert (match e <: t_LoginEvent with
                         | LoginEvent_ChallengeObserved
                             (ChallengeObservation_Observed
                                ChallengeConsumption_Accepted) -> False
                         | _ -> True);
                 login_step_accepted_implies_has d e has;
                 assert (request_ok nr);
                 all_requests_ok_update w.w_reqs i nr;
                 count_pair_inflight_update_eq w.w_reqs i nr;
                 count_rec_held_update_eq w.w_reqs i nr;
                 assert (w.w_login_accepts <= 1)
               end
           | LoginStage_Issue ->
               if has
               then begin
                 let nr = LoginReq t.f_driver dev has idx in
                 assert (request_ok nr);
                 all_requests_ok_update w.w_reqs i nr;
                 count_pair_inflight_update_eq w.w_reqs i nr;
                 count_rec_held_update_eq w.w_reqs i nr;
                 assert (w.w_login_accepts <= 1)
               end
               else begin
                 (* unreachable: TrackToken implies the pre-state accepted *)
                 let nr =
                   LoginReq t.f_driver dev true
                     (FStar.List.Tot.length w.w_tokens) in
                 assert (request_ok nr);
                 all_requests_ok_update w.w_reqs i nr;
                 count_pair_inflight_update_eq w.w_reqs i nr;
                 count_rec_held_update_eq w.w_reqs i nr;
                 assert (t.f_effect = LoginEffect_TrackToken);
                 (match t.f_effect <: t_LoginEffect with
                  | LoginEffect_TrackToken -> ()
                  | _ -> ());
                 assert (d.f_challenge_accepted = true);
                 assert (has = true);
                 assert False
               end
           | _ ->
               let nr = LoginReq t.f_driver dev has idx in
               assert (match e <: t_LoginEvent with
                       | LoginEvent_ChallengeObserved
                           (ChallengeObservation_Observed
                              ChallengeConsumption_Accepted) -> False
                       | _ -> True);
               login_step_accepted_implies_has d e has;
               assert (request_ok nr);
               all_requests_ok_update w.w_reqs i nr;
               count_pair_inflight_update_eq w.w_reqs i nr;
               count_rec_held_update_eq w.w_reqs i nr;
               assert (w.w_login_accepts <= 1))
        end
        else ()
    | _ -> ()
  else ()

// ── Invariant preservation: revocation / logout ────────────────────────────

let rec revoke_effect_requires_authority
      (d: t_RevocationDriver) (e: t_RevocationEvent)
  : Lemma
    (requires (revocation_state_is_sound d))
    (ensures (
      let t = Vela_session_policy.Revocation_driver.step d e in
      is_revoke_effect t.f_effect ==>
      (t.f_driver.f_actor_active && t.f_driver.f_same_account))) =
  revoke_effect_authority d e

let revocation_step_non_target_keeps_account
      (d: t_RevocationDriver) (e: t_RevocationEvent)
  : Lemma
    (requires (
      revocation_state_is_sound d /\
      (match e <: t_RevocationEvent with
       | RevocationEvent_TargetObserved _ -> False
       | _ -> True)))
    (ensures (
      (Vela_session_policy.Revocation_driver.step d e).f_driver.f_same_account =
      d.f_same_account)) =
  match e <: t_RevocationEvent with
  | RevocationEvent_TargetObserved _ -> ()
  | RevocationEvent_LockoutObserved _ -> ()
  | RevocationEvent_RecordObserved _ -> ()
  | RevocationEvent_CascadeObserved _ -> ()

let revocation_lookup_account
      (d: t_RevocationDriver) (w: world) (actor: actor_ctx) (target: nat)
  : Lemma
    (requires (
      revocation_state_is_sound d /\
      (d.f_same_account ==> actor.ac_owner = actor.ac_target_owner)))
    (ensures (
      let t =
        Vela_session_policy.Revocation_driver.step d
          (RevocationEvent_TargetObserved (target_observation w actor target)) in
      (t.f_driver.f_same_account ==> actor.ac_owner = actor.ac_target_owner))) =
  match d.f_stage <: t_RevocationStage with
  | RevocationStage_Observe ->
      (match target_observation w actor target <: t_DeviceLookupObservation with
       | DeviceLookupObservation_Present obs ->
           (match obs.f_same_account <: bool with
            | true -> ()
            | false -> ())
       | _ -> ())
  | _ -> ()

let spawn_revoke_inv (w: world) (actor: nat) (target: nat)
  : Lemma (requires (inv w)) (ensures (inv (spawn_revoke w actor target))) =
  if actor < FStar.List.Tot.length w.w_devices &&
     target < FStar.List.Tot.length w.w_devices
  then begin
    let active = device_active w actor in
    let start =
      begin_revocation ({ f_authenticated = true; f_device_active = active }) in
    assert (revocation_state_is_sound start.f_driver);
    let r =
      RevokeReq start.f_driver
        ({ ac_owner = device_account w actor;
           ac_active = active;
           ac_target_owner = device_account w target }) target in
    assert (request_ok r);
    all_requests_ok_cons r w.w_reqs;
    count_pair_inflight_cons_false r w.w_reqs;
    count_rec_held_cons_false r w.w_reqs
  end

let deliver_revoke_inv (w: world) (i: nat) (e: t_RevocationEvent)
  : Lemma
    (requires (
      inv w /\
      i < FStar.List.Tot.length w.w_reqs /\
      (match FStar.List.Tot.index w.w_reqs i with
       | RevokeReq d actor target ->
           revocation_state_is_sound d /\
           (d.f_actor_active = actor.ac_active) /\
           ((Vela_session_policy.Revocation_driver.step d e).f_driver.f_same_account
              ==> actor.ac_owner = actor.ac_target_owner)
       | _ -> False)))
    (ensures (inv (deliver_revoke w i e))) =
  let r = FStar.List.Tot.index w.w_reqs i in
  match r with
  | RevokeReq d actor target ->
      if revocation_state_is_sound d
      then begin
        all_requests_ok_index w.w_reqs i;
        let t = Vela_session_policy.Revocation_driver.step d e in
        assert (revocation_state_is_sound t.f_driver);
        assert (revocation_effect_is_sound t.f_driver t.f_effect);
        revocation_step_keeps_actor_active d e;
        let nr = RevokeReq t.f_driver actor target in
        assert (request_ok nr);
        all_requests_ok_update w.w_reqs i nr;
        count_pair_inflight_update_eq w.w_reqs i nr;
        count_rec_held_update_eq w.w_reqs i nr;
        revoke_effect_authority d e;
        if is_revoke_effect t.f_effect
        then begin
          assert (t.f_driver.f_same_account = true);
          assert (t.f_driver.f_actor_active = true);
          assert (d.f_actor_active = true);
          assert (actor.ac_active = true);
          assert (actor.ac_owner = actor.ac_target_owner)
        end
      end
  | _ -> ()

let lookup_revoke_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (LookupRevoke i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d actor target ->
        if revocation_state_is_sound d
        then begin
          all_requests_ok_index w.w_reqs i;
          let e =
            RevocationEvent_TargetObserved (target_observation w actor target) in
          revocation_lookup_account d w actor target;
          deliver_revoke_inv w i e
        end
        else ()
    | _ -> ()
  else ()

let lockout_revoke_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (LockoutRevoke i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d actor target ->
        if revocation_state_is_sound d
        then begin
          all_requests_ok_index w.w_reqs i;
          let e =
            RevocationEvent_LockoutObserved
              Vela_session_policy.Revocation_driver.LockoutObservation_Applied in
          revocation_step_non_target_keeps_account d e;
          deliver_revoke_inv w i e
        end
        else ()
    | _ -> ()
  else ()

let record_revoke_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (RecordRevoke i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d actor target ->
        if revocation_state_is_sound d
        then begin
          all_requests_ok_index w.w_reqs i;
          let e =
            RevocationEvent_RecordObserved RecordObservation_Updated in
          revocation_step_non_target_keeps_account d e;
          deliver_revoke_inv w i e
        end
        else ()
    | _ -> ()
  else ()

let cascade_revoke_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (CascadeRevoke i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d actor target ->
        if revocation_state_is_sound d
        then begin
          all_requests_ok_index w.w_reqs i;
          let e =
            RevocationEvent_CascadeObserved CascadeObservation_Completed in
          revocation_step_non_target_keeps_account d e;
          deliver_revoke_inv w i e
        end
        else ()
    | _ -> ()
  else ()

let spawn_logout_inv (w: world) (token_index: nat)
  : Lemma (requires (inv w)) (ensures (inv (spawn_logout w token_index))) =
  if token_index < FStar.List.Tot.length w.w_tokens
  then begin
    let start = begin_logout () in
    assert (logout_state_is_sound start.f_driver);
    let r = LogoutReq start.f_driver token_index in
    assert (request_ok r);
    all_requests_ok_cons r w.w_reqs;
    count_pair_inflight_cons_false r w.w_reqs;
    count_rec_held_cons_false r w.w_reqs
  end

let deliver_logout_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_logout w i LogoutObservation_Applied))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | LogoutReq d token_index ->
        if logout_state_is_sound d
        then begin
          all_requests_ok_index w.w_reqs i;
          let t = logout_step d LogoutObservation_Applied in
          assert (logout_state_is_sound t.f_driver);
          let nr = LogoutReq t.f_driver token_index in
          assert (request_ok nr);
          all_requests_ok_update w.w_reqs i nr;
          count_pair_inflight_update_eq w.w_reqs i nr;
          count_rec_held_update_eq w.w_reqs i nr
        end
        else ()
    | _ -> ()
  else ()

// ── Invariant preservation: account deletion ───────────────────────────────

let deletion_step_keeps_same_account (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (deletion_state_is_sound d))
    (ensures (
      (Vela_session_policy.Deletion_driver.step d e).f_driver.f_same_account =
      d.f_same_account)) =
  match e <: t_DeletionEvent with
  | DeletionEvent_DevicesScanned _ ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_ObserveDevices -> ()
       | _ -> ())
  | DeletionEvent_DeviceLockout _ ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_LockoutDevices -> ()
       | _ -> ())
  | DeletionEvent_WebSessionsScanned _ ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_ObserveWebSessions -> ()
       | _ -> ())
  | DeletionEvent_WebSessionLockout _ ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_LockoutWebSessions -> ()
       | _ -> ())
  | DeletionEvent_Transaction _ ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_BeginTransaction -> ()
       | _ -> ())
  | DeletionEvent_TableDeleted _ ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_DeleteTable _ -> ()
       | _ -> ())
  | DeletionEvent_UsersDeleted _ ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_DeleteUsers -> ()
       | _ -> ())
  | DeletionEvent_Commit _ ->
      (match d.f_stage <: t_DeletionStage with
       | DeletionStage_Commit -> ()
       | _ -> ())

let deletion_commit_requires_same_account (d: t_DeletionDriver) (e: t_DeletionEvent)
  : Lemma
    (requires (deletion_state_is_sound d))
    (ensures (
      let t = Vela_session_policy.Deletion_driver.step d e in
      is_commit_effect t.f_effect ==> t.f_driver.f_same_account)) =
  let t = Vela_session_policy.Deletion_driver.step d e in
  assert (deletion_effect_is_sound t.f_driver t.f_effect);
  match t.f_effect <: t_DeletionEffect with
  | DeletionEffect_CommitTransaction -> ()
  | _ -> ()

let spawn_delete_inv (w: world) (actor: nat) (target: nat)
  : Lemma (requires (inv w)) (ensures (inv (spawn_delete w actor target))) =
  if actor < FStar.List.Tot.length w.w_devices
  then begin
    let session = device_account w actor in
    let active = device_active w actor in
    let start =
      begin_deletion
        ({ f_authenticated = true;
           f_device_active = active;
           f_scoped_to_session_account = (session = target) }) in
    assert (deletion_state_is_sound start.f_driver);
    let r =
      DeleteReq start.f_driver
        ({ dc_session = session; dc_target = target }) in
    assert (request_ok r);
    all_requests_ok_cons r w.w_reqs;
    count_pair_inflight_cons_false r w.w_reqs;
    count_rec_held_cons_false r w.w_reqs
  end

let deliver_delete_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_delete w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | DeleteReq d ctx ->
        if deletion_state_is_sound d
        then
          (match d.f_stage <: t_DeletionStage with
           | DeletionStage_Done -> ()
           | _ ->
               all_requests_ok_index w.w_reqs i;
               let e = delete_event w d ctx in
               let t = Vela_session_policy.Deletion_driver.step d e in
               assert (deletion_state_is_sound t.f_driver);
               deletion_step_keeps_same_account d e;
               let nr = DeleteReq t.f_driver ctx in
               assert (request_ok nr);
               all_requests_ok_update w.w_reqs i nr;
               count_pair_inflight_update_eq w.w_reqs i nr;
               count_rec_held_update_eq w.w_reqs i nr;
               deletion_commit_requires_same_account d e;
               if is_commit_effect t.f_effect
               then begin
                 assert (t.f_driver.f_same_account = true);
                 assert (ctx.dc_session = ctx.dc_target)
               end)
        else ()
    | _ -> ()
  else ()

// ── Invariant preservation: pairing completion ─────────────────────────────

let spawn_pair_inv (w: world) (sacc: nat) (sdev: nat) (declared: i64) (sig_ok: bool)
  : Lemma (requires (inv w))
    (ensures (inv (spawn_pair w sacc sdev declared sig_ok))) =
  let ctx =
    ({ pc_session_account = sacc; pc_session_device = sdev;
       pc_declared = declared; pc_signature_ok = sig_ok }) in
  let start = begin_completion (grant_observation w ctx) in
  assert (pairing_state_is_sound start.f_driver);
  let r = PairReq start.f_driver ctx false in
  assert (request_ok r);
  all_requests_ok_cons r w.w_reqs;
  count_pair_inflight_cons_false r w.w_reqs;
  count_rec_held_cons_false r w.w_reqs

let deliver_pair_account_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_pair_account w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | PairReq d ctx opener_live ->
        if pairing_state_is_sound d
        then begin
          all_requests_ok_index w.w_reqs i;
          let t = on_completion_account d (pair_account_observation w ctx) in
          assert (pairing_state_is_sound t.f_driver);
          let nr = PairReq t.f_driver ctx opener_live in
          assert (request_ok nr);
          all_requests_ok_update w.w_reqs i nr;
          count_pair_inflight_update_eq w.w_reqs i nr;
          count_rec_held_update_eq w.w_reqs i nr
        end
        else ()
    | _ -> ()
  else ()

let deliver_pair_preflight_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_pair_preflight w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | PairReq d ctx opener_live ->
        if pairing_state_is_sound d
        then begin
          all_requests_ok_index w.w_reqs i;
          let live = pair_opener_active w ctx in
          let obs = pair_preflight_observation w ctx in
          let t = on_completion_ready_event d obs in
          assert (pairing_state_is_sound t.f_driver);
          assert (pairing_effect_is_sound t.f_driver t.f_effect);
          let take =
            (match t.f_effect <: t_PairingEffect with
             | PairingEffect_TakeCeremony -> true
             | _ -> false) in
          if (match d.f_stage <: t_PairingStage with
              | PairingStage_Start -> true
              | _ -> false) &&
             (match d.f_ceremony <: t_PairingCeremony with
              | PairingCeremony_CompleteGrant -> true
              | _ -> false) &&
             not d.f_wrote
          then begin
            pair_preflight_take_opener d obs;
            if take then assert (live = true) else ()
          end
          else assert (not take);
          let new_opener = if take then live else opener_live in
          let nr = PairReq t.f_driver ctx new_opener in
          assert (request_ok nr);
          all_requests_ok_update w.w_reqs i nr;
          count_pair_inflight_update_eq w.w_reqs i nr;
          count_rec_held_update_eq w.w_reqs i nr;
          assert (not (take && not live))
        end
        else ()
    | _ -> ()
  else ()

let deliver_pair_take_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_pair_take w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | PairReq d ctx opener_live ->
        if pairing_state_is_sound d
        then
          (match d.f_stage <: t_PairingStage with
           | PairingStage_Applied ->
               all_requests_ok_index w.w_reqs i;
               let obs = take_observation w in
               let t = on_ceremony_taken_event d obs in
               assert (pairing_state_is_sound t.f_driver);
               assert (pairing_effect_is_sound t.f_driver t.f_effect);
               let taken =
                 (match t.f_effect <: t_PairingEffect with
                  | PairingEffect_InsertDevice -> true
                  | _ -> false) in
               let nr = PairReq t.f_driver ctx opener_live in
               assert (request_ok nr);
               all_requests_ok_update w.w_reqs i nr;
               assert (taken = w.w_pair.pg_present);
               if taken
               then begin
                 assert (w.w_pair.pg_present = true);
                 assert (not (pair_inflight (FStar.List.Tot.index w.w_reqs i)));
                 count_pair_inflight_update_one w.w_reqs i nr
               end
               else begin
                 assert (w.w_pair.pg_present = false);
                 count_pair_inflight_update_eq w.w_reqs i nr
               end;
               count_rec_held_update_eq w.w_reqs i nr
           | _ -> ())
        else ()
    | _ -> ()
  else ()

let deliver_pair_insert_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_pair_insert w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | PairReq d ctx opener_live ->
        if pairing_state_is_sound d
        then
          (match d.f_stage <: t_PairingStage with
           | PairingStage_InFlight ->
               all_requests_ok_index w.w_reqs i;
               let ok = insert_guard w w.w_pair.pg_account ctx.pc_declared in
               let obs =
                 (if ok then DeviceInsertObservation_Inserted
                  else DeviceInsertObservation_Skipped) in
               let t = on_device_inserted_event d obs in
               assert (pairing_state_is_sound t.f_driver);
               assert (pairing_effect_is_sound t.f_driver t.f_effect);
               let inserted =
                 (match t.f_effect <: t_PairingEffect with
                  | PairingEffect_WriteResult -> true
                  | _ -> false) in
               let nr = PairReq t.f_driver ctx opener_live in
               assert (request_ok nr);
               all_requests_ok_update w.w_reqs i nr;
               count_pair_inflight_ge_one w.w_reqs i;
               assert (count_pair_inflight w.w_reqs = 1);
               count_pair_inflight_update_zero w.w_reqs i nr;
               count_rec_held_update_eq w.w_reqs i nr;
               if inserted
               then begin
                 assert (w.w_pair.pg_present = false);
                 assert (count_pair_inflight w.w_reqs = 1);
                 assert (w.w_pair.pg_devices = 0);
                 assert (account_present w w.w_pair.pg_account = true);
                 assert (opener_live = true)
               end
               else begin
                 assert (w.w_pair.pg_present = false);
                 assert (count_pair_inflight w.w_reqs = 1)
               end
           | _ -> ())
        else ()
    | _ -> ()
  else ()

let rec count_rec_held_update_one (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (
      i < FStar.List.Tot.length l /\
      not (rec_held (FStar.List.Tot.index l i)) /\
      rec_held r))
    (ensures (count_rec_held (update l i r) = count_rec_held l + 1))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else count_rec_held_update_one t (i - 1) r

let rec count_rec_held_update_zero (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (
      i < FStar.List.Tot.length l /\
      rec_held (FStar.List.Tot.index l i) /\
      not (rec_held r)))
    (ensures (count_rec_held (update l i r) + 1 = count_rec_held l))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else count_rec_held_update_zero t (i - 1) r

// ── Invariant preservation: recovery redemption ────────────────────────────

let spawn_rec_inv (w: world)
  : Lemma (requires (inv w)) (ensures (inv (spawn_rec w))) =
  let ready : Vela_recovery_policy.t_ReadyToConsume =
    { f_epoch = w.w_rec.rg_epoch; f_possession = w.w_rec.rg_possession } in
  let start = begin_redemption ready in
  assert (redemption_state_is_sound start.f_driver);
  let r = RecReq start.f_driver in
  assert (request_ok r);
  all_requests_ok_cons r w.w_reqs;
  count_pair_inflight_cons_false r w.w_reqs;
  count_rec_held_cons_false r w.w_reqs

let deliver_rec_consume_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_rec_consume w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RecReq d ->
        if redemption_state_is_sound d
        then
          (match d.f_stage <: t_RedemptionStage with
           | RedemptionStage_Consume ->
               all_requests_ok_index w.w_reqs i;
               let t = on_grant_consumed d (consume_observation w) in
               assert (redemption_state_is_sound t.f_driver);
               assert (redemption_effect_is_sound t.f_driver t.f_effect);
               let nr = RecReq t.f_driver in
               assert (request_ok nr);
               all_requests_ok_update w.w_reqs i nr;
               count_pair_inflight_update_eq w.w_reqs i nr;
               assert (not (rec_held (FStar.List.Tot.index w.w_reqs i)));
               (match t.f_effect <: t_RedemptionEffect with
                | RedemptionEffect_FinalPolicy ->
                    assert (w.w_rec.rg_present = true);
                    count_rec_held_update_one w.w_reqs i nr
                | RedemptionEffect_RestoreAndFail _ ->
                    assert (w.w_rec.rg_present = true);
                    count_rec_held_update_eq w.w_reqs i nr
                | _ ->
                    assert (w.w_rec.rg_present = false);
                    count_rec_held_update_eq w.w_reqs i nr)
           | _ -> ())
        else ()
    | _ -> ()
  else ()

let deliver_rec_policy_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_rec_policy w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RecReq d ->
        if redemption_state_is_sound d
        then
          (match d.f_stage <: t_RedemptionStage with
           | RedemptionStage_FinalPolicy ->
               all_requests_ok_index w.w_reqs i;
               let t = on_final_policy_observed d (rec_policy_observation w d) in
               assert (redemption_state_is_sound t.f_driver);
               assert (redemption_effect_is_sound t.f_driver t.f_effect);
               let nr = RecReq t.f_driver in
               assert (request_ok nr);
               all_requests_ok_update w.w_reqs i nr;
               count_pair_inflight_update_eq w.w_reqs i nr;
               assert (rec_held (FStar.List.Tot.index w.w_reqs i));
               count_rec_held_ge_one w.w_reqs i;
               (match t.f_effect <: t_RedemptionEffect with
                | RedemptionEffect_Insert _ ->
                    assert (w.w_rec.rg_present = false);
                    count_rec_held_update_eq w.w_reqs i nr
                | RedemptionEffect_RestoreAndFail _ ->
                    assert (w.w_rec.rg_present = false);
                    count_rec_held_update_zero w.w_reqs i nr
                | _ ->
                    assert (w.w_rec.rg_present = false);
                    count_rec_held_update_zero w.w_reqs i nr)
           | _ -> ())
        else ()
    | _ -> ()
  else ()

let deliver_rec_insert_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_rec_insert w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RecReq d ->
        if redemption_state_is_sound d
        then
          (match d.f_stage <: t_RedemptionStage with
           | RedemptionStage_Insert ->
               all_requests_ok_index w.w_reqs i;
               let ok = insert_guard w w.w_rec.rg_account d.f_epoch in
               let obs =
                 (if ok then InsertObservation_Inserted
                  else InsertObservation_Skipped) in
               let t = on_insert_completed d obs in
               assert (redemption_state_is_sound t.f_driver);
               assert (redemption_effect_is_sound t.f_driver t.f_effect);
               let nr = RecReq t.f_driver in
               assert (request_ok nr);
               all_requests_ok_update w.w_reqs i nr;
               count_pair_inflight_update_eq w.w_reqs i nr;
               assert (rec_held (FStar.List.Tot.index w.w_reqs i));
               count_rec_held_ge_one w.w_reqs i;
               assert (w.w_rec.rg_present = false);
               assert (w.w_rec.rg_devices = 0);
               (match t.f_effect <: t_RedemptionEffect with
                | RedemptionEffect_Complete ->
                    count_rec_held_update_zero w.w_reqs i nr;
                    assert (account_present w w.w_rec.rg_account = true)
                | _ ->
                    count_rec_held_update_eq w.w_reqs i nr)
           | _ -> ())
        else ()
    | _ -> ()
  else ()

let deliver_rec_recheck_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_rec_recheck w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RecReq d ->
        if redemption_state_is_sound d
        then
          (match d.f_stage <: t_RedemptionStage with
           | RedemptionStage_Recheck ->
               all_requests_ok_index w.w_reqs i;
               let t = on_authority_rechecked d (rec_recheck_observation w d) in
               assert (redemption_state_is_sound t.f_driver);
               assert (redemption_effect_is_sound t.f_driver t.f_effect);
               let nr = RecReq t.f_driver in
               assert (request_ok nr);
               all_requests_ok_update w.w_reqs i nr;
               count_pair_inflight_update_eq w.w_reqs i nr;
               assert (rec_held (FStar.List.Tot.index w.w_reqs i));
               count_rec_held_ge_one w.w_reqs i;
               count_rec_held_update_zero w.w_reqs i nr
           | _ -> ())
        else ()
    | _ -> ()
  else ()

// ── Invariant preservation: admission ──────────────────────────────────────

let deliver_use_inv (w: world) (token_index: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_use w token_index))) =
  if token_index < FStar.List.Tot.length w.w_tokens
  then
    let tk = FStar.List.Tot.index w.w_tokens token_index in
    if not tk.tk_live
    then ()
    else begin
      let observation = admission_observation w tk in
      match plan_admission observation <: t_AdmissionDecision with
      | AdmissionDecision_Admit ->
          assert (admission_is_authorized observation);
          assert (observation.f_device_revoked = false);
          assert (observation.f_account_present = true);
          assert (observation.f_device_row_active = true)
      | AdmissionDecision_Reject _ -> ()
    end
  else ()

// ── One action preserves the invariant ─────────────────────────────────────

let world_step_inv (w: world) (a: action)
  : Lemma (requires (inv w)) (ensures (inv (world_step w a))) =
  match a with
  | SpawnLogin dev -> spawn_login_inv w dev
  | LoginStep i -> deliver_login_inv w i
  | SpawnRevoke actor target -> spawn_revoke_inv w actor target
  | LookupRevoke i -> lookup_revoke_inv w i
  | LockoutRevoke i -> lockout_revoke_inv w i
  | RecordRevoke i -> record_revoke_inv w i
  | CascadeRevoke i -> cascade_revoke_inv w i
  | SpawnLogout token_index -> spawn_logout_inv w token_index
  | LogoutStep i -> deliver_logout_inv w i
  | SpawnDelete actor target -> spawn_delete_inv w actor target
  | DeleteStep i -> deliver_delete_inv w i
  | SpawnPair sacc sdev declared sig_ok ->
      spawn_pair_inv w sacc sdev declared sig_ok
  | PairAccount i -> deliver_pair_account_inv w i
  | PairPreflight i -> deliver_pair_preflight_inv w i
  | PairTake i -> deliver_pair_take_inv w i
  | PairInsert i -> deliver_pair_insert_inv w i
  | SpawnRec -> spawn_rec_inv w
  | RecConsume i -> deliver_rec_consume_inv w i
  | RecPolicy i -> deliver_rec_policy_inv w i
  | RecInsert i -> deliver_rec_insert_inv w i
  | RecRecheck i -> deliver_rec_recheck_inv w i
  | Use token_index -> deliver_use_inv w token_index

let rec run_world_inv (w: world) (schedule: list action)
  : Lemma (requires (inv w)) (ensures (inv (run_world w schedule)))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest -> world_step_inv w a; run_world_inv (world_step w a) rest

// ── Initial world and headline theorem ─────────────────────────────────────

let initial_inv () : Lemma (inv initial) = ()

/// Headline theorem: every interleaving of login, token use, revoke, logout,
/// account deletion, pairing completion and recovery redemption preserves all
/// forbidden-event counters at zero and both per-object at-most-one bounds.
let cross_driver_composition_theorem (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      inv w /\
      w.w_cross_account = 0 /\
      w.w_revoked_actor = 0 /\
      w.w_cross_delete = 0 /\
      w.w_admit_revoked = 0 /\
      w.w_admit_deleted = 0 /\
      w.w_pair_insert_deleted = 0 /\
      w.w_pair_revoked_approver = 0 /\
      w.w_rec_insert_deleted = 0 /\
      w.w_double_login = 0 /\
      w.w_double_pair = 0 /\
      w.w_double_rec = 0) =
  initial_inv ();
  run_world_inv initial schedule

