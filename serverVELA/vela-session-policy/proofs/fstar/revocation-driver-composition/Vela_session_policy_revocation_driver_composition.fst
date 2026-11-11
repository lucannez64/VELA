module Vela_session_policy_revocation_driver_composition

/// Concurrent composition of the *extracted* device revocation, logout and
/// admission drivers (`Vela_session_policy.Revocation_driver`).
///
/// One device/token state is shared by any number of requests, each running its
/// own `RevocationDriver` or `LogoutDriver`. A schedule is an arbitrary list of
/// actions: spawn a revoke or logout request, deliver the next observation,
/// log in on a device, or use a token.
///
/// The world abstracts the effects the handler performs:
///
/// - the target `devices` lookup is one step; the observation is derived from
///   the request's spawn-time account facts and the world's revoked flag, never
///   chosen by the schedule, so a lying lookup cannot weaken the theorem;
/// - the sled lockout (every tracked JTI plus the `device:revoked:` sentinel)
///   is applied exactly when the driver emits `LockoutDevice`;
/// - the durable SQL `revoked = 1` row is applied exactly when the driver emits
///   `RecordRevocation`;
/// - the approved-web-session cascade is applied exactly when the driver emits
///   `CascadeWebSessions`;
/// - a login creates a device token only for a device whose row is not revoked;
/// - a use builds the admission observation from the token and device state and
///   calls the extracted `plan_admission`.
///
/// Theorem: for every schedule,
///
/// - the driver never authorizes a revocation for a cross-account target
///   (`w_cross_account = 0`);
/// - the driver never authorizes a revocation from an actor that was already
///   revoked when the request started (`w_revoked_actor = 0`);
/// - no use of a device token is admitted after that device's row was revoked
///   (`w_admitted_after_revoke = 0`);
/// - every live request remains sound.
///
/// The counters are incremented at the point the *driver* authorizes the
/// forbidden effect (`LockoutDevice` / `RecordRevocation`), or, for admission,
/// at the point the extracted `plan_admission` admits the token — never by a
/// modelled SQL guard refusing a write. The mutation notes in the evidence
/// directory show the composition theorem fails when the driver's same-account
/// or actor-activity check is removed.
///
/// Assumptions (not proved here): sled and SQL writes are linearizable, the
/// handler performs exactly the effect the driver returns in the same step as
/// its observation, devices are not transferred between accounts (so the
/// spawn-time owner comparison stays valid), and the driver's observations
/// originate from the world construction below. SQL guard semantics, token
/// cryptography, TTL expiry and multi-node replication remain outside this
/// module.
///
/// This module deliberately does not import the per-request lemma module: the
/// composition is a statement about the extracted driver alone. That also makes
/// the mutation checks fail here, not in an unrelated lemma.

open FStar.Mul
open Core_models
open Vela_session_policy.Revocation_driver

let b2n (b: bool) : nat = if b then 1 else 0

// ── Generic list helpers (Core_models shadows the unqualified names) ────────

let rec update (#a: Type) (l: list a) (i: nat) (x: a)
  : Tot (list a) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update t (i - 1) x

let rec update_length (#a: Type) (l: list a) (i: nat) (x: a)
  : Lemma (ensures (FStar.List.Tot.length (update l i x) = FStar.List.Tot.length l))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else update_length t (i - 1) x

// ── World model ────────────────────────────────────────────────────────────

noeq type device = {
  d_owner: nat;
  d_revoked: bool;
  d_sentinel: bool;
}

noeq type token = {
  t_device: nat;
  t_jti_revoked: bool;
  t_live: bool;
  /// Web-session tokens are modelled so the cascade has a target; the
  /// composition's login/use actions create device tokens only.
  t_web: bool;
}

/// The actor facts captured when the request started. `ac_owner` is the
/// account of the requesting device, `ac_target_owner` is the account of the
/// target row read at spawn time (devices are never transferred in this model),
/// and `ac_active` is the spawn-time non-revoked state. A later concurrent
/// revocation of the actor does not retroactively change this fact (the
/// historical handler authorizes before writing; the model test pins the same
/// behaviour).
noeq type actor_ctx = {
  ac_owner: nat;
  ac_active: bool;
  ac_target_owner: nat;
}

noeq type request =
  | RevokeReq : t_RevocationDriver -> actor_ctx -> nat -> request
  | LogoutReq : t_LogoutDriver -> nat -> request

noeq type world = {
  w_devices: list device;
  w_tokens: list token;
  w_reqs: list request;
  /// Driver authorizations of a revoke effect for a cross-account target.
  w_cross_account: nat;
  /// Driver authorizations of a revoke effect for an actor that was already
  /// revoked when the request started.
  w_revoked_actor: nat;
  /// Uses admitted for a token whose device row is already revoked.
  w_admitted_after_revoke: nat;
  /// Count of driver-authorized revoke effects (a reachability witness aid).
  w_revoke_effects: nat;
}

let row_revoked (w: world) (i: nat) : bool =
  if i < FStar.List.Tot.length w.w_devices
  then (FStar.List.Tot.index w.w_devices i).d_revoked
  else false

let token_jti_revoked (w: world) (i: nat) : bool =
  if i < FStar.List.Tot.length w.w_tokens
  then (FStar.List.Tot.index w.w_tokens i).t_jti_revoked
  else false

let token_live (w: world) (i: nat) : bool =
  if i < FStar.List.Tot.length w.w_tokens
  then (FStar.List.Tot.index w.w_tokens i).t_live
  else false

let token_device (w: world) (i: nat) : nat =
  if i < FStar.List.Tot.length w.w_tokens
  then (FStar.List.Tot.index w.w_tokens i).t_device
  else 0

let sentinel (w: world) (i: nat) : bool =
  if i < FStar.List.Tot.length w.w_devices
  then (FStar.List.Tot.index w.w_devices i).d_sentinel
  else false

let device_owner (w: world) (i: nat) : nat =
  if i < FStar.List.Tot.length w.w_devices
  then (FStar.List.Tot.index w.w_devices i).d_owner
  else 0

let rec all_device_scoped (tokens: list token) : bool =
  match tokens with
  | [] -> true
  | tk :: rest -> not tk.t_web && all_device_scoped rest

let rec all_device_scoped_index (tokens: list token) (i: nat)
  : Lemma
    (requires (all_device_scoped tokens /\ i < FStar.List.Tot.length tokens))
    (ensures (not (FStar.List.Tot.index tokens i).t_web))
    (decreases tokens) =
  match tokens with
  | _ :: rest -> if i = 0 then () else all_device_scoped_index rest (i - 1)

/// Per-request invariant. `same_account` may only be true when the spawn-time
/// owner comparison said the accounts match, and `actor_active` is exactly the
/// spawn-time fact.
let request_ok (r: request) : bool =
  match r with
  | RevokeReq d actor target ->
      revocation_state_is_sound d &&
      (not d.f_same_account || actor.ac_owner = actor.ac_target_owner) &&
      (d.f_actor_active = actor.ac_active)
  | LogoutReq d _ -> logout_state_is_sound d

let rec all_requests_ok (l: list request) : bool =
  match l with
  | [] -> true
  | r :: rest -> request_ok r && all_requests_ok rest

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
  : Lemma (all_requests_ok (r :: l) = (request_ok r && all_requests_ok l)) = ()

/// The shared invariant. Every counter is a property of the extracted drivers:
/// the revoke counters count driver effects, and the admission counter counts
/// an `Admit` from `plan_admission`.
let inv (w: world) : prop =
  all_requests_ok w.w_reqs /\
  all_device_scoped w.w_tokens /\
  w.w_cross_account = 0 /\
  w.w_revoked_actor = 0 /\
  w.w_admitted_after_revoke = 0

// ── World effects ──────────────────────────────────────────────────────────

let mark_sentinel (devs: list device) (i: nat) : list device =
  if i < FStar.List.Tot.length devs
  then update devs i ({ (FStar.List.Tot.index devs i) with d_sentinel = true })
  else devs

let mark_revoked (devs: list device) (i: nat) : list device =
  if i < FStar.List.Tot.length devs
  then update devs i ({ (FStar.List.Tot.index devs i) with d_revoked = true })
  else devs

let rec mark_device_jtis (tokens: list token) (dev: nat) : list token =
  match tokens with
  | [] -> []
  | tk :: rest ->
      (if tk.t_device = dev
       then { tk with t_jti_revoked = true }
       else tk) :: mark_device_jtis rest dev

let rec revoke_web_tokens (tokens: list token) (dev: nat) : list token =
  match tokens with
  | [] -> []
  | tk :: rest ->
      (if tk.t_device = dev && tk.t_web
       then { tk with t_jti_revoked = true; t_live = false }
       else tk) :: revoke_web_tokens rest dev

/// Apply exactly the effect the extracted driver returned.
let apply_effect (w: world) (target: nat) (e: t_RevocationEffect) : world =
  match e <: t_RevocationEffect with
  | RevocationEffect_LockoutDevice ->
      { w with
        w_devices = mark_sentinel w.w_devices target;
        w_tokens = mark_device_jtis w.w_tokens target }
  | RevocationEffect_RecordRevocation ->
      { w with w_devices = mark_revoked w.w_devices target }
  | RevocationEffect_CascadeWebSessions ->
      { w with w_tokens = revoke_web_tokens w.w_tokens target }
  | _ -> w

let is_revoke_effect (e: t_RevocationEffect) : bool =
  match e <: t_RevocationEffect with
  | RevocationEffect_LockoutDevice -> true
  | RevocationEffect_RecordRevocation -> true
  | _ -> false

/// Count a driver authorization. The counters are keyed on the effect, not on
/// whether a modelled SQL guard later accepts the write.
let count_authorization (w: world) (actor: actor_ctx) (e: t_RevocationEffect) : world =
  if is_revoke_effect e
  then
    { w with
      w_cross_account =
        w.w_cross_account + (if actor.ac_owner <> actor.ac_target_owner then 1 else 0);
      w_revoked_actor =
        w.w_revoked_actor + (if actor.ac_active then 0 else 1);
      w_revoke_effects = w.w_revoke_effects + 1 }
  else w

// ── Delivering an event to a request ───────────────────────────────────────

let deliver_revoke (w: world) (i: nat) (e: t_RevocationEvent) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | LogoutReq _ _ -> w
    | RevokeReq d actor target ->
        if revocation_state_is_sound d
        then
          let t = step d e in
          let w1 = { w with w_reqs = update w.w_reqs i (RevokeReq t.f_driver actor target) } in
          let w2 = apply_effect w1 target t.f_effect in
          count_authorization w2 actor t.f_effect
        else w
  else w

let mark_token_jti (tokens: list token) (i: nat) : list token =
  if i < FStar.List.Tot.length tokens
  then update tokens i ({ (FStar.List.Tot.index tokens i) with t_jti_revoked = true })
  else tokens

let deliver_logout (w: world) (i: nat) (obs: t_LogoutObservation) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq _ _ _ -> w
    | LogoutReq d token_index ->
        if logout_state_is_sound d
        then
          let t = logout_step d obs in
          let w1 = { w with w_reqs = update w.w_reqs i (LogoutReq t.f_driver token_index) } in
          if (match t.f_effect <: t_LogoutEffect with
              | LogoutEffect_Complete -> true
              | _ -> false)
          then { w1 with w_tokens = mark_token_jti w1.w_tokens token_index }
          else w1
        else w
  else w

// ── The honest target lookup observation ───────────────────────────────────

/// The lookup compares the target row's account with the authenticated
/// caller's account. Both values are fixed at spawn time; devices are not
/// transferred in this model, so the comparison is stable.
let target_observation (w: world) (actor: actor_ctx) (target: nat)
  : t_DeviceLookupObservation =
  if target < FStar.List.Tot.length w.w_devices
  then
    DeviceLookupObservation_Present
      ({ f_same_account = (actor.ac_owner = actor.ac_target_owner);
         f_already_revoked = row_revoked w target })
  else DeviceLookupObservation_Absent

// ── Arbitrary schedules ────────────────────────────────────────────────────

type action =
  | SpawnRevoke : nat -> nat -> action
  | LookupRevoke : nat -> action
  | LockoutRevoke : nat -> t_LockoutObservation -> action
  | RecordRevoke : nat -> t_RecordObservation -> action
  | CascadeRevoke : nat -> t_CascadeObservation -> action
  | SpawnLogout : nat -> action
  | LogoutStep : nat -> t_LogoutObservation -> action
  | Login : nat -> action
  | Use : nat -> action

let world_step (w: world) (a: action) : world =
  match a with
  | SpawnRevoke actor target ->
      if actor < FStar.List.Tot.length w.w_devices &&
         target < FStar.List.Tot.length w.w_devices
      then
        let active = not (row_revoked w actor) in
        let start =
          begin_revocation
            ({ f_authenticated = true; f_device_active = active })
        in
        { w with
          w_reqs =
            RevokeReq start.f_driver
              ({ ac_owner = device_owner w actor;
                 ac_active = active;
                 ac_target_owner = device_owner w target }) target
            :: w.w_reqs }
      else w
  | LookupRevoke i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        match FStar.List.Tot.index w.w_reqs i with
        | LogoutReq _ _ -> w
        | RevokeReq _ actor target ->
            deliver_revoke w i
              (RevocationEvent_TargetObserved (target_observation w actor target))
      else w
  | LockoutRevoke i obs ->
      deliver_revoke w i (RevocationEvent_LockoutObserved obs)
  | RecordRevoke i obs ->
      deliver_revoke w i (RevocationEvent_RecordObserved obs)
  | CascadeRevoke i obs ->
      deliver_revoke w i (RevocationEvent_CascadeObserved obs)
  | SpawnLogout token_index ->
      if token_index < FStar.List.Tot.length w.w_tokens
      then
        { w with
          w_reqs = LogoutReq (begin_logout ()).f_driver token_index :: w.w_reqs }
      else w
  | LogoutStep i obs -> deliver_logout w i obs
  | Login dev ->
      if dev < FStar.List.Tot.length w.w_devices && not (row_revoked w dev)
      then
        { w with
          w_tokens =
            { t_device = dev; t_jti_revoked = false; t_live = true; t_web = false }
            :: w.w_tokens }
      else w
  | Use token_index ->
      if token_index < FStar.List.Tot.length w.w_tokens
      then
        let tk = FStar.List.Tot.index w.w_tokens token_index in
        if not tk.t_live then w
        else
          let observation =
            ({ f_jti_revoked = tk.t_jti_revoked;
               f_device_revoked = sentinel w tk.t_device;
               f_account_present = true;
               f_device_row_active = not (row_revoked w tk.t_device);
               f_device_scoped = not tk.t_web })
          in
          match plan_admission observation <: t_AdmissionDecision with
          | AdmissionDecision_Admit ->
              if row_revoked w tk.t_device
              then { w with w_admitted_after_revoke = w.w_admitted_after_revoke + 1 }
              else w
          | AdmissionDecision_Reject _ -> w
      else w

let rec run_world (w: world) (schedule: list action) : Tot world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

// ── Driver-side facts used by the composition proof ────────────────────────

/// A revoke-authorizing effect from the extracted driver carries an active
/// actor and a same-account target. This is read off the extracted
/// `revocation_effect_is_sound` postcondition of `step`.
let revoke_effect_authority (d: t_RevocationDriver) (e: t_RevocationEvent)
  : Lemma
    (requires (revocation_state_is_sound d))
    (ensures (
      match (step d e).f_effect <: t_RevocationEffect with
      | RevocationEffect_LockoutDevice ->
          (step d e).f_driver.f_actor_active /\
          (step d e).f_driver.f_same_account
      | RevocationEffect_RecordRevocation ->
          (step d e).f_driver.f_actor_active /\
          (step d e).f_driver.f_same_account
      | _ -> True)) =
  ()

/// A step never changes `actor_active`.
let step_keeps_actor_active (d: t_RevocationDriver) (e: t_RevocationEvent)
  : Lemma
    (requires (revocation_state_is_sound d))
    (ensures ((step d e).f_driver.f_actor_active = d.f_actor_active)) =
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

/// A non-lookup step never changes `same_account`.
let step_non_target_keeps_account (d: t_RevocationDriver) (e: t_RevocationEvent)
  : Lemma
    (requires (
      revocation_state_is_sound d /\
      (match e <: t_RevocationEvent with
       | RevocationEvent_TargetObserved _ -> False
       | _ -> True)))
    (ensures ((step d e).f_driver.f_same_account = d.f_same_account)) =
  match e <: t_RevocationEvent with
  | RevocationEvent_TargetObserved _ -> ()
  | RevocationEvent_LockoutObserved _ -> ()
  | RevocationEvent_RecordObserved _ -> ()
  | RevocationEvent_CascadeObserved _ -> ()

/// The honest lookup either rejects the target (leaving `same_account` false)
/// or records the true owner equality. Combined with the per-request invariant
/// for non-lookup events, this keeps `same_account` honest for the whole trace.
let lookup_account
      (d: t_RevocationDriver) (w: world) (actor: actor_ctx) (target: nat)
  : Lemma
    (requires (
      revocation_state_is_sound d /\
      (d.f_same_account ==> actor.ac_owner = actor.ac_target_owner)))
    (ensures (
      let t = step d
        (RevocationEvent_TargetObserved (target_observation w actor target)) in
      (t.f_driver.f_same_account ==> actor.ac_owner = actor.ac_target_owner))) =
  match d.f_stage <: t_RevocationStage with
  | RevocationStage_Observe ->
      (match target_observation w actor target <: t_DeviceLookupObservation with
       | DeviceLookupObservation_Present obs ->
           if obs.f_same_account then () else ()
       | _ -> ())
  | _ -> ()

// ── Effect application preserves the token invariant ───────────────────────

let rec mark_device_jtis_scoped (tokens: list token) (dev: nat)
  : Lemma
    (requires (all_device_scoped tokens))
    (ensures (all_device_scoped (mark_device_jtis tokens dev)))
    (decreases tokens) =
  match tokens with
  | [] -> ()
  | _ :: rest -> mark_device_jtis_scoped rest dev

let rec revoke_web_tokens_scoped (tokens: list token) (dev: nat)
  : Lemma
    (requires (all_device_scoped tokens))
    (ensures (all_device_scoped (revoke_web_tokens tokens dev)))
    (decreases tokens) =
  match tokens with
  | [] -> ()
  | _ :: rest -> revoke_web_tokens_scoped rest dev

let rec mark_token_jti_scoped (tokens: list token) (i: nat)
  : Lemma
    (requires (all_device_scoped tokens))
    (ensures (all_device_scoped (mark_token_jti tokens i)))
    (decreases tokens) =
  match tokens with
  | [] -> ()
  | _ :: rest -> if i = 0 then () else mark_token_jti_scoped rest (i - 1)

let apply_effect_scoped (w: world) (target: nat) (e: t_RevocationEffect)
  : Lemma
    (requires (all_device_scoped w.w_tokens))
    (ensures (all_device_scoped (apply_effect w target e).w_tokens)) =
  match e <: t_RevocationEffect with
  | RevocationEffect_LockoutDevice -> mark_device_jtis_scoped w.w_tokens target
  | RevocationEffect_RecordRevocation -> ()
  | RevocationEffect_CascadeWebSessions -> revoke_web_tokens_scoped w.w_tokens target
  | _ -> ()

// ── Invariant preservation ─────────────────────────────────────────────────

/// Delivering an arbitrary event to a revoke request preserves the invariant,
/// provided the step's post-state keeps the account implication. Callers
/// discharge that premise either with the honest lookup observation or with the
/// non-lookup stability lemma.
let deliver_revoke_inv (w: world) (i: nat) (e: t_RevocationEvent)
  : Lemma
    (requires (
      inv w /\
      i < FStar.List.Tot.length w.w_reqs /\
      (match FStar.List.Tot.index w.w_reqs i with
       | RevokeReq d actor target ->
           revocation_state_is_sound d /\
           (d.f_actor_active = actor.ac_active) /\
           ((step d e).f_driver.f_same_account ==> actor.ac_owner = actor.ac_target_owner)
       | LogoutReq _ _ -> False)))
    (ensures (inv (deliver_revoke w i e))) =
  let r = FStar.List.Tot.index w.w_reqs i in
  match r with
  | LogoutReq _ _ -> ()
  | RevokeReq d actor target ->
      if revocation_state_is_sound d
      then begin
        let t = step d e in
        let w1 = { w with w_reqs = update w.w_reqs i (RevokeReq t.f_driver actor target) } in
        let w2 = apply_effect w1 target t.f_effect in
        let w3 = count_authorization w2 actor t.f_effect in
        // Request soundness and the account/actor facts.
        assert (revocation_state_is_sound t.f_driver = true);
        step_keeps_actor_active d e;
        all_requests_ok_update w.w_reqs i (RevokeReq t.f_driver actor target);
        // Token scope is preserved by the effect.
        apply_effect_scoped w1 target t.f_effect;
        // No forbidden authorization: a revoke effect implies both facts.
        revoke_effect_authority d e;
        if is_revoke_effect t.f_effect
        then begin
          assert (t.f_driver.f_same_account = true);
          assert (t.f_driver.f_actor_active = true);
          assert (actor.ac_owner = actor.ac_target_owner);
          assert (actor.ac_active = true)
        end
      end

let deliver_logout_inv (w: world) (i: nat) (obs: t_LogoutObservation)
  : Lemma
    (requires (
      inv w /\
      i < FStar.List.Tot.length w.w_reqs /\
      (match FStar.List.Tot.index w.w_reqs i with
       | LogoutReq d _ -> logout_state_is_sound d
       | RevokeReq _ _ _ -> False)))
    (ensures (inv (deliver_logout w i obs))) =
  let r = FStar.List.Tot.index w.w_reqs i in
  match r with
  | RevokeReq _ _ _ -> ()
  | LogoutReq d token_index ->
      if logout_state_is_sound d
      then begin
        let t = logout_step d obs in
        let w1 = { w with w_reqs = update w.w_reqs i (LogoutReq t.f_driver token_index) } in
        assert (logout_state_is_sound t.f_driver = true);
        all_requests_ok_update w.w_reqs i (LogoutReq t.f_driver token_index);
        mark_token_jti_scoped w.w_tokens token_index
      end

let admit_implies_active_row (o: t_AdmissionObservation)
  : Lemma
    (requires (
      admission_decision_matches_spec o AdmissionDecision_Admit))
    (ensures (admission_is_authorized o)) =
  ()

let spawn_revoke_inv (w: world) (actor: nat) (target: nat)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (SpawnRevoke actor target)))) =
  if actor < FStar.List.Tot.length w.w_devices &&
     target < FStar.List.Tot.length w.w_devices
  then begin
    let active = not (row_revoked w actor) in
    let start = begin_revocation
      ({ f_authenticated = true; f_device_active = active }) in
    assert (revocation_state_is_sound start.f_driver = true);
    assert (start.f_driver.f_same_account = false);
    assert (start.f_driver.f_actor_active = active);
    all_requests_ok_cons
      (RevokeReq start.f_driver
        ({ ac_owner = device_owner w actor;
           ac_active = active;
           ac_target_owner = device_owner w target }) target)
      w.w_reqs
  end

let lookup_revoke_inv (w: world) (i: nat)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (LookupRevoke i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | LogoutReq _ _ -> ()
    | RevokeReq d actor target ->
        if revocation_state_is_sound d
        then begin
          all_requests_ok_index w.w_reqs i;
          let e = RevocationEvent_TargetObserved (target_observation w actor target) in
          lookup_account d w actor target;
          deliver_revoke_inv w i e
        end
        else ()

let lockout_revoke_inv (w: world) (i: nat) (obs: t_LockoutObservation)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (LockoutRevoke i obs)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | LogoutReq _ _ -> ()
    | RevokeReq d actor target ->
        if revocation_state_is_sound d
        then begin
          all_requests_ok_index w.w_reqs i;
          let e = RevocationEvent_LockoutObserved obs in
          step_non_target_keeps_account d e;
          deliver_revoke_inv w i e
        end
        else ()

let record_revoke_inv (w: world) (i: nat) (obs: t_RecordObservation)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (RecordRevoke i obs)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | LogoutReq _ _ -> ()
    | RevokeReq d actor target ->
        if revocation_state_is_sound d
        then begin
          all_requests_ok_index w.w_reqs i;
          let e = RevocationEvent_RecordObserved obs in
          step_non_target_keeps_account d e;
          deliver_revoke_inv w i e
        end
        else ()

let cascade_revoke_inv (w: world) (i: nat) (obs: t_CascadeObservation)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (CascadeRevoke i obs)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | LogoutReq _ _ -> ()
    | RevokeReq d actor target ->
        if revocation_state_is_sound d
        then begin
          all_requests_ok_index w.w_reqs i;
          let e = RevocationEvent_CascadeObserved obs in
          step_non_target_keeps_account d e;
          deliver_revoke_inv w i e
        end
        else ()

let spawn_logout_inv (w: world) (token_index: nat)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (SpawnLogout token_index)))) =
  if token_index < FStar.List.Tot.length w.w_tokens
  then begin
    let start = begin_logout () in
    assert (logout_state_is_sound start.f_driver = true);
    all_requests_ok_cons (LogoutReq start.f_driver token_index) w.w_reqs
  end

let logout_step_inv (w: world) (i: nat) (obs: t_LogoutObservation)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (LogoutStep i obs)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq _ _ _ -> ()
    | LogoutReq d _ ->
        if logout_state_is_sound d
        then begin
          all_requests_ok_index w.w_reqs i;
          deliver_logout_inv w i obs
        end
        else ()

let login_inv (w: world) (dev: nat)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (Login dev)))) = ()

let use_inv (w: world) (token_index: nat)
  : Lemma (requires (inv w))
    (ensures (inv (world_step w (Use token_index)))) =
  if token_index < FStar.List.Tot.length w.w_tokens
  then begin
    let tk = FStar.List.Tot.index w.w_tokens token_index in
    all_device_scoped_index w.w_tokens token_index;
    if not tk.t_live then ()
    else begin
      let observation =
        ({ f_jti_revoked = tk.t_jti_revoked;
           f_device_revoked = sentinel w tk.t_device;
           f_account_present = true;
           f_device_row_active = not (row_revoked w tk.t_device);
           f_device_scoped = true })
      in
      match plan_admission observation <: t_AdmissionDecision with
      | AdmissionDecision_Admit ->
          admit_implies_active_row observation;
          assert (not (row_revoked w tk.t_device))
      | AdmissionDecision_Reject _ -> ()
    end
  end

let world_step_inv (w: world) (a: action)
  : Lemma (requires (inv w)) (ensures (inv (world_step w a))) =
  match a with
  | SpawnRevoke actor target -> spawn_revoke_inv w actor target
  | LookupRevoke i -> lookup_revoke_inv w i
  | LockoutRevoke i obs -> lockout_revoke_inv w i obs
  | RecordRevoke i obs -> record_revoke_inv w i obs
  | CascadeRevoke i obs -> cascade_revoke_inv w i obs
  | SpawnLogout token_index -> spawn_logout_inv w token_index
  | LogoutStep i obs -> logout_step_inv w i obs
  | Login dev -> login_inv w dev
  | Use token_index -> use_inv w token_index

let rec run_world_inv (w: world) (schedule: list action)
  : Lemma (requires (inv w)) (ensures (inv (run_world w schedule)))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest -> world_step_inv w a; run_world_inv (world_step w a) rest

// ── Initial world and headline composition theorem ─────────────────────────

let initial : world =
  {
    w_devices =
      [ { d_owner = 0; d_revoked = false; d_sentinel = false };
        { d_owner = 0; d_revoked = false; d_sentinel = false };
        { d_owner = 1; d_revoked = false; d_sentinel = false } ];
    w_tokens = [];
    w_reqs = [];
    w_cross_account = 0;
    w_revoked_actor = 0;
    w_admitted_after_revoke = 0;
    w_revoke_effects = 0;
  }

let initial_inv () : Lemma (inv initial) = ()

/// Headline theorem: whatever the number of concurrent revoke/logout/login/use
/// requests, their interleaving and their observations, the extracted drivers
/// never authorize a cross-account revocation or a revocation from an already
/// revoked actor, no device token is admitted after its device row was revoked,
/// and every live request is sound.
let revocation_composition_theorem (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      inv w /\
      w.w_cross_account = 0 /\
      w.w_revoked_actor = 0 /\
      w.w_admitted_after_revoke = 0) =
  initial_inv ();
  run_world_inv initial schedule

/// The three named consequences, useful for the evidence log.
let no_cross_account_revocation (schedule: list action)
  : Lemma ((run_world initial schedule).w_cross_account = 0) =
  revocation_composition_theorem schedule

let revoked_actor_never_revokes (schedule: list action)
  : Lemma ((run_world initial schedule).w_revoked_actor = 0) =
  revocation_composition_theorem schedule

let revoked_device_tokens_never_admitted (schedule: list action)
  : Lemma ((run_world initial schedule).w_admitted_after_revoke = 0) =
  revocation_composition_theorem schedule

// ── Non-vacuity: reachable successes and refusals ──────────────────────────

#push-options "--fuel 4 --ifuel 2"

let run_cons (w: world) (a: action) (rest: list action)
  : Lemma (run_world w (a :: rest) == run_world (world_step w a) rest) = ()

let run_nil (w: world) : Lemma (run_world w [] == w) = ()

// A login, then a complete self-revoke, then a use of the old token.
let v1 = world_step initial (Login 0)
let v2 = world_step v1 (SpawnRevoke 0 0)
let v3 = world_step v2 (LookupRevoke 0)
let v4 = world_step v3 (LockoutRevoke 0 LockoutObservation_Applied)
let v5 = world_step v4 (RecordRevoke 0 RecordObservation_Updated)
let v6 = world_step v5 (CascadeRevoke 0 CascadeObservation_Completed)
let v7 = world_step v6 (Use 0)

let v1_ok ()
  : Lemma (FStar.List.Tot.length v1.w_tokens = 1 /\
           token_device v1 0 = 0 /\
           token_live v1 0 = true /\
           v1.w_cross_account = 0 /\ v1.w_revoked_actor = 0 /\
           v1.w_admitted_after_revoke = 0) = ()
let v2_ok ()
  : Lemma (
      let r = FStar.List.Tot.index v2.w_reqs 0 in
      FStar.List.Tot.length v2.w_reqs = 1 /\
      v2.w_cross_account = 0 /\ v2.w_revoked_actor = 0) = v1_ok ()
let v3_ok ()
  : Lemma (row_revoked v3 0 = false /\ sentinel v3 0 = true /\
           v3.w_revoke_effects = 1 /\
           token_jti_revoked v3 0 = true /\
           v3.w_cross_account = 0 /\ v3.w_revoked_actor = 0) = v2_ok ()
let v4_ok ()
  : Lemma (row_revoked v4 0 = true /\ sentinel v4 0 = true /\
           v4.w_revoke_effects = 2 /\
           v4.w_cross_account = 0 /\ v4.w_revoked_actor = 0) = v3_ok ()
let v5_ok ()
  : Lemma (
      let r = FStar.List.Tot.index v5.w_reqs 0 in
      (match r with
       | RevokeReq d _ _ -> d.f_recorded = true | _ -> False) /\
      v5.w_cross_account = 0 /\ v5.w_revoked_actor = 0) = v4_ok ()
let v6_ok ()
  : Lemma (
      let r = FStar.List.Tot.index v6.w_reqs 0 in
      (match r with
       | RevokeReq d _ _ -> d.f_responded = true /\ d.f_recorded = true /\
                             d.f_cascade_done = true
       | _ -> False) /\
      v6.w_cross_account = 0 /\ v6.w_revoked_actor = 0) = v5_ok ()
let v7_ok ()
  : Lemma (
      v7.w_revoke_effects = 2 /\
      v7.w_cross_account = 0 /\ v7.w_revoked_actor = 0 /\
      v7.w_admitted_after_revoke = 0) = v6_ok ()

let revoke_then_use_schedule : list action =
  [ Login 0; SpawnRevoke 0 0; LookupRevoke 0;
    LockoutRevoke 0 LockoutObservation_Applied;
    RecordRevoke 0 RecordObservation_Updated;
    CascadeRevoke 0 CascadeObservation_Completed;
    Use 0 ]

/// A device token issued before the revoke is not admitted afterwards; the
/// row is revoked, and the driver counters stay zero.
let revoked_token_is_not_admitted ()
  : Lemma (
      let w = run_world initial revoke_then_use_schedule in
      row_revoked w 0 = true /\ w.w_admitted_after_revoke = 0 /\
      w.w_cross_account = 0 /\ w.w_revoked_actor = 0) =
  run_cons initial (Login 0) (FStar.List.Tot.tl revoke_then_use_schedule);
  run_cons v1 (SpawnRevoke 0 0)
    [LookupRevoke 0; LockoutRevoke 0 LockoutObservation_Applied;
     RecordRevoke 0 RecordObservation_Updated;
     CascadeRevoke 0 CascadeObservation_Completed; Use 0];
  run_cons v2 (LookupRevoke 0)
    [LockoutRevoke 0 LockoutObservation_Applied;
     RecordRevoke 0 RecordObservation_Updated;
     CascadeRevoke 0 CascadeObservation_Completed; Use 0];
  run_cons v3 (LockoutRevoke 0 LockoutObservation_Applied)
    [RecordRevoke 0 RecordObservation_Updated;
     CascadeRevoke 0 CascadeObservation_Completed; Use 0];
  run_cons v4 (RecordRevoke 0 RecordObservation_Updated)
    [CascadeRevoke 0 CascadeObservation_Completed; Use 0];
  run_cons v5 (CascadeRevoke 0 CascadeObservation_Completed) [Use 0];
  run_cons v6 (Use 0) [];
  run_nil v7;
  v7_ok ()

// A cross-account target is refused before any effect.
let c1 = world_step initial (SpawnRevoke 0 2)
let c2 = world_step c1 (LookupRevoke 0)

let c2_ok ()
  : Lemma (
      let r = FStar.List.Tot.index c2.w_reqs 0 in
      (match r with
       | RevokeReq d _ _ -> d.f_failed = true /\ d.f_same_account = false /\
                             d.f_locked_out = false /\ d.f_recorded = false
       | _ -> False) /\
      c2.w_revoke_effects = 0 /\ c2.w_cross_account = 0 /\
      c2.w_revoked_actor = 0 /\ row_revoked c2 0 = false /\
      row_revoked c2 2 = false) = ()

let cross_account_schedule : list action = [ SpawnRevoke 0 2; LookupRevoke 0 ]

let cross_account_revoke_is_refused ()
  : Lemma (
      let w = run_world initial cross_account_schedule in
      w.w_revoke_effects = 0 /\ w.w_cross_account = 0 /\
      row_revoked w 0 = false /\ row_revoked w 2 = false) =
  run_cons initial (SpawnRevoke 0 2) [LookupRevoke 0];
  run_cons c1 (LookupRevoke 0) [];
  run_nil c2;
  c2_ok ()

// A revoked actor is refused at spawn, before the lookup.
let a1 = world_step initial (SpawnRevoke 0 0)
let a2 = world_step a1 (LookupRevoke 0)
let a3 = world_step a2 (LockoutRevoke 0 LockoutObservation_Applied)
let a4 = world_step a3 (RecordRevoke 0 RecordObservation_Updated)
let a5 = world_step a4 (CascadeRevoke 0 CascadeObservation_Completed)
let a6 = world_step a5 (SpawnRevoke 0 1)
let a7 = world_step a6 (LookupRevoke 0)
let a8 = world_step a7 (LockoutRevoke 0 LockoutObservation_Applied)
let a9 = world_step a8 (RecordRevoke 0 RecordObservation_Updated)
let a5_ok ()
  : Lemma (row_revoked a5 0 = true /\ a5.w_revoke_effects = 2 /\
           a5.w_cross_account = 0 /\ a5.w_revoked_actor = 0) = ()
let a6_ok ()
  : Lemma (
      let r = FStar.List.Tot.index a6.w_reqs 0 in
      (match r with
       | RevokeReq d actor _ ->
           actor.ac_active = false /\ d.f_actor_active = false /\
           d.f_failed = true
       | _ -> False) /\
      a6.w_cross_account = 0 /\ a6.w_revoked_actor = 0) = a5_ok ()
let a7_ok () : Lemma (a7.w_revoke_effects = 2 /\ a7.w_cross_account = 0 /\
                      a7.w_revoked_actor = 0) = a6_ok ()
let a8_ok () : Lemma (a8.w_revoke_effects = 2 /\ a8.w_cross_account = 0 /\
                      a8.w_revoked_actor = 0) = a7_ok ()
let a9_ok () : Lemma (a9.w_revoke_effects = 2 /\ a9.w_cross_account = 0 /\
                      a9.w_revoked_actor = 0) = a8_ok ()

let revoked_actor_schedule : list action =
  [ SpawnRevoke 0 0; LookupRevoke 0; LockoutRevoke 0 LockoutObservation_Applied;
    RecordRevoke 0 RecordObservation_Updated;
    CascadeRevoke 0 CascadeObservation_Completed;
    SpawnRevoke 0 1; LookupRevoke 0;
    LockoutRevoke 0 LockoutObservation_Applied;
    RecordRevoke 0 RecordObservation_Updated ]

let revoked_actor_cannot_revoke ()
  : Lemma (
      let w = run_world initial revoked_actor_schedule in
      w.w_revoke_effects = 2 /\ w.w_revoked_actor = 0 /\
      w.w_cross_account = 0 /\ row_revoked w 1 = false) =
  run_cons initial (SpawnRevoke 0 0) (FStar.List.Tot.tl revoked_actor_schedule);
  run_cons a1 (LookupRevoke 0)
    [LockoutRevoke 0 LockoutObservation_Applied;
     RecordRevoke 0 RecordObservation_Updated;
     CascadeRevoke 0 CascadeObservation_Completed;
     SpawnRevoke 0 1; LookupRevoke 0;
     LockoutRevoke 0 LockoutObservation_Applied;
     RecordRevoke 0 RecordObservation_Updated];
  run_cons a2 (LockoutRevoke 0 LockoutObservation_Applied)
    [RecordRevoke 0 RecordObservation_Updated;
     CascadeRevoke 0 CascadeObservation_Completed;
     SpawnRevoke 0 1; LookupRevoke 0;
     LockoutRevoke 0 LockoutObservation_Applied;
     RecordRevoke 0 RecordObservation_Updated];
  run_cons a3 (RecordRevoke 0 RecordObservation_Updated)
    [CascadeRevoke 0 CascadeObservation_Completed;
     SpawnRevoke 0 1; LookupRevoke 0;
     LockoutRevoke 0 LockoutObservation_Applied;
     RecordRevoke 0 RecordObservation_Updated];
  run_cons a4 (CascadeRevoke 0 CascadeObservation_Completed)
    [SpawnRevoke 0 1; LookupRevoke 0;
     LockoutRevoke 0 LockoutObservation_Applied;
     RecordRevoke 0 RecordObservation_Updated];
  run_cons a5 (SpawnRevoke 0 1)
    [LookupRevoke 0; LockoutRevoke 0 LockoutObservation_Applied;
     RecordRevoke 0 RecordObservation_Updated];
  run_cons a6 (LookupRevoke 0)
    [LockoutRevoke 0 LockoutObservation_Applied;
     RecordRevoke 0 RecordObservation_Updated];
  run_cons a7 (LockoutRevoke 0 LockoutObservation_Applied)
    [RecordRevoke 0 RecordObservation_Updated];
  run_cons a8 (RecordRevoke 0 RecordObservation_Updated) [];
  run_nil a9;
  a9_ok ()

// A repeated revoke of an already-revoked device repeats lockout and cascade
// but writes no second SQL record.
let b1 = world_step a5 (SpawnRevoke 1 0)
let b2 = world_step b1 (LookupRevoke 0)
let b3 = world_step b2 (LockoutRevoke 0 LockoutObservation_Applied)
let b4 = world_step b3 (CascadeRevoke 0 CascadeObservation_Completed)
let b2_ok ()
  : Lemma (
      let r = FStar.List.Tot.index b2.w_reqs 0 in
      (match r with
       | RevokeReq d _ _ -> d.f_already_revoked = true /\ d.f_same_account = true
       | _ -> False) /\
      b2.w_revoke_effects = 3 /\ b2.w_cross_account = 0) = a5_ok ()
let b4_ok ()
  : Lemma (
      let r = FStar.List.Tot.index b4.w_reqs 0 in
      (match r with
       | RevokeReq d _ _ -> d.f_failed = true /\ d.f_recorded = false /\
                             d.f_cascade_done = true
       | _ -> False) /\
      b4.w_cross_account = 0 /\ b4.w_revoked_actor = 0) = b2_ok ()

let repeated_revoke_schedule : list action =
  [ SpawnRevoke 0 0; LookupRevoke 0; LockoutRevoke 0 LockoutObservation_Applied;
    RecordRevoke 0 RecordObservation_Updated;
    CascadeRevoke 0 CascadeObservation_Completed;
    SpawnRevoke 1 0; LookupRevoke 0;
    LockoutRevoke 0 LockoutObservation_Applied;
    CascadeRevoke 0 CascadeObservation_Completed ]

let repeated_revoke_writes_no_second_record ()
  : Lemma (
      let w = run_world initial repeated_revoke_schedule in
      w.w_revoke_effects = 3 /\ w.w_cross_account = 0 /\
      w.w_revoked_actor = 0) =
  run_cons initial (SpawnRevoke 0 0) (FStar.List.Tot.tl repeated_revoke_schedule);
  run_cons a1 (LookupRevoke 0)
    [LockoutRevoke 0 LockoutObservation_Applied;
     RecordRevoke 0 RecordObservation_Updated;
     CascadeRevoke 0 CascadeObservation_Completed;
     SpawnRevoke 1 0; LookupRevoke 0;
     LockoutRevoke 0 LockoutObservation_Applied;
     CascadeRevoke 0 CascadeObservation_Completed];
  run_cons a2 (LockoutRevoke 0 LockoutObservation_Applied)
    [RecordRevoke 0 RecordObservation_Updated;
     CascadeRevoke 0 CascadeObservation_Completed;
     SpawnRevoke 1 0; LookupRevoke 0;
     LockoutRevoke 0 LockoutObservation_Applied;
     CascadeRevoke 0 CascadeObservation_Completed];
  run_cons a3 (RecordRevoke 0 RecordObservation_Updated)
    [CascadeRevoke 0 CascadeObservation_Completed;
     SpawnRevoke 1 0; LookupRevoke 0;
     LockoutRevoke 0 LockoutObservation_Applied;
     CascadeRevoke 0 CascadeObservation_Completed];
  run_cons a4 (CascadeRevoke 0 CascadeObservation_Completed)
    [SpawnRevoke 1 0; LookupRevoke 0;
     LockoutRevoke 0 LockoutObservation_Applied;
     CascadeRevoke 0 CascadeObservation_Completed];
  run_cons a5 (SpawnRevoke 1 0)
    [LookupRevoke 0; LockoutRevoke 0 LockoutObservation_Applied;
     CascadeRevoke 0 CascadeObservation_Completed];
  run_cons b1 (LookupRevoke 0)
    [LockoutRevoke 0 LockoutObservation_Applied;
     CascadeRevoke 0 CascadeObservation_Completed];
  run_cons b2 (LockoutRevoke 0 LockoutObservation_Applied)
    [CascadeRevoke 0 CascadeObservation_Completed];
  run_cons b3 (CascadeRevoke 0 CascadeObservation_Completed) [];
  run_nil b4;
  b4_ok ()

// A logout revokes exactly the token's JTI; a later use is refused.
let l1 = world_step initial (Login 0)
let l2 = world_step l1 (SpawnLogout 0)
let l3 = world_step l2 (LogoutStep 0 LogoutObservation_Applied)
let l4 = world_step l3 (Use 0)
let l3_ok ()
  : Lemma (token_jti_revoked l3 0 = true /\
           l3.w_admitted_after_revoke = 0) = ()
let l4_ok ()
  : Lemma (l4.w_admitted_after_revoke = 0 /\ l4.w_cross_account = 0 /\
           l4.w_revoked_actor = 0) = l3_ok ()

let logout_schedule : list action =
  [ Login 0; SpawnLogout 0; LogoutStep 0 LogoutObservation_Applied; Use 0 ]

let logout_kills_the_token ()
  : Lemma (
      let w = run_world initial logout_schedule in
      w.w_admitted_after_revoke = 0 /\
      token_jti_revoked w 0 = true) =
  run_cons initial (Login 0)
    [SpawnLogout 0; LogoutStep 0 LogoutObservation_Applied; Use 0];
  run_cons l1 (SpawnLogout 0) [LogoutStep 0 LogoutObservation_Applied; Use 0];
  run_cons l2 (LogoutStep 0 LogoutObservation_Applied) [Use 0];
  run_cons l3 (Use 0) [];
  run_nil l4;
  l4_ok ()

#pop-options
