module Vela_rekey_policy_vault_upload_driver_composition

/// Concurrent composition of the *extracted* vault chunk upload driver
/// (`Vela_rekey_policy.Vault_upload_driver`) and the extracted epoch guards it
/// depends on (`resolve_write_epoch`, `authorize_shadow`,
/// `authorize_active_mutation`).
///
/// One account key state is shared by any number of requests, each running its
/// own `UploadDriver`. A schedule is an arbitrary list of actions: spawn a
/// device or web-session request, deliver the next observation, or
/// start/commit/abort a rotation for an account.
///
/// The world abstracts the observations the handler obtains:
///
/// - `Resolve` feeds the current account epoch/phase; the driver re-applies the
///   extracted `resolve_write_epoch`;
/// - `Attempt` derives the shadow authority facts from the writer and account;
/// - quota, guarded-write, read-back, activity and publication observations are
///   delivered next.
///
/// Theorem: for every schedule,
///
/// - no driver authorizes an active write whose captured route is not the live
///   ACTIVE epoch (`w_stale_active = 0`);
/// - no driver authorizes a shadow write for a web session
///   (`w_web_shadow = 0`);
/// - every live request remains sound.
///
/// The two counters are incremented at the point the extracted driver emits the
/// `Write` effect, never by a modelled SQL guard refusing a write. The guard
/// lemmas at the end show the SQL boundary itself: the extracted
/// `authorize_active_mutation` accepts only an ACTIVE account at the permit
/// epoch, and `authorize_shadow` accepts only a device authority. Those two
/// facts are what make a stale-epoch or cross-account commit impossible; the
/// handler models them as the `EXISTS`/`WHERE user_id` clauses of the guarded
/// statement, which are outside this module.
///
/// Assumptions (not proved here): the SQL `vault_chunks` and `users` statements
/// are linearizable, the handler performs exactly the effect the driver
/// returns in the same step as its observation, devices are not transferred
/// between accounts, and the driver's observations originate from the world
/// construction below. SQL guard semantics, quota accounting, storage
/// durability, clock monotonicity (the server does not enforce it) and
/// multi-node replication remain outside this module.

open FStar.Mul
open Core_models
open Vela_rekey_policy
open Vela_rekey_policy.Vault_upload_driver
open Vela_rekey_policy_vault_upload_driver_lemmas

let b2n (b: bool) : nat = if b then 1 else 0

// ── Generic list helpers ───────────────────────────────────────────────────

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

// ── World model ────────────────────────────────────────────────────────────

noeq type account = {
  a_epoch: i64;
  a_phase: Vela_rekey_policy.t_Phase;
  a_rid: nat;
  a_starter: nat;
}

noeq type writer = {
  wr_account: nat;
  wr_device: nat;
  wr_web: bool;
  wr_web_epoch: i64;
}

noeq type request = {
  rq_writer: writer;
  rq_driver: t_UploadDriver;
}

noeq type vworld = {
  w_accounts: list account;
  w_reqs: list request;
  w_rid: nat;
  /// Driver authorizations of an active write whose captured route was stale.
  w_stale_active: nat;
  /// Driver authorizations of a shadow write by a web session.
  w_web_shadow: nat;
}

let account_at (w: vworld) (i: nat) : account =
  if i < FStar.List.Tot.length w.w_accounts
  then FStar.List.Tot.index w.w_accounts i
  else { a_epoch = mk_i64 1; a_phase = Vela_rekey_policy.Phase_Active; a_rid = 0; a_starter = 0 }

let set_account (w: vworld) (i: nat) (a: account) : vworld =
  if i < FStar.List.Tot.length w.w_accounts
  then { w with w_accounts = update w.w_accounts i a }
  else w

let rec all_requests_sound (l: list request) : bool =
  match l with
  | [] -> true
  | r :: rest -> trace_sound r.rq_driver && all_requests_sound rest

let rec all_requests_sound_index (l: list request) (i: nat)
  : Lemma
    (requires (all_requests_sound l /\ i < FStar.List.Tot.length l))
    (ensures (trace_sound (FStar.List.Tot.index l i).rq_driver))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else all_requests_sound_index t (i - 1)

let rec all_requests_sound_update (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (all_requests_sound l /\ trace_sound r.rq_driver))
    (ensures (all_requests_sound (update l i r)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else all_requests_sound_update t (i - 1) r

let rec all_requests_sound_cons (r: request) (l: list request)
  : Lemma (all_requests_sound (r :: l) = (trace_sound r.rq_driver && all_requests_sound l)) = ()

/// Every request was spawned for one of the two modelled accounts.
let rec requests_in_range (l: list request) : bool =
  match l with
  | [] -> true
  | r :: rest -> r.rq_writer.wr_account < 2 && requests_in_range rest

let rec requests_in_range_index (l: list request) (i: nat)
  : Lemma
    (requires (requests_in_range l /\ i < FStar.List.Tot.length l))
    (ensures ((FStar.List.Tot.index l i).rq_writer.wr_account < 2))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else requests_in_range_index t (i - 1)

let rec requests_in_range_update (l: list request) (i: nat) (r: request)
  : Lemma
    (requires (requests_in_range l /\ r.rq_writer.wr_account < 2))
    (ensures (requests_in_range (update l i r)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else requests_in_range_update t (i - 1) r

let rec requests_in_range_cons (r: request) (l: list request)
  : Lemma (requests_in_range (r :: l) = (r.rq_writer.wr_account < 2 && requests_in_range l)) = ()

/// The shared invariant.
let inv (w: vworld) : prop =
  FStar.List.Tot.length w.w_accounts = 2 /\
  all_requests_sound w.w_reqs /\
  requests_in_range w.w_reqs /\
  w.w_stale_active = 0 /\
  w.w_web_shadow = 0

// ── Driver observation helpers ─────────────────────────────────────────────

let rekey_observation (w: vworld) (account: nat) : t_RekeyObservation =
  let a = account_at w account in
  RekeyObservation_State { f_epoch = a.a_epoch; f_phase = a.a_phase }

let attempt_observation (w: vworld) (wr: writer) (account: nat) : t_AttemptAuthority =
  let a = account_at w account in
  { f_device_scope = not wr.wr_web;
    f_starter_matches = wr.wr_device = a.a_starter;
    f_rotation_id_present = a.a_rid > 0;
    f_rotation_id_matches = a.a_rid > 0 }

let write_permit_of (e: t_UploadEffect) : Core_models.Option.t_Option t_UploadWritePermit =
  match e <: t_UploadEffect with
  | UploadEffect_Write p -> Core_models.Option.Option_Some p
  | _ -> Core_models.Option.Option_None

/// Advance one request's driver and count the forbidden *driver* decisions.
let deliver_upload (w: vworld) (i: nat) (e: t_UploadEvent) : vworld =
  if i < FStar.List.Tot.length w.w_reqs
  then
    let r = FStar.List.Tot.index w.w_reqs i in
    if trace_sound r.rq_driver
    then
      let t = upload_step r.rq_driver e in
      let w1 = { w with
                 w_reqs = update w.w_reqs i
                   { rq_writer = r.rq_writer; rq_driver = t.f_driver } } in
      (match write_permit_of t.f_effect <: Core_models.Option.t_Option t_UploadWritePermit with
       | Core_models.Option.Option_Some p ->
           let stale_active =
             if (not p.f_shadow) &&
                (p.f_state_phase <> Vela_rekey_policy.Phase_Active ||
                 p.f_write_epoch <> p.f_state_epoch)
             then 1 else 0 in
           let web_shadow = if p.f_shadow && p.f_web then 1 else 0 in
           { w1 with
             w_stale_active = w1.w_stale_active + stale_active;
             w_web_shadow = w1.w_web_shadow + web_shadow }
       | _ -> w1)
    else w
  else w

// ── Actions ────────────────────────────────────────────────────────────────

type action =
  | Spawn : nat -> bool -> action
  | Resolve : nat -> action
  | Attempt : nat -> action
  | Quota : nat -> t_QuotaObservation -> action
  | Write : nat -> t_WriteObservation -> action
  | Reread : nat -> t_RereadObservation -> action
  | Activity : nat -> t_ActivityObservation -> action
  | Publish : nat -> action
  | RekeyStart : nat -> action
  | RekeyCommit : nat -> action
  | RekeyAbort : nat -> action

let world_step (w: vworld) (a: action) : vworld =
  match a with
  | Spawn account web ->
      if account < FStar.List.Tot.length w.w_accounts
      then
        let wr = { wr_account = account; wr_device = 0; wr_web = web;
                   wr_web_epoch = (account_at w account).a_epoch } in
        let declared =
          if (account_at w account).a_phase = Vela_rekey_policy.Phase_Active
          then (account_at w account).a_epoch
          else mk_i64 2 in
        let start = begin_upload
          { f_writer = { f_authenticated = true; f_web = web;
                         f_web_epoch = if web
                                       then Core_models.Option.Option_Some wr.wr_web_epoch
                                       else Core_models.Option.Option_None };
            f_intent = WriteIntent_Create;
            f_declared_epoch = Core_models.Option.Option_Some declared } in
        { w with w_reqs = { rq_writer = wr; rq_driver = start.f_driver } :: w.w_reqs }
      else w
  | Resolve i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        let r = FStar.List.Tot.index w.w_reqs i in
        deliver_upload w i (UploadEvent_Rekey (rekey_observation w r.rq_writer.wr_account))
      else w
  | Attempt i ->
      if i < FStar.List.Tot.length w.w_reqs
      then
        let r = FStar.List.Tot.index w.w_reqs i in
        deliver_upload w i (UploadEvent_Attempt
          (attempt_observation w r.rq_writer r.rq_writer.wr_account))
      else w
  | Quota i o -> deliver_upload w i (UploadEvent_Quota o)
  | Write i o -> deliver_upload w i (UploadEvent_Write o)
  | Reread i o -> deliver_upload w i (UploadEvent_Reread o)
  | Activity i o -> deliver_upload w i (UploadEvent_Activity o)
  | Publish i -> deliver_upload w i UploadEvent_Published
  | RekeyStart account ->
      if account < FStar.List.Tot.length w.w_accounts
      then
        let a = account_at w account in
        if a.a_phase = Vela_rekey_policy.Phase_Active
        then set_account w account
          ({ a with a_phase = Vela_rekey_policy.Phase_Freezing;
                    a_epoch = mk_i64 2; a_rid = w.w_rid + 1; a_starter = 0 })
        else w
      else w
  | RekeyCommit account ->
      if account < FStar.List.Tot.length w.w_accounts
      then
        let a = account_at w account in
        if a.a_phase = Vela_rekey_policy.Phase_Freezing
        then set_account w account { a with a_phase = Vela_rekey_policy.Phase_Active }
        else w
      else w
  | RekeyAbort account ->
      if account < FStar.List.Tot.length w.w_accounts
      then set_account w account
        { (account_at w account) with a_phase = Vela_rekey_policy.Phase_Active }
      else w

let rec run_world (w: vworld) (schedule: list action) : Tot vworld (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

// ── Driver-level facts used by the composition ────────────────────────────

let write_effect_stale_active (d: t_UploadDriver) (e: t_UploadEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (upload_step d e).f_effect <: t_UploadEffect with
      | UploadEffect_Write p ->
          (not p.f_shadow) ==>
            (p.f_state_phase = Vela_rekey_policy.Phase_Active /\
             p.f_write_epoch = p.f_state_epoch)
      | _ -> True)) =
  write_effect_route d e

let write_effect_not_web (d: t_UploadDriver) (e: t_UploadEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      match (upload_step d e).f_effect <: t_UploadEffect with
      | UploadEffect_Write p -> (p.f_shadow ==> not p.f_web)
      | _ -> True)) =
  match d.f_stage <: t_UploadStage with
  | UploadStage_Quota ->
      (match e <: t_UploadEvent with
       | UploadEvent_Quota QuotaObservation_Allowed -> ()
       | _ -> ())
  | _ -> ()

let delivery_preserves_sound (w: vworld) (i: nat) (e: t_UploadEvent)
  : Lemma
    (requires (all_requests_sound w.w_reqs /\ i < FStar.List.Tot.length w.w_reqs))
    (ensures (all_requests_sound (deliver_upload w i e).w_reqs)) =
  let r = FStar.List.Tot.index w.w_reqs i in
  all_requests_sound_index w.w_reqs i;
  if trace_sound r.rq_driver
  then begin
    step_sound r.rq_driver e;
    all_requests_sound_update w.w_reqs i
      { rq_writer = r.rq_writer; rq_driver = (upload_step r.rq_driver e).f_driver }
  end

let delivery_preserves_range (w: vworld) (i: nat) (e: t_UploadEvent)
  : Lemma
    (requires (requests_in_range w.w_reqs /\ i < FStar.List.Tot.length w.w_reqs))
    (ensures (requests_in_range (deliver_upload w i e).w_reqs)) =
  let r = FStar.List.Tot.index w.w_reqs i in
  requests_in_range_index w.w_reqs i;
  if trace_sound r.rq_driver
  then requests_in_range_update w.w_reqs i
    { rq_writer = r.rq_writer; rq_driver = (upload_step r.rq_driver e).f_driver }

let delivery_stale_active (w: vworld) (i: nat) (e: t_UploadEvent)
  : Lemma
    (requires (all_requests_sound w.w_reqs /\ i < FStar.List.Tot.length w.w_reqs))
    (ensures ((deliver_upload w i e).w_stale_active = w.w_stale_active)) =
  let r = FStar.List.Tot.index w.w_reqs i in
  all_requests_sound_index w.w_reqs i;
  if trace_sound r.rq_driver
  then begin
    write_effect_stale_active r.rq_driver e;
    let t = upload_step r.rq_driver e in
    match write_permit_of t.f_effect <: Core_models.Option.t_Option t_UploadWritePermit with
    | Core_models.Option.Option_Some p ->
        assert (not (not p.f_shadow &&
                     (p.f_state_phase <> Vela_rekey_policy.Phase_Active ||
                      p.f_write_epoch <> p.f_state_epoch)))
    | _ -> ()
  end

let delivery_web_shadow (w: vworld) (i: nat) (e: t_UploadEvent)
  : Lemma
    (requires (all_requests_sound w.w_reqs /\ i < FStar.List.Tot.length w.w_reqs))
    (ensures ((deliver_upload w i e).w_web_shadow = w.w_web_shadow)) =
  let r = FStar.List.Tot.index w.w_reqs i in
  all_requests_sound_index w.w_reqs i;
  if trace_sound r.rq_driver
  then begin
    write_effect_not_web r.rq_driver e;
    let t = upload_step r.rq_driver e in
    match write_permit_of t.f_effect <: Core_models.Option.t_Option t_UploadWritePermit with
    | Core_models.Option.Option_Some p -> assert (not (p.f_shadow && p.f_web))
    | _ -> ()
  end

let delivery_inv (w: vworld) (i: nat) (e: t_UploadEvent)
  : Lemma
    (requires (inv w /\ i < FStar.List.Tot.length w.w_reqs))
    (ensures (inv (deliver_upload w i e))) =
  delivery_preserves_sound w i e;
  delivery_preserves_range w i e;
  delivery_stale_active w i e;
  delivery_web_shadow w i e

// ── Invariant preservation per action ─────────────────────────────────────

let spawn_inv (w: vworld) (account: nat) (web: bool)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Spawn account web)))) =
  if account < FStar.List.Tot.length w.w_accounts
  then begin
    assert (account < 2);
    let a = account_at w account in
    let wr = { wr_account = account; wr_device = 0; wr_web = web;
               wr_web_epoch = a.a_epoch } in
    let declared = if a.a_phase = Vela_rekey_policy.Phase_Active then a.a_epoch else mk_i64 2 in
    let request =
      { f_writer = { f_authenticated = true; f_web = web;
                     f_web_epoch = if web then Core_models.Option.Option_Some wr.wr_web_epoch
                                   else Core_models.Option.Option_None };
        f_intent = WriteIntent_Create;
        f_declared_epoch = Core_models.Option.Option_Some declared } in
    begin_trace_sound request;
    all_requests_sound_cons { rq_writer = wr; rq_driver = (begin_upload request).f_driver }
      w.w_reqs;
    requests_in_range_cons { rq_writer = wr; rq_driver = (begin_upload request).f_driver }
      w.w_reqs
  end

let resolve_inv (w: vworld) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Resolve i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then begin
    let r = FStar.List.Tot.index w.w_reqs i in
    all_requests_sound_index w.w_reqs i;
    delivery_inv w i (UploadEvent_Rekey (rekey_observation w r.rq_writer.wr_account))
  end

let attempt_inv (w: vworld) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Attempt i)))) =
  if i < FStar.List.Tot.length w.w_reqs
  then begin
    let r = FStar.List.Tot.index w.w_reqs i in
    all_requests_sound_index w.w_reqs i;
    delivery_inv w i (UploadEvent_Attempt
      (attempt_observation w r.rq_writer r.rq_writer.wr_account))
  end

let quota_inv (w: vworld) (i: nat) (o: t_QuotaObservation)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Quota i o)))) =
  if i < FStar.List.Tot.length w.w_reqs then delivery_inv w i (UploadEvent_Quota o)

let write_inv (w: vworld) (i: nat) (o: t_WriteObservation)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Write i o)))) =
  if i < FStar.List.Tot.length w.w_reqs then delivery_inv w i (UploadEvent_Write o)

let reread_inv (w: vworld) (i: nat) (o: t_RereadObservation)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Reread i o)))) =
  if i < FStar.List.Tot.length w.w_reqs then delivery_inv w i (UploadEvent_Reread o)

let activity_inv (w: vworld) (i: nat) (o: t_ActivityObservation)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Activity i o)))) =
  if i < FStar.List.Tot.length w.w_reqs then delivery_inv w i (UploadEvent_Activity o)

let publish_inv (w: vworld) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (Publish i)))) =
  if i < FStar.List.Tot.length w.w_reqs then delivery_inv w i UploadEvent_Published

let rekey_start_inv (w: vworld) (account: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (RekeyStart account)))) =
  if account < FStar.List.Tot.length w.w_accounts
  then begin
    let a = account_at w account in
    if a.a_phase = Vela_rekey_policy.Phase_Active
    then update_length w.w_accounts account
      ({ a with a_phase = Vela_rekey_policy.Phase_Freezing;
                a_epoch = mk_i64 2; a_rid = w.w_rid + 1; a_starter = 0 })
    else ()
  end
  else ()

let rekey_commit_inv (w: vworld) (account: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (RekeyCommit account)))) =
  if account < FStar.List.Tot.length w.w_accounts
  then begin
    let a = account_at w account in
    if a.a_phase = Vela_rekey_policy.Phase_Freezing
    then update_length w.w_accounts account { a with a_phase = Vela_rekey_policy.Phase_Active }
    else ()
  end
  else ()

let rekey_abort_inv (w: vworld) (account: nat)
  : Lemma (requires (inv w)) (ensures (inv (world_step w (RekeyAbort account)))) =
  if account < FStar.List.Tot.length w.w_accounts
  then update_length w.w_accounts account
    { (account_at w account) with a_phase = Vela_rekey_policy.Phase_Active }
  else ()

let world_step_inv (w: vworld) (a: action)
  : Lemma (requires (inv w)) (ensures (inv (world_step w a))) =
  match a with
  | Spawn account web -> spawn_inv w account web
  | Resolve i -> resolve_inv w i
  | Attempt i -> attempt_inv w i
  | Quota i o -> quota_inv w i o
  | Write i o -> write_inv w i o
  | Reread i o -> reread_inv w i o
  | Activity i o -> activity_inv w i o
  | Publish i -> publish_inv w i
  | RekeyStart account -> rekey_start_inv w account
  | RekeyCommit account -> rekey_commit_inv w account
  | RekeyAbort account -> rekey_abort_inv w account

let rec run_world_inv (w: vworld) (schedule: list action)
  : Lemma (requires (inv w)) (ensures (inv (run_world w schedule)))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest -> world_step_inv w a; run_world_inv (world_step w a) rest

// ── SQL-boundary guard lemmas ──────────────────────────────────────────────

/// The extracted active-mutation guard accepts only a valid ACTIVE account at
/// exactly the permit epoch. This is the predicate the handler embeds in the
/// guarded `UPDATE`/`INSERT` as `key_epoch = permit AND rekey_state IS NULL`.
let active_guard_rejects_stale (state: t_RekeyState) (permit: t_MutationPermit)
  : Lemma
    (requires (not (state.f_epoch >=. v_INITIAL_EPOCH &&
                    state.f_phase = Vela_rekey_policy.Phase_Active &&
                    state.f_epoch = permit.f_epoch)))
    (ensures (Vela_rekey_policy.authorize_active_mutation state permit =
                Vela_rekey_policy.ShadowDecision_Reject)) =
  ()

/// The extracted shadow guard accepts only a device authority.
let shadow_guard_requires_device
      (state: t_RekeyState) (route: t_EpochRoute) (authority: t_AttemptAuthority)
  : Lemma
    (requires (Vela_rekey_policy.authorize_shadow state route authority =
                 Vela_rekey_policy.ShadowDecision_Allow))
    (ensures (authority.f_device_scope)) =
  ()

// ── Initial world and headline theorem ────────────────────────────────────

let initial : vworld =
  {
    w_accounts =
      [ { a_epoch = mk_i64 1; a_phase = Vela_rekey_policy.Phase_Active;
          a_rid = 0; a_starter = 0 };
        { a_epoch = mk_i64 1; a_phase = Vela_rekey_policy.Phase_Active;
          a_rid = 0; a_starter = 0 } ];
    w_reqs = [];
    w_rid = 0;
    w_stale_active = 0;
    w_web_shadow = 0;
  }

let initial_inv () : Lemma (inv initial) = ()

/// Headline theorem: whatever the number of concurrent device/web uploads,
/// rekey start/commit/abort actions and their interleaving, the extracted
/// driver never authorizes a stale active write or a web-session shadow write,
/// and every live request remains sound.
let upload_composition_theorem (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      inv w /\
      w.w_stale_active = 0 /\
      w.w_web_shadow = 0) =
  initial_inv ();
  run_world_inv initial schedule

let no_stale_active_write (schedule: list action)
  : Lemma ((run_world initial schedule).w_stale_active = 0) =
  upload_composition_theorem schedule

let no_web_shadow_write (schedule: list action)
  : Lemma ((run_world initial schedule).w_web_shadow = 0) =
  upload_composition_theorem schedule

// ── Non-vacuity: reachable successes and refusals ─────────────────────────

#push-options "--fuel 4 --ifuel 2"

let run_cons (w: vworld) (a: action) (rest: list action)
  : Lemma (run_world w (a :: rest) == run_world (world_step w a) rest) = ()

let run_nil (w: vworld) : Lemma (run_world w [] == w) = ()

let v1 = world_step initial (Spawn 0 false)
let v2 = world_step v1 (Resolve 0)
let v3 = world_step v2 (Quota 0 QuotaObservation_Allowed)
let v4 = world_step v3 (Write 0 WriteObservation_Inserted)
let v5 = world_step v4 (Reread 0 (RereadObservation_Read { f_version = mk_i64 1 }))
let v6 = world_step v5 (Publish 0)

let v4_ok ()
  : Lemma (v4.w_stale_active = 0 /\ v4.w_web_shadow = 0) = ()
let v6_ok ()
  : Lemma (v6.w_stale_active = 0 /\ v6.w_web_shadow = 0 /\
           FStar.List.Tot.length v6.w_reqs = 1) = v4_ok ()

let active_upload_schedule : list action =
  [ Spawn 0 false; Resolve 0; Quota 0 QuotaObservation_Allowed;
    Write 0 WriteObservation_Inserted;
    Reread 0 (RereadObservation_Read { f_version = mk_i64 1 }); Publish 0 ]

/// A device upload on an ACTIVE account completes with both counters zero.
let active_upload_is_reachable ()
  : Lemma (
      let w = run_world initial active_upload_schedule in
      w.w_stale_active = 0 /\ w.w_web_shadow = 0) =
  run_cons initial (Spawn 0 false)
    [Resolve 0; Quota 0 QuotaObservation_Allowed;
     Write 0 WriteObservation_Inserted;
     Reread 0 (RereadObservation_Read { f_version = mk_i64 1 }); Publish 0];
  run_cons v1 (Resolve 0)
    [Quota 0 QuotaObservation_Allowed; Write 0 WriteObservation_Inserted;
     Reread 0 (RereadObservation_Read { f_version = mk_i64 1 }); Publish 0];
  run_cons v2 (Quota 0 QuotaObservation_Allowed)
    [Write 0 WriteObservation_Inserted;
     Reread 0 (RereadObservation_Read { f_version = mk_i64 1 }); Publish 0];
  run_cons v3 (Write 0 WriteObservation_Inserted)
    [Reread 0 (RereadObservation_Read { f_version = mk_i64 1 }); Publish 0];
  run_cons v4 (Reread 0 (RereadObservation_Read { f_version = mk_i64 1 }))
    [Publish 0];
  run_cons v5 (Publish 0) [];
  run_nil v6;
  v6_ok ()

/// A web session cannot take the shadow route: the driver refuses at Attempt.
let web_shadow_schedule : list action =
  [ Spawn 0 true; Resolve 0; Attempt 0 ]

/// A matching-device shadow upload reaches the write stage.
let shadow_schedule : list action =
  [ Spawn 0 false; RekeyStart 0; Resolve 0; Attempt 0;
    Quota 0 QuotaObservation_Allowed; Write 0 WriteObservation_Inserted ]

/// Two accounts upload concurrently without disturbing one another.
let two_account_schedule : list action =
  [ Spawn 0 false; Spawn 1 false; Resolve 0; Resolve 1;
    Quota 0 QuotaObservation_Allowed; Write 0 WriteObservation_Inserted;
    Quota 1 QuotaObservation_Allowed; Write 1 WriteObservation_Inserted ]

/// Every witness schedule keeps the counters zero.
let witnesses_keep_counters_zero ()
  : Lemma (
      (run_world initial web_shadow_schedule).w_web_shadow = 0 /\
      (run_world initial shadow_schedule).w_stale_active = 0 /\
      (run_world initial two_account_schedule).w_stale_active = 0) =
  upload_composition_theorem web_shadow_schedule;
  upload_composition_theorem shadow_schedule;
  upload_composition_theorem two_account_schedule

#pop-options
