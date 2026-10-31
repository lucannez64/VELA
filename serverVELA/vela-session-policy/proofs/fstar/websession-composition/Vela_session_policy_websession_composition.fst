module Vela_session_policy_websession_composition

/// Concurrent composition of the *extracted* web-session decision drivers over
/// one shared world: browser start, device grant, token exchange, session
/// delete, and device revocation (which cascades to the sessions the device
/// approved, U-18).
///
/// A schedule is an arbitrary finite interleaving of actions. Each request owns
/// its own extracted driver value (`StartDriver`, `GrantDriver`,
/// `TokenDriver`, `DeleteDriver`, `RevocationDriver`). Every observation that is
/// a fact about the shared state (session row, `web_token` challenge, the
/// per-session `web_session:token_issued:<id>` claim, the lockout sentinel,
/// devices, accounts) is computed from the live world at the step the handler
/// reads it; the effect the driver returns is applied in that same step. The
/// effect of a stage is applied by the action that delivers that effect's
/// observation (for example the token claim action performs the atomic
/// `set_ex_nx` and feeds the resulting `Claimed`/`AlreadyClaimed`).
///
/// Theorem (`composition_theorem`) for every schedule:
///
/// 1. at most one token per web session, counted on the extracted token
///    driver's `IssueToken` decision (`s_issue_decisions <= 1`), never on the
///    claim store;
/// 2. no token is issued for a session after its delete committed the lockout
///    sentinel and SQL revocation (`w_token_after_delete = 0`), and none after
///    the session's approver-revocation cascade committed
///    (`w_token_after_approver = 0`);
/// 3. a grant is authorized only from the owning account's active approver
///    (`w_cross_account_grant = 0`, `w_inactive_grant = 0`) and never for a
///    non-pending session (`w_nonpending_grant = 0`);
/// 4. start creates no authority: it inserts only a `pending` row
///    (`w_start_authority = 0`) and no token is issued from a session that was
///    not granted (`w_token_from_pending = 0`);
/// 5. no cross-account delete (`w_cross_account_delete = 0`).
///
/// Assumptions (not proved here): SQL statements and the guarded grant/delete
/// updates are linearizable and atomic; sled `get_del` (challenge take) and
/// `set_ex_nx` (token claim) are atomic; the handler performs exactly the
/// effect the driver returns, in the same step as its observation; the token
/// issue effect re-checks the `device:revoked:<session_id>` sentinel before it
/// releases a token (the handler's `issue_token` does; regression test
/// `web_session_token_is_not_issued_after_its_lockout`); the approver
/// revocation commit for a web session is its cascade (sentinel + row
/// revocation), which follows the device row update in the same request.
/// Hybrid verification, PASETO signing, the clock, TTL expiry, rate limits and
/// multi-node visibility remain outside this module.

open FStar.Mul
open Core_models
open Vela_session_policy
open Vela_session_policy.Websession_driver
open Vela_session_policy.Revocation_driver

let b2n (b: bool) : nat = if b then 1 else 0

// ── Generic list helpers (Core_models shadows the unqualified names) ────────

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

let rec update_out (#a: eqtype) (l: list a) (i: nat) (x: a)
  : Lemma (requires (i >= FStar.List.Tot.length l))
    (ensures (update l i x = l))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else update_out t (i - 1) x

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

/// Account/device identities are bounded nats so they can be injected into
/// the driver's `u128` identity without an unchecked cast.
let small = n:nat{n < 340282366920938463463374607431768211456}

type session_phase =
  | Phase_Pending
  | Phase_Granted
  | Phase_Revoked

/// One `web_sessions` row plus the per-session store keys the composition
/// shares. `s_owner` is `user_id` (granted account), `s_approver_user` is
/// `approver_user_id` (the account the browser committed to at start),
/// `s_approver_dev` is `approved_by` (set at grant). `s_sentinel` is
/// `device:revoked:<id>`; `s_claimed` is `web_session:token_issued:<id>`.
type session = {
  s_id: nat;
  s_phase: session_phase;
  s_owner: option small;
  s_approver_user: option small;
  s_approver_dev: option nat;
  s_rw: bool;
  s_epoch: i64;
  s_nonce_ok: bool;
  s_web_vk: bool;
  s_sentinel: bool;
  /// The sentinel was written by `DELETE /web-session/:id`.
  s_lockout_delete: bool;
  /// The sentinel was written by the device-revocation cascade.
  s_lockout_cascade: bool;
  /// The delete request's SQL revocation committed for this row.
  s_revoked_by_delete: bool;
  s_claimed: bool;
  /// The extracted token driver's `IssueToken` decisions for this session.
  s_issue_decisions: nat;
}

/// One `devices` row. `d_revoked` is the durable `revoked = 1` flag; the
/// account policy's device-revocation cascade uses it for grants and the
/// approved-session cascade.
noeq type device = {
  d_owner: small;
  d_present: bool;
  d_revoked: bool;
  d_sentinel: bool;
}

noeq type account = {
  a_present: bool;
  a_active: bool;
  a_epoch: i64;
}

/// One key of the shared challenge store. `c_web_token` records the purpose the
/// key was issued for; a take removes the key whatever its purpose.
noeq type challenge = {
  c_web_token: bool;
  c_present: bool;
}

/// One issued web-session token. `t_after_delete`/`t_after_approver` are
/// diagnostics for the two revocation orders.
noeq type token = {
  t_sid: nat;
  t_after_delete: bool;
  t_after_approver: bool;
}

noeq type start_ctx = {
  st_approver_user: option small;
  st_rw: bool;
  st_epoch: i64;
  st_nonce_ok: bool;
  st_web_vk: bool;
}

noeq type grant_ctx = {
  g_actor_dev: nat;
  g_actor_user: small;
  g_ttl: Core_models.Option.t_Option i64;
}

noeq type revoke_ctx = {
  rv_actor_dev: nat;
  rv_target_dev: nat;
}

noeq type request =
  | StartReq : t_StartDriver -> start_ctx -> request
  | GrantReq : t_GrantDriver -> grant_ctx -> nat -> request
  /// The session id, the challenge key, and whether the observed row was a
  /// grant-eligible row (the driver's `session_eligible` fact).
  | TokenReq : t_TokenDriver -> nat -> nat -> bool -> request
  /// The actor account, the session id, and whether the lockout sentinel was
  /// written for this request.
  | DeleteReq : t_DeleteDriver -> small -> nat -> bool -> request
  | RevokeReq : t_RevocationDriver -> revoke_ctx -> request

noeq type world = {
  w_accounts: list account;
  w_devices: list device;
  w_sessions: list session;
  w_challenges: list challenge;
  w_tokens: list token;
  w_reqs: list request;
  /// Tokens actually released after the session's delete lockout/revocation.
  w_token_after_delete: nat;
  /// Tokens actually released after the session's approver cascade.
  w_token_after_approver: nat;
  /// Grants the token driver authorized from a non-owning account.
  w_cross_account_grant: nat;
  /// Grants authorized while the approver device was not active.
  w_inactive_grant: nat;
  /// Grants authorized for a non-pending session.
  w_nonpending_grant: nat;
  /// Tokens authorized from a session that was not granted (`start` rows).
  w_token_from_pending: nat;
  /// Deletes authorized for a non-owning account.
  w_cross_account_delete: nat;
  /// Start inserts that carried any authority (must stay zero).
  w_start_authority: nat;
  /// Reachability aids.
  w_tokens_issued: nat;
  w_grants: nat;
  w_delete_lockouts: nat;
}

// ── Live accessors ─────────────────────────────────────────────────────────

let empty_session : session =
  { s_id = 0;
    s_phase = Phase_Pending;
    s_owner = None;
    s_approver_user = None;
    s_approver_dev = None;
    s_rw = false;
    s_epoch = mk_i64 0;
    s_nonce_ok = false;
    s_web_vk = false;
    s_sentinel = false;
    s_lockout_delete = false;
    s_lockout_cascade = false;
    s_revoked_by_delete = false;
    s_claimed = false;
    s_issue_decisions = 0 }

let session_at (w: world) (i: nat) : session =
  if i < FStar.List.Tot.length w.w_sessions
  then FStar.List.Tot.index w.w_sessions i
  else empty_session

let empty_device : device =
  { d_owner = 0; d_present = false; d_revoked = false; d_sentinel = false }

let device_at (w: world) (i: nat) : device =
  if i < FStar.List.Tot.length w.w_devices
  then FStar.List.Tot.index w.w_devices i
  else empty_device

let empty_account : account =
  { a_present = false; a_active = false; a_epoch = mk_i64 0 }

let account_at (w: world) (i: nat) : account =
  if i < FStar.List.Tot.length w.w_accounts
  then FStar.List.Tot.index w.w_accounts i
  else empty_account

let empty_challenge : challenge = { c_web_token = false; c_present = false }

let challenge_at (w: world) (i: nat) : challenge =
  if i < FStar.List.Tot.length w.w_challenges
  then FStar.List.Tot.index w.w_challenges i
  else empty_challenge

let device_active (w: world) (i: nat) : bool =
  i < FStar.List.Tot.length w.w_devices &&
  (device_at w i).d_present &&
  not (device_at w i).d_revoked

let device_owner (w: world) (i: nat) : small = (device_at w i).d_owner

let account_present (w: world) (i: nat) : bool = (account_at w i).a_present
let account_active (w: world) (i: nat) : bool = (account_at w i).a_active
let account_epoch (w: world) (i: nat) : i64 = (account_at w i).a_epoch

let uid (n: small) : u128 = mk_u128 n

let map_option_u128 (o: option small) : Core_models.Option.t_Option u128 =
  match o with
  | Some n -> Core_models.Option.Option_Some (uid n)
  | None -> Core_models.Option.Option_None

let phase_to_policy (p: session_phase) : t_SessionPhase =
  match p with
  | Phase_Pending -> SessionPhase_Pending
  | Phase_Granted -> SessionPhase_Granted
  | Phase_Revoked -> SessionPhase_Revoked

let mode_to_policy (rw: bool) : t_SessionMode =
  if rw then SessionMode_ReadWrite else SessionMode_ReadOnly

let policy_to_mode (m: t_SessionMode) : bool =
  match m <: t_SessionMode with
  | SessionMode_ReadWrite -> true
  | SessionMode_ReadOnly -> false

// ── Request and session invariants ─────────────────────────────────────────

/// The live row and its per-session store keys stay mutually consistent.
let session_ok (s: session) : bool =
  s.s_issue_decisions <= 1 &&
  (not (s.s_issue_decisions > 0) || s.s_claimed) &&
  (not s.s_lockout_delete || s.s_sentinel) &&
  (not s.s_lockout_cascade || s.s_sentinel) &&
  (not s.s_revoked_by_delete || s.s_sentinel) &&
  (match s.s_phase <: session_phase with
   | Phase_Revoked -> s.s_sentinel
   | _ -> true) &&
  (match s.s_phase <: session_phase with
   | Phase_Pending -> s.s_owner = None && s.s_approver_dev = None
   | Phase_Granted -> s.s_owner <> None && s.s_approver_dev <> None
   | Phase_Revoked -> true)

let rec all_sessions_ok (l: list session) : Tot bool (decreases l) =
  match l with
  | [] -> true
  | s :: rest -> session_ok s && all_sessions_ok rest

let request_ok (r: request) : prop =
  match r with
  | StartReq d _ -> start_state_is_sound d
  | GrantReq d _ _ -> grant_state_is_sound d
  | TokenReq d _ _ eligible ->
      token_state_is_sound d /\ (d.f_session_eligible ==> eligible)
  | DeleteReq d user _ locked ->
      delete_state_is_sound d /\ (d.f_locked ==> locked) /\
      d.f_actor_user = uid user
  | RevokeReq d _ -> revocation_state_is_sound d

let rec all_reqs_ok (l: list request) : Tot prop (decreases l) =
  match l with
  | [] -> True
  | r :: rest -> request_ok r /\ all_reqs_ok rest

let counters_ok (w: world) : prop =
  w.w_token_after_delete = 0 /\
  w.w_token_after_approver = 0 /\
  w.w_cross_account_grant = 0 /\
  w.w_inactive_grant = 0 /\
  w.w_nonpending_grant = 0 /\
  w.w_token_from_pending = 0 /\
  w.w_cross_account_delete = 0 /\
  w.w_start_authority = 0

let inv (w: world) : prop =
  all_sessions_ok w.w_sessions /\
  all_reqs_ok w.w_reqs /\
  counters_ok w

// ── List lemmas for the invariant ──────────────────────────────────────────

let rec all_sessions_ok_index (l: list session) (i: nat)
  : Lemma (requires (all_sessions_ok l /\ i < FStar.List.Tot.length l))
    (ensures (session_ok (FStar.List.Tot.index l i)))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else all_sessions_ok_index t (i - 1)

let rec all_sessions_ok_update (l: list session) (i: nat) (s: session)
  : Lemma (requires (all_sessions_ok l /\ session_ok s))
    (ensures (all_sessions_ok (update l i s)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else all_sessions_ok_update t (i - 1) s

let rec all_sessions_ok_snoc (l: list session) (s: session)
  : Lemma (requires (all_sessions_ok l /\ session_ok s))
    (ensures (all_sessions_ok (snoc l s)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> all_sessions_ok_snoc t s

/// A session whose id is its list position.
let cascade_one (s: session) (target: nat) : session =
  if s.s_approver_dev = Some target
  then { s with s_sentinel = true; s_lockout_cascade = true;
                s_phase = Phase_Revoked }
  else s

let rec cascade_sessions (l: list session) (target: nat)
  : Tot (list session) (decreases l) =
  match l with
  | [] -> []
  | s :: t -> cascade_one s target :: cascade_sessions t target

let cascade_one_ok (s: session) (target: nat)
  : Lemma (requires (session_ok s))
    (ensures (session_ok (cascade_one s target))) =
  match s.s_approver_dev with
  | Some d -> if d = target then () else ()
  | None -> ()

let rec all_sessions_ok_cascade (l: list session) (target: nat)
  : Lemma (requires (all_sessions_ok l))
    (ensures (all_sessions_ok (cascade_sessions l target)))
    (decreases l) =
  match l with
  | [] -> ()
  | s :: t ->
      cascade_one_ok s target;
      all_sessions_ok_cascade t target

let rec all_reqs_ok_index (l: list request) (i: nat)
  : Lemma (requires (all_reqs_ok l /\ i < FStar.List.Tot.length l))
    (ensures (request_ok (FStar.List.Tot.index l i)))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else all_reqs_ok_index t (i - 1)

let rec all_reqs_ok_update (l: list request) (i: nat) (r: request)
  : Lemma (requires (all_reqs_ok l /\ request_ok r))
    (ensures (all_reqs_ok (update l i r)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else all_reqs_ok_update t (i - 1) r

let all_reqs_ok_cons (r: request) (l: list request)
  : Lemma (requires (request_ok r /\ all_reqs_ok l))
    (ensures (all_reqs_ok (r :: l))) = ()

/// A session whose id is its list position.
let new_pending (ctx: start_ctx) (id: nat) : session =
  { s_id = id;
    s_phase = Phase_Pending;
    s_owner = None;
    s_approver_user = ctx.st_approver_user;
    s_approver_dev = None;
    s_rw = ctx.st_rw;
    s_epoch = ctx.st_epoch;
    s_nonce_ok = ctx.st_nonce_ok;
    s_web_vk = ctx.st_web_vk;
    s_sentinel = false;
    s_lockout_delete = false;
    s_lockout_cascade = false;
    s_revoked_by_delete = false;
    s_claimed = false;
    s_issue_decisions = 0 }

let no_authority (s: session) : bool =
  (match s.s_phase <: session_phase with
   | Phase_Pending -> true
   | _ -> false) &&
  s.s_owner = None &&
  s.s_approver_dev = None &&
  s.s_issue_decisions = 0

let new_pending_ok (ctx: start_ctx) (id: nat)
  : Lemma (session_ok (new_pending ctx id)) = ()

let new_pending_no_authority (ctx: start_ctx) (id: nat)
  : Lemma (no_authority (new_pending ctx id)) = ()

// ── Live observations ──────────────────────────────────────────────────────

let grant_observation (w: world) (actor_user: small) (sid: nat) : t_GrantObservation =
  let s = session_at w sid in
  { f_phase = phase_to_policy s.s_phase;
    f_mode = mode_to_policy s.s_rw;
    f_approver_user = map_option_u128 s.s_approver_user;
    f_authenticated_user = uid actor_user;
    f_nonce_length = (if s.s_nonce_ok then mk_usize 32 else mk_usize 0);
    f_nonce_equal = s.s_nonce_ok;
    f_has_web_vk = s.s_web_vk;
    f_declared_epoch = s.s_epoch }

let token_observation (w: world) (sid: nat) : t_TokenSessionObservation =
  let s = session_at w sid in
  { f_phase = phase_to_policy s.s_phase;
    f_mode = mode_to_policy s.s_rw;
    f_granted_user = map_option_u128 s.s_owner;
    f_approver_user = map_option_u128 s.s_approver_user;
    f_nonce_present = s.s_nonce_ok;
    f_web_vk_present = s.s_web_vk;
    f_key_epoch = s.s_epoch;
    f_now = mk_i64 0;
    f_expires_at = Core_models.Option.Option_Some (mk_i64 1) }

let delete_facts (s: session) : t_DeleteSessionFacts =
  { f_session_user = map_option_u128 s.s_owner;
    f_approver_user = map_option_u128 s.s_approver_user }

let delete_observation (w: world) (sid: nat) : t_DeleteLookupObservation =
  if sid < FStar.List.Tot.length w.w_sessions
  then DeleteLookupObservation_Present (delete_facts (session_at w sid))
  else DeleteLookupObservation_Absent

/// The live lockout row is the delete driver's owner: `user_id`, or the
/// committed approver while still pending.
let delete_live_owner (obs: t_DeleteLookupObservation) : Core_models.Option.t_Option u128 =
  match obs <: t_DeleteLookupObservation with
  | DeleteLookupObservation_Present facts -> delete_owner facts
  | _ -> Core_models.Option.Option_None

let device_observation (w: world) (actor: nat) (target: nat) : t_DeviceLookupObservation =
  if target < FStar.List.Tot.length w.w_devices && (device_at w target).d_present
  then DeviceLookupObservation_Present
    ({ f_same_account = (device_owner w target = device_owner w actor);
       f_already_revoked = (device_at w target).d_revoked })
  else DeviceLookupObservation_Absent

// ── Facts about the extracted drivers used below ────────────────────────────

/// A grant permit implies the observed approver is the authenticated account
/// and the observed row is pending: the composition counts the driver's
/// decision, not a re-decision.
let grant_update_observation (d: t_GrantDriver) (obs: t_GrantObservation)
  : Lemma
    (requires (
      grant_state_is_sound d /\
      (match d.f_stage <: t_GrantStage with
       | GrantStage_ObserveSession -> True
       | _ -> False) /\
      (match (grant_step d (GrantEvent_SessionObserved
                              (GrantLookupObservation_Present obs))).f_effect
             <: t_GrantEffect with
       | GrantEffect_UpdateGrant _ -> True
       | _ -> False)))
    (ensures (
      obs.f_approver_user = Core_models.Option.Option_Some obs.f_authenticated_user /\
      obs.f_phase = SessionPhase_Pending)) =
  let t = grant_step d (GrantEvent_SessionObserved
                          (GrantLookupObservation_Present obs)) in
  match t.f_effect <: t_GrantEffect with
  | GrantEffect_UpdateGrant _ ->
      let decision = plan_observed_grant obs in
      assert (grant_decision_matches_spec (grant_facts obs) decision);
      (match decision <: t_GrantDecision with
       | GrantDecision_Grant _ ->
           assert (grant_is_authorized (grant_facts obs));
           assert ((grant_facts obs).f_phase = SessionPhase_Pending);
           assert ((grant_facts obs).f_approver_matches);
           assert (grant_facts_match_observation obs (grant_facts obs));
           assert (obs.f_phase = SessionPhase_Pending);
           assert (obs.f_approver_user = Core_models.Option.Option_Some obs.f_authenticated_user)
       | GrantDecision_Reject -> ())
  | _ -> ()

/// The token driver reaches the challenge stage only from a granted row.
let token_consume_granted (d: t_TokenDriver) (obs: t_TokenSessionObservation)
  : Lemma
    (requires (
      token_state_is_sound d /\
      (match d.f_stage <: t_TokenStage with
       | TokenStage_ObserveSession -> True
       | _ -> False)))
    (ensures (
      let t = token_step d (TokenEvent_SessionObserved
                              (TokenLookupObservation_Present obs)) in
      (match t.f_effect <: t_TokenEffect with
       | TokenEffect_ConsumeWebTokenChallenge ->
           obs.f_phase = SessionPhase_Granted
       | _ -> True))) =
  let t = token_step d (TokenEvent_SessionObserved
                          (TokenLookupObservation_Present obs)) in
  match obs.f_phase <: t_SessionPhase with
  | SessionPhase_Granted -> ()
  | SessionPhase_Pending ->
      assert (not (t.f_driver.f_session_eligible))
  | SessionPhase_Revoked ->
      assert (not (t.f_driver.f_session_eligible))
  | SessionPhase_Expired ->
      assert (not (t.f_driver.f_session_eligible))

/// The token driver's `session_eligible` fact can only be set by a granted
/// observation.
let token_eligible_granted (d: t_TokenDriver) (obs: t_TokenSessionObservation)
  : Lemma
    (requires (
      token_state_is_sound d /\
      (match d.f_stage <: t_TokenStage with
       | TokenStage_ObserveSession -> True
       | _ -> False)))
    (ensures (
      (token_step d (TokenEvent_SessionObserved
                       (TokenLookupObservation_Present obs))).f_driver.f_session_eligible = true ==>
      obs.f_phase = SessionPhase_Granted)) =
  token_consume_granted d obs;
  let t = token_step d (TokenEvent_SessionObserved
                          (TokenLookupObservation_Present obs)) in
  if t.f_driver.f_session_eligible
  then
    (match t.f_effect <: t_TokenEffect with
     | TokenEffect_ConsumeWebTokenChallenge -> ()
     | _ ->
         match d.f_stage <: t_TokenStage with
         | TokenStage_ObserveSession -> ())
  else ()

/// The extracted driver's `AlreadyClaimed` branch is terminal: it never
/// emits `IssueToken`. This is what makes the claim counter at most one.
let token_already_claimed_terminal (d: t_TokenDriver)
  : Lemma
    (requires (
      token_state_is_sound d /\
      (match d.f_stage <: t_TokenStage with
       | TokenStage_Claim -> True
       | _ -> False)))
    (ensures (
      (token_step d
         (TokenEvent_ClaimObserved TokenClaimObservation_AlreadyClaimed)).f_effect =
      TokenEffect_Fail TokenFailure_AlreadyIssued)) = ()

/// A delete lockout is authorized only when the live owner equals the actor.
let delete_lockout_owner (d: t_DeleteDriver) (user: small) (obs: t_DeleteLookupObservation)
  : Lemma
    (requires (
      delete_state_is_sound d /\
      d.f_actor_user = uid user /\
      (match d.f_stage <: t_DeleteStage with
       | DeleteStage_Observe -> True
       | _ -> False)))
    (ensures (
      (match (delete_step d (DeleteEvent_SessionObserved obs)).f_effect
              <: t_DeleteEffect with
       | DeleteEffect_LockoutSession ->
           delete_live_owner obs = Core_models.Option.Option_Some (uid user)
       | _ -> True))) =
  match obs <: t_DeleteLookupObservation with
  | DeleteLookupObservation_Present facts ->
      if delete_owner facts =. (Core_models.Option.Option_Some (uid user))
      then ()
      else ()
  | _ -> ()

// ── Spawning requests ──────────────────────────────────────────────────────

let spawn_start (w: world) (ctx: start_ctx) : world =
  { w with w_reqs = StartReq (begin_start ()).f_driver ctx :: w.w_reqs }

let spawn_grant (w: world) (ctx: grant_ctx) (sid: nat) : world =
  let actor : t_GrantActorObservation =
    { f_authenticated = true;
      f_device_active = device_active w ctx.g_actor_dev } in
  { w with w_reqs =
      GrantReq (begin_grant actor ctx.g_ttl).f_driver ctx sid :: w.w_reqs }

let spawn_token (w: world) (sid: nat) (ch: nat) : world =
  { w with w_reqs = TokenReq (begin_token ()).f_driver sid ch false :: w.w_reqs }

let spawn_delete (w: world) (user: small) (sid: nat) : world =
  let actor : t_DeleteActorObservation =
    { f_authenticated = true; f_user = uid user } in
  { w with w_reqs =
      DeleteReq (begin_delete actor).f_driver user sid false :: w.w_reqs }

let spawn_revoke (w: world) (actor_dev: nat) (target_dev: nat) : world =
  let actor : t_ActorObservation =
    { f_authenticated = true;
      f_device_active = device_active w actor_dev } in
  { w with w_reqs =
      RevokeReq (begin_revocation actor).f_driver
        ({ rv_actor_dev = actor_dev; rv_target_dev = target_dev }) :: w.w_reqs }

// ── Deliveries ─────────────────────────────────────────────────────────────

let set_req (w: world) (i: nat) (r: request) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then { w with w_reqs = update w.w_reqs i r }
  else w

let deliver_start_event (w: world) (i: nat) (e: t_StartEvent) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | StartReq d ctx ->
        if start_state_is_sound d
        then
          let t = start_step d e in
          set_req w i (StartReq t.f_driver ctx)
        else w
    | _ -> w
  else w

let deliver_start_inserted (w: world) (i: nat) (inserted: bool) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | StartReq d ctx ->
        if start_state_is_sound d
        then
          match d.f_stage <: t_StartStage with
          | StartStage_Insert ->
              let s = new_pending ctx (FStar.List.Tot.length w.w_sessions) in
              let w1 =
                if inserted
                then { w with
                       w_sessions = snoc w.w_sessions s;
                       w_start_authority =
                         w.w_start_authority + b2n (not (no_authority s)) }
                else w in
              let t = start_step d
                (StartEvent_Inserted
                   (if inserted then StartInsertObservation_Inserted
                    else StartInsertObservation_Failed)) in
              set_req w1 i (StartReq t.f_driver ctx)
          | _ ->
              let t = start_step d
                (StartEvent_Inserted StartInsertObservation_Inserted) in
              set_req w i (StartReq t.f_driver ctx)
        else w
    | _ -> w
  else w

let deliver_grant_event (w: world) (i: nat) (e: t_GrantEvent) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | GrantReq d ctx sid ->
        if grant_state_is_sound d
        then
          let t = grant_step d e in
          set_req w i (GrantReq t.f_driver ctx sid)
        else w
    | _ -> w
  else w

let deliver_grant_session (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | GrantReq d ctx sid ->
        if grant_state_is_sound d
        then
          match d.f_stage <: t_GrantStage with
          | GrantStage_ObserveSession ->
              let present = sid < FStar.List.Tot.length w.w_sessions in
              let obs = grant_observation w ctx.g_actor_user sid in
              let lookup =
                if present
                then GrantLookupObservation_Present obs
                else GrantLookupObservation_Absent in
              let t = grant_step d (GrantEvent_SessionObserved lookup) in
              let w1 = set_req w i (GrantReq t.f_driver ctx sid) in
              (match t.f_effect <: t_GrantEffect with
               | GrantEffect_UpdateGrant _ ->
                   let cross =
                     not (obs.f_approver_user =
                          Core_models.Option.Option_Some obs.f_authenticated_user) in
                   let nonpending =
                     not (obs.f_phase = SessionPhase_Pending) in
                   { w1 with
                     w_cross_account_grant =
                       w1.w_cross_account_grant + b2n cross;
                     w_nonpending_grant =
                       w1.w_nonpending_grant + b2n nonpending }
               | _ -> w1)
          | _ ->
              let t = grant_step d
                (GrantEvent_SessionObserved GrantLookupObservation_Absent) in
              set_req w i (GrantReq t.f_driver ctx sid)
        else w
    | _ -> w
  else w

let grant_cas_ok (w: world) (ctx: grant_ctx) (sid: nat) (u: t_GrantUpdate) : bool =
  if sid < FStar.List.Tot.length w.w_sessions
  then
    let s = session_at w sid in
    (match s.s_phase <: session_phase with
     | Phase_Pending -> true
     | _ -> false) &&
    account_present w ctx.g_actor_user &&
    account_active w ctx.g_actor_user &&
    account_epoch w ctx.g_actor_user =. u.f_epoch &&
    device_active w ctx.g_actor_dev &&
    device_owner w ctx.g_actor_dev = ctx.g_actor_user
  else false

let grant_bad_active (w: world) (ctx: grant_ctx) : bool =
  not (device_active w ctx.g_actor_dev &&
       account_active w ctx.g_actor_user &&
       device_owner w ctx.g_actor_dev = ctx.g_actor_user)

let grant_cas_active (w: world) (ctx: grant_ctx) (sid: nat) (u: t_GrantUpdate)
  : Lemma (grant_cas_ok w ctx sid u = true ==> not (grant_bad_active w ctx)) = ()

let apply_grant (w: world) (sid: nat) (ctx: grant_ctx) (u: t_GrantUpdate) : world =
  if sid < FStar.List.Tot.length w.w_sessions
  then
    let s = session_at w sid in
    let s' =
      { s with
        s_phase = Phase_Granted;
        s_owner = Some ctx.g_actor_user;
        s_approver_dev = Some ctx.g_actor_dev;
        s_rw = policy_to_mode u.f_mode;
        s_epoch = u.f_epoch } in
    { w with
      w_sessions = update w.w_sessions sid s';
      w_grants = w.w_grants + 1;
      w_inactive_grant = w.w_inactive_grant + b2n (grant_bad_active w ctx) }
  else w

let deliver_grant_update (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | GrantReq d ctx sid ->
        if grant_state_is_sound d
        then
          match d.f_stage <: t_GrantStage with
          | GrantStage_Update ->
              let u : t_GrantUpdate =
                { f_mode = d.f_permit_mode;
                  f_epoch = d.f_permit_epoch;
                  f_ttl_secs = d.f_ttl_secs } in
              let ok = grant_cas_ok w ctx sid u in
              let obs =
                if ok then GrantUpdateObservation_Updated
                else GrantUpdateObservation_Conflict in
              let t = grant_step d (GrantEvent_UpdateObserved obs) in
              let w1 = set_req w i (GrantReq t.f_driver ctx sid) in
              if ok then apply_grant w1 sid ctx u else w1
          | _ ->
              let t = grant_step d
                (GrantEvent_UpdateObserved GrantUpdateObservation_Conflict) in
              set_req w i (GrantReq t.f_driver ctx sid)
        else w
    | _ -> w
  else w

let deliver_token_event (w: world) (i: nat) (e: t_TokenEvent) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | TokenReq d sid ch eligible ->
        if token_state_is_sound d
        then
          let t = token_step d e in
          set_req w i (TokenReq t.f_driver sid ch eligible)
        else w
    | _ -> w
  else w

let deliver_token_session (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | TokenReq d sid ch _eligible ->
        if token_state_is_sound d
        then
          match d.f_stage <: t_TokenStage with
          | TokenStage_ObserveSession ->
              let present = sid < FStar.List.Tot.length w.w_sessions in
              let obs = token_observation w sid in
              let lookup =
                if present
                then TokenLookupObservation_Present obs
                else TokenLookupObservation_Absent in
              let eligible =
                if present
                then (match obs.f_phase <: t_SessionPhase with
                      | SessionPhase_Granted -> true
                      | _ -> false)
                else false in
              let t = token_step d (TokenEvent_SessionObserved lookup) in
              set_req w i (TokenReq t.f_driver sid ch eligible)
          | _ ->
              let t = token_step d
                (TokenEvent_SessionObserved TokenLookupObservation_Absent) in
              set_req w i (TokenReq t.f_driver sid ch _eligible)
        else w
    | _ -> w
  else w

let deliver_token_challenge (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | TokenReq d sid ch eligible ->
        if token_state_is_sound d
        then
          match d.f_stage <: t_TokenStage with
          | TokenStage_Challenge ->
              let c = challenge_at w ch in
              let present =
                ch < FStar.List.Tot.length w.w_challenges && c.c_present in
              let consumption =
                if present
                then (if c.c_web_token
                      then Vela_session_policy.Challenge.ChallengeConsumption_Accepted
                      else Vela_session_policy.Challenge.ChallengeConsumption_WrongPurpose)
                else Vela_session_policy.Challenge.ChallengeConsumption_Missing in
              let w1 =
                if present
                then { w with
                       w_challenges =
                         update w.w_challenges ch { c with c_present = false } }
                else w in
              let t = token_step d
                (TokenEvent_ChallengeObserved
                   (TokenChallengeObservation_Observed consumption)) in
              set_req w1 i (TokenReq t.f_driver sid ch eligible)
          | _ ->
              let t = token_step d
                (TokenEvent_ChallengeObserved
                   (TokenChallengeObservation_Observed
                      Vela_session_policy.Challenge.ChallengeConsumption_Missing)) in
              set_req w i (TokenReq t.f_driver sid ch eligible)
        else w
    | _ -> w
  else w

let apply_token_claim
      (w: world) (i: nat) (sid: nat) (ch: nat) (eligible: bool)
      (t: t_TokenTransition) (s: session) (already: bool) : world =
  let w1 =
    if already || sid >= FStar.List.Tot.length w.w_sessions
    then w
    else { w with
           w_sessions =
             update w.w_sessions sid ({ s with s_claimed = true }) } in
  let w2 = set_req w1 i (TokenReq t.f_driver sid ch eligible) in
  match t.f_effect <: t_TokenEffect with
  | TokenEffect_IssueToken _ ->
      let s2 =
        { s with s_claimed = true;
                 s_issue_decisions = s.s_issue_decisions + 1 } in
      { w2 with
        w_sessions = update w.w_sessions sid s2;
        w_token_from_pending =
          w2.w_token_from_pending + b2n (not eligible) }
  | _ -> w2

let deliver_token_claim (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | TokenReq d sid ch eligible ->
        if token_state_is_sound d
        then
          match d.f_stage <: t_TokenStage with
          | TokenStage_Claim ->
              let s = session_at w sid in
              let already = s.s_claimed in
              let obs =
                if already then TokenClaimObservation_AlreadyClaimed
                else TokenClaimObservation_Claimed in
              let t = token_step d (TokenEvent_ClaimObserved obs) in
              apply_token_claim w i sid ch eligible t s already
          | _ ->
              let t = token_step d
                (TokenEvent_ClaimObserved TokenClaimObservation_AlreadyClaimed) in
              set_req w i (TokenReq t.f_driver sid ch eligible)
        else w
    | _ -> w
  else w

let deliver_token_issued (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | TokenReq d sid ch eligible ->
        if token_state_is_sound d
        then
          match d.f_stage <: t_TokenStage with
          | TokenStage_Issue ->
              let s = session_at w sid in
              let allowed = not s.s_sentinel in
              let obs =
                if allowed then TokenIssueObservation_Issued
                else TokenIssueObservation_Failed in
              let t = token_step d (TokenEvent_Issued obs) in
              let w1 = set_req w i (TokenReq t.f_driver sid ch eligible) in
              if allowed
              then
                let after_delete = s.s_revoked_by_delete in
                let after_approver = s.s_lockout_cascade in
                { w1 with
                  w_tokens =
                    snoc w1.w_tokens
                      ({ t_sid = sid;
                         t_after_delete = after_delete;
                         t_after_approver = after_approver });
                  w_tokens_issued = w1.w_tokens_issued + 1;
                  w_token_after_delete =
                    w1.w_token_after_delete + b2n after_delete;
                  w_token_after_approver =
                    w1.w_token_after_approver + b2n after_approver }
              else w1
          | _ ->
              let t = token_step d
                (TokenEvent_Issued TokenIssueObservation_Failed) in
              set_req w i (TokenReq t.f_driver sid ch eligible)
        else w
    | _ -> w
  else w

let deliver_delete_session (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | DeleteReq d user sid locked ->
        if delete_state_is_sound d
        then
          match d.f_stage <: t_DeleteStage with
          | DeleteStage_Observe ->
              let obs = delete_observation w sid in
              let t = delete_step d (DeleteEvent_SessionObserved obs) in
              let w1 = set_req w i (DeleteReq t.f_driver user sid locked) in
              (match t.f_effect <: t_DeleteEffect with
               | DeleteEffect_LockoutSession ->
                   let cross =
                     not (delete_live_owner obs =
                          Core_models.Option.Option_Some (uid user)) in
                   { w1 with
                     w_cross_account_delete =
                       w1.w_cross_account_delete + b2n cross }
               | _ -> w1)
          | _ ->
              let t = delete_step d
                (DeleteEvent_SessionObserved DeleteLookupObservation_Absent) in
              set_req w i (DeleteReq t.f_driver user sid locked)
        else w
    | _ -> w
  else w

let delete_sentinel_step (d: t_DeleteDriver) (applied: bool)
  : Lemma
    (requires (
      delete_state_is_sound d /\
      (match d.f_stage <: t_DeleteStage with
       | DeleteStage_Lockout -> True
       | _ -> False)))
    (ensures (
      let t = delete_step d
        (DeleteEvent_SentinelWritten
           (if applied then DeleteSentinelObservation_Applied
            else DeleteSentinelObservation_StorageFailed)) in
      t.f_driver.f_locked = applied /\
      t.f_driver.f_actor_user = d.f_actor_user)) = ()

let deliver_delete_sentinel (w: world) (i: nat) (applied: bool) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | DeleteReq d user sid locked ->
        if delete_state_is_sound d
        then
          match d.f_stage <: t_DeleteStage with
          | DeleteStage_Lockout ->
              let w1 =
                if applied
                then
                  let s = session_at w sid in
                  { w with
                    w_sessions =
                      update w.w_sessions sid
                        ({ s with s_sentinel = true;
                                  s_lockout_delete = true }) }
                else w in
              let t = delete_step d
                (DeleteEvent_SentinelWritten
                   (if applied then DeleteSentinelObservation_Applied
                    else DeleteSentinelObservation_StorageFailed)) in
              set_req w1 i (DeleteReq t.f_driver user sid applied)
          | _ ->
              let t = delete_step d
                (DeleteEvent_SentinelWritten DeleteSentinelObservation_Applied) in
              set_req w i (DeleteReq t.f_driver user sid locked)
        else w
    | _ -> w
  else w

let deliver_delete_record (w: world) (i: nat) (updated: bool) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | DeleteReq d user sid locked ->
        if delete_state_is_sound d
        then
          match d.f_stage <: t_DeleteStage with
          | DeleteStage_Record ->
              let w1 =
                if updated
                then
                  let s = session_at w sid in
                  { w with
                    w_sessions =
                      update w.w_sessions sid
                        ({ s with s_phase = Phase_Revoked;
                                  s_revoked_by_delete = true;
                                  s_sentinel = s.s_sentinel || locked }) }
                else w in
              let t = delete_step d
                (DeleteEvent_RecordObserved
                   (if updated then DeleteRecordObservation_Updated
                    else DeleteRecordObservation_Failed)) in
              set_req w1 i (DeleteReq t.f_driver user sid locked)
          | _ ->
              let t = delete_step d
                (DeleteEvent_RecordObserved DeleteRecordObservation_Failed) in
              set_req w i (DeleteReq t.f_driver user sid locked)
        else w
    | _ -> w
  else w

let deliver_revoke_event (w: world) (i: nat) (e: t_RevocationEvent) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d ctx ->
        if revocation_state_is_sound d
        then
          let t = step d e in
          set_req w i (RevokeReq t.f_driver ctx)
        else w
    | _ -> w
  else w

let deliver_revoke_lookup (w: world) (i: nat) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d ctx ->
        if revocation_state_is_sound d
        then
          match d.f_stage <: t_RevocationStage with
          | RevocationStage_Observe ->
              let obs =
                device_observation w ctx.rv_actor_dev ctx.rv_target_dev in
              deliver_revoke_event w i
                (RevocationEvent_TargetObserved obs)
          | _ -> deliver_revoke_event w i
                   (RevocationEvent_TargetObserved
                      DeviceLookupObservation_Absent)
        else w
    | _ -> w
  else w

let deliver_revoke_lockout (w: world) (i: nat) (applied: bool) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d ctx ->
        if revocation_state_is_sound d
        then
          match d.f_stage <: t_RevocationStage with
          | RevocationStage_Lockout ->
              let w1 =
                if applied && ctx.rv_target_dev < FStar.List.Tot.length w.w_devices
                then
                  let dev = device_at w ctx.rv_target_dev in
                  { w with
                    w_devices =
                      update w.w_devices ctx.rv_target_dev
                        ({ dev with d_sentinel = true }) }
                else w in
              let t = step d
                (RevocationEvent_LockoutObserved
                   (if applied then LockoutObservation_Applied
                    else LockoutObservation_StorageFailed)) in
              set_req w1 i (RevokeReq t.f_driver ctx)
          | RevocationStage_RepeatLockout ->
              let w1 =
                if applied && ctx.rv_target_dev < FStar.List.Tot.length w.w_devices
                then
                  let dev = device_at w ctx.rv_target_dev in
                  { w with
                    w_devices =
                      update w.w_devices ctx.rv_target_dev
                        ({ dev with d_sentinel = true }) }
                else w in
              let t = step d
                (RevocationEvent_LockoutObserved
                   (if applied then LockoutObservation_Applied
                    else LockoutObservation_StorageFailed)) in
              set_req w1 i (RevokeReq t.f_driver ctx)
          | _ ->
              let t = step d
                (RevocationEvent_LockoutObserved
                   LockoutObservation_StorageFailed) in
              set_req w i (RevokeReq t.f_driver ctx)
        else w
    | _ -> w
  else w

let deliver_revoke_record (w: world) (i: nat) (updated: bool) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d ctx ->
        if revocation_state_is_sound d
        then
          match d.f_stage <: t_RevocationStage with
          | RevocationStage_Record ->
              let w1 =
                if updated && ctx.rv_target_dev < FStar.List.Tot.length w.w_devices
                then
                  let dev = device_at w ctx.rv_target_dev in
                  { w with
                    w_devices =
                      update w.w_devices ctx.rv_target_dev
                        ({ dev with d_revoked = true }) }
                else w in
              let t = step d
                (RevocationEvent_RecordObserved
                   (if updated then RecordObservation_Updated
                    else RecordObservation_Failed)) in
              set_req w1 i (RevokeReq t.f_driver ctx)
          | _ ->
              let t = step d
                (RevocationEvent_RecordObserved RecordObservation_Failed) in
              set_req w i (RevokeReq t.f_driver ctx)
        else w
    | _ -> w
  else w

let deliver_revoke_cascade (w: world) (i: nat) (completed: bool) : world =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d ctx ->
        if revocation_state_is_sound d
        then
          match d.f_stage <: t_RevocationStage with
          | RevocationStage_Cascade ->
              let w1 =
                if completed
                then { w with
                       w_sessions =
                         cascade_sessions w.w_sessions ctx.rv_target_dev }
                else w in
              let t = step d
                (RevocationEvent_CascadeObserved
                   (if completed then CascadeObservation_Completed
                    else CascadeObservation_StorageFailed)) in
              set_req w1 i (RevokeReq t.f_driver ctx)
          | RevocationStage_RepeatCascade ->
              let w1 =
                if completed
                then { w with
                       w_sessions =
                         cascade_sessions w.w_sessions ctx.rv_target_dev }
                else w in
              let t = step d
                (RevocationEvent_CascadeObserved
                   (if completed then CascadeObservation_Completed
                    else CascadeObservation_StorageFailed)) in
              set_req w1 i (RevokeReq t.f_driver ctx)
          | _ ->
              let t = step d
                (RevocationEvent_CascadeObserved
                   CascadeObservation_StorageFailed) in
              set_req w i (RevokeReq t.f_driver ctx)
        else w
    | _ -> w
  else w

// ── Arbitrary schedules ────────────────────────────────────────────────────

noeq type action =
  | SpawnStart : start_ctx -> action
  | StartLimit : nat -> bool -> action
  | StartValidated : nat -> bool -> action
  | StartInserted : nat -> bool -> action
  | SpawnGrant : grant_ctx -> nat -> action
  | GrantValidated : nat -> bool -> action
  | GrantSession : nat -> action
  | GrantUpdate : nat -> action
  | SpawnToken : nat -> nat -> action
  | TokenLimits : nat -> bool -> action
  | TokenSession : nat -> action
  | TokenChallenge : nat -> action
  | TokenSignature : nat -> t_TokenSignatureObservation -> action
  | TokenFailure : nat -> t_TokenFailureRecordObservation -> action
  | TokenReset : nat -> bool -> action
  | TokenClaim : nat -> action
  | TokenIssued : nat -> action
  | SpawnDelete : small -> nat -> action
  | DeleteSession : nat -> action
  | DeleteSentinel : nat -> bool -> action
  | DeleteRecord : nat -> bool -> action
  | SpawnRevoke : nat -> nat -> action
  | RevokeLookup : nat -> action
  | RevokeLockout : nat -> bool -> action
  | RevokeRecord : nat -> bool -> action
  | RevokeCascade : nat -> bool -> action

let world_step (w: world) (a: action) : world =
  match a with
  | SpawnStart ctx -> spawn_start w ctx
  | StartLimit i allowed ->
      deliver_start_event w i
        (StartEvent_LimitObserved
           (if allowed then StartLimitObservation_Allowed
            else StartLimitObservation_Limited))
  | StartValidated i valid ->
      deliver_start_event w i
        (StartEvent_Validated
           (if valid then StartValidationObservation_Valid
            else StartValidationObservation_Invalid))
  | StartInserted i inserted -> deliver_start_inserted w i inserted
  | SpawnGrant ctx sid -> spawn_grant w ctx sid
  | GrantValidated i valid ->
      deliver_grant_event w i
        (GrantEvent_Validated
           (if valid then GrantValidationObservation_Valid
            else GrantValidationObservation_Invalid))
  | GrantSession i -> deliver_grant_session w i
  | GrantUpdate i -> deliver_grant_update w i
  | SpawnToken sid ch -> spawn_token w sid ch
  | TokenLimits i allowed ->
      deliver_token_event w i
        (TokenEvent_LimitsObserved
           (if allowed then TokenLimitObservation_Allowed
            else TokenLimitObservation_Limited))
  | TokenSession i -> deliver_token_session w i
  | TokenChallenge i -> deliver_token_challenge w i
  | TokenSignature i obs -> deliver_token_event w i (TokenEvent_SignatureObserved obs)
  | TokenFailure i obs -> deliver_token_event w i (TokenEvent_FailureRecorded obs)
  | TokenReset i ok ->
      deliver_token_event w i
        (TokenEvent_ResetObserved
           (if ok then TokenResetObservation_Reset { f_now = mk_i64 0 }
            else TokenResetObservation_StorageFailed))
  | TokenClaim i -> deliver_token_claim w i
  | TokenIssued i -> deliver_token_issued w i
  | SpawnDelete user sid -> spawn_delete w user sid
  | DeleteSession i -> deliver_delete_session w i
  | DeleteSentinel i applied -> deliver_delete_sentinel w i applied
  | DeleteRecord i updated -> deliver_delete_record w i updated
  | SpawnRevoke actor target -> spawn_revoke w actor target
  | RevokeLookup i -> deliver_revoke_lookup w i
  | RevokeLockout i applied -> deliver_revoke_lockout w i applied
  | RevokeRecord i updated -> deliver_revoke_record w i updated
  | RevokeCascade i completed -> deliver_revoke_cascade w i completed

let rec run_world (w: world) (schedule: list action) : Tot world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

// ── Session update lemmas ──────────────────────────────────────────────────

let session_ok_grant (s: session) (ctx: grant_ctx) (u: t_GrantUpdate)
  : Lemma
    (requires (
      session_ok s /\
      (match s.s_phase <: session_phase with
       | Phase_Pending -> True
       | _ -> False)))
    (ensures (
      session_ok
        ({ s with
           s_phase = Phase_Granted;
           s_owner = Some ctx.g_actor_user;
           s_approver_dev = Some ctx.g_actor_dev;
           s_rw = policy_to_mode u.f_mode;
           s_epoch = u.f_epoch }))) =
  match s.s_phase <: session_phase with
  | Phase_Pending -> ()
  | _ -> ()

let session_ok_sentinel (s: session)
  : Lemma
    (requires (session_ok s))
    (ensures (session_ok ({ s with s_sentinel = true;
                                    s_lockout_delete = true }))) = ()

let session_ok_claim (s: session)
  : Lemma
    (requires (session_ok s))
    (ensures (session_ok ({ s with s_claimed = true }))) = ()

let session_ok_claim_issue (s: session)
  : Lemma
    (requires (session_ok s /\ s.s_issue_decisions = 0))
    (ensures (session_ok ({ s with s_claimed = true;
                                    s_issue_decisions = 1 }))) = ()

let session_ok_record (s: session) (locked: bool)
  : Lemma
    (requires (session_ok s /\ locked = true))
    (ensures (
      session_ok
        ({ s with
           s_phase = Phase_Revoked;
           s_revoked_by_delete = true;
           s_sentinel = s.s_sentinel || locked }))) = ()

// ── Invariant preservation: spawning ───────────────────────────────────────

let spawn_start_inv (w: world) (ctx: start_ctx)
  : Lemma (requires (inv w)) (ensures (inv (spawn_start w ctx))) =
  let r = StartReq (begin_start ()).f_driver ctx in
  assert (request_ok r);
  all_reqs_ok_cons r w.w_reqs

let spawn_grant_inv (w: world) (ctx: grant_ctx) (sid: nat)
  : Lemma (requires (inv w)) (ensures (inv (spawn_grant w ctx sid))) =
  let actor : t_GrantActorObservation =
    { f_authenticated = true;
      f_device_active = device_active w ctx.g_actor_dev } in
  let r = GrantReq (begin_grant actor ctx.g_ttl).f_driver ctx sid in
  assert (request_ok r);
  all_reqs_ok_cons r w.w_reqs

let spawn_token_inv (w: world) (sid: nat) (ch: nat)
  : Lemma (requires (inv w)) (ensures (inv (spawn_token w sid ch))) =
  let r = TokenReq (begin_token ()).f_driver sid ch false in
  assert (request_ok r);
  all_reqs_ok_cons r w.w_reqs

let spawn_delete_inv (w: world) (user: small) (sid: nat)
  : Lemma (requires (inv w)) (ensures (inv (spawn_delete w user sid))) =
  let actor : t_DeleteActorObservation =
    { f_authenticated = true; f_user = uid user } in
  let r = DeleteReq (begin_delete actor).f_driver user sid false in
  assert (request_ok r);
  assert ((begin_delete actor).f_driver.f_actor_user = uid user);
  all_reqs_ok_cons r w.w_reqs

let spawn_revoke_inv (w: world) (actor_dev: nat) (target_dev: nat)
  : Lemma (requires (inv w)) (ensures (inv (spawn_revoke w actor_dev target_dev))) =
  let actor : t_ActorObservation =
    { f_authenticated = true;
      f_device_active = device_active w actor_dev } in
  let r = RevokeReq (begin_revocation actor).f_driver
            ({ rv_actor_dev = actor_dev; rv_target_dev = target_dev }) in
  assert (request_ok r);
  all_reqs_ok_cons r w.w_reqs

// ── Invariant preservation: start ──────────────────────────────────────────

let start_event_inv (w: world) (i: nat) (e: t_StartEvent)
  : Lemma (requires (inv w)) (ensures (inv (deliver_start_event w i e))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | StartReq d ctx ->
        if start_state_is_sound d
        then begin
          all_reqs_ok_index w.w_reqs i;
          let t = start_step d e in
          let nr = StartReq t.f_driver ctx in
          assert (request_ok nr);
          all_reqs_ok_update w.w_reqs i nr
        end
        else ()
    | _ -> ()
  else ()

let start_inserted_inv (w: world) (i: nat) (inserted: bool)
  : Lemma (requires (inv w)) (ensures (inv (deliver_start_inserted w i inserted))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | StartReq d ctx ->
        if start_state_is_sound d
        then
          match d.f_stage <: t_StartStage with
          | StartStage_Insert ->
              all_reqs_ok_index w.w_reqs i;
              let s = new_pending ctx (FStar.List.Tot.length w.w_sessions) in
              new_pending_ok ctx (FStar.List.Tot.length w.w_sessions);
              new_pending_no_authority ctx (FStar.List.Tot.length w.w_sessions);
              let t = start_step d
                (StartEvent_Inserted
                   (if inserted then StartInsertObservation_Inserted
                    else StartInsertObservation_Failed)) in
              let nr = StartReq t.f_driver ctx in
              assert (request_ok nr);
              if inserted
              then begin
                all_sessions_ok_snoc w.w_sessions s;
                all_reqs_ok_update w.w_reqs i nr
              end
              else all_reqs_ok_update w.w_reqs i nr
          | _ ->
              all_reqs_ok_index w.w_reqs i;
              let t = start_step d
                (StartEvent_Inserted StartInsertObservation_Inserted) in
              let nr = StartReq t.f_driver ctx in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
        else ()
    | _ -> ()
  else ()

// ── Invariant preservation: grant ──────────────────────────────────────────

let grant_event_inv (w: world) (i: nat) (e: t_GrantEvent)
  : Lemma (requires (inv w)) (ensures (inv (deliver_grant_event w i e))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | GrantReq d ctx sid ->
        if grant_state_is_sound d
        then begin
          all_reqs_ok_index w.w_reqs i;
          let t = grant_step d e in
          let nr = GrantReq t.f_driver ctx sid in
          assert (request_ok nr);
          all_reqs_ok_update w.w_reqs i nr
        end
        else ()
    | _ -> ()
  else ()

let grant_session_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_grant_session w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | GrantReq d ctx sid ->
        if grant_state_is_sound d
        then
          match d.f_stage <: t_GrantStage with
          | GrantStage_ObserveSession ->
              all_reqs_ok_index w.w_reqs i;
              let present = sid < FStar.List.Tot.length w.w_sessions in
              let obs = grant_observation w ctx.g_actor_user sid in
              let lookup =
                if present then GrantLookupObservation_Present obs
                else GrantLookupObservation_Absent in
              let t = grant_step d (GrantEvent_SessionObserved lookup) in
              let w1 = set_req w i (GrantReq t.f_driver ctx sid) in
              assert (request_ok (GrantReq t.f_driver ctx sid));
              all_reqs_ok_update w.w_reqs i (GrantReq t.f_driver ctx sid);
              (match t.f_effect <: t_GrantEffect with
               | GrantEffect_UpdateGrant _ ->
                   grant_update_observation d obs;
                   assert (obs.f_approver_user =
                           Core_models.Option.Option_Some obs.f_authenticated_user);
                   assert (obs.f_phase = SessionPhase_Pending);
                   assert (w1.w_cross_account_grant + b2n
                             (not (obs.f_approver_user =
                                   Core_models.Option.Option_Some
                                     obs.f_authenticated_user)) = 0);
                   assert (w1.w_nonpending_grant + b2n
                             (not (obs.f_phase = SessionPhase_Pending)) = 0)
               | _ -> ())
          | _ ->
              all_reqs_ok_index w.w_reqs i;
              let t = grant_step d
                (GrantEvent_SessionObserved GrantLookupObservation_Absent) in
              let nr = GrantReq t.f_driver ctx sid in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
        else ()
    | _ -> ()
  else ()

let grant_update_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_grant_update w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | GrantReq d ctx sid ->
        if grant_state_is_sound d
        then
          match d.f_stage <: t_GrantStage with
          | GrantStage_Update ->
              all_reqs_ok_index w.w_reqs i;
              let u : t_GrantUpdate =
                { f_mode = d.f_permit_mode;
                  f_epoch = d.f_permit_epoch;
                  f_ttl_secs = d.f_ttl_secs } in
              let ok = grant_cas_ok w ctx sid u in
              let obs =
                if ok then GrantUpdateObservation_Updated
                else GrantUpdateObservation_Conflict in
              let t = grant_step d (GrantEvent_UpdateObserved obs) in
              let w1 = set_req w i (GrantReq t.f_driver ctx sid) in
              assert (request_ok (GrantReq t.f_driver ctx sid));
              all_reqs_ok_update w.w_reqs i (GrantReq t.f_driver ctx sid);
              if ok
              then begin
                assert (sid < FStar.List.Tot.length w.w_sessions);
                all_sessions_ok_index w.w_sessions sid;
                assert ((match (session_at w sid).s_phase <: session_phase with
                         | Phase_Pending -> True
                         | _ -> False));
                session_ok_grant (session_at w sid) ctx u;
                all_sessions_ok_update w.w_sessions sid
                  ({ (session_at w sid) with
                     s_phase = Phase_Granted;
                     s_owner = Some ctx.g_actor_user;
                     s_approver_dev = Some ctx.g_actor_dev;
                     s_rw = policy_to_mode u.f_mode;
                     s_epoch = u.f_epoch });
                grant_cas_active w ctx sid u;
                assert (not (grant_bad_active w ctx));
                assert (grant_bad_active w1 ctx = false)
              end
              else ()
          | _ ->
              all_reqs_ok_index w.w_reqs i;
              let t = grant_step d
                (GrantEvent_UpdateObserved GrantUpdateObservation_Conflict) in
              let nr = GrantReq t.f_driver ctx sid in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
        else ()
    | _ -> ()
  else ()

// ── Invariant preservation: token ──────────────────────────────────────────

let token_event_inv (w: world) (i: nat) (e: t_TokenEvent)
  : Lemma
    (requires (
      inv w /\
      (match e <: t_TokenEvent with
       | TokenEvent_SessionObserved _ -> False
       | TokenEvent_ChallengeObserved _ -> False
       | TokenEvent_ClaimObserved _ -> False
       | TokenEvent_Issued _ -> False
       | _ -> True)))
    (ensures (inv (deliver_token_event w i e))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | TokenReq d sid ch eligible ->
        if token_state_is_sound d
        then begin
          all_reqs_ok_index w.w_reqs i;
          let t = token_step d e in
          let nr = TokenReq t.f_driver sid ch eligible in
          assert (request_ok nr);
          all_reqs_ok_update w.w_reqs i nr
        end
        else ()
    | _ -> ()
  else ()

let token_session_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_token_session w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | TokenReq d sid ch old_eligible ->
        if token_state_is_sound d
        then
          match d.f_stage <: t_TokenStage with
          | TokenStage_ObserveSession ->
              all_reqs_ok_index w.w_reqs i;
              let present = sid < FStar.List.Tot.length w.w_sessions in
              let obs = token_observation w sid in
              let lookup =
                if present then TokenLookupObservation_Present obs
                else TokenLookupObservation_Absent in
              let eligible =
                if present
                then (match obs.f_phase <: t_SessionPhase with
                      | SessionPhase_Granted -> true
                      | _ -> false)
                else false in
              let t = token_step d (TokenEvent_SessionObserved lookup) in
              let nr = TokenReq t.f_driver sid ch eligible in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
          | _ ->
              all_reqs_ok_index w.w_reqs i;
              let t = token_step d
                (TokenEvent_SessionObserved TokenLookupObservation_Absent) in
              let nr = TokenReq t.f_driver sid ch old_eligible in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
        else ()
    | _ -> ()
  else ()

let token_challenge_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_token_challenge w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | TokenReq d sid ch eligible ->
        if token_state_is_sound d
        then
          match d.f_stage <: t_TokenStage with
          | TokenStage_Challenge ->
              all_reqs_ok_index w.w_reqs i;
              let c = challenge_at w ch in
              let present =
                ch < FStar.List.Tot.length w.w_challenges && c.c_present in
              let consumption =
                if present
                then (if c.c_web_token
                      then Vela_session_policy.Challenge.ChallengeConsumption_Accepted
                      else Vela_session_policy.Challenge.ChallengeConsumption_WrongPurpose)
                else Vela_session_policy.Challenge.ChallengeConsumption_Missing in
              let w1 =
                if present
                then { w with
                       w_challenges =
                         update w.w_challenges ch { c with c_present = false } }
                else w in
              let t = token_step d
                (TokenEvent_ChallengeObserved
                   (TokenChallengeObservation_Observed consumption)) in
              let nr = TokenReq t.f_driver sid ch eligible in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
          | _ ->
              all_reqs_ok_index w.w_reqs i;
              let t = token_step d
                (TokenEvent_ChallengeObserved
                   (TokenChallengeObservation_Observed
                      Vela_session_policy.Challenge.ChallengeConsumption_Missing)) in
              let nr = TokenReq t.f_driver sid ch eligible in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
        else ()
    | _ -> ()
  else ()

let apply_token_claim_issue_inv
      (w: world) (i: nat) (sid: nat) (ch: nat) (eligible: bool)
      (t: t_TokenTransition) (s: session) (already: bool)
  : Lemma
    (requires (
      inv w /\
      request_ok (TokenReq t.f_driver sid ch eligible) /\
      already = false /\ eligible = true /\
      session_ok s /\ s = session_at w sid /\ s.s_issue_decisions = 0 /\
      (match t.f_effect <: t_TokenEffect with
       | TokenEffect_IssueToken _ -> True
       | _ -> False)))
    (ensures (inv (apply_token_claim w i sid ch eligible t s already))) =
  let w1 =
    if already || sid >= FStar.List.Tot.length w.w_sessions
    then w
    else { w with
           w_sessions =
             update w.w_sessions sid ({ s with s_claimed = true }) } in
  let w2 = set_req w1 i (TokenReq t.f_driver sid ch eligible) in
  let r =
    { s with s_claimed = true;
             s_issue_decisions = s.s_issue_decisions + 1 } in
  assert (s.s_issue_decisions + 1 = 1);
  session_ok_claim_issue s;
  assert (session_ok r);
  if sid < FStar.List.Tot.length w.w_sessions
  then begin
    all_sessions_ok_index w.w_sessions sid;
    all_sessions_ok_update w.w_sessions sid r
  end
  else begin
    update_out w.w_sessions sid r;
    assert (update w.w_sessions sid r = w.w_sessions)
  end;
  assert ((apply_token_claim w i sid ch eligible t s already).w_sessions =
          update w.w_sessions sid r);
  all_reqs_ok_update w1.w_reqs i (TokenReq t.f_driver sid ch eligible);
  assert (all_reqs_ok (apply_token_claim w i sid ch eligible t s already).w_reqs);
  assert (b2n (not eligible) = 0);
  assert (counters_ok (apply_token_claim w i sid ch eligible t s already))

let apply_token_claim_other_inv
      (w: world) (i: nat) (sid: nat) (ch: nat) (eligible: bool)
      (t: t_TokenTransition) (s: session) (already: bool)
  : Lemma
    (requires (
      inv w /\
      request_ok (TokenReq t.f_driver sid ch eligible) /\
      session_ok s /\
      (match t.f_effect <: t_TokenEffect with
       | TokenEffect_IssueToken _ -> False
       | _ -> True)))
    (ensures (inv (apply_token_claim w i sid ch eligible t s already))) =
  let w1 =
    if already || sid >= FStar.List.Tot.length w.w_sessions
    then w
    else { w with
           w_sessions =
             update w.w_sessions sid ({ s with s_claimed = true }) } in
  let w2 = set_req w1 i (TokenReq t.f_driver sid ch eligible) in
  all_reqs_ok_update w1.w_reqs i (TokenReq t.f_driver sid ch eligible);
  if not already && sid < FStar.List.Tot.length w.w_sessions
  then begin
    all_sessions_ok_index w.w_sessions sid;
    session_ok_claim s;
    all_sessions_ok_update w.w_sessions sid ({ s with s_claimed = true })
  end
  else ();
  assert ((apply_token_claim w i sid ch eligible t s already).w_sessions =
          w1.w_sessions);
  assert (all_reqs_ok (apply_token_claim w i sid ch eligible t s already).w_reqs);
  assert (counters_ok (apply_token_claim w i sid ch eligible t s already))

#push-options "--fuel 4 --ifuel 2"

let token_claim_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_token_claim w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | TokenReq d sid ch eligible ->
        if token_state_is_sound d
        then
          match d.f_stage <: t_TokenStage with
          | TokenStage_Claim ->
              all_reqs_ok_index w.w_reqs i;
              let s = session_at w sid in
              let already = s.s_claimed in
              let obs =
                if already then TokenClaimObservation_AlreadyClaimed
                else TokenClaimObservation_Claimed in
              let t = token_step d (TokenEvent_ClaimObserved obs) in
              assert (request_ok (TokenReq t.f_driver sid ch eligible));
              (match t.f_effect <: t_TokenEffect with
               | TokenEffect_IssueToken _ ->
                   assert (eligible = true);
                   (match already <: bool with
                    | false ->
                        if sid < FStar.List.Tot.length w.w_sessions
                        then all_sessions_ok_index w.w_sessions sid
                        else ();
                        assert (session_ok s);
                        assert (s.s_issue_decisions = 0);
                        apply_token_claim_issue_inv w i sid ch eligible t s already
                    | true ->
                        token_already_claimed_terminal d;
                        assert False)
               | _ ->
                   if sid < FStar.List.Tot.length w.w_sessions
                   then all_sessions_ok_index w.w_sessions sid
                   else ();
                   assert (session_ok s);
                   apply_token_claim_other_inv w i sid ch eligible t s already)
          | _ ->
              all_reqs_ok_index w.w_reqs i;
              let t = token_step d
                (TokenEvent_ClaimObserved TokenClaimObservation_AlreadyClaimed) in
              let nr = TokenReq t.f_driver sid ch eligible in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
        else ()
    | _ -> ()
  else ()

#pop-options

let token_issued_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_token_issued w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | TokenReq d sid ch eligible ->
        if token_state_is_sound d
        then
          match d.f_stage <: t_TokenStage with
          | TokenStage_Issue ->
              all_reqs_ok_index w.w_reqs i;
              let s = session_at w sid in
              let allowed = not s.s_sentinel in
              let obs =
                if allowed then TokenIssueObservation_Issued
                else TokenIssueObservation_Failed in
              let t = token_step d (TokenEvent_Issued obs) in
              let w1 = set_req w i (TokenReq t.f_driver sid ch eligible) in
              assert (request_ok (TokenReq t.f_driver sid ch eligible));
              all_reqs_ok_update w.w_reqs i (TokenReq t.f_driver sid ch eligible);
              if allowed
              then begin
                if sid < FStar.List.Tot.length w.w_sessions
                then begin
                  all_sessions_ok_index w.w_sessions sid;
                  assert (not s.s_revoked_by_delete);
                  assert (not s.s_lockout_cascade)
                end
                else ();
                assert (w1.w_token_after_delete + b2n s.s_revoked_by_delete = 0);
                assert (w1.w_token_after_approver + b2n s.s_lockout_cascade = 0)
              end
              else ()
          | _ ->
              all_reqs_ok_index w.w_reqs i;
              let t = token_step d
                (TokenEvent_Issued TokenIssueObservation_Failed) in
              let nr = TokenReq t.f_driver sid ch eligible in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
        else ()
    | _ -> ()
  else ()

// ── Invariant preservation: delete ─────────────────────────────────────────

let delete_session_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_delete_session w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | DeleteReq d user sid locked ->
        if delete_state_is_sound d
        then
          match d.f_stage <: t_DeleteStage with
          | DeleteStage_Observe ->
              all_reqs_ok_index w.w_reqs i;
              let obs = delete_observation w sid in
              let t = delete_step d (DeleteEvent_SessionObserved obs) in
              let w1 = set_req w i (DeleteReq t.f_driver user sid locked) in
              assert (request_ok (DeleteReq t.f_driver user sid locked));
              all_reqs_ok_update w.w_reqs i
                (DeleteReq t.f_driver user sid locked);
              (match t.f_effect <: t_DeleteEffect with
               | DeleteEffect_LockoutSession ->
                   delete_lockout_owner d user obs;
                   assert (delete_live_owner obs =
                           Core_models.Option.Option_Some (uid user));
                   assert (w1.w_cross_account_delete + b2n
                             (not (delete_live_owner obs =
                                   Core_models.Option.Option_Some (uid user))) = 0)
               | _ -> ())
          | _ ->
              all_reqs_ok_index w.w_reqs i;
              let t = delete_step d
                (DeleteEvent_SessionObserved DeleteLookupObservation_Absent) in
              let nr = DeleteReq t.f_driver user sid locked in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
        else ()
    | _ -> ()
  else ()

let delete_sentinel_inv (w: world) (i: nat) (applied: bool)
  : Lemma (requires (inv w)) (ensures (inv (deliver_delete_sentinel w i applied))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | DeleteReq d user sid locked ->
        if delete_state_is_sound d
        then
          match d.f_stage <: t_DeleteStage with
          | DeleteStage_Lockout ->
              all_reqs_ok_index w.w_reqs i;
              let w1 =
                if applied
                then
                  let s = session_at w sid in
                  { w with
                    w_sessions =
                      update w.w_sessions sid
                        ({ s with s_sentinel = true;
                                  s_lockout_delete = true }) }
                else w in
              if applied
              then begin
                if sid < FStar.List.Tot.length w.w_sessions
                then begin
                  all_sessions_ok_index w.w_sessions sid;
                  session_ok_sentinel (session_at w sid);
                  all_sessions_ok_update w.w_sessions sid
                    ({ (session_at w sid) with s_sentinel = true;
                                                 s_lockout_delete = true })
                end
                else begin
                  update_out w.w_sessions sid
                    ({ (session_at w sid) with s_sentinel = true;
                                                 s_lockout_delete = true });
                  assert (update w.w_sessions sid
                            ({ (session_at w sid) with s_sentinel = true;
                                                         s_lockout_delete = true }) =
                          w.w_sessions)
                end
              end
              else ();
              let t = delete_step d
                (DeleteEvent_SentinelWritten
                   (if applied then DeleteSentinelObservation_Applied
                    else DeleteSentinelObservation_StorageFailed)) in
              delete_sentinel_step d applied;
              let nr = DeleteReq t.f_driver user sid applied in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr;
              assert (all_reqs_ok (deliver_delete_sentinel w i applied).w_reqs);
              assert (all_sessions_ok (deliver_delete_sentinel w i applied).w_sessions);
              assert (counters_ok (deliver_delete_sentinel w i applied))
          | _ ->
              all_reqs_ok_index w.w_reqs i;
              let t = delete_step d
                (DeleteEvent_SentinelWritten DeleteSentinelObservation_Applied) in
              let nr = DeleteReq t.f_driver user sid locked in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
        else ()
    | _ -> ()
  else ()

let delete_record_inv (w: world) (i: nat) (updated: bool)
  : Lemma (requires (inv w)) (ensures (inv (deliver_delete_record w i updated))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | DeleteReq d user sid locked ->
        if delete_state_is_sound d
        then
          match d.f_stage <: t_DeleteStage with
          | DeleteStage_Record ->
              all_reqs_ok_index w.w_reqs i;
              assert (locked = true);
              let w1 =
                if updated
                then
                  let s = session_at w sid in
                  { w with
                    w_sessions =
                      update w.w_sessions sid
                        ({ s with s_phase = Phase_Revoked;
                                  s_revoked_by_delete = true;
                                  s_sentinel = s.s_sentinel || locked }) }
                else w in
              if updated
              then begin
                if sid < FStar.List.Tot.length w.w_sessions
                then begin
                  all_sessions_ok_index w.w_sessions sid;
                  session_ok_record (session_at w sid) locked;
                  all_sessions_ok_update w.w_sessions sid
                    ({ (session_at w sid) with
                       s_phase = Phase_Revoked;
                       s_revoked_by_delete = true;
                       s_sentinel = (session_at w sid).s_sentinel || locked })
                end
                else begin
                  update_out w.w_sessions sid
                    ({ (session_at w sid) with
                       s_phase = Phase_Revoked;
                       s_revoked_by_delete = true;
                       s_sentinel = (session_at w sid).s_sentinel || locked })
                end
              end
              else ();
              let t = delete_step d
                (DeleteEvent_RecordObserved
                   (if updated then DeleteRecordObservation_Updated
                    else DeleteRecordObservation_Failed)) in
              let nr = DeleteReq t.f_driver user sid locked in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr;
              assert (all_reqs_ok (deliver_delete_record w i updated).w_reqs);
              assert (all_sessions_ok (deliver_delete_record w i updated).w_sessions);
              assert (counters_ok (deliver_delete_record w i updated))
          | _ ->
              all_reqs_ok_index w.w_reqs i;
              let t = delete_step d
                (DeleteEvent_RecordObserved DeleteRecordObservation_Failed) in
              let nr = DeleteReq t.f_driver user sid locked in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
        else ()
    | _ -> ()
  else ()

// ── Invariant preservation: device revocation ──────────────────────────────

let revoke_event_inv (w: world) (i: nat) (e: t_RevocationEvent)
  : Lemma (requires (inv w)) (ensures (inv (deliver_revoke_event w i e))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d ctx ->
        if revocation_state_is_sound d
        then begin
          all_reqs_ok_index w.w_reqs i;
          let t = step d e in
          let nr = RevokeReq t.f_driver ctx in
          assert (request_ok nr);
          all_reqs_ok_update w.w_reqs i nr
        end
        else ()
    | _ -> ()
  else ()

let revoke_lookup_inv (w: world) (i: nat)
  : Lemma (requires (inv w)) (ensures (inv (deliver_revoke_lookup w i))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d ctx ->
        if revocation_state_is_sound d
        then
          match d.f_stage <: t_RevocationStage with
          | RevocationStage_Observe ->
              let obs = device_observation w ctx.rv_actor_dev ctx.rv_target_dev in
              revoke_event_inv w i (RevocationEvent_TargetObserved obs)
          | _ ->
              revoke_event_inv w i
                (RevocationEvent_TargetObserved DeviceLookupObservation_Absent)
        else ()
    | _ -> ()
  else ()

let revoke_lockout_inv (w: world) (i: nat) (applied: bool)
  : Lemma (requires (inv w)) (ensures (inv (deliver_revoke_lockout w i applied))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d ctx ->
        if revocation_state_is_sound d
        then
          match d.f_stage <: t_RevocationStage with
          | RevocationStage_Lockout ->
              all_reqs_ok_index w.w_reqs i;
              let t = step d
                (RevocationEvent_LockoutObserved
                   (if applied then LockoutObservation_Applied
                    else LockoutObservation_StorageFailed)) in
              let nr = RevokeReq t.f_driver ctx in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
          | RevocationStage_RepeatLockout ->
              all_reqs_ok_index w.w_reqs i;
              let t = step d
                (RevocationEvent_LockoutObserved
                   (if applied then LockoutObservation_Applied
                    else LockoutObservation_StorageFailed)) in
              let nr = RevokeReq t.f_driver ctx in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
          | _ ->
              all_reqs_ok_index w.w_reqs i;
              let t = step d
                (RevocationEvent_LockoutObserved
                   LockoutObservation_StorageFailed) in
              let nr = RevokeReq t.f_driver ctx in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
        else ()
    | _ -> ()
  else ()

let revoke_record_inv (w: world) (i: nat) (updated: bool)
  : Lemma (requires (inv w)) (ensures (inv (deliver_revoke_record w i updated))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d ctx ->
        if revocation_state_is_sound d
        then
          match d.f_stage <: t_RevocationStage with
          | RevocationStage_Record ->
              all_reqs_ok_index w.w_reqs i;
              let t = step d
                (RevocationEvent_RecordObserved
                   (if updated then RecordObservation_Updated
                    else RecordObservation_Failed)) in
              let nr = RevokeReq t.f_driver ctx in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
          | _ ->
              all_reqs_ok_index w.w_reqs i;
              let t = step d
                (RevocationEvent_RecordObserved RecordObservation_Failed) in
              let nr = RevokeReq t.f_driver ctx in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
        else ()
    | _ -> ()
  else ()

let revoke_cascade_inv (w: world) (i: nat) (completed: bool)
  : Lemma (requires (inv w)) (ensures (inv (deliver_revoke_cascade w i completed))) =
  if i < FStar.List.Tot.length w.w_reqs
  then
    match FStar.List.Tot.index w.w_reqs i with
    | RevokeReq d ctx ->
        if revocation_state_is_sound d
        then
          match d.f_stage <: t_RevocationStage with
          | RevocationStage_Cascade ->
              all_reqs_ok_index w.w_reqs i;
              let t = step d
                (RevocationEvent_CascadeObserved
                   (if completed then CascadeObservation_Completed
                    else CascadeObservation_StorageFailed)) in
              let nr = RevokeReq t.f_driver ctx in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr;
              if completed
              then all_sessions_ok_cascade w.w_sessions ctx.rv_target_dev
              else ()
          | RevocationStage_RepeatCascade ->
              all_reqs_ok_index w.w_reqs i;
              let t = step d
                (RevocationEvent_CascadeObserved
                   (if completed then CascadeObservation_Completed
                    else CascadeObservation_StorageFailed)) in
              let nr = RevokeReq t.f_driver ctx in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr;
              if completed
              then all_sessions_ok_cascade w.w_sessions ctx.rv_target_dev
              else ()
          | _ ->
              all_reqs_ok_index w.w_reqs i;
              let t = step d
                (RevocationEvent_CascadeObserved
                   CascadeObservation_StorageFailed) in
              let nr = RevokeReq t.f_driver ctx in
              assert (request_ok nr);
              all_reqs_ok_update w.w_reqs i nr
        else ()
    | _ -> ()
  else ()

// ── One action preserves the invariant ─────────────────────────────────────

let world_step_inv (w: world) (a: action)
  : Lemma (requires (inv w)) (ensures (inv (world_step w a))) =
  match a with
  | SpawnStart ctx -> spawn_start_inv w ctx
  | StartLimit i allowed ->
      start_event_inv w i
        (StartEvent_LimitObserved
           (if allowed then StartLimitObservation_Allowed
            else StartLimitObservation_Limited))
  | StartValidated i valid ->
      start_event_inv w i
        (StartEvent_Validated
           (if valid then StartValidationObservation_Valid
            else StartValidationObservation_Invalid))
  | StartInserted i inserted -> start_inserted_inv w i inserted
  | SpawnGrant ctx sid -> spawn_grant_inv w ctx sid
  | GrantValidated i valid ->
      grant_event_inv w i
        (GrantEvent_Validated
           (if valid then GrantValidationObservation_Valid
            else GrantValidationObservation_Invalid))
  | GrantSession i -> grant_session_inv w i
  | GrantUpdate i -> grant_update_inv w i
  | SpawnToken sid ch -> spawn_token_inv w sid ch
  | TokenLimits i allowed ->
      token_event_inv w i
        (TokenEvent_LimitsObserved
           (if allowed then TokenLimitObservation_Allowed
            else TokenLimitObservation_Limited))
  | TokenSession i -> token_session_inv w i
  | TokenChallenge i -> token_challenge_inv w i
  | TokenSignature i obs ->
      token_event_inv w i (TokenEvent_SignatureObserved obs)
  | TokenFailure i obs ->
      token_event_inv w i (TokenEvent_FailureRecorded obs)
  | TokenReset i ok ->
      token_event_inv w i
        (TokenEvent_ResetObserved
           (if ok then TokenResetObservation_Reset { f_now = mk_i64 0 }
            else TokenResetObservation_StorageFailed))
  | TokenClaim i -> token_claim_inv w i
  | TokenIssued i -> token_issued_inv w i
  | SpawnDelete user sid -> spawn_delete_inv w user sid
  | DeleteSession i -> delete_session_inv w i
  | DeleteSentinel i applied -> delete_sentinel_inv w i applied
  | DeleteRecord i updated -> delete_record_inv w i updated
  | SpawnRevoke actor target -> spawn_revoke_inv w actor target
  | RevokeLookup i -> revoke_lookup_inv w i
  | RevokeLockout i applied -> revoke_lockout_inv w i applied
  | RevokeRecord i updated -> revoke_record_inv w i updated
  | RevokeCascade i completed -> revoke_cascade_inv w i completed

let rec run_world_inv (w: world) (schedule: list action)
  : Lemma (requires (inv w)) (ensures (inv (run_world w schedule)))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest -> world_step_inv w a; run_world_inv (world_step w a) rest

// ── Initial world and headline theorem ─────────────────────────────────────

let initial : world =
  { w_accounts = [ { a_present = true; a_active = true; a_epoch = mk_i64 1 } ];
    w_devices = [ { d_owner = 0; d_present = true; d_revoked = false;
                    d_sentinel = false } ];
    w_sessions = [];
    w_challenges = [];
    w_tokens = [];
    w_reqs = [];
    w_token_after_delete = 0;
    w_token_after_approver = 0;
    w_cross_account_grant = 0;
    w_inactive_grant = 0;
    w_nonpending_grant = 0;
    w_token_from_pending = 0;
    w_cross_account_delete = 0;
    w_start_authority = 0;
    w_tokens_issued = 0;
    w_grants = 0;
    w_delete_lockouts = 0 }

let initial_inv () : Lemma (inv initial) = ()

/// Headline theorem. For every schedule:
/// 1. every session has at most one `IssueToken` decision;
/// 2. no token is released after the session's delete lockout/revocation or
///    after its approver-revocation cascade;
/// 3. grants are authorized only from the owning, active approver and only for
///    a pending session;
/// 4. start inserts only a pending row and no token comes from such a row;
/// 5. no cross-account delete is authorized.
let composition_theorem (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      inv w /\
      all_sessions_ok w.w_sessions /\
      w.w_token_after_delete = 0 /\
      w.w_token_after_approver = 0 /\
      w.w_cross_account_grant = 0 /\
      w.w_inactive_grant = 0 /\
      w.w_nonpending_grant = 0 /\
      w.w_token_from_pending = 0 /\
      w.w_cross_account_delete = 0 /\
      w.w_start_authority = 0) =
  initial_inv ();
  run_world_inv initial schedule;
  let w = run_world initial schedule in
  assert (inv w)

let no_double_token (schedule: list action)
  : Lemma (all_sessions_ok (run_world initial schedule).w_sessions) =
  composition_theorem schedule

let no_token_after_revocation (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      w.w_token_after_delete = 0 /\ w.w_token_after_approver = 0) =
  composition_theorem schedule

let grants_only_from_the_owner (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      w.w_cross_account_grant = 0 /\ w.w_inactive_grant = 0 /\
      w.w_nonpending_grant = 0) =
  composition_theorem schedule

let start_creates_no_authority (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      w.w_start_authority = 0 /\ w.w_token_from_pending = 0) =
  composition_theorem schedule

let no_cross_account_delete (schedule: list action)
  : Lemma ((run_world initial schedule).w_cross_account_delete = 0) =
  composition_theorem schedule


// ── Reachability witnesses ─────────────────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"

let witness_session : session =
  { s_id = 0;
    s_phase = Phase_Granted;
    s_owner = Some 0;
    s_approver_user = Some 0;
    s_approver_dev = Some 0;
    s_rw = true;
    s_epoch = mk_i64 1;
    s_nonce_ok = true;
    s_web_vk = true;
    s_sentinel = false;
    s_lockout_delete = false;
    s_lockout_cascade = false;
    s_revoked_by_delete = false;
    s_claimed = false;
    s_issue_decisions = 0 }

let witness_world : world =
  { w_accounts = [ { a_present = true; a_active = true; a_epoch = mk_i64 1 } ];
    w_devices = [ { d_owner = 0; d_present = true; d_revoked = false;
                    d_sentinel = false } ];
    w_sessions = [ witness_session ];
    w_challenges = [ { c_web_token = true; c_present = true };
                     { c_web_token = true; c_present = true } ];
    w_tokens = [];
    w_reqs = [];
    w_token_after_delete = 0;
    w_token_after_approver = 0;
    w_cross_account_grant = 0;
    w_inactive_grant = 0;
    w_nonpending_grant = 0;
    w_token_from_pending = 0;
    w_cross_account_delete = 0;
    w_start_authority = 0;
    w_tokens_issued = 0;
    w_grants = 0;
    w_delete_lockouts = 0 }

let witness_world_inv () : Lemma (inv witness_world) = ()

/// A complete token exchange: the session is granted, has a web_token
/// challenge, and the driver takes it, verifies, resets, claims and issues.
let v1 = world_step witness_world (SpawnToken 0 0)
let v2 = world_step v1 (TokenLimits 0 true)
let v3 = world_step v2 (TokenSession 0)
let v4 = world_step v3 (TokenChallenge 0)
let v5 = world_step v4
  (TokenSignature 0 TokenSignatureObservation_Valid)
let v6 = world_step v5 (TokenReset 0 true)
let v7 = world_step v6 (TokenClaim 0)
let v8 = world_step v7 (TokenIssued 0)

/// Witness 1: exactly one token is issued and the session carries exactly one
/// `IssueToken` decision.
let one_token_is_reachable ()
  : Lemma (
      v8.w_tokens_issued = 1 /\
      FStar.List.Tot.length v8.w_tokens = 1 /\
      (session_at v8 0).s_issue_decisions = 1 /\
      (session_at v8 0).s_claimed = true) =
  assert_norm (
    v8.w_tokens_issued = 1 /\
    FStar.List.Tot.length v8.w_tokens = 1 /\
    (session_at v8 0).s_issue_decisions = 1 /\
    (session_at v8 0).s_claimed = true)

/// A second, independently fresh challenge and proof cannot mint a second
/// token: the claim key is already set, so the driver stops at
/// `AlreadyClaimed`.
let v9 = world_step v8 (SpawnToken 0 1)
let v10 = world_step v9 (TokenLimits 0 true)
let v11 = world_step v10 (TokenSession 0)
let v12 = world_step v11 (TokenChallenge 0)
let v13 = world_step v12
  (TokenSignature 0 TokenSignatureObservation_Valid)
let v14 = world_step v13 (TokenReset 0 true)
let v15 = world_step v14 (TokenClaim 0)

/// Witness 2: the second attempt is refused; still exactly one token.
let second_token_attempt_is_refused ()
  : Lemma (
      v15.w_tokens_issued = 1 /\
      FStar.List.Tot.length v15.w_tokens = 1 /\
      (session_at v15 0).s_issue_decisions = 1 /\
      (match FStar.List.Tot.index v15.w_reqs 0 with
       | TokenReq d _ _ _ ->
           d.f_failed = true /\
           (match d.f_stage <: t_TokenStage with
            | TokenStage_Done -> true
            | _ -> false)
       | _ -> False)) =
  assert_norm (
    v15.w_tokens_issued = 1 /\
    FStar.List.Tot.length v15.w_tokens = 1 /\
    (session_at v15 0).s_issue_decisions = 1 /\
    (match FStar.List.Tot.index v15.w_reqs 0 with
     | TokenReq d _ _ _ ->
         d.f_failed = true /\
         (match d.f_stage <: t_TokenStage with
          | TokenStage_Done -> true
          | _ -> false)
     | _ -> False))

/// Delete locks the session out and revokes the row.
let d1 = world_step witness_world (SpawnDelete 0 0)
let d2 = world_step d1 (DeleteSession 0)
let d3 = world_step d2 (DeleteSentinel 0 true)
let d4 = world_step d3 (DeleteRecord 0 true)
let d5 = world_step d4 (SpawnToken 0 0)
let d6 = world_step d5 (TokenLimits 0 true)
let d7 = world_step d6 (TokenSession 0)

/// Witness 3: after the delete committed the sentinel and SQL revocation, a
/// fresh token request is refused at its session observation and no token is
/// issued.
let token_after_delete_is_refused ()
  : Lemma (
      d7.w_tokens_issued = 0 /\
      (session_at d7 0).s_phase = Phase_Revoked /\
      (session_at d7 0).s_sentinel = true /\
      (session_at d7 0).s_revoked_by_delete = true /\
      (match FStar.List.Tot.index d7.w_reqs 0 with
       | TokenReq d _ _ _ ->
           d.f_failed = true /\ d.f_session_loaded = false
       | _ -> False)) =
  assert_norm (
    d7.w_tokens_issued = 0 /\
    (session_at d7 0).s_phase = Phase_Revoked /\
    (session_at d7 0).s_sentinel = true /\
    (session_at d7 0).s_revoked_by_delete = true /\
    (match FStar.List.Tot.index d7.w_reqs 0 with
     | TokenReq d _ _ _ ->
         d.f_failed = true /\ d.f_session_loaded = false
     | _ -> False))

/// A start inserts only a fresh pending row and creates no authority.
let st1 = world_step witness_world
  (SpawnStart { st_approver_user = Some 0; st_rw = true;
                st_epoch = mk_i64 1; st_nonce_ok = true;
                st_web_vk = true })
let st2 = world_step st1 (StartLimit 0 true)
let st3 = world_step st2 (StartValidated 0 true)
let st4 = world_step st3 (StartInserted 0 true)

let start_creates_a_pending_row_only ()
  : Lemma (
      st4.w_start_authority = 0 /\
      FStar.List.Tot.length st4.w_sessions = 2 /\
      (match session_at st4 1 with
       | s ->
           (match s.s_phase <: session_phase with
            | Phase_Pending -> true
            | _ -> false) /\
           s.s_owner = None /\
           s.s_approver_dev = None /\
           s.s_issue_decisions = 0)) =
  assert_norm (
    st4.w_start_authority = 0 /\
    FStar.List.Tot.length st4.w_sessions = 2 /\
    (match session_at st4 1 with
     | s ->
         (match s.s_phase <: session_phase with
          | Phase_Pending -> true
          | _ -> false) /\
         s.s_owner = None /\
         s.s_approver_dev = None /\
         s.s_issue_decisions = 0))

#pop-options
