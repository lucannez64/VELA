module Vela_recovery_policy_possession_driver_composition

/// Concurrent composition of the *extracted* possession-proof recovery driver.
///
/// One single-use proof state is shared by any number of requests, each running
/// its own `Vela_recovery_policy.Possession_driver.step_proof_recover`. A
/// schedule is an arbitrary list of actions: start a request, count an attempt,
/// consume the proof state, deliver the live-account / proof / grant-store
/// observations to any request. The world abstracts the handler's effects:
///
/// - the rate limiter: counting consumes one unit of the shared attempt budget
///   and is the only way a request may reach the single-use consume;
/// - the store's atomic `get_del` (a consumption sees the state iff it is still
///   present, and removes it in the same step);
/// - the `users` row query and commitment decode, the hybrid verification and
///   the single-use grant store, whose observations the schedule chooses.
///
/// Theorem: for every schedule and every initial budget `k`, at most one grant
/// is issued for the one proof state, and the number of counted attempts is at
/// most `k`. Assumptions (not proved here): `get_del` is linearizable, the
/// handler performs exactly the effect the driver returns, the proof state is
/// created once by an admitted initiation, and an observation reaches the
/// driver in the same step as its effect. SQL/row and observation origins
/// remain outside this module.

open FStar.Mul
open Core_models
open Vela_recovery_policy
open Vela_recovery_policy.Possession_driver
open Vela_recovery_policy_possession_driver_lemmas

let b2n (b: bool) : nat = if b then 1 else 0

/// A request holds the consumed proof-state token between a matched
/// consumption and the grant decision.
let holds (d: t_ProofRecoverDriver) : nat =
  if is_live d || is_verify d then 1 else 0

/// The token released by a matched `Present` consumption observation.
let consume_release (e: t_ProofRecoverEvent) : nat =
  match e <: t_ProofRecoverEvent with
  | ProofRecoverEvent_AttemptConsumed
      (AttemptConsumptionObservation_Present
        { f_user_matches = user_matches; f_attempt_matches = attempt_matches;
          f_key_epoch = _ }) ->
      b2n (user_matches && attempt_matches)
  | _ -> 0

// ── Per-request token accounting over the extracted step ───────────────────

/// A step never creates a held token or a grant out of nothing: the only source
/// is a matched `Present` consumption observation.
let step_tokens (d: t_ProofRecoverDriver) (e: t_ProofRecoverEvent)
  : Lemma
    (requires (trace_sound d))
    (ensures (
      let t = step_proof_recover d e in
      holds t.f_driver + issued t.f_effect <= holds d + consume_release e)) =
  trace_sound_matches_rust d;
  step_sound d e;
  match e <: t_ProofRecoverEvent with
  | ProofRecoverEvent_AttemptCounted _ -> ()
  | ProofRecoverEvent_AttemptConsumed obs ->
      (match obs <: t_AttemptConsumptionObservation with
       | AttemptConsumptionObservation_Missing -> ()
       | AttemptConsumptionObservation_Corrupt -> ()
       | AttemptConsumptionObservation_Present _ -> ())
  | ProofRecoverEvent_AccountObserved _ -> ()
  | ProofRecoverEvent_ProofObserved _ -> ()
  | ProofRecoverEvent_GrantStored _ -> ()

/// For every non-consumption event the step creates no token from the store.
let step_tokens_other (d: t_ProofRecoverDriver) (e: t_ProofRecoverEvent)
  : Lemma
    (requires (
      trace_sound d = true /\
      (match e <: t_ProofRecoverEvent with
       | ProofRecoverEvent_AttemptConsumed _ -> False
       | _ -> True)))
    (ensures (
      let t = step_proof_recover d e in
      holds t.f_driver + issued t.f_effect <= holds d)) =
  step_tokens d e;
  match e <: t_ProofRecoverEvent with
  | ProofRecoverEvent_AttemptCounted _ -> ()
  | ProofRecoverEvent_AttemptConsumed _ -> ()
  | ProofRecoverEvent_AccountObserved _ -> ()
  | ProofRecoverEvent_ProofObserved _ -> ()
  | ProofRecoverEvent_GrantStored _ -> ()

// ── Request lists ──────────────────────────────────────────────────────────

let rec update (l: list t_ProofRecoverDriver) (i: nat) (x: t_ProofRecoverDriver)
  : Tot (list t_ProofRecoverDriver) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update t (i - 1) x

let rec all_sound (l: list t_ProofRecoverDriver) : bool =
  match l with
  | [] -> true
  | d :: r -> trace_sound d && all_sound r

let rec held (l: list t_ProofRecoverDriver) : nat =
  match l with
  | [] -> 0
  | d :: r -> holds d + held r

let rec counted (l: list t_ProofRecoverDriver) : nat =
  match l with
  | [] -> 0
  | d :: r -> b2n d.f_budget_counted + counted r

let rec index_sound (l: list t_ProofRecoverDriver) (i: nat)
  : Lemma
    (requires (all_sound l /\ i < FStar.List.Tot.length l))
    (ensures (trace_sound (FStar.List.Tot.index l i)))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else index_sound t (i - 1)

let rec update_sound (l: list t_ProofRecoverDriver) (i: nat) (x: t_ProofRecoverDriver)
  : Lemma
    (requires (all_sound l /\ trace_sound x))
    (ensures (all_sound (update l i x)))
    (decreases l) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else update_sound t (i - 1) x

let rec update_held (l: list t_ProofRecoverDriver) (i: nat) (x: t_ProofRecoverDriver)
  : Lemma
    (requires (i < FStar.List.Tot.length l))
    (ensures (held (update l i x) + holds (FStar.List.Tot.index l i) = held l + holds x))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else update_held t (i - 1) x

let rec update_counted (l: list t_ProofRecoverDriver) (i: nat) (x: t_ProofRecoverDriver)
  : Lemma
    (requires (i < FStar.List.Tot.length l))
    (ensures (
      counted (update l i x) + b2n (FStar.List.Tot.index l i).f_budget_counted =
      counted l + b2n x.f_budget_counted))
    (decreases l) =
  match l with
  | _ :: t -> if i = 0 then () else update_counted t (i - 1) x

/// Replacing a request without changing its counted bit keeps the budget count.
let counted_unchanged (l: list t_ProofRecoverDriver) (i: nat) (x: t_ProofRecoverDriver)
  : Lemma
    (requires (
      i < FStar.List.Tot.length l /\
      (FStar.List.Tot.index l i).f_budget_counted = x.f_budget_counted))
    (ensures (counted (update l i x) = counted l)) =
  update_counted l i x

/// Admitting an uncounted request increases the counted total by one.
let counted_admitted (l: list t_ProofRecoverDriver) (i: nat) (x: t_ProofRecoverDriver)
  : Lemma
    (requires (
      i < FStar.List.Tot.length l /\
      not (FStar.List.Tot.index l i).f_budget_counted /\
      x.f_budget_counted))
    (ensures (counted (update l i x) = counted l + 1)) =
  update_counted l i x

// ── The shared world and arbitrary schedules ───────────────────────────────

noeq type world = {
  proof_state: bool;
  budget: nat;
  grants: nat;
  reqs: list t_ProofRecoverDriver;
}

type action =
  | Spawn : action
  | Count : nat -> action
  | Consume : nat -> t_AttemptConsumptionObservation -> action
  | Live : nat -> t_ProofAccountObservation -> action
  | Prove : nat -> t_ProofObservation -> action
  | Store : nat -> t_GrantStoreObservation -> action

/// Deliver an event to request `i` and perform the effect the driver returns.
/// `proof_state_mid` is the store's proof-state bit after the atomic effect.
let deliver (w: world) (i: nat{i < FStar.List.Tot.length w.reqs})
    (e: t_ProofRecoverEvent) (proof_state_mid: bool) : world =
  let d = FStar.List.Tot.index w.reqs i in
  if proof_recover_state_is_sound d then
    let t = step_proof_recover d e in
    { proof_state = proof_state_mid;
      budget = w.budget;
      grants = w.grants + issued t.f_effect;
      reqs = update w.reqs i t.f_driver }
  else { w with proof_state = proof_state_mid }

let world_step (w: world) (a: action) : world =
  match a with
  | Spawn -> { w with reqs = (begin_proof_recover ()).f_driver :: w.reqs }
  | Count i ->
      if i < FStar.List.Tot.length w.reqs && is_attempt (FStar.List.Tot.index w.reqs i)
      then
        if w.budget > 0
        then
          deliver { w with budget = w.budget - 1 } i
            (ProofRecoverEvent_AttemptCounted AttemptBudgetObservation_Admitted)
            w.proof_state
        else
          deliver w i
            (ProofRecoverEvent_AttemptCounted AttemptBudgetObservation_Limited)
            w.proof_state
      else w
  | Consume i obs ->
      if i < FStar.List.Tot.length w.reqs && is_consume (FStar.List.Tot.index w.reqs i)
      then
        if w.proof_state
        then
          (match obs <: t_AttemptConsumptionObservation with
           | AttemptConsumptionObservation_Missing ->
               // A present state cannot be observed missing.
               w
           | _ ->
               deliver { w with proof_state = false } i
                 (ProofRecoverEvent_AttemptConsumed obs) false)
        else
          deliver w i
            (ProofRecoverEvent_AttemptConsumed AttemptConsumptionObservation_Missing)
            false
      else w
  | Live i obs ->
      if i < FStar.List.Tot.length w.reqs && is_live (FStar.List.Tot.index w.reqs i)
      then deliver w i (ProofRecoverEvent_AccountObserved obs) w.proof_state
      else w
  | Prove i obs ->
      if i < FStar.List.Tot.length w.reqs && is_verify (FStar.List.Tot.index w.reqs i)
      then deliver w i (ProofRecoverEvent_ProofObserved obs) w.proof_state
      else w
  | Store i obs ->
      if i < FStar.List.Tot.length w.reqs && is_issue (FStar.List.Tot.index w.reqs i)
      then deliver w i (ProofRecoverEvent_GrantStored obs) w.proof_state
      else w

let rec run_world (w: world) (schedule: list action) : Tot world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

/// Token conservation: the proof state in the store, grants issued and tokens
/// held by in-flight requests never exceed one. The attempt budget is consumed
/// only by counted requests.
let inv (w: world) (k: nat) : prop =
  all_sound w.reqs /\
  b2n w.proof_state + w.grants + held w.reqs <= 1 /\
  w.budget + counted w.reqs <= k

/// Deliver while preserving both token conservation and the counted budget.
let deliver_inv (w: world) (i: nat{i < FStar.List.Tot.length w.reqs})
    (e: t_ProofRecoverEvent) (proof_state_mid: bool) (k: nat)
  : Lemma
    (requires (
      inv w k /\
      (let d = FStar.List.Tot.index w.reqs i in
       proof_recover_state_is_sound d ==>
       (let t = step_proof_recover d e in
        counted (update w.reqs i t.f_driver) = counted w.reqs /\
        b2n proof_state_mid + issued t.f_effect + holds t.f_driver
          <= b2n w.proof_state + holds d))))
    (ensures (inv (deliver w i e proof_state_mid) k)) =
  let d = FStar.List.Tot.index w.reqs i in
  index_sound w.reqs i;
  trace_sound_matches_rust d;
  assert (proof_recover_state_is_sound d = true);
  step_sound d e;
  let t = step_proof_recover d e in
  update_sound w.reqs i t.f_driver;
  update_held w.reqs i t.f_driver

/// Admitting an attempt preserves the invariant: one budget unit is spent and
/// the request's counted flag flips on.
let deliver_admit_inv (w: world) (i: nat{i < FStar.List.Tot.length w.reqs}) (k: nat)
  : Lemma
    (requires (
      inv w k /\ w.budget > 0 /\
      is_attempt (FStar.List.Tot.index w.reqs i)))
    (ensures (
      inv (deliver { w with budget = w.budget - 1 } i
             (ProofRecoverEvent_AttemptCounted AttemptBudgetObservation_Admitted)
             w.proof_state) k)) =
  let d = FStar.List.Tot.index w.reqs i in
  index_sound w.reqs i;
  trace_sound_matches_rust d;
  let e = ProofRecoverEvent_AttemptCounted AttemptBudgetObservation_Admitted in
  step_tokens_other d e;
  step_sound d e;
  let t = step_proof_recover d e in
  assert (not d.f_budget_counted);
  assert (t.f_driver.f_budget_counted);
  counted_admitted w.reqs i t.f_driver;
  update_sound w.reqs i t.f_driver;
  update_held w.reqs i t.f_driver

/// Every action preserves the invariant.
let world_step_inv (w: world) (a: action) (k: nat)
  : Lemma (requires (inv w k)) (ensures (inv (world_step w a) k)) =
  match a with
  | Spawn ->
      begin_sound ();
      trace_sound_matches_rust (begin_proof_recover ()).f_driver
  | Count i ->
      if i < FStar.List.Tot.length w.reqs && is_attempt (FStar.List.Tot.index w.reqs i)
      then begin
        index_sound w.reqs i;
        let d0 = FStar.List.Tot.index w.reqs i in
        trace_sound_matches_rust d0;
        if w.budget > 0 then begin
          assert (w.budget > 0);
          deliver_admit_inv w i k
        end else begin
          let e = ProofRecoverEvent_AttemptCounted AttemptBudgetObservation_Limited in
          let t = step_proof_recover d0 e in
          step_tokens_other d0 e;
          assert (not d0.f_budget_counted);
          assert (not t.f_driver.f_budget_counted);
          counted_unchanged w.reqs i t.f_driver;
          deliver_inv w i e w.proof_state k
        end
      end
  | Consume i obs ->
      if i < FStar.List.Tot.length w.reqs && is_consume (FStar.List.Tot.index w.reqs i)
      then begin
        index_sound w.reqs i;
        trace_sound_matches_rust (FStar.List.Tot.index w.reqs i);
        if w.proof_state then begin
          match obs <: t_AttemptConsumptionObservation with
          | AttemptConsumptionObservation_Missing -> ()
          | _ ->
              let e = ProofRecoverEvent_AttemptConsumed obs in
              let d = FStar.List.Tot.index w.reqs i in
              let t = step_proof_recover d e in
              counted_unchanged w.reqs i t.f_driver;
              step_tokens d e;
              assert (issued t.f_effect + holds t.f_driver
                      <= b2n w.proof_state + holds d);
              deliver_inv w i e false k
        end else begin
          let e = ProofRecoverEvent_AttemptConsumed AttemptConsumptionObservation_Missing in
          let d = FStar.List.Tot.index w.reqs i in
          let t = step_proof_recover d e in
          counted_unchanged w.reqs i t.f_driver;
          step_tokens d e;
          deliver_inv w i e false k
        end
      end
  | Live i obs ->
      if i < FStar.List.Tot.length w.reqs && is_live (FStar.List.Tot.index w.reqs i)
      then begin
        index_sound w.reqs i;
        trace_sound_matches_rust (FStar.List.Tot.index w.reqs i);
        let e = ProofRecoverEvent_AccountObserved obs in
        let d = FStar.List.Tot.index w.reqs i in
        let t = step_proof_recover d e in
        counted_unchanged w.reqs i t.f_driver;
        step_tokens_other d e;
        deliver_inv w i e w.proof_state k
      end
  | Prove i obs ->
      if i < FStar.List.Tot.length w.reqs && is_verify (FStar.List.Tot.index w.reqs i)
      then begin
        index_sound w.reqs i;
        trace_sound_matches_rust (FStar.List.Tot.index w.reqs i);
        let e = ProofRecoverEvent_ProofObserved obs in
        let d = FStar.List.Tot.index w.reqs i in
        let t = step_proof_recover d e in
        counted_unchanged w.reqs i t.f_driver;
        step_tokens_other d e;
        deliver_inv w i e w.proof_state k
      end
  | Store i obs ->
      if i < FStar.List.Tot.length w.reqs && is_issue (FStar.List.Tot.index w.reqs i)
      then begin
        index_sound w.reqs i;
        trace_sound_matches_rust (FStar.List.Tot.index w.reqs i);
        let e = ProofRecoverEvent_GrantStored obs in
        let d = FStar.List.Tot.index w.reqs i in
        let t = step_proof_recover d e in
        counted_unchanged w.reqs i t.f_driver;
        step_tokens_other d e;
        deliver_inv w i e w.proof_state k
      end

let rec run_world_inv (w: world) (schedule: list action) (k: nat)
  : Lemma (requires (inv w k)) (ensures (inv (run_world w schedule) k))
    (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest ->
      world_step_inv w a k;
      run_world_inv (world_step w a) rest k

let initial (k: nat) : world =
  { proof_state = true; budget = k; grants = 0; reqs = [] }

let initial_inv (k: nat) : Lemma (inv (initial k) k) = ()

/// Headline theorem: whatever the number of concurrent requests, their
/// interleaving, the observations they receive, and whether the proof verified,
/// one proof state yields at most one grant, and at most `k` attempts are
/// counted against an initial budget of `k`.
let one_proof_state_at_most_one_grant (k: nat) (schedule: list action)
  : Lemma (
      let w = run_world (initial k) schedule in
      w.grants <= 1 /\ counted w.reqs <= k /\ w.budget <= k) =
  initial_inv k;
  run_world_inv (initial k) schedule k

// ── Non-vacuity: one grant is reachable, races and budget refusal too ──────

#push-options "--fuel 4 --ifuel 2"

let run_cons (w: world) (a: action) (rest: list action)
  : Lemma (run_world w (a :: rest) == run_world (world_step w a) rest) = ()

let run_nil (w: world) : Lemma (run_world w [] == w) = ()

/// One request counts an attempt, consumes the matched proof state, passes the
/// live current-epoch check, verifies, and stores exactly one grant.
let s1 = world_step (initial 1) Spawn
let s2 = world_step s1 (Count 0)
let s3 = world_step s2 (Consume 0 matched_attempt)
let s4 = world_step s3 (Live 0 active_account)
let s5 = world_step s4 (Prove 0 verified_proof)
let s6 = world_step s5 (Store 0 GrantStoreObservation_Stored)

let s1_ok () : Lemma (s1.proof_state = true /\ s1.budget = 1 /\ s1.grants = 0 /\
                      FStar.List.Tot.length s1.reqs = 1) = ()
let s2_ok () : Lemma (s2.proof_state = true /\ s2.budget = 0 /\
                      FStar.List.Tot.length s2.reqs = 1 /\
                      is_consume (FStar.List.Tot.index s2.reqs 0)) = s1_ok ()
let s3_ok () : Lemma (s3.proof_state = false /\ s3.grants = 0 /\
                      FStar.List.Tot.length s3.reqs = 1 /\
                      is_live (FStar.List.Tot.index s3.reqs 0)) = s2_ok ()
let s4_ok () : Lemma (s4.proof_state = false /\
                      FStar.List.Tot.length s4.reqs = 1 /\
                      is_verify (FStar.List.Tot.index s4.reqs 0)) = s3_ok ()
let s5_ok () : Lemma (s5.grants = 1 /\
                      FStar.List.Tot.length s5.reqs = 1 /\
                      is_issue (FStar.List.Tot.index s5.reqs 0)) = s4_ok ()
let s6_ok () : Lemma (s6.grants = 1 /\
                      is_done (FStar.List.Tot.index s6.reqs 0)) = s5_ok ()

let success_schedule : list action =
  [ Spawn; Count 0; Consume 0 matched_attempt; Live 0 active_account;
    Prove 0 verified_proof; Store 0 GrantStoreObservation_Stored ]

let one_grant_is_reachable ()
  : Lemma ((run_world (initial 1) success_schedule).grants = 1) =
  run_cons (initial 1) Spawn [Count 0; Consume 0 matched_attempt; Live 0 active_account;
                              Prove 0 verified_proof; Store 0 GrantStoreObservation_Stored];
  run_cons s1 (Count 0) [Consume 0 matched_attempt; Live 0 active_account;
                         Prove 0 verified_proof; Store 0 GrantStoreObservation_Stored];
  run_cons s2 (Consume 0 matched_attempt) [Live 0 active_account;
                                           Prove 0 verified_proof; Store 0 GrantStoreObservation_Stored];
  run_cons s3 (Live 0 active_account) [Prove 0 verified_proof; Store 0 GrantStoreObservation_Stored];
  run_cons s4 (Prove 0 verified_proof) [Store 0 GrantStoreObservation_Stored];
  run_cons s5 (Store 0 GrantStoreObservation_Stored) [];
  run_nil s6;
  s6_ok ()

/// Two racing requests share the proof state: the second consumption sees it
/// missing and fails; exactly one grant is issued.
let r1 = world_step (initial 2) Spawn
let r2 = world_step r1 Spawn
let r3 = world_step r2 (Count 0)
let r4 = world_step r3 (Count 1)
let r5 = world_step r4 (Consume 0 matched_attempt)
let r6 = world_step r5 (Consume 1 matched_attempt)
let r7 = world_step r6 (Live 0 active_account)
let r8 = world_step r7 (Prove 0 verified_proof)
let r9 = world_step r8 (Store 0 GrantStoreObservation_Stored)
let r2_ok () : Lemma (r2.proof_state = true /\ r2.budget = 2 /\
                      FStar.List.Tot.length r2.reqs = 2 /\
                      is_attempt (FStar.List.Tot.index r2.reqs 0) /\
                      is_attempt (FStar.List.Tot.index r2.reqs 1)) = ()
let r4_ok () : Lemma (r4.budget = 0 /\ FStar.List.Tot.length r4.reqs = 2 /\
                      is_consume (FStar.List.Tot.index r4.reqs 0) /\
                      is_consume (FStar.List.Tot.index r4.reqs 1)) = r2_ok ()
let r5_ok () : Lemma (r5.proof_state = false /\ r5.grants = 0 /\
                      is_live (FStar.List.Tot.index r5.reqs 0) /\
                      is_consume (FStar.List.Tot.index r5.reqs 1)) = r4_ok ()
let r6_ok () : Lemma (r6.proof_state = false /\ r6.grants = 0 /\
                      is_live (FStar.List.Tot.index r6.reqs 0) /\
                      is_done (FStar.List.Tot.index r6.reqs 1)) = r5_ok ()
let r8_ok () : Lemma (is_issue (FStar.List.Tot.index r8.reqs 0) /\ r8.grants = 1) = r6_ok ()
let r9_ok () : Lemma (r9.grants = 1 /\ FStar.List.Tot.length r9.reqs = 2 /\
                      is_done (FStar.List.Tot.index r9.reqs 1)) = r8_ok ()

let race_schedule : list action =
  [ Spawn; Spawn; Count 0; Count 1; Consume 0 matched_attempt;
    Consume 1 matched_attempt; Live 0 active_account; Prove 0 verified_proof;
    Store 0 GrantStoreObservation_Stored ]

let race_issues_one_grant ()
  : Lemma (
      let w = run_world (initial 2) race_schedule in
      w.grants = 1 /\ w.proof_state = false) =
  run_cons (initial 2) Spawn [Spawn; Count 0; Count 1; Consume 0 matched_attempt;
                              Consume 1 matched_attempt; Live 0 active_account;
                              Prove 0 verified_proof; Store 0 GrantStoreObservation_Stored];
  run_cons r1 Spawn [Count 0; Count 1; Consume 0 matched_attempt;
                     Consume 1 matched_attempt; Live 0 active_account;
                     Prove 0 verified_proof; Store 0 GrantStoreObservation_Stored];
  run_cons r2 (Count 0) [Count 1; Consume 0 matched_attempt;
                         Consume 1 matched_attempt; Live 0 active_account;
                         Prove 0 verified_proof; Store 0 GrantStoreObservation_Stored];
  run_cons r3 (Count 1) [Consume 0 matched_attempt; Consume 1 matched_attempt;
                         Live 0 active_account; Prove 0 verified_proof;
                         Store 0 GrantStoreObservation_Stored];
  run_cons r4 (Consume 0 matched_attempt) [Consume 1 matched_attempt;
                                           Live 0 active_account;
                                           Prove 0 verified_proof;
                                           Store 0 GrantStoreObservation_Stored];
  run_cons r5 (Consume 1 matched_attempt) [Live 0 active_account;
                                           Prove 0 verified_proof;
                                           Store 0 GrantStoreObservation_Stored];
  run_cons r6 (Live 0 active_account) [Prove 0 verified_proof;
                                       Store 0 GrantStoreObservation_Stored];
  run_cons r7 (Prove 0 verified_proof) [Store 0 GrantStoreObservation_Stored];
  run_cons r8 (Store 0 GrantStoreObservation_Stored) [];
  run_nil r9;
  r9_ok ()

/// The attempt budget is enforced: with one unit, the second request is
/// refused before it can consume the proof state.
let b1 = world_step (initial 1) Spawn
let b2 = world_step b1 Spawn
let b3 = world_step b2 (Count 0)
let b4 = world_step b3 (Count 1)
let b3_ok () : Lemma (b3.budget = 0 /\ b3.proof_state = true /\
                      is_consume (FStar.List.Tot.index b3.reqs 0)) = ()
let b4_ok () : Lemma (b4.budget = 0 /\ b4.grants = 0 /\ b4.proof_state = true) =
  b3_ok ()

let budget_schedule : list action =
  [ Spawn; Spawn; Count 0; Count 1 ]

let budget_is_enforced ()
  : Lemma (
      let w = run_world (initial 1) budget_schedule in
      w.budget = 0 /\ w.grants = 0 /\ w.proof_state = true /\
      counted w.reqs = 1) =
  run_cons (initial 1) Spawn [Spawn; Count 0; Count 1];
  run_cons b1 Spawn [Count 0; Count 1];
  run_cons b2 (Count 0) [Count 1];
  run_cons b3 (Count 1) [];
  run_nil b4;
  b4_ok ()

/// A stale attempt epoch passes the binding but is rejected at the live epoch.
let t1 = world_step (initial 1) Spawn
let t2 = world_step t1 (Count 0)
let t3 = world_step t2 (Consume 0 stale_attempt)
let t4 = world_step t3 (Live 0 active_account)
let t5 = world_step t4 (Prove 0 verified_proof)
let t4_ok () : Lemma (is_verify (FStar.List.Tot.index t4.reqs 0)) = ()
let t5_ok () : Lemma (t5.grants = 0 /\
                      is_done (FStar.List.Tot.index t5.reqs 0) /\
                      last_effect (FStar.List.Tot.index t4.reqs 0)
                        [ProofRecoverEvent_ProofObserved verified_proof] =
                        ProofRecoverEffect_Fail ProofRecoverFailure_ProofRejected) = t4_ok ()

let stale_schedule : list action =
  [ Spawn; Count 0; Consume 0 stale_attempt; Live 0 active_account;
    Prove 0 verified_proof ]

let stale_attempt_issues_no_grant ()
  : Lemma ((run_world (initial 1) stale_schedule).grants = 0) =
  run_cons (initial 1) Spawn [Count 0; Consume 0 stale_attempt;
                              Live 0 active_account; Prove 0 verified_proof];
  run_cons t1 (Count 0) [Consume 0 stale_attempt; Live 0 active_account;
                         Prove 0 verified_proof];
  run_cons t2 (Consume 0 stale_attempt) [Live 0 active_account; Prove 0 verified_proof];
  run_cons t3 (Live 0 active_account) [Prove 0 verified_proof];
  run_cons t4 (Prove 0 verified_proof) [];
  run_nil t5;
  t5_ok ()

/// Freezing pauses the request after the attempt is consumed, without a grant.
let f1 = world_step (initial 1) Spawn
let f2 = world_step f1 (Count 0)
let f3 = world_step f2 (Consume 0 matched_attempt)
let f4 = world_step f3 (Live 0 ({ active_account with f_account_epoch_active = false }))
let f4_ok () : Lemma (f4.grants = 0 /\
                      is_done (FStar.List.Tot.index f4.reqs 0) /\
                      last_effect (FStar.List.Tot.index f3.reqs 0)
                        [ProofRecoverEvent_AccountObserved
                          ({ active_account with f_account_epoch_active = false })] =
                        ProofRecoverEffect_Fail ProofRecoverFailure_RotationPaused) = ()

let freezing_schedule : list action =
  [ Spawn; Count 0; Consume 0 matched_attempt;
    Live 0 ({ active_account with f_account_epoch_active = false }) ]

let freezing_issues_no_grant ()
  : Lemma ((run_world (initial 1) freezing_schedule).grants = 0) =
  run_cons (initial 1) Spawn [Count 0; Consume 0 matched_attempt;
                              Live 0 ({ active_account with f_account_epoch_active = false })];
  run_cons f1 (Count 0) [Consume 0 matched_attempt;
                         Live 0 ({ active_account with f_account_epoch_active = false })];
  run_cons f2 (Consume 0 matched_attempt)
    [Live 0 ({ active_account with f_account_epoch_active = false })];
  run_cons f3 (Live 0 ({ active_account with f_account_epoch_active = false })) [];
  run_nil f4;
  f4_ok ()

/// An unverified proof is rejected without a grant.
let p1 = world_step (initial 1) Spawn
let p2 = world_step p1 (Count 0)
let p3 = world_step p2 (Consume 0 matched_attempt)
let p4 = world_step p3 (Live 0 active_account)
let p5 = world_step p4 (Prove 0 rejected_proof)
let p5_ok () : Lemma (p5.grants = 0 /\
                      is_done (FStar.List.Tot.index p5.reqs 0) /\
                      last_effect (FStar.List.Tot.index p4.reqs 0)
                        [ProofRecoverEvent_ProofObserved rejected_proof] =
                        ProofRecoverEffect_Fail ProofRecoverFailure_ProofRejected) = ()

let bad_proof_schedule : list action =
  [ Spawn; Count 0; Consume 0 matched_attempt; Live 0 active_account;
    Prove 0 rejected_proof ]

let bad_proof_issues_no_grant ()
  : Lemma ((run_world (initial 1) bad_proof_schedule).grants = 0) =
  run_cons (initial 1) Spawn [Count 0; Consume 0 matched_attempt;
                              Live 0 active_account; Prove 0 rejected_proof];
  run_cons p1 (Count 0) [Consume 0 matched_attempt; Live 0 active_account;
                         Prove 0 rejected_proof];
  run_cons p2 (Consume 0 matched_attempt) [Live 0 active_account; Prove 0 rejected_proof];
  run_cons p3 (Live 0 active_account) [Prove 0 rejected_proof];
  run_cons p4 (Prove 0 rejected_proof) [];
  run_nil p5;
  p5_ok ()

#pop-options
