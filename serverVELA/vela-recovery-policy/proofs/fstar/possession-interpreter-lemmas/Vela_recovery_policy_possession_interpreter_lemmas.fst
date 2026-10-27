module Vela_recovery_policy_possession_interpreter_lemmas

/// The extracted `run_possession_initiation` and `run_possession_recover` are
/// the loops the two possession-proof handlers run: the server expands the
/// same macro text, adding only `.await` after each executor call. This module
/// proves, for every executor implementation, that
///
/// 1. each loop calls the executor exactly as its `run_ev` below does: one
///    method per turn, chosen by the effect the driver has just emitted, with
///    that effect's argument (the grant permit), and nothing once the driver
///    reached a verdict (`run_*_is_run_ev`);
/// 2. the observations the executor returned form a list `evs` in which each
///    observation answers the effect it was returned for, and the final driver
///    is the driver's `run_*_from_begin evs` (`run_ev_follows_the_driver`);
/// 3. the loop reaches a verdict within its budget, or stops early because an
///    effect aborted (the handler then renders the recorded error)
///    (`run_ev_reaches_a_verdict`);
/// 4. hence every per-request possession theorem holds for the state the real
///    handler ends in (`run_*_theorem`).
///
/// What remains outside: each executor method's I/O, and the macro expansion
/// (the server's copy differs only by `.await`).

open FStar.Mul
open Core_models
open Vela_recovery_policy
open Vela_recovery_policy.Possession_driver
open Vela_recovery_policy.Possession_interpreter
open Vela_recovery_policy_possession_driver_lemmas

// ══════════════════════════════════════════════════════════════════════════
// Challenge initiation
// ══════════════════════════════════════════════════════════════════════════

let initiation_terminal (e: t_InitiateEffect) : bool =
  match e with
  | InitiateEffect_Complete | InitiateEffect_Fail _ | InitiateEffect_Idle -> true
  | _ -> false

let initiation_responds_to (e: t_InitiateEffect) (ev: t_InitiateEvent) : bool =
  match e, ev with
  | InitiateEffect_Observe, InitiateEvent_Observed _
  | InitiateEffect_StoreChallenge, InitiateEvent_Stored _ -> true
  | _ -> false

let initiation_sound (t: t_InitiateTransition) : bool =
  initiation_transition_is_sound t

let initiation_acc_transition (#io_t: Type0) (acc: bool & io_t & t_InitiateTransition)
  : t_InitiateTransition =
  let (_, _, t) = acc in t

let initiation_acc_aborted (#io_t: Type0) (acc: bool & io_t & t_InitiateTransition) : bool =
  let (a, _, _) = acc in a

let initiation_result_acc (#io_t: Type0) (#ev: Type0)
      (result: bool & io_t & t_InitiateTransition & ev)
  : (bool & io_t & t_InitiateTransition) =
  let (a, s, t, _) = result in (a, s, t)

let initiation_turn_ev (#io_t: Type0) {| i: t_PossessionInitiationIo io_t |}
      (acc: bool & io_t & t_InitiateTransition)
  : Pure (bool & io_t & t_InitiateTransition & option t_InitiateEvent)
    (requires initiation_sound (initiation_acc_transition acc))
    (ensures fun result ->
      initiation_sound (initiation_acc_transition (initiation_result_acc result))) =
  let (aborted, s, t) = acc in
  if aborted then (aborted, s, t, None)
  else
    match t.f_effect with
    | InitiateEffect_Observe ->
        let (s', o) = f_observe #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = InitiateEvent_Observed observation in
             (aborted, s', step_initiation t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | InitiateEffect_StoreChallenge ->
        let (s', o) = f_store_challenge #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = InitiateEvent_Stored observation in
             (aborted, s', step_initiation t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | InitiateEffect_Complete | InitiateEffect_Fail _ | InitiateEffect_Idle ->
        (aborted, s, t, None)

let initiation_turn (#io_t: Type0) {| i: t_PossessionInitiationIo io_t |}
      (acc: bool & io_t & t_InitiateTransition)
  : (bool & io_t & t_InitiateTransition) =
  if initiation_sound (initiation_acc_transition acc)
  then let (a', s', t', _) = initiation_turn_ev #io_t #i acc in (a', s', t')
  else acc

let rec initiation_iter_turn (#io_t: Type0) {| i: t_PossessionInitiationIo io_t |} (n: nat)
      (acc: bool & io_t & t_InitiateTransition)
  : Tot (bool & io_t & t_InitiateTransition) (decreases n) =
  if n = 0 then acc
  else initiation_iter_turn #io_t #i (n - 1) (initiation_turn #io_t #i acc)

let initiation_cons_opt (o: option t_InitiateEvent) (evs: list t_InitiateEvent)
  : list t_InitiateEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

let rec initiation_run_ev (#io_t: Type0) {| i: t_PossessionInitiationIo io_t |} (n: nat)
      (acc: bool & io_t & t_InitiateTransition)
  : Pure (bool & io_t & t_InitiateTransition & list t_InitiateEvent)
    (requires initiation_sound (initiation_acc_transition acc))
    (ensures fun result ->
      initiation_sound (initiation_acc_transition (initiation_result_acc result)))
    (decreases n) =
  if n = 0 then (let (a, s, t) = acc in (a, s, t, []))
  else
    let (a1, s1, t1, o) = initiation_turn_ev #io_t #i acc in
    let (a2, s2, t2, evs) =
      initiation_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    (a2, s2, t2, initiation_cons_opt o evs)

let rec initiation_fold_is_iter_turn
  (#io_t: Type0) {| i: t_PossessionInitiationIo io_t |}
  (n: nat) (start end_: usize)
  (inv: (bool & io_t & t_InitiateTransition) ->
        (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (bool & io_t & t_InitiateTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (bool & io_t & t_InitiateTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (bool & io_t & t_InitiateTransition){inv acc' (mk_int (v k + 1))}))
   : Lemma
     (requires (v start <= v end_ /\ n = v end_ - v start /\
                (forall (acc: (bool & io_t & t_InitiateTransition))
                   (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                   f acc k == initiation_turn #io_t #i acc)))
     (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
               initiation_iter_turn #io_t #i n init))
     (decreases n)
     [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
      SMTPat (initiation_iter_turn #io_t #i n init)] =
  if v start < v end_
  then initiation_fold_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec initiation_iter_turn_is_run_ev (#io_t: Type0)
      {| i: t_PossessionInitiationIo io_t |} (n: nat)
      (acc: bool & io_t & t_InitiateTransition)
  : Lemma (requires initiation_sound (initiation_acc_transition acc))
          (ensures (let (a2, s2, t2, _) = initiation_run_ev #io_t #i n acc in
                    initiation_iter_turn #io_t #i n acc == (a2, s2, t2)))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (a1, s1, t1, _) = initiation_turn_ev #io_t #i acc in
    initiation_iter_turn_is_run_ev #io_t #i (n - 1) (a1, s1, t1)
  end

let run_possession_initiation_is_run_ev (#io_t: Type0)
      {| i: t_PossessionInitiationIo io_t |} (s: io_t)
  : Lemma
    (let t0 = begin_initiation () in
     let (a2, s2, t2, _) = initiation_run_ev #io_t #i 3 (false, s, t0) in
     run_possession_initiation #io_t #i s ==
       (s2, (if a2 then Core_models.Option.Option_None else Core_models.Option.Option_Some t2))) =
  let t0 = begin_initiation () in
  assert (v v_POSSESSION_INITIATION_MAX_EFFECTS = 3);
  assert (run_possession_initiation #io_t #i s ==
          (let (a2, s2, t2, _) = initiation_run_ev #io_t #i 3 (false, s, t0) in
           (s2, (if a2 then Core_models.Option.Option_None else Core_models.Option.Option_Some t2))))

let rec initiation_responds (t: t_InitiateTransition) (evs: list t_InitiateEvent)
  : Pure bool (requires initiation_sound t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (initiation_terminal t.f_effect) && initiation_responds_to t.f_effect ev &&
      initiation_responds (step_initiation t.f_driver ev) rest

let rec initiation_run_ev_follows_the_driver (#io_t: Type0)
      {| i: t_PossessionInitiationIo io_t |} (n: nat)
      (acc: bool & io_t & t_InitiateTransition)
  : Lemma (requires initiation_sound (initiation_acc_transition acc))
          (ensures (let (_, _, t2, evs) = initiation_run_ev #io_t #i n acc in
                    initiation_trace_sound t2.f_driver /\
                    initiation_responds (initiation_acc_transition acc) evs /\
                    t2.f_driver == run_initiation (initiation_acc_transition acc).f_driver evs))
          (decreases n) =
  initiation_trace_sound_matches_rust (initiation_acc_transition acc).f_driver;
  let (aborted, _, t) = acc in
  if n = 0 then ()
  else if aborted then begin
    let (a1, s1, t1, _) = initiation_turn_ev #io_t #i acc in
    assert (t1 == t);
    initiation_run_ev_follows_the_driver #io_t #i (n - 1) (a1, s1, t1)
  end else begin
    let (a1, s1, t1, o) = initiation_turn_ev #io_t #i acc in
    initiation_run_ev_follows_the_driver #io_t #i (n - 1) (a1, s1, t1);
    match o with
    | None -> ()
    | Some ev ->
        initiation_step_sound t.f_driver ev;
        assert (initiation_responds t (ev :: (let (_, _, _, evs) = initiation_run_ev #io_t #i (n - 1) (a1, s1, t1) in evs)))
  end

let initiation_remaining (e: t_InitiateEffect) : nat =
  match e with
  | InitiateEffect_Observe -> 2
  | InitiateEffect_StoreChallenge -> 1
  | InitiateEffect_Complete | InitiateEffect_Fail _ | InitiateEffect_Idle -> 0

let initiation_remaining_zero_is_terminal (e: t_InitiateEffect)
  : Lemma (requires initiation_remaining e = 0) (ensures initiation_terminal e) =
  match e with
  | InitiateEffect_Observe -> ()
  | InitiateEffect_StoreChallenge -> ()
  | InitiateEffect_Complete -> ()
  | InitiateEffect_Fail _ -> ()
  | InitiateEffect_Idle -> ()

let initiation_step_decreases (t: t_InitiateTransition) (ev: t_InitiateEvent)
  : Lemma
    (requires initiation_sound t /\ not (initiation_terminal t.f_effect) /\
              initiation_responds_to t.f_effect ev)
    (ensures initiation_remaining (step_initiation t.f_driver ev).f_effect <
             initiation_remaining t.f_effect) =
  match t.f_effect with
  | InitiateEffect_Observe -> ()
  | InitiateEffect_StoreChallenge -> ()

let rec initiation_run_ev_aborted (#io_t: Type0)
      {| i: t_PossessionInitiationIo io_t |} (n: nat)
      (acc: bool & io_t & t_InitiateTransition)
  : Lemma (requires initiation_acc_aborted acc /\ initiation_sound (initiation_acc_transition acc))
          (ensures (let (a2, _, _, _) = initiation_run_ev #io_t #i n acc in a2))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (a1, s1, t1, o) = initiation_turn_ev #io_t #i acc in
    assert (a1);
    let (a2, s2, t2, evs) = initiation_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    assert (initiation_run_ev #io_t #i n acc == (a2, s2, t2, initiation_cons_opt o evs));
    initiation_run_ev_aborted #io_t #i (n - 1) (a1, s1, t1)
  end

let rec initiation_run_ev_reaches_a_verdict (#io_t: Type0)
      {| i: t_PossessionInitiationIo io_t |} (n: nat)
      (acc: bool & io_t & t_InitiateTransition)
  : Lemma
    (requires initiation_sound (initiation_acc_transition acc) /\
              initiation_remaining (initiation_acc_transition acc).f_effect <= n)
    (ensures (let (a2, _, t2, _) = initiation_run_ev #io_t #i n acc in
              initiation_terminal t2.f_effect \/ a2))
    (decreases n) =
  let (aborted, _, t) = acc in
  if n = 0 then initiation_remaining_zero_is_terminal t.f_effect
  else begin
    let (a1, s1, t1, o) = initiation_turn_ev #io_t #i acc in
    let (a2, s2, t2, evs) = initiation_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    assert (initiation_run_ev #io_t #i n acc == (a2, s2, t2, initiation_cons_opt o evs));
    if a1 then initiation_run_ev_aborted #io_t #i (n - 1) (a1, s1, t1)
    else begin
      (match o with
       | None ->
           assert (t1 == t);
           assert (initiation_terminal t.f_effect);
           assert (initiation_remaining t.f_effect = 0)
       | Some ev ->
           assert (t1 == step_initiation t.f_driver ev);
           initiation_step_decreases t ev;
           assert (initiation_remaining t1.f_effect <= n - 1));
      initiation_run_ev_reaches_a_verdict #io_t #i (n - 1) (a1, s1, t1)
    end
  end

let run_possession_initiation_theorem (#io_t: Type0)
      {| i: t_PossessionInitiationIo io_t |} (s: io_t)
  : Lemma (
      let (_, outcome) = run_possession_initiation #io_t #i s in
      match outcome with
      | Core_models.Option.Option_None -> True
      | Core_models.Option.Option_Some t ->
          initiation_terminal t.f_effect /\
          initiation_sound t /\
          (exists (evs: list t_InitiateEvent).
            initiation_responds (begin_initiation ()) evs /\
            t.f_driver == run_initiation_from_begin evs /\
            initiation_trace_sound t.f_driver /\
            count_challenge_stores_from_begin evs <= 1 /\
            (t.f_driver.f_stored ==> is_initiation_done t.f_driver))) =
  let t0 = begin_initiation () in
  run_possession_initiation_is_run_ev #io_t #i s;
  let (a2, s2, t2, evs) = initiation_run_ev #io_t #i 3 (false, s, t0) in
  initiation_begin_sound ();
  initiation_trace_sound_matches_rust t0.f_driver;
  initiation_run_ev_follows_the_driver #io_t #i 3 (false, s, t0);
  initiation_run_ev_reaches_a_verdict #io_t #i 3 (false, s, t0);
  if a2 then ()
  else begin
    assert ((let (_, outcome) = run_possession_initiation #io_t #i s in outcome) ==
            Core_models.Option.Option_Some t2);
    assert (initiation_responds t0 evs);
    assert (t2.f_driver == run_initiation t0.f_driver evs);
    initiation_trace_theorem evs;
    assert (t2.f_driver == run_initiation_from_begin evs)
  end

// ══════════════════════════════════════════════════════════════════════════
// Possession proof recovery
// ══════════════════════════════════════════════════════════════════════════

let recover_terminal (e: t_ProofRecoverEffect) : bool =
  match e with
  | ProofRecoverEffect_Complete | ProofRecoverEffect_Fail _ | ProofRecoverEffect_Idle -> true
  | _ -> false

let recover_responds_to (e: t_ProofRecoverEffect) (ev: t_ProofRecoverEvent) : bool =
  match e, ev with
  | ProofRecoverEffect_CountAttempt, ProofRecoverEvent_AttemptCounted _
  | ProofRecoverEffect_ConsumeAttempt, ProofRecoverEvent_AttemptConsumed _
  | ProofRecoverEffect_QueryAccount, ProofRecoverEvent_AccountObserved _
  | ProofRecoverEffect_VerifyProof, ProofRecoverEvent_ProofObserved _
  | ProofRecoverEffect_IssueGrant _, ProofRecoverEvent_GrantStored _ -> true
  | _ -> false

let recover_sound (t: t_ProofRecoverTransition) : bool =
  proof_recover_transition_is_sound t

let recover_acc_transition (#io_t: Type0) (acc: bool & io_t & t_ProofRecoverTransition)
  : t_ProofRecoverTransition =
  let (_, _, t) = acc in t

let recover_acc_aborted (#io_t: Type0) (acc: bool & io_t & t_ProofRecoverTransition) : bool =
  let (a, _, _) = acc in a

let recover_result_acc (#io_t: Type0) (#ev: Type0)
      (result: bool & io_t & t_ProofRecoverTransition & ev)
  : (bool & io_t & t_ProofRecoverTransition) =
  let (a, s, t, _) = result in (a, s, t)

let recover_turn_ev (#io_t: Type0) {| i: t_PossessionRecoverIo io_t |}
      (acc: bool & io_t & t_ProofRecoverTransition)
  : Pure (bool & io_t & t_ProofRecoverTransition & option t_ProofRecoverEvent)
    (requires recover_sound (recover_acc_transition acc))
    (ensures fun result ->
      recover_sound (recover_acc_transition (recover_result_acc result))) =
  let (aborted, s, t) = acc in
  if aborted then (aborted, s, t, None)
  else
    match t.f_effect with
    | ProofRecoverEffect_CountAttempt ->
        let (s', o) = f_count_attempt #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = ProofRecoverEvent_AttemptCounted observation in
             (aborted, s', step_proof_recover t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | ProofRecoverEffect_ConsumeAttempt ->
        let (s', o) = f_consume_attempt #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = ProofRecoverEvent_AttemptConsumed observation in
             (aborted, s', step_proof_recover t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | ProofRecoverEffect_QueryAccount ->
        let (s', o) = f_query_account #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = ProofRecoverEvent_AccountObserved observation in
             (aborted, s', step_proof_recover t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | ProofRecoverEffect_VerifyProof ->
        let (s', o) = f_verify_proof #io_t #i s in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = ProofRecoverEvent_ProofObserved observation in
             (aborted, s', step_proof_recover t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | ProofRecoverEffect_IssueGrant permit ->
        let (s', o) = f_issue_grant #io_t #i s permit in
        (match o with
         | Core_models.Option.Option_Some observation ->
             let ev = ProofRecoverEvent_GrantStored observation in
             (aborted, s', step_proof_recover t.f_driver ev, Some ev)
         | Core_models.Option.Option_None -> (true, s', t, None))
    | ProofRecoverEffect_Complete | ProofRecoverEffect_Fail _ | ProofRecoverEffect_Idle ->
        (aborted, s, t, None)

let recover_turn (#io_t: Type0) {| i: t_PossessionRecoverIo io_t |}
      (acc: bool & io_t & t_ProofRecoverTransition)
  : (bool & io_t & t_ProofRecoverTransition) =
  if recover_sound (recover_acc_transition acc)
  then let (a', s', t', _) = recover_turn_ev #io_t #i acc in (a', s', t')
  else acc

let rec recover_iter_turn (#io_t: Type0) {| i: t_PossessionRecoverIo io_t |} (n: nat)
      (acc: bool & io_t & t_ProofRecoverTransition)
  : Tot (bool & io_t & t_ProofRecoverTransition) (decreases n) =
  if n = 0 then acc
  else recover_iter_turn #io_t #i (n - 1) (recover_turn #io_t #i acc)

let recover_cons_opt (o: option t_ProofRecoverEvent) (evs: list t_ProofRecoverEvent)
  : list t_ProofRecoverEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

let rec recover_run_ev (#io_t: Type0) {| i: t_PossessionRecoverIo io_t |} (n: nat)
      (acc: bool & io_t & t_ProofRecoverTransition)
  : Pure (bool & io_t & t_ProofRecoverTransition & list t_ProofRecoverEvent)
    (requires recover_sound (recover_acc_transition acc))
    (ensures fun result ->
      recover_sound (recover_acc_transition (recover_result_acc result)))
    (decreases n) =
  if n = 0 then (let (a, s, t) = acc in (a, s, t, []))
  else
    let (a1, s1, t1, o) = recover_turn_ev #io_t #i acc in
    let (a2, s2, t2, evs) =
      recover_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    (a2, s2, t2, recover_cons_opt o evs)

let rec recover_fold_is_iter_turn
  (#io_t: Type0) {| i: t_PossessionRecoverIo io_t |}
  (n: nat) (start end_: usize)
  (inv: (bool & io_t & t_ProofRecoverTransition) ->
        (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (bool & io_t & t_ProofRecoverTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (bool & io_t & t_ProofRecoverTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (bool & io_t & t_ProofRecoverTransition){inv acc' (mk_int (v k + 1))}))
   : Lemma
     (requires (v start <= v end_ /\ n = v end_ - v start /\
                (forall (acc: (bool & io_t & t_ProofRecoverTransition))
                   (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                   f acc k == recover_turn #io_t #i acc)))
     (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
               recover_iter_turn #io_t #i n init))
     (decreases n)
     [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
      SMTPat (recover_iter_turn #io_t #i n init)] =
  if v start < v end_
  then recover_fold_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec recover_iter_turn_is_run_ev (#io_t: Type0)
      {| i: t_PossessionRecoverIo io_t |} (n: nat)
      (acc: bool & io_t & t_ProofRecoverTransition)
  : Lemma (requires recover_sound (recover_acc_transition acc))
          (ensures (let (a2, s2, t2, _) = recover_run_ev #io_t #i n acc in
                    recover_iter_turn #io_t #i n acc == (a2, s2, t2)))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (a1, s1, t1, _) = recover_turn_ev #io_t #i acc in
    recover_iter_turn_is_run_ev #io_t #i (n - 1) (a1, s1, t1)
  end

let run_possession_recover_is_run_ev (#io_t: Type0)
      {| i: t_PossessionRecoverIo io_t |} (s: io_t)
  : Lemma
    (let t0 = begin_proof_recover () in
     let (a2, s2, t2, _) = recover_run_ev #io_t #i 6 (false, s, t0) in
     run_possession_recover #io_t #i s ==
       (s2, (if a2 then Core_models.Option.Option_None else Core_models.Option.Option_Some t2))) =
  let t0 = begin_proof_recover () in
  assert (v v_POSSESSION_RECOVER_MAX_EFFECTS = 6);
  assert (run_possession_recover #io_t #i s ==
          (let (a2, s2, t2, _) = recover_run_ev #io_t #i 6 (false, s, t0) in
           (s2, (if a2 then Core_models.Option.Option_None else Core_models.Option.Option_Some t2))))

let rec recover_responds (t: t_ProofRecoverTransition) (evs: list t_ProofRecoverEvent)
  : Pure bool (requires recover_sound t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (recover_terminal t.f_effect) && recover_responds_to t.f_effect ev &&
      recover_responds (step_proof_recover t.f_driver ev) rest

let rec recover_run_ev_follows_the_driver (#io_t: Type0)
      {| i: t_PossessionRecoverIo io_t |} (n: nat)
      (acc: bool & io_t & t_ProofRecoverTransition)
  : Lemma (requires recover_sound (recover_acc_transition acc))
          (ensures (let (_, _, t2, evs) = recover_run_ev #io_t #i n acc in
                    trace_sound t2.f_driver /\
                    recover_responds (recover_acc_transition acc) evs /\
                    t2.f_driver == run (recover_acc_transition acc).f_driver evs))
          (decreases n) =
  trace_sound_matches_rust (recover_acc_transition acc).f_driver;
  let (aborted, _, t) = acc in
  if n = 0 then ()
  else if aborted then begin
    let (a1, s1, t1, _) = recover_turn_ev #io_t #i acc in
    assert (t1 == t);
    recover_run_ev_follows_the_driver #io_t #i (n - 1) (a1, s1, t1)
  end else begin
    let (a1, s1, t1, o) = recover_turn_ev #io_t #i acc in
    recover_run_ev_follows_the_driver #io_t #i (n - 1) (a1, s1, t1);
    match o with
    | None -> ()
    | Some ev ->
        step_sound t.f_driver ev;
        assert (recover_responds t (ev :: (let (_, _, _, evs) = recover_run_ev #io_t #i (n - 1) (a1, s1, t1) in evs)))
  end

let recover_remaining (e: t_ProofRecoverEffect) : nat =
  match e with
  | ProofRecoverEffect_CountAttempt -> 5
  | ProofRecoverEffect_ConsumeAttempt -> 4
  | ProofRecoverEffect_QueryAccount -> 3
  | ProofRecoverEffect_VerifyProof -> 2
  | ProofRecoverEffect_IssueGrant _ -> 1
  | ProofRecoverEffect_Complete | ProofRecoverEffect_Fail _ | ProofRecoverEffect_Idle -> 0

let recover_remaining_zero_is_terminal (e: t_ProofRecoverEffect)
  : Lemma (requires recover_remaining e = 0) (ensures recover_terminal e) =
  match e with
  | ProofRecoverEffect_CountAttempt -> ()
  | ProofRecoverEffect_ConsumeAttempt -> ()
  | ProofRecoverEffect_QueryAccount -> ()
  | ProofRecoverEffect_VerifyProof -> ()
  | ProofRecoverEffect_IssueGrant _ -> ()
  | ProofRecoverEffect_Complete -> ()
  | ProofRecoverEffect_Fail _ -> ()
  | ProofRecoverEffect_Idle -> ()

let recover_step_decreases (t: t_ProofRecoverTransition) (ev: t_ProofRecoverEvent)
  : Lemma
    (requires recover_sound t /\ not (recover_terminal t.f_effect) /\
              recover_responds_to t.f_effect ev)
    (ensures recover_remaining (step_proof_recover t.f_driver ev).f_effect <
             recover_remaining t.f_effect) =
  match t.f_effect with
  | ProofRecoverEffect_CountAttempt -> ()
  | ProofRecoverEffect_ConsumeAttempt -> ()
  | ProofRecoverEffect_QueryAccount -> ()
  | ProofRecoverEffect_VerifyProof -> ()
  | ProofRecoverEffect_IssueGrant _ -> ()

let rec recover_run_ev_aborted (#io_t: Type0)
      {| i: t_PossessionRecoverIo io_t |} (n: nat)
      (acc: bool & io_t & t_ProofRecoverTransition)
  : Lemma (requires recover_acc_aborted acc /\ recover_sound (recover_acc_transition acc))
          (ensures (let (a2, _, _, _) = recover_run_ev #io_t #i n acc in a2))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (a1, s1, t1, o) = recover_turn_ev #io_t #i acc in
    assert (a1);
    let (a2, s2, t2, evs) = recover_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    assert (recover_run_ev #io_t #i n acc == (a2, s2, t2, recover_cons_opt o evs));
    recover_run_ev_aborted #io_t #i (n - 1) (a1, s1, t1)
  end

let rec recover_run_ev_reaches_a_verdict (#io_t: Type0)
      {| i: t_PossessionRecoverIo io_t |} (n: nat)
      (acc: bool & io_t & t_ProofRecoverTransition)
  : Lemma
    (requires recover_sound (recover_acc_transition acc) /\
              recover_remaining (recover_acc_transition acc).f_effect <= n)
    (ensures (let (a2, _, t2, _) = recover_run_ev #io_t #i n acc in
              recover_terminal t2.f_effect \/ a2))
    (decreases n) =
  let (aborted, _, t) = acc in
  if n = 0 then recover_remaining_zero_is_terminal t.f_effect
  else begin
    let (a1, s1, t1, o) = recover_turn_ev #io_t #i acc in
    let (a2, s2, t2, evs) = recover_run_ev #io_t #i (n - 1) (a1, s1, t1) in
    assert (recover_run_ev #io_t #i n acc == (a2, s2, t2, recover_cons_opt o evs));
    if a1 then recover_run_ev_aborted #io_t #i (n - 1) (a1, s1, t1)
    else begin
      (match o with
       | None ->
           assert (t1 == t);
           assert (recover_terminal t.f_effect);
           assert (recover_remaining t.f_effect = 0)
       | Some ev ->
           assert (t1 == step_proof_recover t.f_driver ev);
           recover_step_decreases t ev;
           assert (recover_remaining t1.f_effect <= n - 1));
      recover_run_ev_reaches_a_verdict #io_t #i (n - 1) (a1, s1, t1)
    end
  end

let run_possession_recover_theorem (#io_t: Type0)
      {| i: t_PossessionRecoverIo io_t |} (s: io_t)
  : Lemma (
      let (_, outcome) = run_possession_recover #io_t #i s in
      match outcome with
      | Core_models.Option.Option_None -> True
      | Core_models.Option.Option_Some t ->
          recover_terminal t.f_effect /\
          recover_sound t /\
          (exists (evs: list t_ProofRecoverEvent).
            recover_responds (begin_proof_recover ()) evs /\
            t.f_driver == run_from_begin evs /\
            trace_sound t.f_driver /\
            count_grants_from_begin evs <= 1 /\
            (t.f_driver.f_grant_issued ==>
              (t.f_driver.f_attempt_consumed /\
               t.f_driver.f_user_matches /\
               t.f_driver.f_attempt_matches /\
               t.f_driver.f_proof_verified /\
               t.f_driver.f_account_present /\
               t.f_driver.f_account_epoch_active /\
               t.f_driver.f_commitment_present /\
               t.f_driver.f_commitment_len >. mk_usize 0 /\
               t.f_driver.f_attempt_epoch = observed_recovery_epoch t.f_driver.f_stored_epoch)) /\
            (t.f_driver.f_grant_stored ==> t.f_driver.f_grant_issued))) =
  let t0 = begin_proof_recover () in
  run_possession_recover_is_run_ev #io_t #i s;
  let (a2, s2, t2, evs) = recover_run_ev #io_t #i 6 (false, s, t0) in
  begin_sound ();
  trace_sound_matches_rust t0.f_driver;
  recover_run_ev_follows_the_driver #io_t #i 6 (false, s, t0);
  recover_run_ev_reaches_a_verdict #io_t #i 6 (false, s, t0);
  if a2 then ()
  else begin
    assert ((let (_, outcome) = run_possession_recover #io_t #i s in outcome) ==
            Core_models.Option.Option_Some t2);
    assert (recover_responds t0 evs);
    assert (t2.f_driver == run t0.f_driver evs);
    proof_recover_trace_theorem evs;
    assert (t2.f_driver == run_from_begin evs)
  end
