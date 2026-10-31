module Vela_session_policy_websession_token_interpreter_lemmas



/// This module is the token handler loop of the four web-session handlers.
/// It is checked in its own fstar.exe invocation so the SMT patterns of the
/// fold/iteration lemmas cannot interact across drivers.

open FStar.Mul
open Core_models
open Vela_session_policy.Websession_driver
open Vela_session_policy.Websession_interpreter
open Vela_session_policy_websession_driver_lemmas

let cons_opt (#a: Type) (o: option a) (evs: list a) : list a =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

// ── POST /web-session/:id/token ──────────────────────────────────────────────────────────

let token_terminal (e: t_TokenEffect) : bool =
  match e with
  | TokenEffect_Complete | TokenEffect_Fail _ | TokenEffect_Idle -> true
  | _ -> false

let token_responds_to (e: t_TokenEffect) (ev: t_TokenEvent) : bool =
  match e, ev with
  | TokenEffect_CheckTokenLimits, TokenEvent_LimitsObserved _ -> true
  | TokenEffect_LoadSession, TokenEvent_SessionObserved _ -> true
  | TokenEffect_ConsumeWebTokenChallenge, TokenEvent_ChallengeObserved _ -> true
  | TokenEffect_VerifyWebSignature, TokenEvent_SignatureObserved _ -> true
  | TokenEffect_RecordTokenFailure, TokenEvent_FailureRecorded _ -> true
  | TokenEffect_ResetTokenBackoff, TokenEvent_ResetObserved _ -> true
  | TokenEffect_ClaimToken, TokenEvent_ClaimObserved _ -> true
  | TokenEffect_IssueToken _, TokenEvent_Issued _ -> true
  | _ -> false

let token_sound_transition (t: t_TokenTransition) : bool =
  token_state_is_sound t.f_driver && token_effect_is_sound t.f_driver t.f_effect

let token_turn_ev (#io_t: Type0) {| i: t_TokenIo io_t |} (s: io_t) (t: t_TokenTransition)
  : Pure (io_t & t_TokenTransition & option t_TokenEvent)
    (requires token_state_is_sound t.f_driver)
    (ensures fun _ -> True) =
  match t.f_effect with
  | TokenEffect_CheckTokenLimits ->
      let (s', o) = f_check_token_limits #io_t #i s in
      let ev = TokenEvent_LimitsObserved o in
      (s', token_step t.f_driver ev, Some ev)
  | TokenEffect_LoadSession ->
      let (s', o) = f_token_load_session #io_t #i s in
      let ev = TokenEvent_SessionObserved o in
      (s', token_step t.f_driver ev, Some ev)
  | TokenEffect_ConsumeWebTokenChallenge ->
      let (s', o) = f_consume_web_token_challenge #io_t #i s in
      let ev = TokenEvent_ChallengeObserved o in
      (s', token_step t.f_driver ev, Some ev)
  | TokenEffect_VerifyWebSignature ->
      let (s', o) = f_verify_web_signature #io_t #i s in
      let ev = TokenEvent_SignatureObserved o in
      (s', token_step t.f_driver ev, Some ev)
  | TokenEffect_RecordTokenFailure ->
      let (s', o) = f_record_token_failure #io_t #i s in
      let ev = TokenEvent_FailureRecorded o in
      (s', token_step t.f_driver ev, Some ev)
  | TokenEffect_ResetTokenBackoff ->
      let (s', o) = f_reset_token_backoff #io_t #i s in
      let ev = TokenEvent_ResetObserved o in
      (s', token_step t.f_driver ev, Some ev)
  | TokenEffect_ClaimToken ->
      let (s', o) = f_claim_token #io_t #i s in
      let ev = TokenEvent_ClaimObserved o in
      (s', token_step t.f_driver ev, Some ev)
  | TokenEffect_IssueToken plan ->
      let (s', o) = f_issue_token #io_t #i s plan in
      let ev = TokenEvent_Issued o in
      (s', token_step t.f_driver ev, Some ev)
  | TokenEffect_Complete | TokenEffect_Fail _ | TokenEffect_Idle -> (s, t, None)

let token_turn (#io_t: Type0) {| i: t_TokenIo io_t |} (acc: io_t & t_TokenTransition)
  : (io_t & t_TokenTransition) =
  let (s, t) = acc in
  if token_state_is_sound t.f_driver
  then let (s', t', _) = token_turn_ev #io_t #i s t in (s', t')
  else acc

let rec token_iter_turn (#io_t: Type0) {| i: t_TokenIo io_t |} (n: nat)
  (acc: io_t & t_TokenTransition)
  : Tot (io_t & t_TokenTransition) (decreases n) =
  if n = 0 then acc else token_iter_turn #io_t #i (n - 1) (token_turn #io_t #i acc)

let rec token_run_ev (#io_t: Type0) {| i: t_TokenIo io_t |} (n: nat) (s: io_t)
  (t: t_TokenTransition)
  : Pure (io_t & t_TokenTransition & list t_TokenEvent)
    (requires token_sound_transition t)
    (ensures fun (_, t', _) -> token_sound_transition t')
    (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = token_turn_ev #io_t #i s t in
    let (s2, t2, evs) = token_run_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, cons_opt o evs)

let rec token_fold_range_is_iter_turn
  (#io_t: Type0) {| i: t_TokenIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_TokenTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_TokenTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_TokenTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_TokenTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_TokenTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == token_turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
              token_iter_turn #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (token_iter_turn #io_t #i n init)] =
  if v start < v end_
  then token_fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec token_iter_turn_is_run_ev (#io_t: Type0) {| i: t_TokenIo io_t |} (n: nat) (s: io_t)
  (t: t_TokenTransition)
  : Lemma (requires token_sound_transition t)
          (ensures (let (s2, t2, _) = token_run_ev #io_t #i n s t in
                    token_iter_turn #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, _) = token_turn_ev #io_t #i s t in
    token_iter_turn_is_run_ev #io_t #i (n - 1) s1 t1
  end

let token_run_is_run_ev (#io_t: Type0) {| i: t_TokenIo io_t |} (s: io_t)
  : Lemma (let (s2, t2, _) = token_run_ev #io_t #i 7 s (begin_token ()) in
           run_token #io_t #i s == (s2, t2)) =
  let t0 = begin_token () in
  token_iter_turn_is_run_ev #io_t #i 7 s t0;
  assert (v v_TOKEN_MAX_EFFECTS = 7);
  assert (run_token #io_t #i s == token_iter_turn #io_t #i 7 (s, t0))

let rec token_responds (t: t_TokenTransition) (evs: list t_TokenEvent)
  : Pure bool (requires token_sound_transition t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (token_terminal t.f_effect) && token_responds_to t.f_effect ev &&
      token_responds (token_step t.f_driver ev) rest

let rec token_run_ev_follows_the_driver (#io_t: Type0) {| i: t_TokenIo io_t |}  (n: nat) (s: io_t)
  (t: t_TokenTransition)
  : Lemma (requires token_sound_transition t)
          (ensures (let (_, t2, evs) = token_run_ev #io_t #i n s t in
                    token_trace_sound t.f_driver /\
                    token_responds t evs /\
                    t2.f_driver == token_run t.f_driver evs))
          (decreases n) =
  token_trace_sound_matches_rust t.f_driver;
  if n = 0 then ()
  else begin
    let (s1, t1, o) = token_turn_ev #io_t #i s t in
    token_run_ev_follows_the_driver #io_t #i (n - 1) s1 t1;
    match o with
    | None -> ()
    | Some ev -> token_step_sound t.f_driver ev
  end

let token_remaining (e: t_TokenEffect) : nat =
  match e with
  | TokenEffect_CheckTokenLimits -> 7
  | TokenEffect_LoadSession -> 6
  | TokenEffect_ConsumeWebTokenChallenge -> 5
  | TokenEffect_VerifyWebSignature -> 4
  | TokenEffect_RecordTokenFailure -> 1
  | TokenEffect_ResetTokenBackoff -> 3
  | TokenEffect_ClaimToken -> 2
  | TokenEffect_IssueToken _ -> 1
  | _ -> 0

let token_step_decreases (t: t_TokenTransition) (ev: t_TokenEvent)
  : Lemma (requires token_sound_transition t /\ not (token_terminal t.f_effect) /\ token_responds_to t.f_effect ev)
          (ensures token_remaining (token_step t.f_driver ev).f_effect < token_remaining t.f_effect) =
  match t.f_effect with
  | TokenEffect_CheckTokenLimits -> ()
  | TokenEffect_LoadSession -> ()
  | TokenEffect_ConsumeWebTokenChallenge -> ()
  | TokenEffect_VerifyWebSignature -> ()
  | TokenEffect_RecordTokenFailure -> ()
  | TokenEffect_ResetTokenBackoff -> ()
  | TokenEffect_ClaimToken -> ()
  | TokenEffect_IssueToken _ -> ()
  | _ -> ()

let rec token_run_ev_reaches_a_verdict (#io_t: Type0) {| i: t_TokenIo io_t |} (n: nat) (s: io_t)
  (t: t_TokenTransition)
  : Lemma (requires token_sound_transition t /\ token_remaining t.f_effect <= n)
          (ensures (let (_, t2, _) = token_run_ev #io_t #i n s t in token_terminal t2.f_effect))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, o) = token_turn_ev #io_t #i s t in
    (match o with
     | None -> ()
     | Some ev -> token_step_decreases t ev);
    token_run_ev_reaches_a_verdict #io_t #i (n - 1) s1 t1
  end

let token_run_theorem (#io_t: Type0) {| i: t_TokenIo io_t |} (s: io_t)
  : Lemma (
      let (_, t) = run_token #io_t #i s in
      exists (evs: list t_TokenEvent).
        token_responds (begin_token ()) evs /\
        t.f_driver == token_run_from_begin evs /\
        token_terminal t.f_effect /\
        token_effect_is_sound t.f_driver t.f_effect) =
  let t0 = begin_token () in
  token_run_is_run_ev #io_t #i s;
  token_run_ev_follows_the_driver #io_t #i 7 s t0;
  token_run_ev_reaches_a_verdict #io_t #i 7 s t0;
  let (_, t2, evs) = token_run_ev #io_t #i 7 s t0 in
  assert (token_responds (begin_token ()) evs);
  assert (t2.f_driver == token_run_from_begin evs);
  ()

/// Cancellation (web session token): the handler future may be dropped after any
/// executor call, so the loop stops after an arbitrary prefix of turns. Every
/// such prefix, for every executor and every `k`, ends in a sound driver state
/// whose next effect agrees with it.
let websession_token_cancellation (#io_t: Type0) {| i: t_TokenIo io_t |} (k: nat) (s: io_t)
  (t: t_TokenTransition)
  : Lemma (requires token_sound_transition t)
          (ensures (let (_, t2) = token_iter_turn #io_t #i k (s, t) in token_sound_transition t2)) =
  token_iter_turn_is_run_ev #io_t #i k s t
