module Vela_rekey_policy_vault_upload_interpreter_lemmas

/// The extracted `run_upload` and `run_read` are the loops the vault chunk
/// handlers run: the server expands the same `upload_interpreter!` /
/// `read_interpreter!` macro text, adding only `.await` after each executor
/// call. This module proves, for every executor implementation (any
/// `t_UploadIo`/`t_ReadIo` instance, any behaviour):
///
/// 1. the extracted loop calls the executor exactly as `run_upload_ev` (resp.
///    `run_read_ev`) below does: one method per turn, chosen by the effect the
///    driver has just emitted, with that effect's argument (the write permit),
///    and nothing once the driver reached a verdict
///    (`run_upload_is_run_ev`, `run_read_is_run_ev`);
/// 2. the observations the executor returned form a list `evs` in which each
///    observation answers the effect it was returned for, and the final driver
///    is `run_from_request request evs` (`run_upload_ev_follows_the_driver`);
/// 3. the driver always reaches a verdict within the loop budget of 7 upload
///    effects and 2 read effects (`run_upload_ev_reaches_a_verdict`);
/// 4. hence every per-request upload (resp. read) theorem holds for the state
///    the real handler ends in (`run_upload_theorem`, `run_read_theorem`).
///
/// What remains outside: each executor method's I/O (that it performs what its
/// name says and reports the outcome honestly), and the macro expansion (the
/// server's copy differs only by `.await`).

open FStar.Mul
open Core_models
open Vela_rekey_policy
open Vela_rekey_policy.Vault_upload_driver
open Vela_rekey_policy.Vault_upload_interpreter
open Vela_rekey_policy_vault_upload_driver_lemmas

// ── The specification of one upload interpreter turn ──────────────────────

let is_terminal (e: t_UploadEffect) : bool =
  match e <: t_UploadEffect with
  | UploadEffect_Complete | UploadEffect_Fail _ | UploadEffect_Idle -> true
  | _ -> false

/// The observation kind each effect expects.
let responds_to (e: t_UploadEffect) (ev: t_UploadEvent) : bool =
  match e, ev with
  | UploadEffect_ResolveEpoch, UploadEvent_Rekey _
  | UploadEffect_AuthorizeShadow, UploadEvent_Attempt _
  | UploadEffect_AuthorizeShadow, UploadEvent_AttemptStorage
  | UploadEffect_EnforceQuota, UploadEvent_Quota _
  | UploadEffect_Write _, UploadEvent_Write _
  | UploadEffect_RecheckState, UploadEvent_Recheck _
  | UploadEffect_RereadVersion, UploadEvent_Reread _
  | UploadEffect_RecordShadowActivity, UploadEvent_Activity _
  | UploadEffect_Publish, UploadEvent_Published -> true
  | _ -> false

/// The loop invariant is the driver's own transition soundness predicate: the
/// state invariant plus the fact that the emitted effect agrees with that
/// state.
let loop_sound (t: t_UploadTransition) : bool = upload_loop_is_sound t

/// One turn: call the executor method for the current effect, feed its
/// observation to the extracted `upload_step`, and report the event. A verdict
/// performs nothing.
let turn_ev (#io_t: Type0) {| i: t_UploadIo io_t |} (s: io_t) (t: t_UploadTransition)
  : Pure (io_t & t_UploadTransition & option t_UploadEvent)
    (requires loop_sound t)
    (ensures fun _ -> True) =
  match t.f_effect <: t_UploadEffect with
  | UploadEffect_ResolveEpoch ->
      let (s', o) = f_resolve_epoch #io_t #i s in
      let ev = UploadEvent_Rekey o in
      (s', upload_step t.f_driver ev, Some ev)
  | UploadEffect_AuthorizeShadow ->
      let (s', o) = f_authorize_shadow #io_t #i s in
      let ev =
        match o <: Core_models.Option.t_Option Vela_rekey_policy.t_AttemptAuthority with
        | Core_models.Option.Option_Some authority -> UploadEvent_Attempt authority
        | Core_models.Option.Option_None -> UploadEvent_AttemptStorage in
      (s', upload_step t.f_driver ev, Some ev)
  | UploadEffect_EnforceQuota ->
      let (s', o) = f_enforce_quota #io_t #i s in
      let ev = UploadEvent_Quota o in
      (s', upload_step t.f_driver ev, Some ev)
  | UploadEffect_Write permit ->
      let (s', o) = f_guarded_write #io_t #i s permit in
      let ev = UploadEvent_Write o in
      (s', upload_step t.f_driver ev, Some ev)
  | UploadEffect_RecheckState ->
      let (s', o) = f_recheck_state #io_t #i s in
      let ev = UploadEvent_Recheck o in
      (s', upload_step t.f_driver ev, Some ev)
  | UploadEffect_RereadVersion ->
      let (s', o) = f_reread_version #io_t #i s in
      let ev = UploadEvent_Reread o in
      (s', upload_step t.f_driver ev, Some ev)
  | UploadEffect_RecordShadowActivity ->
      let (s', o) = f_record_shadow_activity #io_t #i s in
      let ev = UploadEvent_Activity o in
      (s', upload_step t.f_driver ev, Some ev)
  | UploadEffect_Publish ->
      let s' = f_publish #io_t #i s in
      let ev = UploadEvent_Published in
      (s', upload_step t.f_driver ev, Some ev)
  | UploadEffect_Complete | UploadEffect_Fail _ | UploadEffect_Idle -> (s, t, None)

/// `turn_ev` without the event, total so it can be compared with the extracted
/// loop body.
let turn (#io_t: Type0) {| i: t_UploadIo io_t |} (acc: io_t & t_UploadTransition)
  : (io_t & t_UploadTransition) =
  let (s, t) = acc in
  if loop_sound t
  then let (s', t', _) = turn_ev #io_t #i s t in (s', t')
  else acc

let rec iter_turn (#io_t: Type0) {| i: t_UploadIo io_t |} (n: nat)
  (acc: io_t & t_UploadTransition)
  : Tot (io_t & t_UploadTransition) (decreases n) =
  if n = 0 then acc else iter_turn #io_t #i (n - 1) (turn #io_t #i acc)

let cons_opt (o: option t_UploadEvent) (evs: list t_UploadEvent) : list t_UploadEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

/// `n` turns, collecting the observations in order.
let rec run_upload_ev (#io_t: Type0) {| i: t_UploadIo io_t |} (n: nat) (s: io_t)
  (t: t_UploadTransition)
  : Pure (io_t & t_UploadTransition & list t_UploadEvent)
    (requires loop_sound t)
    (ensures fun (_, t', _) -> loop_sound t')
    (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = turn_ev #io_t #i s t in
    let (s2, t2, evs) = run_upload_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, cons_opt o evs)

// ── 1. The extracted loop is `run_upload_ev` ──────────────────────────────

/// `fold_range` over a body that is one `turn` per index is `iter_turn`. The
/// two patterns fire together when a goal mentions both the extracted loop and
/// the specification, which binds every variable including the instance.
let rec fold_range_is_iter_turn
  (#io_t: Type0) {| i: t_UploadIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_UploadTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_UploadTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_UploadTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_UploadTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_UploadTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
              iter_turn #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (iter_turn #io_t #i n init)] =
  if v start < v end_
  then fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec iter_turn_is_run_upload_ev (#io_t: Type0) {| i: t_UploadIo io_t |} (n: nat) (s: io_t)
  (t: t_UploadTransition)
  : Lemma (requires loop_sound t)
          (ensures (let (s2, t2, _) = run_upload_ev #io_t #i n s t in
                    iter_turn #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, _) = turn_ev #io_t #i s t in
    iter_turn_is_run_upload_ev #io_t #i (n - 1) s1 t1
  end

/// The extracted loop calls the executor exactly as `run_upload_ev` does.
let run_upload_is_run_ev (#io_t: Type0) {| i: t_UploadIo io_t |} (s: io_t)
  (request: t_UploadRequest)
  : Lemma (let (s2, t2, _) = run_upload_ev #io_t #i 7 s (begin_upload request) in
           run_upload #io_t #i s request == (s2, t2)) =
  iter_turn_is_run_upload_ev #io_t #i 7 s (begin_upload request);
  assert (v v_UPLOAD_MAX_EFFECTS = 7);
  assert (run_upload #io_t #i s request == iter_turn #io_t #i 7 (s, begin_upload request))

// ── 1b. Cancellation: every prefix is a sound driver state ────────────────

/// A dropped handler future stops the upload loop after an arbitrary prefix of
/// turns. For every executor, every `k` and every sound start, the transition
/// after `k` turns is sound: `upload_state_is_sound` carries the per-request
/// state invariants (a matched write implies a resolved write route with a
/// clean permit epoch, no web session ever takes a shadow route past the
/// authorisation point, and a success implies a matched write plus its
/// publication or shadow refresh), and the next effect agrees with the state
/// that produced it.
let upload_cancellation (#io_t: Type0) {| i: t_UploadIo io_t |} (k: nat)
  (s: io_t) (t: t_UploadTransition)
  : Lemma (requires loop_sound t)
          (ensures (let (_, t2) = iter_turn #io_t #i k (s, t) in loop_sound t2)) =
  let (_, t2, _) = run_upload_ev #io_t #i k s t in
  iter_turn_is_run_upload_ev #io_t #i k s t

// ── 2. The observations drive the extracted driver ────────────────────────

/// Each observation answers the effect it was returned for, and no
/// observation follows a verdict.
let rec responds (t: t_UploadTransition) (evs: list t_UploadEvent)
  : Pure bool (requires trace_sound t.f_driver) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (is_terminal t.f_effect) && responds_to t.f_effect ev &&
      responds (upload_step t.f_driver ev) rest

let rec run_upload_ev_follows_the_driver (#io_t: Type0) {| i: t_UploadIo io_t |}
  (n: nat) (s: io_t) (t: t_UploadTransition)
  : Lemma (requires loop_sound t /\ trace_sound t.f_driver)
          (ensures (let (_, t2, evs) = run_upload_ev #io_t #i n s t in
                    trace_sound t2.f_driver /\
                    responds t evs /\
                    t2.f_driver == run t.f_driver evs))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, o) = turn_ev #io_t #i s t in
    (match o with
     | None -> ()
     | Some ev -> step_sound t.f_driver ev);
    run_upload_ev_follows_the_driver #io_t #i (n - 1) s1 t1;
    match o with
    | None -> ()
    | Some ev -> step_sound t.f_driver ev
  end

// ── 3. A verdict within the budget ────────────────────────────────────────

/// Effects still to perform before a verdict, at most.
let remaining (e: t_UploadEffect) : nat =
  match e <: t_UploadEffect with
  | UploadEffect_ResolveEpoch -> 7
  | UploadEffect_AuthorizeShadow -> 6
  | UploadEffect_EnforceQuota -> 5
  | UploadEffect_Write _ -> 4
  | UploadEffect_RecheckState -> 1
  | UploadEffect_RereadVersion -> 3
  | UploadEffect_RecordShadowActivity -> 2
  | UploadEffect_Publish -> 1
  | UploadEffect_Complete | UploadEffect_Fail _ | UploadEffect_Idle -> 0

/// Answering the current effect moves strictly closer to a verdict.
let step_decreases (t: t_UploadTransition) (ev: t_UploadEvent)
  : Lemma (requires loop_sound t /\ not (is_terminal t.f_effect) /\
                     responds_to t.f_effect ev)
          (ensures remaining (upload_step t.f_driver ev).f_effect < remaining t.f_effect) =
  match t.f_effect <: t_UploadEffect with
  | UploadEffect_ResolveEpoch ->
      (match ev <: t_UploadEvent with
       | UploadEvent_Rekey _ -> ()
       | _ -> ())
  | UploadEffect_AuthorizeShadow ->
      (match ev <: t_UploadEvent with
       | UploadEvent_Attempt _ -> ()
       | UploadEvent_AttemptStorage -> ()
       | _ -> ())
  | UploadEffect_EnforceQuota ->
      (match ev <: t_UploadEvent with
       | UploadEvent_Quota _ -> ()
       | _ -> ())
  | UploadEffect_Write _ ->
      (match ev <: t_UploadEvent with
       | UploadEvent_Write _ -> ()
       | _ -> ())
  | UploadEffect_RecheckState ->
      (match ev <: t_UploadEvent with
       | UploadEvent_Recheck _ -> ()
       | _ -> ())
  | UploadEffect_RereadVersion ->
      (match ev <: t_UploadEvent with
       | UploadEvent_Reread _ -> ()
       | _ -> ())
  | UploadEffect_RecordShadowActivity ->
      (match ev <: t_UploadEvent with
       | UploadEvent_Activity _ -> ()
       | _ -> ())
  | UploadEffect_Publish ->
      (match ev <: t_UploadEvent with
       | UploadEvent_Published -> ()
       | _ -> ())
  | UploadEffect_Complete | UploadEffect_Fail _ | UploadEffect_Idle -> ()

let rec run_upload_ev_reaches_a_verdict (#io_t: Type0) {| i: t_UploadIo io_t |}
  (n: nat) (s: io_t) (t: t_UploadTransition)
  : Lemma (requires loop_sound t /\ remaining t.f_effect <= n)
          (ensures (let (_, t2, _) = run_upload_ev #io_t #i n s t in
                    is_terminal t2.f_effect))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, o) = turn_ev #io_t #i s t in
    (match o with
     | None -> ()
     | Some ev -> step_decreases t ev);
    run_upload_ev_reaches_a_verdict #io_t #i (n - 1) s1 t1
  end

// ── 4. The handler's final state satisfies the per-request theorems ───────

let run_upload_theorem (#io_t: Type0) {| i: t_UploadIo io_t |} (s: io_t)
  (request: t_UploadRequest)
  : Lemma (
      let (_, t) = run_upload #io_t #i s request in
      exists (evs: list t_UploadEvent).
        responds (begin_upload request) evs /\
        t.f_driver == run_from_request request evs /\
        is_terminal t.f_effect /\
        loop_sound t /\
        (let d = t.f_driver in
         (d.f_responded ==> d.f_write_matched) /\
         (d.f_responded ==> (d.f_shadow ==> d.f_activity_done)) /\
         (d.f_responded ==> (not d.f_shadow ==> d.f_published)) /\
         (d.f_write_matched ==> route_clean d) /\
         (d.f_shadow ==> shadow_route d) /\
         not (d.f_responded && d.f_failed) /\
         count_complete (begin_upload request).f_driver evs <= 1 /\
         count_fail (begin_upload request).f_driver evs <= 1)) =
  let t0 = begin_upload request in
  begin_trace_sound request;
  run_upload_is_run_ev #io_t #i s request;
  run_upload_ev_follows_the_driver #io_t #i 7 s t0;
  run_upload_ev_reaches_a_verdict #io_t #i 7 s t0;
  let (_, t2, evs) = run_upload_ev #io_t #i 7 s t0 in
  assert (t2.f_driver == run_from_request request evs);
  upload_trace_theorem request evs

// ── The read interpreter ──────────────────────────────────────────────────

let read_is_terminal (e: t_ReadEffect) : bool =
  match e <: t_ReadEffect with
  | ReadEffect_Serve _ | ReadEffect_Fail _ | ReadEffect_Idle -> true
  | _ -> false

let read_responds_to (e: t_ReadEffect) (ev: t_ReadEvent) : bool =
  match e, ev with
  | ReadEffect_ReadEpoch, ReadEvent_Epoch _
  | ReadEffect_ReadEpoch, ReadEvent_EpochStorage
  | ReadEffect_LookupChunk, ReadEvent_Lookup _ -> true
  | _ -> false

let read_loop_sound (t: t_ReadTransition) : bool = read_loop_is_sound t

let read_turn_ev (#io_t: Type0) {| i: t_ReadIo io_t |} (s: io_t) (t: t_ReadTransition)
  : Pure (io_t & t_ReadTransition & option t_ReadEvent)
    (requires read_loop_sound t)
    (ensures fun _ -> True) =
  match t.f_effect <: t_ReadEffect with
  | ReadEffect_ReadEpoch ->
      let (s', o) = f_read_epoch #io_t #i s in
      let ev =
        match o <: Core_models.Option.t_Option t_ReadEpochObservation with
        | Core_models.Option.Option_Some observation -> ReadEvent_Epoch observation
        | Core_models.Option.Option_None -> ReadEvent_EpochStorage in
      (s', read_step t.f_driver ev, Some ev)
  | ReadEffect_LookupChunk ->
      let (s', o) = f_lookup_chunk #io_t #i s in
      let ev = ReadEvent_Lookup o in
      (s', read_step t.f_driver ev, Some ev)
  | ReadEffect_Serve _ | ReadEffect_Fail _ | ReadEffect_Idle -> (s, t, None)

let read_turn (#io_t: Type0) {| i: t_ReadIo io_t |} (acc: io_t & t_ReadTransition)
  : (io_t & t_ReadTransition) =
  let (s, t) = acc in
  if read_loop_sound t
  then let (s', t', _) = read_turn_ev #io_t #i s t in (s', t')
  else acc

let rec read_iter_turn (#io_t: Type0) {| i: t_ReadIo io_t |} (n: nat)
  (acc: io_t & t_ReadTransition)
  : Tot (io_t & t_ReadTransition) (decreases n) =
  if n = 0 then acc else read_iter_turn #io_t #i (n - 1) (read_turn #io_t #i acc)

let read_cons_opt (o: option t_ReadEvent) (evs: list t_ReadEvent) : list t_ReadEvent =
  match o with
  | None -> evs
  | Some ev -> ev :: evs

let rec run_read_ev (#io_t: Type0) {| i: t_ReadIo io_t |} (n: nat) (s: io_t)
  (t: t_ReadTransition)
  : Pure (io_t & t_ReadTransition & list t_ReadEvent)
    (requires read_loop_sound t)
    (ensures fun (_, t', _) -> read_loop_sound t')
    (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = read_turn_ev #io_t #i s t in
    let (s2, t2, evs) = run_read_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, read_cons_opt o evs)

let rec read_fold_range_is_iter_turn
  (#io_t: Type0) {| i: t_ReadIo io_t |}
  (n: nat)
  (start end_: usize)
  (inv: (io_t & t_ReadTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_ReadTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_ReadTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_ReadTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_ReadTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == read_turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f ==
              read_iter_turn #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (read_iter_turn #io_t #i n init)] =
  if v start < v end_
  then read_fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec read_iter_turn_is_run_ev (#io_t: Type0) {| i: t_ReadIo io_t |} (n: nat) (s: io_t)
  (t: t_ReadTransition)
  : Lemma (requires read_loop_sound t)
          (ensures (let (s2, t2, _) = run_read_ev #io_t #i n s t in
                    read_iter_turn #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, _) = read_turn_ev #io_t #i s t in
    read_iter_turn_is_run_ev #io_t #i (n - 1) s1 t1
  end

let run_read_is_run_ev (#io_t: Type0) {| i: t_ReadIo io_t |} (s: io_t)
  (request: t_ReadRequest)
  : Lemma (let (s2, t2, _) = run_read_ev #io_t #i 2 s (begin_read request) in
           run_read #io_t #i s request == (s2, t2)) =
  read_iter_turn_is_run_ev #io_t #i 2 s (begin_read request);
  assert (v v_READ_MAX_EFFECTS = 2);
  assert (run_read #io_t #i s request == read_iter_turn #io_t #i 2 (s, begin_read request))

/// A dropped handler future stops the read loop after an arbitrary prefix of
/// turns. For every executor, every `k` and every sound start, the transition
/// after `k` turns is sound: `read_state_is_sound` carries the per-request
/// state invariants (a served row was read at the served epoch and the lookup
/// matched the request's account and epoch), and the next effect agrees with
/// the state that produced it.
let read_cancellation (#io_t: Type0) {| i: t_ReadIo io_t |} (k: nat) (s: io_t)
  (t: t_ReadTransition)
  : Lemma (requires read_loop_sound t)
          (ensures (let (_, t2) = read_iter_turn #io_t #i k (s, t) in
                    read_loop_sound t2)) =
  let (_, t2, _) = run_read_ev #io_t #i k s t in
  read_iter_turn_is_run_ev #io_t #i k s t

let rec read_responds (t: t_ReadTransition) (evs: list t_ReadEvent)
  : Pure bool (requires read_trace_sound t.f_driver) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (read_is_terminal t.f_effect) && read_responds_to t.f_effect ev &&
      read_responds (read_step t.f_driver ev) rest

let rec run_read_ev_follows_the_driver (#io_t: Type0) {| i: t_ReadIo io_t |}
  (n: nat) (s: io_t) (t: t_ReadTransition)
  : Lemma (requires read_loop_sound t /\ read_trace_sound t.f_driver)
          (ensures (let (_, t2, evs) = run_read_ev #io_t #i n s t in
                    read_trace_sound t2.f_driver /\
                    read_responds t evs /\
                    t2.f_driver == read_run t.f_driver evs))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, o) = read_turn_ev #io_t #i s t in
    (match o with
     | None -> ()
     | Some ev -> read_step_sound t.f_driver ev);
    run_read_ev_follows_the_driver #io_t #i (n - 1) s1 t1;
    match o with
    | None -> ()
    | Some ev -> read_step_sound t.f_driver ev
  end

let read_remaining (e: t_ReadEffect) : nat =
  match e <: t_ReadEffect with
  | ReadEffect_ReadEpoch -> 2
  | ReadEffect_LookupChunk -> 1
  | ReadEffect_Serve _ | ReadEffect_Fail _ | ReadEffect_Idle -> 0

let read_step_decreases (t: t_ReadTransition) (ev: t_ReadEvent)
  : Lemma (requires read_loop_sound t /\ not (read_is_terminal t.f_effect) /\
                     read_responds_to t.f_effect ev)
          (ensures read_remaining (read_step t.f_driver ev).f_effect <
                   read_remaining t.f_effect) =
  match t.f_effect <: t_ReadEffect with
  | ReadEffect_ReadEpoch ->
      (match ev <: t_ReadEvent with
       | ReadEvent_Epoch _ -> ()
       | ReadEvent_EpochStorage -> ()
       | _ -> ())
  | ReadEffect_LookupChunk ->
      (match ev <: t_ReadEvent with
       | ReadEvent_Lookup _ -> ()
       | _ -> ())
  | ReadEffect_Serve _ | ReadEffect_Fail _ | ReadEffect_Idle -> ()

let rec run_read_ev_reaches_a_verdict (#io_t: Type0) {| i: t_ReadIo io_t |}
  (n: nat) (s: io_t) (t: t_ReadTransition)
  : Lemma (requires read_loop_sound t /\ read_remaining t.f_effect <= n)
          (ensures (let (_, t2, _) = run_read_ev #io_t #i n s t in
                    read_is_terminal t2.f_effect))
          (decreases n) =
  if n = 0 then ()
  else begin
    let (s1, t1, o) = read_turn_ev #io_t #i s t in
    (match o with
     | None -> ()
     | Some ev -> read_step_decreases t ev);
    run_read_ev_reaches_a_verdict #io_t #i (n - 1) s1 t1
  end

let run_read_theorem (#io_t: Type0) {| i: t_ReadIo io_t |} (s: io_t)
  (request: t_ReadRequest)
  : Lemma (
      let (_, t) = run_read #io_t #i s request in
      exists (evs: list t_ReadEvent).
        read_responds (begin_read request) evs /\
        t.f_driver == read_run_from_request request evs /\
        read_is_terminal t.f_effect /\
        read_loop_sound t /\
        (let r = t.f_driver in
         (r.f_responded ==> (r.f_authenticated /\ r.f_epoch >=. v_INITIAL_EPOCH)) /\
         not (r.f_responded && r.f_failed))) =
  let t0 = begin_read request in
  begin_read_trace_sound request;
  run_read_is_run_ev #io_t #i s request;
  run_read_ev_follows_the_driver #io_t #i 2 s t0;
  run_read_ev_reaches_a_verdict #io_t #i 2 s t0;
  let (_, t2, evs) = run_read_ev #io_t #i 2 s t0 in
  assert (t2.f_driver == read_run_from_request request evs);
  read_trace_theorem request evs
