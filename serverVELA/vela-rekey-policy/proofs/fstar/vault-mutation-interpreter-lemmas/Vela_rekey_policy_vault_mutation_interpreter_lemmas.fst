module Vela_rekey_policy_vault_mutation_interpreter_lemmas

/// The extracted `run_chunk_delete`, `run_oram`, `run_schema`,
/// `run_capsule_ack` and `run_rekey_capable` are the loops the five handlers
/// run (the server expands the same macro text with `.await`). For every
/// executor implementation this module proves that each loop:
///
/// 1. calls exactly the executor method for the effect the driver emitted, in
///    order, with the effect's argument (the ORAM bucket index), and nothing
///    after the verdict;
/// 2. feeds back observations that answer their effects and ends in
///    `run_from_* request evs`;
/// 3. reaches a verdict within its budget;
/// 4. hence satisfies the corresponding per-request driver theorem;
/// 5. stops in a sound driver state after any prefix of turns, i.e. when the
///    handler future is dropped (`*_cancellation`).

open FStar.Mul
open Core_models
open Vela_rekey_policy.Vault_mutation_driver
open Vela_rekey_policy.Vault_mutation_interpreter
open Vela_rekey_policy_vault_mutation_driver_lemmas

// ══════════════════════════════════════════════════════════════════════════
// Chunk delete
// ══════════════════════════════════════════════════════════════════════════

let cd_terminal (e: t_ChunkDeleteEffect) : bool =
  match e with
  | ChunkDeleteEffect_Complete | ChunkDeleteEffect_Fail _ | ChunkDeleteEffect_Idle -> true
  | _ -> false

let cd_responds_to (e: t_ChunkDeleteEffect) (ev: t_ChunkDeleteEvent) : bool =
  match e, ev with
  | ChunkDeleteEffect_CheckSchema, ChunkDeleteEvent_Schema _
  | ChunkDeleteEffect_ResolveEpoch, ChunkDeleteEvent_Route _
  | ChunkDeleteEffect_ReadVersion, ChunkDeleteEvent_Version _
  | ChunkDeleteEffect_DeleteRow, ChunkDeleteEvent_Delete _
  | ChunkDeleteEffect_Publish, ChunkDeleteEvent_Published -> true
  | _ -> false

let cd_sound (t: t_ChunkDeleteTransition) : bool =
  chunk_delete_state_is_sound t.f_driver && chunk_delete_effect_is_sound t.f_driver t.f_effect

let cd_turn_ev (#io_t: Type0) {| i: t_ChunkDeleteIo io_t |} (s: io_t) (t: t_ChunkDeleteTransition)
  : Pure (io_t & t_ChunkDeleteTransition & option t_ChunkDeleteEvent)
    (requires chunk_delete_state_is_sound t.f_driver) (ensures fun _ -> True) =
  match t.f_effect with
  | ChunkDeleteEffect_CheckSchema ->
      let (s', o) = f_check_schema #io_t #i s in
      let ev = ChunkDeleteEvent_Schema o in
      (s', chunk_delete_step t.f_driver ev, Some ev)
  | ChunkDeleteEffect_ResolveEpoch ->
      let (s', o) = f_resolve_epoch #io_t #i s in
      let ev = ChunkDeleteEvent_Route o in
      (s', chunk_delete_step t.f_driver ev, Some ev)
  | ChunkDeleteEffect_ReadVersion ->
      let (s', o) = f_read_version #io_t #i s in
      let ev = ChunkDeleteEvent_Version o in
      (s', chunk_delete_step t.f_driver ev, Some ev)
  | ChunkDeleteEffect_DeleteRow ->
      let (s', o) = f_delete_row #io_t #i s in
      let ev = ChunkDeleteEvent_Delete o in
      (s', chunk_delete_step t.f_driver ev, Some ev)
  | ChunkDeleteEffect_Publish ->
      let s' = f_publish #io_t #i s in
      let ev = ChunkDeleteEvent_Published in
      (s', chunk_delete_step t.f_driver ev, Some ev)
  | ChunkDeleteEffect_Complete | ChunkDeleteEffect_Fail _ | ChunkDeleteEffect_Idle -> (s, t, None)

let cd_turn (#io_t: Type0) {| i: t_ChunkDeleteIo io_t |} (acc: io_t & t_ChunkDeleteTransition)
  : (io_t & t_ChunkDeleteTransition) =
  let (s, t) = acc in
  if chunk_delete_state_is_sound t.f_driver
  then let (s', t', _) = cd_turn_ev #io_t #i s t in (s', t')
  else acc

let rec cd_iter (#io_t: Type0) {| i: t_ChunkDeleteIo io_t |} (n: nat)
  (acc: io_t & t_ChunkDeleteTransition) : Tot (io_t & t_ChunkDeleteTransition) (decreases n) =
  if n = 0 then acc else cd_iter #io_t #i (n - 1) (cd_turn #io_t #i acc)

let cons_opt_cd (o: option t_ChunkDeleteEvent) (evs: list t_ChunkDeleteEvent) : list t_ChunkDeleteEvent =
  match o with | None -> evs | Some ev -> ev :: evs

let rec cd_run_ev (#io_t: Type0) {| i: t_ChunkDeleteIo io_t |} (n: nat) (s: io_t)
  (t: t_ChunkDeleteTransition)
  : Pure (io_t & t_ChunkDeleteTransition & list t_ChunkDeleteEvent)
    (requires cd_sound t) (ensures fun (_, t', _) -> cd_sound t') (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = cd_turn_ev #io_t #i s t in
    let (s2, t2, evs) = cd_run_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, cons_opt_cd o evs)

let rec cd_fold_range_is_iter_turn (#io_t: Type0) {| i: t_ChunkDeleteIo io_t |}
  (n: nat) (start end_: usize)
  (inv: (io_t & t_ChunkDeleteTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_ChunkDeleteTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_ChunkDeleteTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_ChunkDeleteTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_ChunkDeleteTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == cd_turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f == cd_iter #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (cd_iter #io_t #i n init)] =
  if v start < v end_
  then cd_fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec cd_iter_is_run_ev (#io_t: Type0) {| i: t_ChunkDeleteIo io_t |} (n: nat) (s: io_t)
  (t: t_ChunkDeleteTransition)
  : Lemma (requires cd_sound t)
          (ensures (let (s2, t2, _) = cd_run_ev #io_t #i n s t in cd_iter #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, _) = cd_turn_ev #io_t #i s t in
    cd_iter_is_run_ev #io_t #i (n - 1) s1 t1
  end

let run_chunk_delete_is_run_ev (#io_t: Type0) {| i: t_ChunkDeleteIo io_t |} (s: io_t)
  (request: t_ChunkDeleteRequest)
  : Lemma (let (s2, t2, _) = cd_run_ev #io_t #i 5 s (begin_chunk_delete request) in
           run_chunk_delete #io_t #i s request == (s2, t2)) =
  let t0 = begin_chunk_delete request in
  cd_iter_is_run_ev #io_t #i 5 s t0;
  assert (v v_CHUNK_DELETE_MAX_EFFECTS = 5);
  assert (run_chunk_delete #io_t #i s request == cd_iter #io_t #i 5 (s, t0))

/// Cancellation (`DELETE /vault/chunk/:id`): the handler future may be dropped after any
/// executor call, so the loop stops after an arbitrary prefix of turns. Every
/// such prefix, for every executor and every `k`, ends in a sound driver
/// state whose next effect agrees with it.
let chunk_delete_cancellation (#io_t: Type0) {| i: t_ChunkDeleteIo io_t |} (k: nat) (s: io_t)
  (t: t_ChunkDeleteTransition)
  : Lemma (requires cd_sound t)
          (ensures (let (_, t2) = cd_iter #io_t #i k (s, t) in cd_sound t2)) =
  cd_iter_is_run_ev #io_t #i k s t

let rec cd_responds (t: t_ChunkDeleteTransition) (evs: list t_ChunkDeleteEvent)
  : Pure bool (requires cd_sound t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (cd_terminal t.f_effect) && cd_responds_to t.f_effect ev &&
      cd_responds (chunk_delete_step t.f_driver ev) rest

let rec cd_run_ev_follows (#io_t: Type0) {| i: t_ChunkDeleteIo io_t |} (n: nat) (s: io_t)
  (t: t_ChunkDeleteTransition)
  : Lemma (requires cd_sound t)
          (ensures (let (_, t2, evs) = cd_run_ev #io_t #i n s t in
                    chunk_delete_state_is_sound t.f_driver /\
                    cd_responds t evs /\
                    t2.f_driver == chunk_run t.f_driver evs))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, o) = cd_turn_ev #io_t #i s t in
    cd_run_ev_follows #io_t #i (n - 1) s1 t1;
    match o with | None -> () | Some ev -> chunk_step_sound t.f_driver ev
  end

let cd_remaining (e: t_ChunkDeleteEffect) : nat =
  match e with
  | ChunkDeleteEffect_CheckSchema -> 5
  | ChunkDeleteEffect_ResolveEpoch -> 4
  | ChunkDeleteEffect_ReadVersion -> 3
  | ChunkDeleteEffect_DeleteRow -> 2
  | ChunkDeleteEffect_Publish -> 1
  | ChunkDeleteEffect_Complete | ChunkDeleteEffect_Fail _ | ChunkDeleteEffect_Idle -> 0

let cd_step_decreases (t: t_ChunkDeleteTransition) (ev: t_ChunkDeleteEvent)
  : Lemma (requires cd_sound t /\ not (cd_terminal t.f_effect) /\ cd_responds_to t.f_effect ev)
          (ensures cd_remaining (chunk_delete_step t.f_driver ev).f_effect < cd_remaining t.f_effect) =
  match t.f_effect <: t_ChunkDeleteEffect with
  | ChunkDeleteEffect_CheckSchema -> ()
  | ChunkDeleteEffect_ResolveEpoch -> ()
  | ChunkDeleteEffect_ReadVersion -> ()
  | ChunkDeleteEffect_DeleteRow -> ()
  | ChunkDeleteEffect_Publish -> ()
  | _ -> ()

let rec cd_run_reaches_verdict (#io_t: Type0) {| i: t_ChunkDeleteIo io_t |} (n: nat) (s: io_t)
  (t: t_ChunkDeleteTransition)
  : Lemma (requires cd_sound t /\ cd_remaining t.f_effect <= n)
          (ensures (let (_, t2, _) = cd_run_ev #io_t #i n s t in cd_terminal t2.f_effect))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, o) = cd_turn_ev #io_t #i s t in
    (match o with | None -> () | Some ev -> cd_step_decreases t ev);
    cd_run_reaches_verdict #io_t #i (n - 1) s1 t1
  end

let run_chunk_delete_theorem (#io_t: Type0) {| i: t_ChunkDeleteIo io_t |} (s: io_t)
  (request: t_ChunkDeleteRequest)
  : Lemma (let (_, t) = run_chunk_delete #io_t #i s request in
           exists (evs: list t_ChunkDeleteEvent).
             cd_responds (begin_chunk_delete request) evs /\
             t.f_driver == chunk_run_from request evs /\
             cd_terminal t.f_effect /\
             (let d = t.f_driver in
              chunk_delete_state_is_sound d /\
              (d.f_responded ==> (d.f_deleted /\ d.f_published /\ d.f_permit_epoch = d.f_epoch)) /\
              not (d.f_responded && d.f_failed))) =
  let t0 = begin_chunk_delete request in
  run_chunk_delete_is_run_ev #io_t #i s request;
  cd_run_ev_follows #io_t #i 5 s t0;
  cd_run_reaches_verdict #io_t #i 5 s t0;
  let (_, _, evs) = cd_run_ev #io_t #i 5 s t0 in
  chunk_delete_theorem request evs

// ══════════════════════════════════════════════════════════════════════════
// ORAM path write
// ══════════════════════════════════════════════════════════════════════════

let oram_terminal (e: t_OramEffect) : bool =
  match e with
  | OramEffect_Complete | OramEffect_Fail _ | OramEffect_Idle -> true
  | _ -> false

let oram_responds_to (e: t_OramEffect) (ev: t_OramEvent) : bool =
  match e, ev with
  | OramEffect_ResolveEpoch, OramEvent_Route _
  | OramEffect_EnforceQuota, OramEvent_Quota _
  | OramEffect_WriteBucket _, OramEvent_Bucket _
  | OramEffect_RecheckBucket _, OramEvent_Recheck _
  | OramEffect_Publish, OramEvent_Published -> true
  | _ -> false

let oram_sound (t: t_OramTransition) : bool =
  oram_state_is_sound t.f_driver && oram_effect_is_sound t.f_driver t.f_effect

let oram_turn_ev (#io_t: Type0) {| i: t_OramIo io_t |} (s: io_t) (t: t_OramTransition)
  : Pure (io_t & t_OramTransition & option t_OramEvent)
    (requires oram_state_is_sound t.f_driver) (ensures fun _ -> True) =
  match t.f_effect with
  | OramEffect_ResolveEpoch ->
      let (s', o) = f_resolve_path_epoch #io_t #i s in
      let ev = OramEvent_Route o in
      (s', oram_step t.f_driver ev, Some ev)
  | OramEffect_EnforceQuota ->
      let (s', o) = f_enforce_quota #io_t #i s in
      let ev = OramEvent_Quota o in
      (s', oram_step t.f_driver ev, Some ev)
  | OramEffect_WriteBucket { f_index = index } ->
      let (s', o) = f_write_bucket #io_t #i s index in
      let ev = OramEvent_Bucket o in
      (s', oram_step t.f_driver ev, Some ev)
  | OramEffect_RecheckBucket { f_index = index } ->
      let (s', o) = f_recheck_bucket #io_t #i s index in
      let ev = OramEvent_Recheck o in
      (s', oram_step t.f_driver ev, Some ev)
  | OramEffect_Publish ->
      let s' = f_publish_path #io_t #i s in
      let ev = OramEvent_Published in
      (s', oram_step t.f_driver ev, Some ev)
  | OramEffect_Complete | OramEffect_Fail _ | OramEffect_Idle -> (s, t, None)

let oram_turn (#io_t: Type0) {| i: t_OramIo io_t |} (acc: io_t & t_OramTransition)
  : (io_t & t_OramTransition) =
  let (s, t) = acc in
  if oram_state_is_sound t.f_driver
  then let (s', t', _) = oram_turn_ev #io_t #i s t in (s', t')
  else acc

let rec oram_iter (#io_t: Type0) {| i: t_OramIo io_t |} (n: nat)
  (acc: io_t & t_OramTransition) : Tot (io_t & t_OramTransition) (decreases n) =
  if n = 0 then acc else oram_iter #io_t #i (n - 1) (oram_turn #io_t #i acc)

let cons_opt_oram (o: option t_OramEvent) (evs: list t_OramEvent) : list t_OramEvent =
  match o with | None -> evs | Some ev -> ev :: evs

let rec oram_run_ev (#io_t: Type0) {| i: t_OramIo io_t |} (n: nat) (s: io_t)
  (t: t_OramTransition)
  : Pure (io_t & t_OramTransition & list t_OramEvent)
    (requires oram_sound t) (ensures fun (_, t', _) -> oram_sound t') (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = oram_turn_ev #io_t #i s t in
    let (s2, t2, evs) = oram_run_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, cons_opt_oram o evs)

let rec oram_fold_range_is_iter_turn (#io_t: Type0) {| i: t_OramIo io_t |}
  (n: nat) (start end_: usize)
  (inv: (io_t & t_OramTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_OramTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_OramTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_OramTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_OramTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == oram_turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f == oram_iter #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (oram_iter #io_t #i n init)] =
  if v start < v end_
  then oram_fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec oram_iter_is_run_ev (#io_t: Type0) {| i: t_OramIo io_t |} (n: nat) (s: io_t)
  (t: t_OramTransition)
  : Lemma (requires oram_sound t)
          (ensures (let (s2, t2, _) = oram_run_ev #io_t #i n s t in oram_iter #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, _) = oram_turn_ev #io_t #i s t in
    oram_iter_is_run_ev #io_t #i (n - 1) s1 t1
  end

let run_oram_is_run_ev (#io_t: Type0) {| i: t_OramIo io_t |} (s: io_t)
  (request: t_OramRequest)
  : Lemma (let (s2, t2, _) = oram_run_ev #io_t #i 69 s (begin_oram request) in
           run_oram #io_t #i s request == (s2, t2)) =
  let t0 = begin_oram request in
  oram_iter_is_run_ev #io_t #i 69 s t0;
  assert (v v_ORAM_MAX_EFFECTS = 69);
  assert (run_oram #io_t #i s request == oram_iter #io_t #i 69 (s, t0))

/// Cancellation (`PUT /vault/oram/:tree_id/path/:leaf`): the handler future may be dropped after any
/// executor call, so the loop stops after an arbitrary prefix of turns. Every
/// such prefix, for every executor and every `k`, ends in a sound driver
/// state whose next effect agrees with it.
let oram_cancellation (#io_t: Type0) {| i: t_OramIo io_t |} (k: nat) (s: io_t)
  (t: t_OramTransition)
  : Lemma (requires oram_sound t)
          (ensures (let (_, t2) = oram_iter #io_t #i k (s, t) in oram_sound t2)) =
  oram_iter_is_run_ev #io_t #i k s t

let rec oram_responds (t: t_OramTransition) (evs: list t_OramEvent)
  : Pure bool (requires oram_sound t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (oram_terminal t.f_effect) && oram_responds_to t.f_effect ev &&
      oram_responds (oram_step t.f_driver ev) rest

let rec oram_run_ev_follows (#io_t: Type0) {| i: t_OramIo io_t |} (n: nat) (s: io_t)
  (t: t_OramTransition)
  : Lemma (requires oram_sound t)
          (ensures (let (_, t2, evs) = oram_run_ev #io_t #i n s t in
                    oram_state_is_sound t.f_driver /\
                    oram_responds t evs /\
                    t2.f_driver == oram_run t.f_driver evs))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, o) = oram_turn_ev #io_t #i s t in
    oram_run_ev_follows #io_t #i (n - 1) s1 t1;
    match o with | None -> () | Some ev -> oram_step_sound t.f_driver ev
  end

/// Turns left before the verdict: the route, the quota, the remaining bucket
/// writes, then one recheck or the publication. A path has at most 33
/// buckets, so a fresh request needs at most 36 of the 69 turns.
let clamp (x: int) : nat = if x < 0 then 0 else x

let oram_remaining (t: t_OramTransition) : nat =
  let bc = v t.f_driver.f_bucket_count in
  match t.f_effect with
  | OramEffect_ResolveEpoch -> clamp (bc + 3)
  | OramEffect_EnforceQuota -> clamp (bc + 2)
  | OramEffect_WriteBucket { f_index = index } -> clamp (bc - v index + 1)
  | OramEffect_RecheckBucket _ -> 1
  | OramEffect_Publish -> 1
  | OramEffect_Complete | OramEffect_Fail _ | OramEffect_Idle -> 0

let oram_begin_remaining (r: t_OramRequest)
  : Lemma (oram_remaining (begin_oram r) <= 69) = ()

let oram_step_decreases (t: t_OramTransition) (ev: t_OramEvent)
  : Lemma (requires oram_sound t /\ not (oram_terminal t.f_effect) /\ oram_responds_to t.f_effect ev)
          (ensures oram_remaining (oram_step t.f_driver ev) < oram_remaining t) =
  match t.f_effect <: t_OramEffect with
  | OramEffect_ResolveEpoch -> ()
  | OramEffect_EnforceQuota -> ()
  | OramEffect_WriteBucket _ -> ()
  | OramEffect_RecheckBucket _ -> ()
  | OramEffect_Publish -> ()
  | _ -> ()

let rec oram_run_reaches_verdict (#io_t: Type0) {| i: t_OramIo io_t |} (n: nat) (s: io_t)
  (t: t_OramTransition)
  : Lemma (requires oram_sound t /\ oram_remaining t <= n)
          (ensures (let (_, t2, _) = oram_run_ev #io_t #i n s t in oram_terminal t2.f_effect))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, o) = oram_turn_ev #io_t #i s t in
    (match o with | None -> () | Some ev -> oram_step_decreases t ev);
    oram_run_reaches_verdict #io_t #i (n - 1) s1 t1
  end

let run_oram_theorem (#io_t: Type0) {| i: t_OramIo io_t |} (s: io_t)
  (request: t_OramRequest)
  : Lemma (let (_, t) = run_oram #io_t #i s request in
           exists (evs: list t_OramEvent).
             oram_responds (begin_oram request) evs /\
             t.f_driver == oram_run_from request evs /\
             oram_terminal t.f_effect /\
             (let d = t.f_driver in
              oram_state_is_sound d /\
              (d.f_responded ==> (d.f_published /\ d.f_written = d.f_bucket_count)) /\
              not (d.f_responded && d.f_failed))) =
  let t0 = begin_oram request in
  run_oram_is_run_ev #io_t #i s request;
  oram_run_ev_follows #io_t #i 69 s t0;
  oram_begin_remaining request;
  oram_run_reaches_verdict #io_t #i 69 s t0;
  let (_, _, evs) = oram_run_ev #io_t #i 69 s t0 in
  oram_theorem request evs

// ══════════════════════════════════════════════════════════════════════════
// Schema activation
// ══════════════════════════════════════════════════════════════════════════

let schema_terminal (e: t_SchemaEffect) : bool =
  match e with
  | SchemaEffect_Complete | SchemaEffect_Fail _ | SchemaEffect_Idle -> true
  | _ -> false

let schema_responds_to (e: t_SchemaEffect) (ev: t_SchemaEvent) : bool =
  match e, ev with
  | SchemaEffect_WriteFloor, SchemaEvent_Write _ -> true
  | _ -> false

let schema_sound (t: t_SchemaTransition) : bool =
  schema_state_is_sound t.f_driver && schema_effect_is_sound t.f_driver t.f_effect

let schema_turn_ev (#io_t: Type0) {| i: t_SchemaIo io_t |} (s: io_t) (t: t_SchemaTransition)
  : Pure (io_t & t_SchemaTransition & option t_SchemaEvent)
    (requires schema_state_is_sound t.f_driver) (ensures fun _ -> True) =
  match t.f_effect with
  | SchemaEffect_WriteFloor ->
      let (s', o) = f_write_floor #io_t #i s in
      let ev = SchemaEvent_Write o in
      (s', schema_step t.f_driver ev, Some ev)
  | SchemaEffect_Complete | SchemaEffect_Fail _ | SchemaEffect_Idle -> (s, t, None)

let schema_turn (#io_t: Type0) {| i: t_SchemaIo io_t |} (acc: io_t & t_SchemaTransition)
  : (io_t & t_SchemaTransition) =
  let (s, t) = acc in
  if schema_state_is_sound t.f_driver
  then let (s', t', _) = schema_turn_ev #io_t #i s t in (s', t')
  else acc

let rec schema_iter (#io_t: Type0) {| i: t_SchemaIo io_t |} (n: nat)
  (acc: io_t & t_SchemaTransition) : Tot (io_t & t_SchemaTransition) (decreases n) =
  if n = 0 then acc else schema_iter #io_t #i (n - 1) (schema_turn #io_t #i acc)

let cons_opt_schema (o: option t_SchemaEvent) (evs: list t_SchemaEvent) : list t_SchemaEvent =
  match o with | None -> evs | Some ev -> ev :: evs

let rec schema_run_ev (#io_t: Type0) {| i: t_SchemaIo io_t |} (n: nat) (s: io_t)
  (t: t_SchemaTransition)
  : Pure (io_t & t_SchemaTransition & list t_SchemaEvent)
    (requires schema_sound t) (ensures fun (_, t', _) -> schema_sound t') (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = schema_turn_ev #io_t #i s t in
    let (s2, t2, evs) = schema_run_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, cons_opt_schema o evs)

let rec schema_fold_range_is_iter_turn (#io_t: Type0) {| i: t_SchemaIo io_t |}
  (n: nat) (start end_: usize)
  (inv: (io_t & t_SchemaTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_SchemaTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_SchemaTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_SchemaTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_SchemaTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == schema_turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f == schema_iter #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (schema_iter #io_t #i n init)] =
  if v start < v end_
  then schema_fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec schema_iter_is_run_ev (#io_t: Type0) {| i: t_SchemaIo io_t |} (n: nat) (s: io_t)
  (t: t_SchemaTransition)
  : Lemma (requires schema_sound t)
          (ensures (let (s2, t2, _) = schema_run_ev #io_t #i n s t in schema_iter #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, _) = schema_turn_ev #io_t #i s t in
    schema_iter_is_run_ev #io_t #i (n - 1) s1 t1
  end

let run_schema_is_run_ev (#io_t: Type0) {| i: t_SchemaIo io_t |} (s: io_t)
  (request: t_SchemaRequest)
  : Lemma (let (s2, t2, _) = schema_run_ev #io_t #i 1 s (begin_schema request) in
           run_schema #io_t #i s request == (s2, t2)) =
  let t0 = begin_schema request in
  schema_iter_is_run_ev #io_t #i 1 s t0;
  assert (v v_SCHEMA_MAX_EFFECTS = 1);
  assert (run_schema #io_t #i s request == schema_iter #io_t #i 1 (s, t0))

/// Cancellation (`POST /vault/schema`): the handler future may be dropped after any
/// executor call, so the loop stops after an arbitrary prefix of turns. Every
/// such prefix, for every executor and every `k`, ends in a sound driver
/// state whose next effect agrees with it.
let schema_cancellation (#io_t: Type0) {| i: t_SchemaIo io_t |} (k: nat) (s: io_t)
  (t: t_SchemaTransition)
  : Lemma (requires schema_sound t)
          (ensures (let (_, t2) = schema_iter #io_t #i k (s, t) in schema_sound t2)) =
  schema_iter_is_run_ev #io_t #i k s t

let rec schema_responds (t: t_SchemaTransition) (evs: list t_SchemaEvent)
  : Pure bool (requires schema_sound t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (schema_terminal t.f_effect) && schema_responds_to t.f_effect ev &&
      schema_responds (schema_step t.f_driver ev) rest

let rec schema_run_ev_follows (#io_t: Type0) {| i: t_SchemaIo io_t |} (n: nat) (s: io_t)
  (t: t_SchemaTransition)
  : Lemma (requires schema_sound t)
          (ensures (let (_, t2, evs) = schema_run_ev #io_t #i n s t in
                    schema_state_is_sound t.f_driver /\
                    schema_responds t evs /\
                    t2.f_driver == schema_run t.f_driver evs))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, o) = schema_turn_ev #io_t #i s t in
    schema_run_ev_follows #io_t #i (n - 1) s1 t1;
    match o with | None -> () | Some ev -> schema_step_sound t.f_driver ev
  end

let schema_remaining (e: t_SchemaEffect) : nat =
  match e with
  | SchemaEffect_WriteFloor -> 1
  | SchemaEffect_Complete | SchemaEffect_Fail _ | SchemaEffect_Idle -> 0

let schema_step_decreases (t: t_SchemaTransition) (ev: t_SchemaEvent)
  : Lemma (requires schema_sound t /\ not (schema_terminal t.f_effect) /\ schema_responds_to t.f_effect ev)
          (ensures schema_remaining (schema_step t.f_driver ev).f_effect < schema_remaining t.f_effect) =
  match t.f_effect <: t_SchemaEffect with
  | SchemaEffect_WriteFloor -> ()
  | _ -> ()

let rec schema_run_reaches_verdict (#io_t: Type0) {| i: t_SchemaIo io_t |} (n: nat) (s: io_t)
  (t: t_SchemaTransition)
  : Lemma (requires schema_sound t /\ schema_remaining t.f_effect <= n)
          (ensures (let (_, t2, _) = schema_run_ev #io_t #i n s t in schema_terminal t2.f_effect))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, o) = schema_turn_ev #io_t #i s t in
    (match o with | None -> () | Some ev -> schema_step_decreases t ev);
    schema_run_reaches_verdict #io_t #i (n - 1) s1 t1
  end

let run_schema_theorem (#io_t: Type0) {| i: t_SchemaIo io_t |} (s: io_t)
  (request: t_SchemaRequest)
  : Lemma (let (_, t) = run_schema #io_t #i s request in
           exists (evs: list t_SchemaEvent).
             schema_responds (begin_schema request) evs /\
             t.f_driver == schema_run_from request evs /\
             schema_terminal t.f_effect /\
             (let d = t.f_driver in
              schema_state_is_sound d /\
              (d.f_responded ==> d.f_written) /\
              (d.f_written ==> (d.f_authenticated && d.f_device_scope)))) =
  let t0 = begin_schema request in
  run_schema_is_run_ev #io_t #i s request;
  schema_run_ev_follows #io_t #i 1 s t0;
  schema_run_reaches_verdict #io_t #i 1 s t0;
  let (_, _, evs) = schema_run_ev #io_t #i 1 s t0 in
  schema_theorem request evs

// ══════════════════════════════════════════════════════════════════════════
// Capsule acknowledgement
// ══════════════════════════════════════════════════════════════════════════

let ack_terminal (e: t_CapsuleAckEffect) : bool =
  match e with
  | CapsuleAckEffect_Complete | CapsuleAckEffect_Fail _ | CapsuleAckEffect_Idle -> true
  | _ -> false

let ack_responds_to (e: t_CapsuleAckEffect) (ev: t_CapsuleAckEvent) : bool =
  match e, ev with
  | CapsuleAckEffect_Acknowledge, CapsuleAckEvent_Ack _
  | CapsuleAckEffect_InspectPending, CapsuleAckEvent_Pending _ -> true
  | _ -> false

let ack_sound (t: t_CapsuleAckTransition) : bool =
  capsule_ack_state_is_sound t.f_driver && capsule_ack_effect_is_sound t.f_driver t.f_effect

let ack_turn_ev (#io_t: Type0) {| i: t_CapsuleAckIo io_t |} (s: io_t) (t: t_CapsuleAckTransition)
  : Pure (io_t & t_CapsuleAckTransition & option t_CapsuleAckEvent)
    (requires capsule_ack_state_is_sound t.f_driver) (ensures fun _ -> True) =
  match t.f_effect with
  | CapsuleAckEffect_Acknowledge ->
      let (s', o) = f_acknowledge #io_t #i s in
      let ev = CapsuleAckEvent_Ack o in
      (s', capsule_ack_step t.f_driver ev, Some ev)
  | CapsuleAckEffect_InspectPending ->
      let (s', o) = f_inspect_pending #io_t #i s in
      let ev = CapsuleAckEvent_Pending o in
      (s', capsule_ack_step t.f_driver ev, Some ev)
  | CapsuleAckEffect_Complete | CapsuleAckEffect_Fail _ | CapsuleAckEffect_Idle -> (s, t, None)

let ack_turn (#io_t: Type0) {| i: t_CapsuleAckIo io_t |} (acc: io_t & t_CapsuleAckTransition)
  : (io_t & t_CapsuleAckTransition) =
  let (s, t) = acc in
  if capsule_ack_state_is_sound t.f_driver
  then let (s', t', _) = ack_turn_ev #io_t #i s t in (s', t')
  else acc

let rec ack_iter (#io_t: Type0) {| i: t_CapsuleAckIo io_t |} (n: nat)
  (acc: io_t & t_CapsuleAckTransition) : Tot (io_t & t_CapsuleAckTransition) (decreases n) =
  if n = 0 then acc else ack_iter #io_t #i (n - 1) (ack_turn #io_t #i acc)

let cons_opt_ack (o: option t_CapsuleAckEvent) (evs: list t_CapsuleAckEvent) : list t_CapsuleAckEvent =
  match o with | None -> evs | Some ev -> ev :: evs

let rec ack_run_ev (#io_t: Type0) {| i: t_CapsuleAckIo io_t |} (n: nat) (s: io_t)
  (t: t_CapsuleAckTransition)
  : Pure (io_t & t_CapsuleAckTransition & list t_CapsuleAckEvent)
    (requires ack_sound t) (ensures fun (_, t', _) -> ack_sound t') (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = ack_turn_ev #io_t #i s t in
    let (s2, t2, evs) = ack_run_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, cons_opt_ack o evs)

let rec ack_fold_range_is_iter_turn (#io_t: Type0) {| i: t_CapsuleAckIo io_t |}
  (n: nat) (start end_: usize)
  (inv: (io_t & t_CapsuleAckTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_CapsuleAckTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_CapsuleAckTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_CapsuleAckTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_CapsuleAckTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == ack_turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f == ack_iter #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (ack_iter #io_t #i n init)] =
  if v start < v end_
  then ack_fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec ack_iter_is_run_ev (#io_t: Type0) {| i: t_CapsuleAckIo io_t |} (n: nat) (s: io_t)
  (t: t_CapsuleAckTransition)
  : Lemma (requires ack_sound t)
          (ensures (let (s2, t2, _) = ack_run_ev #io_t #i n s t in ack_iter #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, _) = ack_turn_ev #io_t #i s t in
    ack_iter_is_run_ev #io_t #i (n - 1) s1 t1
  end

let run_capsule_ack_is_run_ev (#io_t: Type0) {| i: t_CapsuleAckIo io_t |} (s: io_t)
  (request: t_CapsuleAckRequest)
  : Lemma (let (s2, t2, _) = ack_run_ev #io_t #i 2 s (begin_capsule_ack request) in
           run_capsule_ack #io_t #i s request == (s2, t2)) =
  let t0 = begin_capsule_ack request in
  ack_iter_is_run_ev #io_t #i 2 s t0;
  assert (v v_CAPSULE_ACK_MAX_EFFECTS = 2);
  assert (run_capsule_ack #io_t #i s request == ack_iter #io_t #i 2 (s, t0))

/// Cancellation (`POST /device/capsule/ack`): the handler future may be dropped after any
/// executor call, so the loop stops after an arbitrary prefix of turns. Every
/// such prefix, for every executor and every `k`, ends in a sound driver
/// state whose next effect agrees with it.
let capsule_ack_cancellation (#io_t: Type0) {| i: t_CapsuleAckIo io_t |} (k: nat) (s: io_t)
  (t: t_CapsuleAckTransition)
  : Lemma (requires ack_sound t)
          (ensures (let (_, t2) = ack_iter #io_t #i k (s, t) in ack_sound t2)) =
  ack_iter_is_run_ev #io_t #i k s t

let rec ack_responds (t: t_CapsuleAckTransition) (evs: list t_CapsuleAckEvent)
  : Pure bool (requires ack_sound t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (ack_terminal t.f_effect) && ack_responds_to t.f_effect ev &&
      ack_responds (capsule_ack_step t.f_driver ev) rest

let rec ack_run_ev_follows (#io_t: Type0) {| i: t_CapsuleAckIo io_t |} (n: nat) (s: io_t)
  (t: t_CapsuleAckTransition)
  : Lemma (requires ack_sound t)
          (ensures (let (_, t2, evs) = ack_run_ev #io_t #i n s t in
                    capsule_ack_state_is_sound t.f_driver /\
                    ack_responds t evs /\
                    t2.f_driver == ack_run t.f_driver evs))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, o) = ack_turn_ev #io_t #i s t in
    ack_run_ev_follows #io_t #i (n - 1) s1 t1;
    match o with | None -> () | Some ev -> ack_step_sound t.f_driver ev
  end

let ack_remaining (e: t_CapsuleAckEffect) : nat =
  match e with
  | CapsuleAckEffect_Acknowledge -> 2
  | CapsuleAckEffect_InspectPending -> 1
  | CapsuleAckEffect_Complete | CapsuleAckEffect_Fail _ | CapsuleAckEffect_Idle -> 0

let ack_step_decreases (t: t_CapsuleAckTransition) (ev: t_CapsuleAckEvent)
  : Lemma (requires ack_sound t /\ not (ack_terminal t.f_effect) /\ ack_responds_to t.f_effect ev)
          (ensures ack_remaining (capsule_ack_step t.f_driver ev).f_effect < ack_remaining t.f_effect) =
  match t.f_effect <: t_CapsuleAckEffect with
  | CapsuleAckEffect_Acknowledge -> ()
  | CapsuleAckEffect_InspectPending -> ()
  | _ -> ()

let rec ack_run_reaches_verdict (#io_t: Type0) {| i: t_CapsuleAckIo io_t |} (n: nat) (s: io_t)
  (t: t_CapsuleAckTransition)
  : Lemma (requires ack_sound t /\ ack_remaining t.f_effect <= n)
          (ensures (let (_, t2, _) = ack_run_ev #io_t #i n s t in ack_terminal t2.f_effect))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, o) = ack_turn_ev #io_t #i s t in
    (match o with | None -> () | Some ev -> ack_step_decreases t ev);
    ack_run_reaches_verdict #io_t #i (n - 1) s1 t1
  end

let run_capsule_ack_theorem (#io_t: Type0) {| i: t_CapsuleAckIo io_t |} (s: io_t)
  (request: t_CapsuleAckRequest)
  : Lemma (let (_, t) = run_capsule_ack #io_t #i s request in
           exists (evs: list t_CapsuleAckEvent).
             ack_responds (begin_capsule_ack request) evs /\
             t.f_driver == ack_run_from request evs /\
             ack_terminal t.f_effect /\
             (let d = t.f_driver in
              capsule_ack_state_is_sound d /\
              (d.f_responded ==> d.f_cleared) /\
              (d.f_cleared ==> (d.f_authenticated && d.f_device_scope)))) =
  let t0 = begin_capsule_ack request in
  run_capsule_ack_is_run_ev #io_t #i s request;
  ack_run_ev_follows #io_t #i 2 s t0;
  ack_run_reaches_verdict #io_t #i 2 s t0;
  let (_, _, evs) = ack_run_ev #io_t #i 2 s t0 in
  ack_theorem request evs

// ══════════════════════════════════════════════════════════════════════════
// Capability attestation
// ══════════════════════════════════════════════════════════════════════════

let capable_terminal (e: t_RekeyCapableEffect) : bool =
  match e with
  | RekeyCapableEffect_Complete | RekeyCapableEffect_Fail _ | RekeyCapableEffect_Idle -> true
  | _ -> false

let capable_responds_to (e: t_RekeyCapableEffect) (ev: t_RekeyCapableEvent) : bool =
  match e, ev with
  | RekeyCapableEffect_Attest, RekeyCapableEvent_Attest _ -> true
  | _ -> false

let capable_sound (t: t_RekeyCapableTransition) : bool =
  rekey_capable_state_is_sound t.f_driver && rekey_capable_effect_is_sound t.f_driver t.f_effect

let capable_turn_ev (#io_t: Type0) {| i: t_RekeyCapableIo io_t |} (s: io_t)
  (t: t_RekeyCapableTransition)
  : Pure (io_t & t_RekeyCapableTransition & option t_RekeyCapableEvent)
    (requires rekey_capable_state_is_sound t.f_driver) (ensures fun _ -> True) =
  match t.f_effect with
  | RekeyCapableEffect_Attest ->
      let (s', o) = f_attest #io_t #i s in
      let ev = RekeyCapableEvent_Attest o in
      (s', rekey_capable_step t.f_driver ev, Some ev)
  | RekeyCapableEffect_Complete | RekeyCapableEffect_Fail _ | RekeyCapableEffect_Idle -> (s, t, None)

let capable_turn (#io_t: Type0) {| i: t_RekeyCapableIo io_t |} (acc: io_t & t_RekeyCapableTransition)
  : (io_t & t_RekeyCapableTransition) =
  let (s, t) = acc in
  if rekey_capable_state_is_sound t.f_driver
  then let (s', t', _) = capable_turn_ev #io_t #i s t in (s', t')
  else acc

let rec capable_iter (#io_t: Type0) {| i: t_RekeyCapableIo io_t |} (n: nat)
  (acc: io_t & t_RekeyCapableTransition) : Tot (io_t & t_RekeyCapableTransition) (decreases n) =
  if n = 0 then acc else capable_iter #io_t #i (n - 1) (capable_turn #io_t #i acc)

let cons_opt_capable (o: option t_RekeyCapableEvent) (evs: list t_RekeyCapableEvent) : list t_RekeyCapableEvent =
  match o with | None -> evs | Some ev -> ev :: evs

let rec capable_run_ev (#io_t: Type0) {| i: t_RekeyCapableIo io_t |} (n: nat) (s: io_t)
  (t: t_RekeyCapableTransition)
  : Pure (io_t & t_RekeyCapableTransition & list t_RekeyCapableEvent)
    (requires capable_sound t) (ensures fun (_, t', _) -> capable_sound t') (decreases n) =
  if n = 0 then (s, t, [])
  else
    let (s1, t1, o) = capable_turn_ev #io_t #i s t in
    let (s2, t2, evs) = capable_run_ev #io_t #i (n - 1) s1 t1 in
    (s2, t2, cons_opt_capable o evs)

let rec capable_fold_range_is_iter_turn (#io_t: Type0) {| i: t_RekeyCapableIo io_t |}
  (n: nat) (start end_: usize)
  (inv: (io_t & t_RekeyCapableTransition) -> (k: usize{Rust_primitives.Hax.Folds.fold_range_wf_index start end_ false (v k)}) -> Type0)
  (init: (io_t & t_RekeyCapableTransition){~(Rust_primitives.Hax.Folds.range_empty start end_) ==> inv init start})
  (f: (acc: (io_t & t_RekeyCapableTransition) ->
       k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k} ->
       acc': (io_t & t_RekeyCapableTransition){inv acc' (mk_int (v k + 1))}))
  : Lemma
    (requires (v start <= v end_ /\ n = v end_ - v start /\
               (forall (acc: (io_t & t_RekeyCapableTransition))
                  (k: usize{v k <= v end_ /\ Rust_primitives.Hax.Folds.fold_range_wf_index start end_ true (v k) /\ inv acc k}).
                  f acc k == capable_turn #io_t #i acc)))
    (ensures (Rust_primitives.Hax.Folds.fold_range start end_ inv init f == capable_iter #io_t #i n init))
    (decreases n)
    [SMTPat (Rust_primitives.Hax.Folds.fold_range start end_ inv init f);
     SMTPat (capable_iter #io_t #i n init)] =
  if v start < v end_
  then capable_fold_range_is_iter_turn #io_t #i (n - 1) (start +! mk_int 1) end_ inv (f init start) f
  else ()

let rec capable_iter_is_run_ev (#io_t: Type0) {| i: t_RekeyCapableIo io_t |} (n: nat) (s: io_t)
  (t: t_RekeyCapableTransition)
  : Lemma (requires capable_sound t)
          (ensures (let (s2, t2, _) = capable_run_ev #io_t #i n s t in capable_iter #io_t #i n (s, t) == (s2, t2)))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, _) = capable_turn_ev #io_t #i s t in
    capable_iter_is_run_ev #io_t #i (n - 1) s1 t1
  end

let run_rekey_capable_is_run_ev (#io_t: Type0) {| i: t_RekeyCapableIo io_t |} (s: io_t)
  (request: t_RekeyCapableRequest)
  : Lemma (let (s2, t2, _) = capable_run_ev #io_t #i 1 s (begin_rekey_capable request) in
           run_rekey_capable #io_t #i s request == (s2, t2)) =
  let t0 = begin_rekey_capable request in
  capable_iter_is_run_ev #io_t #i 1 s t0;
  assert (v v_REKEY_CAPABLE_MAX_EFFECTS = 1);
  assert (run_rekey_capable #io_t #i s request == capable_iter #io_t #i 1 (s, t0))

/// Cancellation (`POST /device/rekey-capable`): the handler future may be dropped after any
/// executor call, so the loop stops after an arbitrary prefix of turns. Every
/// such prefix, for every executor and every `k`, ends in a sound driver
/// state whose next effect agrees with it.
let rekey_capable_cancellation (#io_t: Type0) {| i: t_RekeyCapableIo io_t |} (k: nat) (s: io_t)
  (t: t_RekeyCapableTransition)
  : Lemma (requires capable_sound t)
          (ensures (let (_, t2) = capable_iter #io_t #i k (s, t) in capable_sound t2)) =
  capable_iter_is_run_ev #io_t #i k s t

let rec capable_responds (t: t_RekeyCapableTransition) (evs: list t_RekeyCapableEvent)
  : Pure bool (requires capable_sound t) (ensures fun _ -> True) (decreases evs) =
  match evs with
  | [] -> true
  | ev :: rest ->
      not (capable_terminal t.f_effect) && capable_responds_to t.f_effect ev &&
      capable_responds (rekey_capable_step t.f_driver ev) rest

let rec capable_run_ev_follows (#io_t: Type0) {| i: t_RekeyCapableIo io_t |} (n: nat) (s: io_t)
  (t: t_RekeyCapableTransition)
  : Lemma (requires capable_sound t)
          (ensures (let (_, t2, evs) = capable_run_ev #io_t #i n s t in
                    rekey_capable_state_is_sound t.f_driver /\
                    capable_responds t evs /\
                    t2.f_driver == capable_run t.f_driver evs))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, o) = capable_turn_ev #io_t #i s t in
    capable_run_ev_follows #io_t #i (n - 1) s1 t1;
    match o with | None -> () | Some ev -> capable_step_sound t.f_driver ev
  end

let capable_remaining (e: t_RekeyCapableEffect) : nat =
  match e with
  | RekeyCapableEffect_Attest -> 1
  | RekeyCapableEffect_Complete | RekeyCapableEffect_Fail _ | RekeyCapableEffect_Idle -> 0

let capable_step_decreases (t: t_RekeyCapableTransition) (ev: t_RekeyCapableEvent)
  : Lemma (requires capable_sound t /\ not (capable_terminal t.f_effect) /\ capable_responds_to t.f_effect ev)
          (ensures capable_remaining (rekey_capable_step t.f_driver ev).f_effect < capable_remaining t.f_effect) =
  match t.f_effect <: t_RekeyCapableEffect with
  | RekeyCapableEffect_Attest -> ()
  | _ -> ()

let rec capable_run_reaches_verdict (#io_t: Type0) {| i: t_RekeyCapableIo io_t |} (n: nat) (s: io_t)
  (t: t_RekeyCapableTransition)
  : Lemma (requires capable_sound t /\ capable_remaining t.f_effect <= n)
          (ensures (let (_, t2, _) = capable_run_ev #io_t #i n s t in capable_terminal t2.f_effect))
          (decreases n) =
  if n = 0 then () else begin
    let (s1, t1, o) = capable_turn_ev #io_t #i s t in
    (match o with | None -> () | Some ev -> capable_step_decreases t ev);
    capable_run_reaches_verdict #io_t #i (n - 1) s1 t1
  end

let run_rekey_capable_theorem (#io_t: Type0) {| i: t_RekeyCapableIo io_t |} (s: io_t)
  (request: t_RekeyCapableRequest)
  : Lemma (let (_, t) = run_rekey_capable #io_t #i s request in
           exists (evs: list t_RekeyCapableEvent).
             capable_responds (begin_rekey_capable request) evs /\
             t.f_driver == capable_run_from request evs /\
             capable_terminal t.f_effect /\
             (let d = t.f_driver in
              rekey_capable_state_is_sound d /\
              (d.f_responded ==> d.f_attested) /\
              (d.f_attested ==> (d.f_authenticated && d.f_device_scope)))) =
  let t0 = begin_rekey_capable request in
  run_rekey_capable_is_run_ev #io_t #i s request;
  capable_run_ev_follows #io_t #i 1 s t0;
  capable_run_reaches_verdict #io_t #i 1 s t0;
  let (_, _, evs) = capable_run_ev #io_t #i 1 s t0 in
  capable_theorem request evs
