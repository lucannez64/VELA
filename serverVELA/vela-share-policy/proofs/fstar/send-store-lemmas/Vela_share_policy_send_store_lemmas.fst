module Vela_share_policy_send_store_lemmas

/// F-1 for the one-off share-link executors: for every starting database and
/// every fault point, each `sends` executor's observation (the extracted
/// `classify_send_*` applied to what the extracted `plan_send_*` did in
/// `Vela_share_policy_store_model`) is the truth about the table.

open FStar.Mul
open Core_models
open Vela_share_policy.Store
open Vela_share_policy_store_model

module L = FStar.List.Tot
module SP = FStar.Seq.Properties
module SD = Vela_share_policy.Send_driver

// ── Outcome slices ─────────────────────────────────────────────────────────

/// The slice a classifier reads is the outcome list, element by element.
/// Nothing about the classifiers is restated here, so a changed classifier
/// fails the honesty theorems themselves.
let seq_of_list_facts (l: list t_WriteOutcome)
  : Lemma (forall (i: nat). i < L.length l ==> Seq.index (Seq.seq_of_list l) i == L.index l i) =
  let aux (i: nat) : Lemma (i < L.length l ==> Seq.index (Seq.seq_of_list l) i == L.index l i) =
    if i < L.length l then SP.lemma_seq_of_list_index l i
  in
  FStar.Classical.forall_intro aux

// ── The state a failed run must leave alone ────────────────────────────────

/// No statement among the first `n` is the injected failure.
let no_fault_in (f: option nat) (n: nat) : bool =
  match f with
  | None -> true
  | Some k -> k >= n

/// Only `sends[id]` may differ.
let sends_frame (d post: db) (id: text) : prop =
  (forall (k: text). k <> id ==> post.sends k == d.sends k) /\
  post.items == d.items /\
  post.inbox == d.inbox /\
  post.users == d.users /\
  post.devices == d.devices

/// The row an insert is meant to leave.
let send_row_created
      (owner ciphertext: text)
      (has_passphrase: bool)
      (kdf_salt label: Core_models.Option.t_Option text)
      (view_once: bool)
      (max_views: Core_models.Option.t_Option i64)
      (created_at expires_at: text)
  : send_row =
  {
    sd_owner = owner;
    sd_ciphertext = ciphertext;
    sd_has_passphrase = (if has_passphrase then mk_i64 1 else mk_i64 0);
    sd_kdf_salt = kdf_salt;
    sd_label = label;
    sd_view_once = (if view_once then mk_i64 1 else mk_i64 0);
    sd_max_views = max_views;
    sd_view_count = mk_i64 0;
    sd_created_at = created_at;
    sd_expires_at = expires_at;
    sd_revoked = mk_i64 0;
  }

/// The post-state holds exactly the intended fresh row and nothing else
/// changed.
let send_created (d post: db) (id: text) (row: send_row) : prop =
  post.sends id == Some row /\ sends_frame d post id

/// The consume's SQL guard, read off the starting state.
let consume_live (d: db) (id: text) (now: text) : bool =
  match d.sends id with
  | Some r -> send_live d r now
  | None -> false

/// Exactly one view was consumed from the starting row and nothing else
/// changed.
let send_bumped (d post: db) (id: text) : prop =
  (match d.sends id with
   | Some r -> post.sends id == Some ({ r with sd_view_count = r.sd_view_count +. mk_i64 1 })
   | None -> False) /\
  sends_frame d post id

/// The row belongs to `owner`.
let owned_by (d: db) (id owner: text) : bool =
  match d.sends id with
  | Some r -> r.sd_owner = owner
  | None -> false

// ── Create: CreateSendIo::insert_send ──────────────────────────────────────

#push-options "--fuel 4 --ifuel 2"
/// The create observation is the truth about the insert: it reports no
/// failure exactly when the id was fresh and no statement failed, and then
/// exactly the intended row was added; `failed` exactly when the unique
/// constraint or the injected failure hit, and then the table is unchanged.
let send_create_is_honest
      (d: db) (id owner ciphertext: text)
      (has_passphrase: bool)
      (kdf_salt label: Core_models.Option.t_Option text)
      (view_once: bool)
      (max_views: Core_models.Option.t_Option i64)
      (created_at expires_at: text)
      (f: option nat)
  : Lemma
    (let (obs, post) =
       send_create d id owner ciphertext has_passphrase kdf_salt label view_once
         max_views created_at expires_at f in
     let intended =
       send_row_created owner ciphertext has_passphrase kdf_salt label view_once
         max_views created_at expires_at in
     (obs.SD.f_failed == false <==> (None? (d.sends id) /\ no_fault_in f 1)) /\
     (obs.SD.f_failed == false ==> obs.SD.f_rows == mk_u64 1 /\ send_created d post id intended) /\
     (obs.SD.f_failed == false <==> (None? (d.sends id) /\ send_created d post id intended)) /\
     (obs.SD.f_failed == true ==> post == d)) =
  let r =
    run_send_auto d
      (stmts_of_send
        (plan_send_create id owner ciphertext has_passphrase kdf_salt label view_once
          max_views created_at expires_at))
      0 f
  in
  seq_of_list_facts (fst r)

// ── Consume: FetchSendIo::consume_view ─────────────────────────────────────

/// The consume observation is the truth about the guarded update: `Consumed`
/// exactly when the link was live at `now` and no statement failed, and then
/// exactly one view was consumed; `Unavailable` exactly when the guard did not
/// hold; `Error` exactly when the statement failed; every non-`Consumed` run
/// leaves the table unchanged.
let send_consume_is_honest (d: db) (id now: text) (f: option nat)
  : Lemma
    (let (obs, post) = send_consume d id now f in
     (obs == SD.ConsumeObservation_Consumed <==> (consume_live d id now /\ no_fault_in f 1)) /\
     (obs == SD.ConsumeObservation_Unavailable <==>
        (not (consume_live d id now) /\ no_fault_in f 1)) /\
     (obs == SD.ConsumeObservation_Error <==> faulted f 0) /\
     (obs == SD.ConsumeObservation_Consumed ==> send_bumped d post id) /\
     (obs == SD.ConsumeObservation_Consumed <==> (consume_live d id now /\ send_bumped d post id)) /\
     (obs =!= SD.ConsumeObservation_Consumed ==> post == d)) =
  let r = run_send_auto d (stmts_of_send (plan_send_consume id now)) 0 f in
  seq_of_list_facts (fst r)

// ── Remove: FetchSendIo::remove_fetched ────────────────────────────────────

/// The cleanup reports success exactly when its delete ran, and then no row
/// with that id is left; a failure leaves the table unchanged.
let send_remove_is_honest (d: db) (id: text) (f: option nat)
  : Lemma
    (let (obs, post) = send_remove d id f in
     (obs.SD.f_failed == false <==> no_fault_in f 1) /\
     (obs.SD.f_removed == false <==> obs.SD.f_failed == true) /\
     (obs.SD.f_failed == false ==> post.sends id == None /\ sends_frame d post id) /\
     (obs.SD.f_failed == true ==> post == d)) =
  let r = run_send_auto d (stmts_of_send (plan_send_remove id)) 0 f in
  seq_of_list_facts (fst r)

// ── Delete: DeleteSendIo::delete_link ──────────────────────────────────────

/// The owner-scoped delete reports the rows it changed: `rows` is exactly 1
/// when the caller owned the row and nothing failed, 0 otherwise; on a
/// reported delete only that row is gone, and on any other outcome the table
/// is unchanged. A stranger's delete never removes the row.
let send_delete_is_honest (d: db) (id owner: text) (f: option nat)
  : Lemma
    (let (obs, post) = send_delete d id owner f in
     (obs.SD.f_failed == false <==> no_fault_in f 1) /\
     (obs.SD.f_failed == false ==>
        obs.SD.f_rows == (if owned_by d id owner then mk_u64 1 else mk_u64 0)) /\
     (obs.SD.f_failed == false /\ owned_by d id owner ==>
        post.sends id == None /\ sends_frame d post id) /\
     (obs.SD.f_failed == false /\ not (owned_by d id owner) ==> post == d) /\
     (obs.SD.f_failed == true ==> post == d) /\
     (obs.SD.f_rows <> mk_u64 0 <==> (owned_by d id owner /\ no_fault_in f 1))) =
  let r = run_send_auto d (stmts_of_send (plan_send_delete id owner)) 0 f in
  seq_of_list_facts (fst r)

// ── Read: FetchSendIo::read_send ───────────────────────────────────────────

/// The read observation is the stored row's truth: a present row gives
/// `Payload` with the stored cells, `Missing` exactly when the row is absent,
/// `Unreadable` exactly when the query failed. Reads change nothing.
let send_read_is_honest (d: db) (id: text) (f: option nat)
  : Lemma
    (let obs = send_fetch_read d id f in
     if faulted f 0
     then
       obs.f_read == SD.ReadObservation_Unreadable /\
       obs.f_missing_cell == Core_models.Option.Option_None /\
       obs.f_ciphertext == Core_models.Option.Option_None /\
       obs.f_has_passphrase == false /\
       obs.f_kdf_salt == Core_models.Option.Option_None /\
       obs.f_view_once == false /\
       obs.f_max_views == Core_models.Option.Option_None /\
       obs.f_view_count == mk_i64 0 /\
       obs.f_expires_at == Core_models.Option.Option_None
     else
       (match d.sends id with
        | None ->
          obs.f_read == SD.ReadObservation_Missing /\
          obs.f_missing_cell == Core_models.Option.Option_None /\
          obs.f_ciphertext == Core_models.Option.Option_None /\
          obs.f_expires_at == Core_models.Option.Option_None
        | Some r ->
          obs.f_read == SD.ReadObservation_Payload
            ({ SD.f_view_once = (r.sd_view_once <> mk_i64 0) }) /\
          obs.f_missing_cell == Core_models.Option.Option_None /\
          obs.f_ciphertext == Core_models.Option.Option_Some r.sd_ciphertext /\
          obs.f_has_passphrase == (r.sd_has_passphrase <> mk_i64 0) /\
          obs.f_kdf_salt == r.sd_kdf_salt /\
          obs.f_view_once == (r.sd_view_once <> mk_i64 0) /\
          obs.f_max_views == r.sd_max_views /\
          obs.f_view_count == r.sd_view_count /\
          obs.f_expires_at == Core_models.Option.Option_Some r.sd_expires_at)) =
  ()
#pop-options

// ── Facts the one-off send-link driver relies on ───────────────────────────

/// A consumed view means the link was live at that moment and exactly one
/// view was consumed.
let consumed_views_are_live (d: db) (id now: text) (f: option nat)
  : Lemma
    (let (obs, post) = send_consume d id now f in
     obs == SD.ConsumeObservation_Consumed ==>
       (consume_live d id now /\ send_bumped d post id)) =
  send_consume_is_honest d id now f

/// `Unavailable` means the link was not live: absent, expired, exhausted or
/// revoked.
let unavailable_links_are_not_live (d: db) (id now: text) (f: option nat)
  : Lemma
    (let (obs, _) = send_consume d id now f in
     obs == SD.ConsumeObservation_Unavailable ==> not (consume_live d id now)) =
  send_consume_is_honest d id now f

/// A reported delete (`rows > 0`) means the caller owned the row and only it
/// was removed; a stranger's delete reports nothing and changes nothing.
let delete_reports_only_owner_rows (d: db) (id owner: text) (f: option nat)
  : Lemma
    (let (obs, post) = send_delete d id owner f in
     (obs.SD.f_rows <> mk_u64 0 ==> (owned_by d id owner /\ post.sends id == None)) /\
     (not (owned_by d id owner) ==> post == d)) =
  send_delete_is_honest d id owner f

/// `CompleteCreate` (no failure) means the row holds exactly the permit's
/// bounds, with no views consumed and unrevoked.
let create_writes_the_permit_bounds
      (d: db) (id owner ciphertext: text)
      (has_passphrase: bool)
      (kdf_salt label: Core_models.Option.t_Option text)
      (view_once: bool)
      (max_views: Core_models.Option.t_Option i64)
      (created_at expires_at: text)
      (f: option nat)
  : Lemma
    (let (obs, post) =
       send_create d id owner ciphertext has_passphrase kdf_salt label view_once
         max_views created_at expires_at f in
     obs.SD.f_failed == false ==>
       (obs.SD.f_rows == mk_u64 1 /\
        post.sends id ==
          Some (send_row_created owner ciphertext has_passphrase kdf_salt label
                  view_once max_views created_at expires_at))) =
  send_create_is_honest d id owner ciphertext has_passphrase kdf_salt label
    view_once max_views created_at expires_at f

/// A delivered payload is the stored row.
let fetch_read_delivers_the_stored_row (d: db) (id: text) (f: option nat)
  : Lemma
    (let obs = send_fetch_read d id f in
     (match obs.f_read with
      | SD.ReadObservation_Payload _ ->
        (match d.sends id with
         | Some r ->
           obs.f_ciphertext == Core_models.Option.Option_Some r.sd_ciphertext /\
           obs.f_view_count == r.sd_view_count /\
           obs.f_expires_at == Core_models.Option.Option_Some r.sd_expires_at
         | None -> False)
      | _ -> True)) =
  send_read_is_honest d id f

/// A successful view-once cleanup leaves no row with that id, and a second
/// cleanup still reports success and removes nothing.
let removal_is_final (d: db) (id: text) (f: option nat)
  : Lemma
    (let (obs, post) = send_remove d id f in
     obs.SD.f_failed == false ==>
       (post.sends id == None /\
        (let (obs', post') = send_remove post id f in
         obs'.SD.f_failed == false /\ post'.sends id == None))) =
  send_remove_is_honest d id f;
  let (_, post) = send_remove d id f in
  send_remove_is_honest post id f

// ── Vectors shared with `store_model.rs::tests::send_link_vectors` ─────────
//
// The model's expiry comparison is the `clock` parameter. The Rust mirror
// supplies SQLite's stored-text comparison; these vectors use the two
// constant orders so the same concrete runs are proved without one.

let s (x: string) : text = Alloc.String.String x

let clock_live (a b: text) : bool = true
let clock_expired (a b: text) : bool = false

let vector_link : send_row =
  {
    sd_owner = s "a";
    sd_ciphertext = s "ct";
    sd_has_passphrase = mk_i64 1;
    sd_kdf_salt = Core_models.Option.Option_Some (s "salt");
    sd_label = Core_models.Option.Option_None;
    sd_view_once = mk_i64 0;
    sd_max_views = Core_models.Option.Option_Some (mk_i64 3);
    sd_view_count = mk_i64 0;
    sd_created_at = s "t0";
    sd_expires_at = s "t9";
    sd_revoked = mk_i64 0;
  }

let vector_send_db (clock: text -> text -> bool) : db =
  {
    items = (fun _ -> None);
    inbox = (fun _ -> None);
    users = (fun _ -> None);
    devices = (fun _ -> None);
    sends = (fun (k: text) -> if k = s "l" then Some (vector_link <: send_row) else None);
    item_ids = [];
    inbox_ids = [];
    send_ids = [s "l"];
    clock = clock;
  }

let vector_send_link_create ()
  : Lemma
    (let (obs, post) =
       send_create (vector_send_db clock_live) (s "m") (s "a") (s "ct") true
         (Core_models.Option.Option_Some (s "salt"))
         Core_models.Option.Option_None false
         (Core_models.Option.Option_Some (mk_i64 3)) (s "t0") (s "t9") None in
     obs.SD.f_failed == false /\ obs.SD.f_rows == mk_u64 1 /\
     post.sends (s "m") ==
       Some (send_row_created (s "a") (s "ct") true
               (Core_models.Option.Option_Some (s "salt"))
               Core_models.Option.Option_None false
               (Core_models.Option.Option_Some (mk_i64 3)) (s "t0") (s "t9"))) =
  send_create_is_honest (vector_send_db clock_live) (s "m") (s "a") (s "ct") true
    (Core_models.Option.Option_Some (s "salt")) Core_models.Option.Option_None
    false (Core_models.Option.Option_Some (mk_i64 3)) (s "t0") (s "t9") None

let vector_send_link_duplicate ()
  : Lemma
    (let (obs, post) =
       send_create (vector_send_db clock_live) (s "l") (s "a") (s "ct") false
         Core_models.Option.Option_None Core_models.Option.Option_None false
         Core_models.Option.Option_None (s "t0") (s "t9") None in
     obs.SD.f_failed == true /\ post == vector_send_db clock_live) =
  send_create_is_honest (vector_send_db clock_live) (s "l") (s "a") (s "ct") false
    Core_models.Option.Option_None Core_models.Option.Option_None false
    Core_models.Option.Option_None (s "t0") (s "t9") None

let vector_send_link_consume ()
  : Lemma
    (let (obs, post) = send_consume (vector_send_db clock_live) (s "l") (s "t1") None in
     obs == SD.ConsumeObservation_Consumed /\
     post.sends (s "l") == Some ({ vector_link with sd_view_count = mk_i64 1 })) =
  send_consume_is_honest (vector_send_db clock_live) (s "l") (s "t1") None

let vector_send_link_expired ()
  : Lemma
    (let (obs, post) = send_consume (vector_send_db clock_expired) (s "l") (s "u0") None in
     obs == SD.ConsumeObservation_Unavailable /\ post == vector_send_db clock_expired) =
  send_consume_is_honest (vector_send_db clock_expired) (s "l") (s "u0") None

let vector_send_link_read ()
  : Lemma
    (let obs = send_fetch_read (vector_send_db clock_live) (s "l") None in
     obs.f_read == SD.ReadObservation_Payload ({ SD.f_view_once = false }) /\
     obs.f_ciphertext == Core_models.Option.Option_Some (s "ct") /\
     obs.f_view_count == mk_i64 0 /\
     obs.f_kdf_salt == Core_models.Option.Option_Some (s "salt") /\
     obs.f_missing_cell == Core_models.Option.Option_None) =
  send_read_is_honest (vector_send_db clock_live) (s "l") None

let vector_send_link_missing ()
  : Lemma
    (let obs = send_fetch_read (vector_send_db clock_live) (s "z") None in
     obs.f_read == SD.ReadObservation_Missing) =
  send_read_is_honest (vector_send_db clock_live) (s "z") None

let vector_send_link_remove ()
  : Lemma
    (let (obs, post) = send_remove (vector_send_db clock_live) (s "l") None in
     obs.SD.f_failed == false /\ post.sends (s "l") == None) =
  send_remove_is_honest (vector_send_db clock_live) (s "l") None

let vector_send_link_foreign ()
  : Lemma
    (let (obs, post) = send_delete (vector_send_db clock_live) (s "l") (s "b") None in
     obs.SD.f_rows == mk_u64 0 /\ post == vector_send_db clock_live) =
  send_delete_is_honest (vector_send_db clock_live) (s "l") (s "b") None

let vector_send_link_owner ()
  : Lemma
    (let (obs, post) = send_delete (vector_send_db clock_live) (s "l") (s "a") None in
     obs.SD.f_rows == mk_u64 1 /\ post.sends (s "l") == None) =
  send_delete_is_honest (vector_send_db clock_live) (s "l") (s "a") None
