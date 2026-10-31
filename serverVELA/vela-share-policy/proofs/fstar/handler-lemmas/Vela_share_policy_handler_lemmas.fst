module Vela_share_policy_handler_lemmas

/// F-1 wave 2: the I/O a share/send handler runs *outside* an executor method.
///
/// For every starting database and every fault point, each of these reads,
/// sweeps and rate limiters is proved honest: the extracted `plan_*` carries the
/// caller's request byte for byte, the extracted `classify_*` reports exactly
/// what the statement did, a read observation is the stored rows' truth, and a
/// failed statement changes nothing.

open FStar.Mul
open Core_models
open Vela_share_policy.Store
open Vela_share_policy_store_model

module L = FStar.List.Tot
module SP = FStar.Seq.Properties

/// The empty string as the extracted `String` type.
let empty_text : text = Alloc.String.impl_String__new ()

// ── Outcome slices ─────────────────────────────────────────────────────────

/// The slice a classifier reads is the outcome list, element by element.
let seq_of_list_index_handler (l: list t_HandlerOutcome)
  : Lemma (forall (i: nat). i < L.length l ==> Seq.index (Seq.seq_of_list l) i == L.index l i) =
  let aux (i: nat) : Lemma (i < L.length l ==> Seq.index (Seq.seq_of_list l) i == L.index l i) =
    if i < L.length l then SP.lemma_seq_of_list_index l i
  in
  FStar.Classical.forall_intro aux

/// The slice's length is the list's length.
let slice_handler_len (l: list t_HandlerOutcome{L.length l <= Rust_primitives.Integers.max_usize})
  : Lemma (Core_models.Slice.impl__len (slice_of l) == mk_usize (L.length l)) = ()

/// The same for a rate limiter's outcomes.
let slice_rate_len (l: list t_RateOutcome{L.length l <= Rust_primitives.Integers.max_usize})
  : Lemma (Core_models.Slice.impl__len (slice_of l) == mk_usize (L.length l)) = ()

// ── Filters and membership ────────────────────────────────────────────────

/// A filtered list holds exactly the elements that pass the predicate.
let mem_filter_b (#a: eqtype) (f: a -> Tot bool) (l: list a) (x: a)
  : Lemma (L.mem x (L.filter f l) = (f x && L.mem x l)) =
  L.mem_filter f l x

/// A non-empty stored share key, as a `bool` over the model's option.
let ek_present_b (cell: option text) : bool =
  match cell with
  | Some ek -> not (ek = empty_text)
  | None -> false

// ── `post_send`'s recipient gate ──────────────────────────────────────────

/// What `users[recipient]` says about receiving a share.
let ek_truth (d: db) (user: text) : prop =
  match d.users user with
  | Some u -> b2t (ek_present_b u.us_share_ek)
  | None -> False

/// `observe` for the recipient gate equals the stored row's truth; a failed
/// read cannot receive.
let recipient_probe_is_honest (d: db) (recipient: text) (f: option nat)
  : Lemma
    (let o = recipient_probe d recipient f in
     (o.f_failed = true <==> faulted f 0) /\
     (not (faulted f 0) ==> (o.f_can_receive = true <==> ek_truth d recipient)))
  = ()

/// The recipient gate admits only a stored, non-empty share key.
let probe_admits_only_a_nonempty_share_ek (d: db) (recipient: text) (f: option nat)
  : Lemma
    ((recipient_probe d recipient f).f_can_receive = true ==>
       (ek_truth d recipient /\
        (match d.users recipient with
         | Some u -> Some? u.us_share_ek
         | None -> False)))
  = recipient_probe_is_honest d recipient f

// ── `get_recipient_ek` ────────────────────────────────────────────────────

/// The published key is the stored one unless it is absent or empty.
let recipient_ek_is_honest (d: db) (user: text) (f: option nat)
  : Lemma
    (let o = recipient_ek_read d user f in
     (o.f_failed = true <==> faulted f 0) /\
     (not (faulted f 0) ==>
        (o.f_share_ek ==
          (match d.users user with
           | Some u ->
             (match u.us_share_ek with
              | Some ek -> if ek = empty_text then Core_models.Option.Option_None
                           else Core_models.Option.Option_Some ek
              | None -> Core_models.Option.Option_None)
           | None -> Core_models.Option.Option_None)) /\
        (o.f_signed_at ==
          (match d.users user with
           | Some u -> to_opt u.us_share_ek_since
           | None -> Core_models.Option.Option_None))))
  = ()

// ── `get_inbox`'s cursor ──────────────────────────────────────────────────

/// The cursor observation is the caller's own inbox row's timestamp; another
/// recipient's row and a missing row are both absent; a failed read is failed.
let inbox_cursor_is_honest (d: db) (id recipient: text) (f: option nat)
  : Lemma
    (let o = inbox_cursor_read d id recipient f in
     (o.f_failed = true <==> faulted f 0) /\
     (not (faulted f 0) ==>
        (o.f_absent = true <==>
           (match d.inbox id with
            | Some r -> not (r.ib_recipient = recipient)
            | None -> True)) /\
        (o.f_created_at ==
           (match d.inbox id with
            | Some r ->
              if r.ib_recipient = recipient
              then Core_models.Option.Option_Some r.ib_created_at
              else Core_models.Option.Option_None
            | None -> Core_models.Option.Option_None))))
  = ()

// ── Vectors shared with `store_model.rs::tests::handler_vectors` ──────────

let s (x: string) : text = Alloc.String.String x

let vector_item2 : item =
  { it_sender = s "a"; it_recipient = s "b"; it_capsule = s "c";
    it_created_at = s "t0"; it_updated_at = s "t0"; it_revoked = mk_i64 0 }

let vector_inbox2 : inbox_row =
  { ib_sender = s "a"; ib_recipient = s "b"; ib_capsule = s "cc"; ib_created_at = s "t0" }

let vector_user2 : user_row =
  { us_share_ek = Some (s "ek"); us_share_ek_since = Some (s "t0");
    us_share_ek_device_id = None }


let vector_send2 : send_row =
  { sd_owner = s "a"; sd_ciphertext = s "ct"; sd_has_passphrase = mk_i64 0;
    sd_kdf_salt = Core_models.Option.Option_None;
    sd_label = Core_models.Option.Option_None;
    sd_view_once = mk_i64 0;
    sd_max_views = Core_models.Option.Option_None;
    sd_view_count = mk_i64 0;
    sd_created_at = s "t0"; sd_expires_at = s "t9"; sd_revoked = mk_i64 0 }

let vector_db2 : db =
  {
    items = (fun k -> if k = s "i" then Some vector_item2 else None);
    inbox = (fun k -> if k = s "m" then Some vector_inbox2 else None);
    users = (fun k -> if k = s "u" then Some vector_user2 else None);
    devices = (fun _ -> None);
    sends = (fun k -> if k = s "l" then Some vector_send2 else None);
    item_ids = [s "i"];
    inbox_ids = [s "m"];
    send_ids = [s "l"];
    clock = (fun (a b: text) -> false)
  }

let vector_recipient_probe ()
  : Lemma
    ((recipient_probe vector_db2 (s "u") None).f_can_receive = true /\
     (recipient_probe vector_db2 (s "w") None).f_can_receive = false /\
     (recipient_probe vector_db2 (s "u") (Some 0)).f_failed = true)
  = recipient_probe_is_honest vector_db2 (s "u") None;
    recipient_probe_is_honest vector_db2 (s "w") None;
    recipient_probe_is_honest vector_db2 (s "u") (Some 0)

let vector_inbox_cursor ()
  : Lemma
    (let o = inbox_cursor_read vector_db2 (s "m") (s "b") None in
     o.f_absent = false /\ o.f_created_at == Core_models.Option.Option_Some (s "t0") /\
     (inbox_cursor_read vector_db2 (s "m") (s "a") None).f_absent = true)
  = inbox_cursor_is_honest vector_db2 (s "m") (s "b") None;
    inbox_cursor_is_honest vector_db2 (s "m") (s "a") None

// ── The send admission ────────────────────────────────────────────────────

/// No statement among the first `n` is the injected failure.
let no_fault_in (f: option nat) (n: nat) : bool =
  match f with
  | None -> true
  | Some k -> k >= n

/// A quota count as the classifier carries it.
let nat_i64_is_mk (n: nat{n <= maxint I64}) : Lemma (nat_i64 n == mk_i64 n) = ()
let nat_u64_is_mk (n: nat{n <= maxint U64}) : Lemma (nat_u64 n == mk_u64 n) = ()

/// The admission plan's four statements, in the order the handler runs them.
let admission_plan (recipient sender: text)
  : Lemma
    (stmts_of_handler (plan_send_admission recipient sender) ==
     [HandlerStmt_Begin;
      HandlerStmt_CountInbox { f_recipient = recipient };
      HandlerStmt_SumPairBytes { f_recipient = recipient; f_sender = sender };
      HandlerStmt_SumRecipientBytes { f_recipient = recipient }])
  = ()

#push-options "--fuel 4 --ifuel 2"
/// What the admission plan returns for each fault: the begin and the three
/// reads run in order, and the first failure stops the run.
let admission_outcomes (d: db) (recipient sender: text) (f: option nat)
  : Lemma
    (run_handler d (stmts_of_handler (plan_send_admission recipient sender)) 0 f ==
     (match f with
      | None ->
        [HandlerOutcome_Ran;
         HandlerOutcome_Number (Core_models.Option.Option_Some (nat_i64 (inbox_count d recipient)));
         HandlerOutcome_Number (Core_models.Option.Option_Some (nat_i64 (inbox_pair_bytes d recipient sender)));
         HandlerOutcome_Number (Core_models.Option.Option_Some (nat_i64 (inbox_total_bytes d recipient)))]
      | Some 0 -> [HandlerOutcome_Failed]
      | Some 1 -> [HandlerOutcome_Ran; HandlerOutcome_Failed]
      | Some 2 ->
        [HandlerOutcome_Ran;
         HandlerOutcome_Number (Core_models.Option.Option_Some (nat_i64 (inbox_count d recipient)));
         HandlerOutcome_Failed]
      | Some 3 ->
        [HandlerOutcome_Ran;
         HandlerOutcome_Number (Core_models.Option.Option_Some (nat_i64 (inbox_count d recipient)));
         HandlerOutcome_Number (Core_models.Option.Option_Some (nat_i64 (inbox_pair_bytes d recipient sender)));
         HandlerOutcome_Failed]
      | Some _ ->
        [HandlerOutcome_Ran;
         HandlerOutcome_Number (Core_models.Option.Option_Some (nat_i64 (inbox_count d recipient)));
         HandlerOutcome_Number (Core_models.Option.Option_Some (nat_i64 (inbox_pair_bytes d recipient sender)));
         HandlerOutcome_Number (Core_models.Option.Option_Some (nat_i64 (inbox_total_bytes d recipient)))]))
  = admission_plan recipient sender
#pop-options

#push-options "--fuel 4 --ifuel 2"
/// The admission's three quota facts are the inbox's truth, and the observation
/// names the step that failed; none of the four statements publishes anything.
let send_admission_is_honest
      (d: db) (recipient sender: text) (f: option nat)
  : Lemma
    (requires
      inbox_count d recipient <= maxint I64 /\
      inbox_pair_bytes d recipient sender <= maxint I64 /\
      inbox_total_bytes d recipient <= maxint I64)
    (ensures
      (let o = send_admission d recipient sender f in
       (o.f_stage = AdmissionStage_Ready <==> no_fault_in f 4) /\
       (o.f_stage = AdmissionStage_Ready ==>
          o.f_inbox_count == mk_i64 (inbox_count d recipient) /\
          o.f_pair_bytes == mk_i64 (inbox_pair_bytes d recipient sender) /\
          o.f_total_bytes == mk_i64 (inbox_total_bytes d recipient)) /\
       (faulted f 0 ==> o.f_stage = AdmissionStage_Begin) /\
       (faulted f 1 ==> o.f_stage = AdmissionStage_Count) /\
       (faulted f 2 ==>
          o.f_stage = AdmissionStage_Pair /\
          o.f_inbox_count == mk_i64 (inbox_count d recipient)) /\
       (faulted f 3 ==>
          o.f_stage = AdmissionStage_Total /\
          o.f_inbox_count == mk_i64 (inbox_count d recipient) /\
          o.f_pair_bytes == mk_i64 (inbox_pair_bytes d recipient sender))))
  = admission_outcomes d recipient sender f;
    nat_i64_is_mk (inbox_count d recipient);
    nat_i64_is_mk (inbox_pair_bytes d recipient sender);
    nat_i64_is_mk (inbox_total_bytes d recipient)
#pop-options

/// The driver's quota decision reads the recipient's true pending inbox size:
/// `post_send` hands the verified driver exactly the bytes the inbox holds.
let admission_reports_the_true_inbox_bytes
      (d: db) (recipient sender: text) (f: option nat)
  : Lemma
    (requires
      tables_wf d /\
      inbox_total_bytes d recipient <= maxint I64 /\
      inbox_count d recipient <= maxint I64 /\
      inbox_pair_bytes d recipient sender <= maxint I64)
    (ensures
      (send_admission d recipient sender f).f_stage = AdmissionStage_Ready ==>
        (send_admission d recipient sender f).f_total_bytes
          == mk_i64 (inbox_total_bytes d recipient))
  = send_admission_is_honest d recipient sender f

// ── `get_inbox`'s page ────────────────────────────────────────────────────

/// The plan carries the caller's request, and its rows are exactly the
/// caller's older, unrevoked inbox rows.
let inbox_page_plan_facts
      (d: db) (caller: text) (before: Core_models.Option.t_Option text) (limit: usize)
  : Lemma
    (requires tables_wf d)
    (ensures
      (let stmt = plan_inbox_page caller before limit in
       let spec = inbox_page_spec_of d caller before in
       (match stmt with
        | HandlerStmt_SelectInboxPage
          { f_recipient = recipient; f_before = cursor; f_limit = page } ->
          recipient == caller /\ cursor == before /\ page == limit
        | _ -> False) /\
       inbox_page_spec d stmt == spec /\
       (forall (k: text).
          L.mem k spec = (inbox_page_row_ok d caller before k && L.mem k d.inbox_ids)) /\
       (forall (k: text).
          inbox_page_row_ok d caller before k = true ==> L.mem k spec = true)))
  = ()

#push-options "--fuel 4 --ifuel 2"
/// A page holding `returned` rows keeps at most the page size, reports whether
/// the read returned more, and exposes only the spec's rows.
let pagination_is_honest
      (spec got: list text) (returned: usize)
      (fetch_limit: usize) (limit: usize) (failed: bool)
  : Lemma
    (requires
      v returned == L.length got /\
      (failed = false ==> page_of spec got fetch_limit))
    (ensures
      (let o = classify_listing returned failed limit in
       (failed = true ==> o.f_failed = true /\ o.f_keep == mk_usize 0) /\
       (failed = false ==>
          o.f_failed = false /\
          (o.f_has_more = true <==> L.length got > v limit) /\
          o.f_keep == (if L.length got > v limit then limit else returned) /\
          (forall (k: text). L.mem k got = true ==> L.mem k spec = true) /\
          (L.length spec <= v fetch_limit ==>
             (forall (k: text). L.mem k spec = true ==> L.mem k got = true)))))
  = ()

/// `get_inbox`'s page: the plan carries the caller's cursor and the query's
/// limit, the model's rows are the caller's own unrevoked items, and the
/// classified page (whose size is the caller's, one less than the query's) is
/// exact.
let inbox_page_is_honest
      (d: db) (caller: text) (before: Core_models.Option.t_Option text)
      (fetch_limit: usize) (limit: usize)
      (got: list text) (returned: usize) (failed: bool)
  : Lemma
    (requires
      tables_wf d /\
      v returned == L.length got /\
      (failed = false ==>
         page_of (inbox_page_spec_of d caller before) got fetch_limit))
    (ensures
      (let stmt = plan_inbox_page caller before fetch_limit in
       let spec = inbox_page_spec_of d caller before in
       inbox_page_spec d stmt == spec /\
       (match stmt with
        | HandlerStmt_SelectInboxPage
          { f_recipient = recipient; f_before = cursor; f_limit = page } ->
          recipient == caller /\ cursor == before /\ page == fetch_limit
        | _ -> False) /\
       (forall (k: text).
          inbox_page_row_ok d caller before k = true ==> L.mem k spec = true) /\
       (let o = classify_listing returned failed limit in
        (failed = true ==> o.f_failed = true /\ o.f_keep == mk_usize 0) /\
        (failed = false ==>
           page_of spec got fetch_limit /\
           o.f_failed = false /\
           (o.f_has_more = true <==> L.length got > v limit) /\
           o.f_keep == (if L.length got > v limit then limit else returned) /\
           (forall (k: text). L.mem k got = true ==> L.mem k spec = true) /\
           (L.length spec <= v fetch_limit ==>
              (forall (k: text). L.mem k spec = true ==> L.mem k got = true))))))
  = inbox_page_plan_facts d caller before fetch_limit;
    if failed
    then pagination_is_honest (inbox_page_spec_of d caller before) got returned fetch_limit limit true
    else pagination_is_honest (inbox_page_spec_of d caller before) got returned fetch_limit limit false
#pop-options

// ── `get_linked_items` ────────────────────────────────────────────────────

/// The linked-items listing's rows are exactly the caller's live linked items.
let linked_items_plan_facts (d: db) (caller: text) (limit: usize)
  : Lemma
    (requires tables_wf d)
    (ensures
      (let stmt = plan_linked_items caller limit in
       let spec = L.filter (linked_item_row_ok d caller) d.item_ids in
       (match stmt with
        | HandlerStmt_SelectSharedItems { f_user = user; f_limit = page } ->
          user == caller /\ page == limit
        | _ -> False) /\
       linked_item_spec d stmt == spec /\
       (forall (k: text).
          L.mem k spec = (linked_item_row_ok d caller k && L.mem k d.item_ids)) /\
       (forall (k: text). linked_item_row_ok d caller k = true ==> L.mem k spec = true)))
  = ()

#push-options "--fuel 4 --ifuel 2"
/// `get_linked_items`: the plan is the caller's request, the rows are exactly
/// the caller's live linked items, and the page is bounded.
let linked_items_are_the_store_truth
      (d: db) (caller: text) (limit: usize) (got: list text) (returned: usize) (failed: bool)
  : Lemma
    (requires
      tables_wf d /\
      v returned == L.length got /\
      (failed = false ==> page_of (L.filter (linked_item_row_ok d caller) d.item_ids) got limit))
    (ensures
      (let stmt = plan_linked_items caller limit in
       let spec = L.filter (linked_item_row_ok d caller) d.item_ids in
       linked_item_spec d stmt == spec /\
       (match stmt with
        | HandlerStmt_SelectSharedItems { f_user = user; f_limit = page } ->
          user == caller /\ page == limit
        | _ -> False) /\
       (forall (k: text). linked_item_row_ok d caller k = true ==> L.mem k spec = true) /\
       (let o = classify_listing returned failed limit in
        (failed = true ==> o.f_failed = true) /\
        (failed = false ==>
           page_of spec got limit /\
           o.f_failed = false /\
           (o.f_has_more = true <==> L.length got > v limit) /\
           o.f_keep == (if L.length got > v limit then limit else returned)))))
  = linked_items_plan_facts d caller limit;
    if failed
    then pagination_is_honest (L.filter (linked_item_row_ok d caller) d.item_ids) got returned limit limit true
    else pagination_is_honest (L.filter (linked_item_row_ok d caller) d.item_ids) got returned limit limit false

/// A linked item is live for its two parties only: it is unrevoked and the
/// caller is its sender or its recipient.
let linked_item_spec_is_live (d: db) (caller: text) (limit: usize)
  : Lemma
    (requires tables_wf d)
    (ensures
      (forall (k: text).
         L.mem k (linked_item_spec d (plan_linked_items caller limit)) = true ==>
           (match d.items k with
            | Some it ->
              it.it_revoked = mk_i64 0 /\ (it.it_sender = caller \/ it.it_recipient = caller)
            | None -> False)))
  = linked_items_plan_facts d caller limit

// ── `list_share_links` ────────────────────────────────────────────────────

/// The owner listing's rows are exactly the caller's live, unexpired links.
let own_sends_plan_facts (d: db) (caller now: text) (limit: usize)
  : Lemma
    (requires tables_wf d)
    (ensures
      (let stmt = plan_own_sends caller now limit in
       let spec = L.filter (own_send_row_ok d caller now) d.send_ids in
       (match stmt with
        | HandlerStmt_SelectOwnedSends { f_owner = owner; f_now = instant; f_limit = page } ->
          owner == caller /\ instant == now /\ page == limit
        | _ -> False) /\
       own_send_spec d stmt == spec /\
       (forall (k: text). L.mem k spec = (own_send_row_ok d caller now k && L.mem k d.send_ids)) /\
       (forall (k: text). own_send_row_ok d caller now k = true ==> L.mem k spec = true)))
  = ()

/// `list_share_links`: the plan carries the caller, the request instant and the
/// page size; the rows are exactly the caller's live, unexpired links.
let own_sends_are_the_store_truth
      (d: db) (caller now: text) (limit: usize) (got: list text) (returned: usize) (failed: bool)
  : Lemma
    (requires
      tables_wf d /\
      v returned == L.length got /\
      (failed = false ==> page_of (L.filter (own_send_row_ok d caller now) d.send_ids) got limit))
    (ensures
      (let stmt = plan_own_sends caller now limit in
       let spec = L.filter (own_send_row_ok d caller now) d.send_ids in
       own_send_spec d stmt == spec /\
       (match stmt with
        | HandlerStmt_SelectOwnedSends { f_owner = owner; f_now = instant; f_limit = page } ->
          owner == caller /\ instant == now /\ page == limit
        | _ -> False) /\
       (forall (k: text). own_send_row_ok d caller now k = true ==> L.mem k spec = true) /\
       (let o = classify_listing returned failed limit in
        (failed = true ==> o.f_failed = true) /\
        (failed = false ==>
           page_of spec got limit /\
           o.f_failed = false /\
           (o.f_has_more = true <==> L.length got > v limit) /\
           o.f_keep == (if L.length got > v limit then limit else returned)))))
  = own_sends_plan_facts d caller now limit;
    if failed
    then pagination_is_honest (L.filter (own_send_row_ok d caller now) d.send_ids) got returned limit limit true
    else pagination_is_honest (L.filter (own_send_row_ok d caller now) d.send_ids) got returned limit limit false

/// An owned send row is live for its owner: unrevoked and not yet expired.
let own_send_spec_is_live (d: db) (caller now: text) (limit: usize)
  : Lemma
    (requires tables_wf d)
    (ensures
      (forall (k: text).
         L.mem k (own_send_spec d (plan_own_sends caller now limit)) = true ==>
           (match d.sends k with
            | Some r ->
              r.sd_owner = caller /\ r.sd_revoked = mk_i64 0 /\ d.clock r.sd_expires_at now
            | None -> False)))
  = own_sends_plan_facts d caller now limit

// ── The two expiry sweeps ─────────────────────────────────────────────────

/// The inbox sweep deletes exactly the rows the cutoff names, reports how many
/// it deleted, and leaves every other table untouched; a failed sweep changes
/// nothing.
let inbox_sweep_is_honest (d: db) (cutoff: text) (f: option nat)
  : Lemma
    (requires L.length (inbox_expired d cutoff) <= maxint U64)
    (ensures
      (let (o, post) = inbox_sweep d cutoff f in
       let gone = inbox_expired d cutoff in
       (o.f_failed = true <==> faulted f 0) /\
       (o.f_purged == (if faulted f 0 then mk_u64 0 else mk_u64 (L.length gone))) /\
       (faulted f 0 ==> post == d) /\
       (not (faulted f 0) ==>
          (forall (k: text). L.mem k gone = true ==> post.inbox k == None) /\
          (forall (k: text). L.mem k gone = false ==> post.inbox k == d.inbox k) /\
          post.items == d.items /\ post.users == d.users /\
          post.devices == d.devices /\ post.sends == d.sends /\
          (forall (k: text).
             L.mem k gone = true <==>
               ((match d.inbox k with
                 | Some r -> d.clock cutoff r.ib_created_at
                 | None -> false) && L.mem k d.inbox_ids = true)))))
  = nat_u64_is_mk (L.length (inbox_expired d cutoff))

/// The one-off-link sweep deletes exactly the expired links, reports how many
/// it deleted, and leaves every other table untouched; a failure changes
/// nothing.
let sends_sweep_is_honest (d: db) (cutoff: text) (f: option nat)
  : Lemma
    (requires L.length (sends_expired d cutoff) <= maxint U64)
    (ensures
      (let (o, post) = sends_sweep d cutoff f in
       let gone = sends_expired d cutoff in
       (o.f_failed = true <==> faulted f 0) /\
       (o.f_purged == (if faulted f 0 then mk_u64 0 else mk_u64 (L.length gone))) /\
       (faulted f 0 ==> post == d) /\
       (not (faulted f 0) ==>
          (forall (k: text). L.mem k gone = true ==> post.sends k == None) /\
          (forall (k: text). L.mem k gone = false ==> post.sends k == d.sends k) /\
          post.items == d.items /\ post.inbox == d.inbox /\
          post.users == d.users /\ post.devices == d.devices /\
          (forall (k: text).
             L.mem k gone = true <==>
               ((match d.sends k with
                 | Some r -> d.clock cutoff r.sd_expires_at
                 | None -> false) && L.mem k d.send_ids = true)))))
  = nat_u64_is_mk (L.length (sends_expired d cutoff))

/// The inbox sweep deletes every expired row and nothing else, in store terms.
let inbox_sweep_deletes_only_expired (d: db) (cutoff: text) (f: option nat)
  : Lemma
    (requires tables_wf d /\ L.length (inbox_expired d cutoff) <= maxint U64)
    (ensures
      (not (faulted f 0) ==>
         (forall (k: text).
            (match d.inbox k with
             | Some r -> d.clock cutoff r.ib_created_at
             | None -> False) ==>
              (snd (inbox_sweep d cutoff f)).inbox k == None)))
  = inbox_sweep_is_honest d cutoff f

/// The one-off-link sweep deletes every expired link and nothing else.
let sends_sweep_deletes_only_expired (d: db) (cutoff: text) (f: option nat)
  : Lemma
    (requires tables_wf d /\ L.length (sends_expired d cutoff) <= maxint U64)
    (ensures
      (not (faulted f 0) ==>
         (forall (k: text).
            (match d.sends k with
             | Some r -> d.clock cutoff r.sd_expires_at
             | None -> False) ==>
              (snd (sends_sweep d cutoff f)).sends k == None)))
  = sends_sweep_is_honest d cutoff f

// ── The share/send rate limiters ──────────────────────────────────────────

/// A rate limiter allows the request exactly when its counter was below the
/// budget, records exactly one more request against its own key, and reports
/// failure when the store failed.
let rate_limit_is_honest (k: kv) (key: text) (limit: u64) (window_secs: i64) (f: option nat)
  : Lemma
    (requires k key + 1 <= maxint U64)
    (ensures
      (let (o, k') = rate_limit k key limit window_secs f in
       (o.f_failed = true <==> faulted f 0) /\
       (faulted f 0 ==> k' == k /\ o.f_count == mk_u64 0 /\ o.f_allowed = false) /\
       (not (faulted f 0) ==>
          k' key == k key + 1 /\
          (forall (other: text). not (other = key) ==> k' other == k other) /\
          o.f_count == mk_u64 (k key + 1) /\
          (o.f_allowed = true <==> k key < v limit))))
  = nat_u64_is_mk (k key + 1)
#pop-options

// ── Vectors shared with `store_model.rs::tests::handler_vectors` ──────────

/// One inbox row for the recipient with a two-character capsule.
#push-options "--fuel 4 --ifuel 2"
/// The vector database's modelled facts, proved once.
let vector_db2_facts ()
  : Lemma
    (tables_wf vector_db2 /\
     inbox_count vector_db2 (s "b") == 1 /\
     inbox_pair_bytes vector_db2 (s "b") (s "a") == 2 /\
     inbox_total_bytes vector_db2 (s "b") == 2 /\
     inbox_count vector_db2 (s "b") <= maxint I64 /\
     inbox_pair_bytes vector_db2 (s "b") (s "a") <= maxint I64 /\
     inbox_total_bytes vector_db2 (s "b") <= maxint I64)
  = assert_norm (capsule_text_len vector_inbox2 == 2);
    assert_norm (inbox_count vector_db2 (s "b") == 1);
    assert_norm (inbox_pair_bytes vector_db2 (s "b") (s "a") == 2);
    assert_norm (inbox_total_bytes vector_db2 (s "b") == 2);
    assert_norm (tables_wf vector_db2)

let vector_send_admission ()
  : Lemma
    (let o = send_admission vector_db2 (s "b") (s "a") None in
     o.f_stage = AdmissionStage_Ready /\
     o.f_inbox_count == mk_i64 1 /\
     o.f_pair_bytes == mk_i64 2 /\
     o.f_total_bytes == mk_i64 2)
  = vector_db2_facts ();
    send_admission_is_honest vector_db2 (s "b") (s "a") None

let vector_send_admission_begin_fault ()
  : Lemma
    (let o = send_admission vector_db2 (s "b") (s "a") (Some 0) in
     o.f_stage = AdmissionStage_Begin /\
     o.f_total_bytes == mk_i64 0)
  = vector_db2_facts ();
    send_admission_is_honest vector_db2 (s "b") (s "a") (Some 0)

let vector_inbox_sweep ()
  : Lemma
    (let (o, post) = inbox_sweep vector_db2 (s "t0") None in
     o.f_purged == mk_u64 0 /\
     post.inbox (s "m") == vector_db2.inbox (s "m") /\
     post.items == vector_db2.items)
  = inbox_sweep_is_honest vector_db2 (s "t5") None

let vector_rate_limit ()
  : Lemma
    (let (o, k') = rate_limit (fun _ -> 0) (s "rl") (mk_u64 120) (mk_i64 3600) None in
     o.f_allowed = true /\ o.f_count == mk_u64 1 /\ k' (s "rl") == 1)
  = rate_limit_is_honest (fun _ -> 0) (s "rl") (mk_u64 120) (mk_i64 3600) None
#pop-options
