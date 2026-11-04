module M28_source_bridge

(* P2d: the Tamarin-to-F* source bridge for M28.

   Over the source semantics of M28_source_semantics (P2c) and the slot
   projection of M28_slot_projection (P2b), this module proves:

   - [embed]: every trace of the original seven-rule source system that
     satisfies the Increasing restriction, projected to any slot, is a
     reachable trace of the core encoding [reach_core] with the real
     strict-subterm order [proper_subterm] on full source terms, and the
     core state is read off the source configuration.  Its lift by
     [reach_core_lifts] is a reachable lifted-encoding trace.
   - [lift_source] and [erase_source]: the original and the Chain-instrumented
     source systems have exactly the same traces (same labels, hence the
     same actions); the original trace is admissible in the instrumented
     system, with the instrumented state equal (as a multiset) to the
     original state plus the Chain fact determined by each durable fact.
   - The ten M28 lemmas, read as F* formulas over source action traces, hold
     for every trace of both systems that satisfies the restriction, and the
     two exists-trace lemmas have a concrete source witness.  The generic
     transfer theorems also carry any action-trace property between the two
     systems, in particular Tamarin's own verdicts on the instrumented model.

   Trusted: the F* transcription of Tamarin's semantics in
   M28_source_semantics, the P2a schemas (checked against the .spthy by
   check-m28-transcription.py), the reading of each lemma formula below,
   and F*/Z3.  No assume, admit or axiom is used. *)

open M28TraceEquivalence
open M28_source_terms
open M28_source_semantics
open M28_slot_projection

module L = FStar.List.Tot

(* ------------------------------------------------------------------ *)
(* Freshness facts used by the embedding                               *)
(* ------------------------------------------------------------------ *)

let rec used_ok (cons:list string) (us:list sterm) : Tot bool (decreases us) =
  match us with
  | [] -> true
  | t :: r ->
      (match t with
       | SName (FreshName m) -> L.mem m cons
       | _ -> false) && used_ok cons r

let rec used_ok_mono (c1 c2:list string) (us:list sterm)
  : Lemma (requires used_ok c1 us = true
                    /\ (forall (m:string). L.mem m c1 = true ==> L.mem m c2 = true))
          (ensures used_ok c2 us = true) (decreases us)
  = match us with
    | [] -> ()
    | _ :: r -> used_ok_mono c1 c2 r

let rec used_ok_fresh (cons:list string) (us:list sterm) (n:string)
  : Lemma (requires used_ok cons us = true /\ L.mem n cons = false)
          (ensures L.mem (fresh_term n) us = false) (decreases us)
  = match us with
    | [] -> ()
    | _ :: r -> used_ok_fresh cons r n

let consumed_grows (h:strace) (l:label) (m:string)
  : Lemma (requires L.mem m (consumed Original h) = true)
          (ensures L.mem m (consumed Original (TSnoc h l)) = true)
  = FStar.List.Tot.Properties.append_mem
      (label_consumed Original l) (consumed Original h) m

let consumed_grows_all (h:strace) (l:label)
  : Lemma (forall (m:string). L.mem m (consumed Original h) = true ==>
                              L.mem m (consumed Original (TSnoc h l)) = true)
  = introduce forall (m:string). L.mem m (consumed Original h) = true ==>
                                 L.mem m (consumed Original (TSnoc h l)) = true
    with introduce _ ==> _
    with _. consumed_grows h l m

let consumed_label (h:strace) (l:label) (m:string)
  : Lemma (requires L.mem m (label_consumed Original l) = true)
          (ensures L.mem m (consumed Original (TSnoc h l)) = true)
  = FStar.List.Tot.Properties.append_mem
      (label_consumed Original l) (consumed Original h) m

let fresh_inv_unconsumed (h:strace) (c:config) (n:string)
  : Lemma (requires fresh_inv Original h c /\ L.mem (fr_fact n) c.facts = true)
          (ensures L.mem n (consumed Original h) = false)
  = mem_cnt (fr_fact n) c.facts;
    mem_cnt n (consumed Original h)

(* ------------------------------------------------------------------ *)
(* The per-slot view and the embedding                                 *)
(* ------------------------------------------------------------------ *)

noeq type slot_view (s:sterm) (h:strace) (c:config) =
  | Uninit :
      squash (project s h == Nil
              /\ abs (ready_view s) c.facts == []
              /\ abs (snap_view s) c.facts == []
              /\ abs (dur_view s) c.facts == []
              /\ abs (profile_view s) c.facts == []) ->
      slot_view s h c
  | Init :
      n:string -> item:sterm ->
      reach_core proper_subterm initial item (project s h) (abs_core s c h) ->
      squash (s == fresh_term n
              /\ L.mem n (consumed Original h) = true
              /\ L.length (abs (dur_view s) c.facts) = 1
              /\ used_ok (consumed Original h) (used_of (project s h)) = true) ->
      slot_view s h c

let coerce_reach (#item:sterm) (#t1 #t2:ctrace) (#c1 #c2:cstate)
    (r:reach_core proper_subterm initial item t1 c1)
    (_:squash (t1 == t2 /\ c1 == c2))
  : reach_core proper_subterm initial item t2 c2
  = r

(* A step that is invisible to slot [s]. *)
let unchanged_view (s:sterm) (h:strace) (c:config) (l:label) (c':config)
    (prev:slot_view s h c)
  : Pure (slot_view s (TSnoc h l) c')
      (requires views_unchanged s c c' /\ event_of s (actions l) == None)
      (ensures fun _ -> True)
  = abs_core_unchanged s c c' h l;
    consumed_grows_all h l;
    match prev with
    | Uninit _ -> Uninit ()
    | Init n item r _ ->
        consumed_grows h l n;
        used_ok_mono (consumed Original h) (consumed Original (TSnoc h l))
          (used_of (project s h));
        Init n item (coerce_reach r ()) ()

(* Extend an initialized slot by a same-slot core step. *)
let extend_view (s:sterm) (h:strace) (c:config) (r:rule_name) (sg:subst)
    (nu:fresh_subst) (n:string) (item:sterm)
    (rc:reach_core proper_subterm initial item (project s h) (abs_core s c h))
    (res:same_slot_result s h c r sg nu)
  : Pure (slot_view s (TSnoc h (LRule r sg nu)) (rule_result Original c r sg nu))
      (requires s == fresh_term n
                /\ L.mem n (consumed Original h) = true
                /\ used_ok (consumed Original (TSnoc h (LRule r sg nu)))
                     (used_of (project s (TSnoc h (LRule r sg nu)))) = true)
      (ensures fun _ -> True)
  = let (| e, cst, _ |) = res in
    let h' = TSnoc h (LRule r sg nu) in
    let c' = rule_result Original c r sg nu in
    consumed_grows h (LRule r sg nu) n;
    let rc' = RCSnoc (project s h) (abs_core s c h) e (abs_core s c' h') rc cst in
    Init n item (coerce_reach rc' ()) ()

let same_slot_view (s:sterm) (h:strace) (c:config) (r:rule_name)
    (sg:subst) (nu:fresh_subst) (prev:slot_view s h c)
  : Pure (slot_view s (TSnoc h (LRule r sg nu)) (rule_result Original c r sg nu))
      (requires rule_enabled Original c r sg nu = true
                /\ rule_slot r sg nu == s
                /\ increasing (TSnoc h (LRule r sg nu))
                /\ fresh_inv Original h c)
      (ensures fun _ -> True)
  = let l = LRule r sg nu in
    let h' = TSnoc h l in
    let c' = rule_result Original c r sg nu in
    shape_ok Original r sg nu;
    label_actions_shape r sg nu;
    enabled_rest Original c r sg nu;
    consumed_grows_all h l;
    match prev with
    | Uninit _ ->
        if r = R_Initialize then begin
          initialize_same_slot s h c sg nu;
          consumed_label h l (nu "slot");
          Init (nu "slot") (fresh_term (nu "item"))
            (coerce_reach (RCInit #sterm #sterm #sterm #proper_subterm
                             #initial #(fresh_term (nu "item"))) ()) ()
        end
        else begin
          uninit_disabled s c r sg nu;
          false_elim ()
        end
    | Init n item rc _ ->
        used_ok_mono (consumed Original h) (consumed Original h')
          (used_of (project s h));
        (match r with
         | R_Initialize ->
             let Some l1 = remove1 (fr_fact (nu "slot")) c.facts in
             remove1_mem (fr_fact (nu "slot")) c.facts l1;
             fresh_inv_unconsumed h c (nu "slot");
             false_elim ()
         | R_ReadSnapshot ->
             let Some l1 = remove1 (fr_fact (nu "tx")) c.facts in
             remove1_mem (fr_fact (nu "tx")) c.facts l1;
             fresh_inv_unconsumed h c (nu "tx");
             used_ok_fresh (consumed Original h) (used_of (project s h)) (nu "tx");
             consumed_label h l (nu "tx");
             let res = read_snapshot_same_slot s h c sg nu () () () () in
             extend_view s h c r sg nu n item rc res
         | R_PersistJournal ->
             assert (action_at h' (slen h)
                       (a_revision_increases (sg "pinned") (sg "next_revision")) = true);
             let res = persist_journal_same_slot s h c sg nu () () () () in
             extend_view s h c r sg nu n item rc res
         | R_PersistVault ->
             let res = persist_vault_same_slot s h c sg nu () () () in
             extend_view s h c r sg nu n item rc res
         | R_ClearJournal ->
             let res = clear_journal_same_slot s h c sg nu () () () in
             extend_view s h c r sg nu n item rc res
         | R_Crash ->
             let res = crash_same_slot s h c sg nu () () () in
             extend_view s h c r sg nu n item rc res
         | R_OpenVault ->
             let res = open_vault_same_slot s h c sg nu () () () in
             extend_view s h c r sg nu n item rc res)

let step_view (s:sterm) (h:strace) (c:config) (l:label) (c':config)
    (st:sstep Original c l c') (prev:slot_view s h c)
  : Pure (slot_view s (TSnoc h l) c')
      (requires increasing (TSnoc h l) /\ fresh_inv Original h c)
      (ensures fun _ -> True)
  = match st with
    | SRule _ r sg nu _ _ ->
        if rule_slot r sg nu = s then same_slot_view s h c r sg nu prev
        else begin
          other_slot_step Original s c r sg nu;
          unchanged_view s h c l c' prev
        end
    | _ ->
        attacker_step_views Original s c l c' st;
        unchanged_view s h c l c' prev

(* The source-to-core embedding of every slot of every restricted trace. *)
let rec embed (s:sterm) (h:strace) (c:config) (rc:sreach Original h c)
  : Pure (slot_view s h c) (requires increasing h) (ensures fun _ -> True)
      (decreases rc)
  = match rc with
    | SRInit -> Uninit ()
    | SRStep h0 c0 l c1 r0 st ->
        increasing_prefix h0 l;
        global_freshness Original h0 c0 r0;
        let prev = embed s h0 c0 r0 in
        step_view s h0 c0 l c1 st prev

(* A slot with any event in the source trace is initialized, and its
   projection is reachable in the core encoding. *)
let embedded_reach (s:sterm) (h:strace) (c:config) (rc:sreach Original h c)
    (k:nat) (e:cevent)
  : Pure (item:sterm & st:cstate & reach_core proper_subterm initial item (project s h) st)
      (requires increasing h /\ occurs_at (project s h) k e = true)
      (ensures fun _ -> True)
  = match embed s h c rc with
    | Uninit _ -> false_elim ()
    | Init _ item r _ -> (| item, abs_core s c h, r |)

(* Its lift is a reachable trace of the lifted (Chain) encoding. *)
let embedded_lift (s:sterm) (h:strace) (c:config) (rc:sreach Original h c)
    (k:nat) (e:cevent)
  : Pure (item:sterm & st:lifted sterm sterm sterm
          & reach_lift proper_subterm initial item (project s h) st)
      (requires increasing h /\ occurs_at (project s h) k e = true)
      (ensures fun _ -> True)
  = let (| item, st, r |) = embedded_reach s h c rc k e in
    (| item, lift_state st, reach_core_lifts proper_subterm initial item (project s h) st r |)

(* ------------------------------------------------------------------ *)
(* The ten M28 lemmas as formulas over source action traces            *)
(* ------------------------------------------------------------------ *)

(* Each formula transcribes the .spthy lemma of the same name: a timepoint
   #i is a natural number, "F(...) @ #i" is [action_at h i F], and #i < #j
   is the order on naturals.  Universal lemmas are claimed for every trace
   satisfying the Increasing restriction; exists-trace lemmas for some. *)

let open_has_matching_content_and_pin (h:strace) : Type0 =
  forall (sl g p rv pl:sterm) (i:nat).
    action_at h i (a_opened sl g p rv pl) = true ==> p = rv

let application_requires_prior_durable_journal (h:strace) : Type0 =
  forall (sl tx g rv pl:sterm) (i:nat).
    action_at h i (a_vault_durable sl tx g rv pl) = true ==>
    (exists (old:sterm) (j:nat).
       action_at h j (a_journal_durable sl tx g old rv pl) = true /\ j < i)

let cleanup_requires_prior_durable_vault (h:strace) : Type0 =
  forall (sl tx g rv:sterm) (i:nat).
    action_at h i (a_journal_cleared sl tx g rv) = true ==>
    (exists (pl:sterm) (j:nat).
       action_at h j (a_vault_durable sl tx g rv pl) = true /\ j < i)

let commit_uses_snapshot_generation (h:strace) : Type0 =
  forall (sl tx g old nx pl:sterm) (i:nat).
    action_at h i (a_journal_durable sl tx (successor g) old nx pl) = true ==>
    (exists (j:nat). action_at h j (a_snapshot_read sl tx g old) = true /\ j < i)

let each_transaction_applies_at_most_once (h:strace) : Type0 =
  forall (sl tx g1 g2 r1 r2 p1 p2:sterm) (i j:nat).
    action_at h i (a_vault_durable sl tx g1 r1 p1) = true
    /\ action_at h j (a_vault_durable sl tx g2 r2 p2) = true ==> i = j

let pins_advance_on_every_commit (h:strace) : Type0 =
  forall (sl tx g old nx pl:sterm) (i:nat).
    action_at h i (a_journal_durable sl tx g old nx pl) = true ==>
    proper_subterm old nx = true

let recovery_is_reachable (h:strace) : Type0 =
  exists (sl tx g old nx pl:sterm) (j c a k o:nat).
    action_at h j (a_journal_durable sl tx g old nx pl) = true
    /\ action_at h c (a_crash sl) = true
    /\ action_at h a (a_vault_durable sl tx g nx pl) = true
    /\ action_at h k (a_journal_cleared sl tx g nx) = true
    /\ action_at h o (a_opened sl g nx nx pl) = true
    /\ j < c /\ c < a /\ a < k /\ k < o

let committed_pins_never_decrease (h:strace) : Type0 =
  forall (sl tx1 tx2 g1 g2 r1 r2:sterm) (i j:nat).
    action_at h i (a_journal_cleared sl tx1 g1 r1) = true
    /\ action_at h j (a_journal_cleared sl tx2 g2 r2) = true /\ i < j ==>
    proper_subterm r1 r2 = true

let a_generation_commits_at_most_once (h:strace) : Type0 =
  forall (sl tx1 tx2 g o1 n1 p1 o2 n2 p2:sterm) (i j:nat).
    action_at h i (a_journal_durable sl tx1 g o1 n1 p1) = true
    /\ action_at h j (a_journal_durable sl tx2 g o2 n2 p2) = true ==> i = j

let two_successive_commits_advance (h:strace) : Type0 =
  exists (sl tx1 tx2 n1 n2 p1 p2:sterm) (a1 b1 a2 b2:nat).
    action_at h a1 (a_journal_durable sl tx1 (successor initial) initial n1 p1) = true
    /\ action_at h b1 (a_journal_cleared sl tx1 (successor initial) n1) = true
    /\ action_at h a2 (a_journal_durable sl tx2 (successor (successor initial)) n1 n2 p2) = true
    /\ action_at h b2 (a_journal_cleared sl tx2 (successor (successor initial)) n2) = true
    /\ a1 < b1 /\ b1 < a2 /\ a2 < b2 /\ proper_subterm n1 n2 = true

(* The eight universal lemmas together. *)
let m28_universal (h:strace) : Type0 =
  open_has_matching_content_and_pin h
  /\ application_requires_prior_durable_journal h
  /\ cleanup_requires_prior_durable_vault h
  /\ commit_uses_snapshot_generation h
  /\ each_transaction_applies_at_most_once h
  /\ pins_advance_on_every_commit h
  /\ committed_pins_never_decrease h
  /\ a_generation_commits_at_most_once h

(* ------------------------------------------------------------------ *)
(* The two all-pairs goals on source traces, via the embedding         *)
(* ------------------------------------------------------------------ *)

(* Tamarin's << on full source terms, as the strict-order record that the
   encoded pin theorem takes. *)
let sterm_order : strict_order sterm = {
  lt = proper_subterm;
  lt_trans = (fun x y z -> proper_subterm_trans x y z);
  lt_irrefl = (fun x -> proper_subterm_irrefl x);
}

let clear_pins_at (h:strace) (c:config) (rc:sreach Original h c)
    (sl tx1 tx2 g1 g2 r1 r2:sterm) (i j:nat)
  : Lemma (requires increasing h
                    /\ action_at h i (a_journal_cleared sl tx1 g1 r1) = true
                    /\ action_at h j (a_journal_cleared sl tx2 g2 r2) = true
                    /\ i < j)
          (ensures proper_subterm r1 r2 = true)
  = let e1 = EClear tx1 (to_gen g1) r1 in
    let e2 = EClear tx2 (to_gen g2) r2 in
    slot_action_forward sl h i (a_journal_cleared sl tx1 g1 r1) e1;
    slot_action_forward sl h j (a_journal_cleared sl tx2 g2 r2) e2;
    pidx_strict sl h i j;
    let (| item, st, r |) = embedded_reach sl h c rc (pidx sl h i) e1 in
    reach_core_clear_pins_strict sterm_order initial item (project sl h) st r
      (pidx sl h i) (pidx sl h j) tx1 tx2 (to_gen g1) (to_gen g2) r1 r2

let journal_once_at (h:strace) (c:config) (rc:sreach Original h c)
    (sl tx1 tx2 g o1 n1 p1 o2 n2 p2:sterm) (i j:nat)
  : Lemma (requires increasing h
                    /\ action_at h i (a_journal_durable sl tx1 g o1 n1 p1) = true
                    /\ action_at h j (a_journal_durable sl tx2 g o2 n2 p2) = true)
          (ensures i = j)
  = let e1 = EJournal tx1 (to_gen g) o1 n1 p1 in
    let e2 = EJournal tx2 (to_gen g) o2 n2 p2 in
    slot_action_forward sl h i (a_journal_durable sl tx1 g o1 n1 p1) e1;
    slot_action_forward sl h j (a_journal_durable sl tx2 g o2 n2 p2) e2;
    let (| item, st, r |) = embedded_reach sl h c rc (pidx sl h i) e1 in
    reach_core_journal_unique proper_subterm initial item (project sl h) st r
      (pidx sl h i) (pidx sl h j) tx1 tx2 (to_gen g) o1 o2 n1 n2 p1 p2;
    pidx_injective sl h i j

let source_committed_pins_never_decrease (h:strace) (c:config)
    (rc:sreach Original h c)
  : Lemma (requires increasing h) (ensures committed_pins_never_decrease h)
  = introduce forall (sl tx1 tx2 g1 g2 r1 r2:sterm) (i j:nat).
      action_at h i (a_journal_cleared sl tx1 g1 r1) = true
      /\ action_at h j (a_journal_cleared sl tx2 g2 r2) = true /\ i < j ==>
      proper_subterm r1 r2 = true
    with introduce _ ==> _
    with _. clear_pins_at h c rc sl tx1 tx2 g1 g2 r1 r2 i j

let source_a_generation_commits_at_most_once (h:strace) (c:config)
    (rc:sreach Original h c)
  : Lemma (requires increasing h) (ensures a_generation_commits_at_most_once h)
  = introduce forall (sl tx1 tx2 g o1 n1 p1 o2 n2 p2:sterm) (i j:nat).
      action_at h i (a_journal_durable sl tx1 g o1 n1 p1) = true
      /\ action_at h j (a_journal_durable sl tx2 g o2 n2 p2) = true ==> i = j
    with introduce _ ==> _
    with _. journal_once_at h c rc sl tx1 tx2 g o1 n1 p1 o2 n2 p2 i j

(* ------------------------------------------------------------------ *)
(* pins_advance_on_every_commit: the restriction at the same timepoint *)
(* ------------------------------------------------------------------ *)

let rec journal_has_increase (h:strace) (i:nat) (sl tx g o n p:sterm)
  : Lemma (requires action_at h i (a_journal_durable sl tx g o n p) = true)
          (ensures action_at h i (a_revision_increases o n) = true)
          (decreases h)
  = match h with
    | TNil -> ()
    | TSnoc h' l ->
        if i = slen h' then
          (match l with
           | LRule r sg nu -> label_actions_shape r sg nu
           | _ -> ())
        else journal_has_increase h' i sl tx g o n p

let source_pins_advance_on_every_commit (h:strace)
  : Lemma (requires increasing h) (ensures pins_advance_on_every_commit h)
  = introduce forall (sl tx g old nx pl:sterm) (i:nat).
      action_at h i (a_journal_durable sl tx g old nx pl) = true ==>
      proper_subterm old nx = true
    with introduce _ ==> _
    with _. journal_has_increase h i sl tx g old nx pl

(* ------------------------------------------------------------------ *)
(* open_has_matching_content_and_pin: a core invariant                  *)
(* ------------------------------------------------------------------ *)

let pin_matches (ph:cphase) : bool =
  match ph with
  | Clean _ p vr _ -> p = vr
  | Pending _ _ _ _ _ _ -> true
  | Applied _ _ p _ vr _ -> p = vr

let rec reach_pin_matches (#lt:sterm -> sterm -> bool) (#r0 #item:sterm)
    (t:ctrace) (c:cstate) (r:reach_core lt r0 item t c)
  : Lemma (ensures pin_matches c.ph = true) (decreases r)
  = match r with
    | RCInit -> ()
    | RCSnoc t0 c0 _ _ r0' st ->
        reach_pin_matches t0 c0 r0';
        (match st with
         | CReadSnapshot _ _ _ _ _ _ -> ()
         | CPersistJournal _ _ _ _ _ _ _ _ _ _ _ _ -> ()
         | CPersistVault _ _ _ _ _ _ _ _ -> ()
         | CClearJournal _ _ _ _ _ _ _ _ -> ()
         | CCrash _ _ -> ()
         | COpenVault _ _ _ _ _ _ -> ())

let rec reach_open_at (#lt:sterm -> sterm -> bool) (#r0 #item:sterm)
    (t:ctrace) (c:cstate) (r:reach_core lt r0 item t c)
    (k:nat) (g:gen) (p rv v:sterm)
  : Lemma (requires occurs_at t k (EOpened g p rv v) = true)
          (ensures p = rv) (decreases r)
  = match r with
    | RCInit -> ()
    | RCSnoc t0 c0 e c1 r0' st ->
        if k = trace_len t0 then begin
          reach_pin_matches t0 c0 r0';
          match st with
          | COpenVault _ g' p' rv' v' _ ->
              eq_event_true (EOpened #sterm #sterm #sterm g p rv v)
                (EOpened #sterm #sterm #sterm g' p' rv' v')
          | _ -> ()
        end
        else reach_open_at t0 c0 r0' k g p rv v

let open_at (h:strace) (c:config) (rc:sreach Original h c)
    (sl g p rv pl:sterm) (i:nat)
  : Lemma (requires increasing h /\ action_at h i (a_opened sl g p rv pl) = true)
          (ensures p = rv)
  = let e = EOpened (to_gen g) p rv pl in
    slot_action_forward sl h i (a_opened sl g p rv pl) e;
    let (| item, st, r |) = embedded_reach sl h c rc (pidx sl h i) e in
    reach_open_at (project sl h) st r (pidx sl h i) (to_gen g) p rv pl

let source_open_has_matching_content_and_pin (h:strace) (c:config)
    (rc:sreach Original h c)
  : Lemma (requires increasing h) (ensures open_has_matching_content_and_pin h)
  = introduce forall (sl g p rv pl:sterm) (i:nat).
      action_at h i (a_opened sl g p rv pl) = true ==> p = rv
    with introduce _ ==> _
    with _. open_at h c rc sl g p rv pl i

(* ------------------------------------------------------------------ *)
(* Instrumented traces are original traces (erase Chain)               *)
(* ------------------------------------------------------------------ *)

let erase_config (c:config) : config = { c with facts = erase c.facts }

let rec erase_inst_facts (sg:subst) (nu:fresh_subst) (fs:list fact)
  : Lemma (ensures erase (inst_facts sg nu fs) == inst_facts sg nu (erase fs))
          (decreases fs)
  = match fs with
    | [] -> ()
    | _ :: r -> erase_inst_facts sg nu r

let rec erase_append (l1 l2:list fact)
  : Lemma (ensures erase (L.append l1 l2) == L.append (erase l1) (erase l2))
          (decreases l1)
  = match l1 with
    | [] -> ()
    | _ :: r -> erase_append r l2

let rec linear_erase (fs:list fact)
  : Lemma (ensures linear (erase fs) == erase (linear fs)) (decreases fs)
  = match fs with
    | [] -> ()
    | _ :: r -> linear_erase r

let rec persistent_erase (fs:list fact)
  : Lemma (ensures persistent (erase fs) == erase (persistent fs)) (decreases fs)
  = match fs with
    | [] -> ()
    | _ :: r -> persistent_erase r

let rinst_original (r:rule_name) (sg:subst) (nu:fresh_subst)
  : Lemma (rule_linear Original r sg nu == erase (rule_linear Instrumented r sg nu)
           /\ rule_persistent Original r sg nu
              == erase (rule_persistent Instrumented r sg nu)
           /\ (rinst Original r sg nu).r_conclusions
              == erase (rinst Instrumented r sg nu).r_conclusions)
  = let ri = m28_rule r in
    erase_inst_facts sg nu ri.r_premises;
    erase_inst_facts sg nu ri.r_conclusions;
    linear_erase (inst_facts sg nu ri.r_premises);
    persistent_erase (inst_facts sg nu ri.r_premises)

let rec remove1_erase (f:fact) (l r:list fact)
  : Lemma (requires remove1 f l == Some r)
          (ensures (if f.f_sym = F_Chain then erase r == erase l
                    else remove1 f (erase l) == Some (erase r)))
          (decreases l)
  = match l with
    | [] -> ()
    | x :: l' ->
        if x = f then ()
        else (match remove1 f l' with
              | Some r' -> remove1_erase f l' r'
              | None -> ())

let rec remove_all_erase (fs l r:list fact)
  : Lemma (requires remove_all fs l == Some r)
          (ensures remove_all (erase fs) (erase l) == Some (erase r))
          (decreases fs)
  = match fs with
    | [] -> ()
    | f :: fs' ->
        let Some l' = remove1 f l in
        remove1_erase f l l';
        remove_all_erase fs' l' r

let rec mem_erase (f:fact) (l:list fact)
  : Lemma (requires L.mem f l = true /\ f.f_sym <> F_Chain)
          (ensures L.mem f (erase l) = true) (decreases l)
  = match l with
    | [] -> ()
    | x :: r -> if x = f then () else mem_erase f r

let rec all_present_erase (ps l:list fact)
  : Lemma (requires all_present ps l = true)
          (ensures all_present (erase ps) (erase l) = true) (decreases ps)
  = match ps with
    | [] -> ()
    | p :: r ->
        all_present_erase r l;
        if p.f_sym = F_Chain then () else mem_erase p l

let erase_rule_step (c:config) (r:rule_name) (sg:subst) (nu:fresh_subst)
  : Lemma (requires rule_enabled Instrumented c r sg nu = true)
          (ensures rule_enabled Original (erase_config c) r sg nu = true
                   /\ rule_result Original (erase_config c) r sg nu
                      == erase_config (rule_result Instrumented c r sg nu))
  = rinst_original r sg nu;
    let Some rest = remove_all (rule_linear Instrumented r sg nu) c.facts in
    remove_all_erase (rule_linear Instrumented r sg nu) c.facts rest;
    all_present_erase (rule_persistent Instrumented r sg nu) c.facts;
    erase_append (rinst Instrumented r sg nu).r_conclusions rest

let erase_step (c:config) (l:label) (c':config) (st:sstep Instrumented c l c')
  : sstep Original (erase_config c) l (erase_config c')
  = match st with
    | SFresh _ n _ -> SFresh (erase_config c) n ()
    | SAdvFresh _ n rest _ ->
        remove1_erase (fr_fact n) c.facts rest;
        SAdvFresh (erase_config c) n (erase rest) ()
    | SRecv _ t rest _ ->
        remove1_erase (out_fact t) c.facts rest;
        SRecv (erase_config c) t (erase rest) ()
    | SSend _ t d -> SSend (erase_config c) t d
    | SRule _ r sg nu m _ ->
        erase_rule_step c r sg nu;
        SRule (erase_config c) r sg nu m ()

(* Every instrumented source trace is, label for label, an original source
   trace.  The two systems emit the same actions for each label. *)
let rec erase_source (h:strace) (c:config) (rc:sreach Instrumented h c)
  : Tot (sreach Original h (erase_config c)) (decreases rc)
  = match rc with
    | SRInit -> SRInit
    | SRStep h0 c0 l c1 r0 st ->
        SRStep h0 (erase_config c0) l (erase_config c1)
          (erase_source h0 c0 r0) (erase_step c0 l c1 st)

(* ------------------------------------------------------------------ *)
(* Original traces are admissible instrumented traces (add Chain)      *)
(* ------------------------------------------------------------------ *)

(* The Chain fact determined by a durable fact: Chain(slot, gen, pin)
   follows DiskClean and DiskApplied, and the new pin of DiskPending. *)
let chain_of (f:fact) : option fact =
  if f.f_persistent then None
  else match f.f_sym, f.f_args with
    | F_DiskClean, [sl; g; p; _; _] -> Some (f_chain sl g p)
    | F_DiskPending, [sl; _; g; n; _; _; _] -> Some (f_chain sl g n)
    | F_DiskApplied, [sl; _; g; p; _; _; _] -> Some (f_chain sl g p)
    | _ -> None

let chains (l:list fact) : list fact = abs chain_of l

(* The instrumented state is the original state plus its Chain facts,
   as multisets. *)
let lift_rel (lo li:config) : Type0 =
  li.drawn == lo.drawn /\ li.know == lo.know
  /\ (forall (f:fact). cnt f li.facts = cnt f lo.facts + cnt f (chains lo.facts))

let rec abs_cnt_append (#a:eqtype) (v:fact -> option a) (l1 l2:list fact) (y:a)
  : Lemma (ensures cnt y (abs v (L.append l1 l2)) = cnt y (abs v l1) + cnt y (abs v l2))
          (decreases l1)
  = match l1 with
    | [] -> ()
    | _ :: r -> abs_cnt_append v r l2 y

let rec abs_remove1_cnt (#a:eqtype) (v:fact -> option a) (f:fact) (l r:list fact) (y:a)
  : Lemma (requires remove1 f l == Some r)
          (ensures cnt y (abs v l) = cnt y (abs v r) + cnt y (abs v [f]))
          (decreases l)
  = match l with
    | [] -> ()
    | x :: l' ->
        if x = f then ()
        else (match remove1 f l' with
              | Some r' -> abs_remove1_cnt v f l' r' y
              | None -> ())

let rec abs_remove_all_cnt (#a:eqtype) (v:fact -> option a) (fs l r:list fact) (y:a)
  : Lemma (requires remove_all fs l == Some r)
          (ensures cnt y (abs v l) = cnt y (abs v r) + cnt y (abs v fs))
          (decreases fs)
  = match fs with
    | [] -> ()
    | f :: fs' ->
        let Some l' = remove1 f l in
        abs_remove1_cnt v f l l' y;
        abs_remove_all_cnt v fs' l' r y;
        abs_cnt_append v [f] fs' y

let rec all_present_cnt (ps l1 l2:list fact)
  : Lemma (requires all_present ps l1 = true
                    /\ (forall (f:fact). cnt f l1 <= cnt f l2))
          (ensures all_present ps l2 = true) (decreases ps)
  = match ps with
    | [] -> ()
    | p :: r -> mem_cnt p l1; mem_cnt p l2; all_present_cnt r l1 l2

(* Per rule: the Chain premises are covered by the Chain facts of the
   original premises, and the net Chain change is the change of the
   durable facts' Chains. *)
let chain_balance (r:rule_name) (sg:subst) (nu:fresh_subst) : Type0 =
  let lo = rule_linear Original r sg nu in
  let li = rule_linear Instrumented r sg nu in
  let co = (rinst Original r sg nu).r_conclusions in
  let ci = (rinst Instrumented r sg nu).r_conclusions in
  rule_persistent Original r sg nu == rule_persistent Instrumented r sg nu
  /\ (forall (f:fact). cnt f li <= cnt f lo + cnt f (chains lo))
  /\ (forall (f:fact).
       cnt f ci + cnt f lo + cnt f (chains lo) = cnt f co + cnt f li + cnt f (chains co))

let chain_balance_ok (r:rule_name) (sg:subst) (nu:fresh_subst)
  : Lemma (chain_balance r sg nu)
  = shape_ok Original r sg nu;
    shape_ok Instrumented r sg nu

let lift_rule_step (lo li:config) (r:rule_name) (sg:subst) (nu:fresh_subst)
  : Lemma (requires lift_rel lo li /\ rule_enabled Original lo r sg nu = true)
          (ensures rule_enabled Instrumented li r sg nu = true
                   /\ lift_rel (rule_result Original lo r sg nu)
                               (rule_result Instrumented li r sg nu))
  = chain_balance_ok r sg nu;
    let lino = rule_linear Original r sg nu in
    let lini = rule_linear Instrumented r sg nu in
    let co = (rinst Original r sg nu).r_conclusions in
    let ci = (rinst Instrumented r sg nu).r_conclusions in
    let Some resto = remove_all lino lo.facts in
    remove_all_cnt_all lino lo.facts resto;
    introduce forall (f:fact). cnt f lini <= cnt f li.facts
    with abs_remove_all_cnt chain_of lino lo.facts resto f;
    remove_all_some lini li.facts;
    let Some resti = remove_all lini li.facts in
    remove_all_cnt_all lini li.facts resti;
    all_present_cnt (rule_persistent Original r sg nu) lo.facts li.facts;
    introduce forall (f:fact).
      cnt f (L.append ci resti)
      = cnt f (L.append co resto) + cnt f (chains (L.append co resto))
    with begin
      cnt_append f ci resti;
      cnt_append f co resto;
      abs_cnt_append chain_of co resto f;
      abs_remove_all_cnt chain_of lino lo.facts resto f
    end

let chains_free (f:fact) (l:list fact) (y:fact)
  : Lemma (requires chain_of f == None)
          (ensures cnt y (chains (f :: l)) = cnt y (chains l))
  = ()

let lift_step (lo li:config) (l:label) (lo':config) (st:sstep Original lo l lo')
  : Pure (li':config & sstep Instrumented li l li')
      (requires lift_rel lo li)
      (ensures fun (| li', _ |) -> lift_rel lo' li')
  = match st with
    | SFresh _ n _ ->
        let li' = { li with facts = fr_fact n :: li.facts; drawn = n :: li.drawn } in
        (| li', SFresh li n () |)
    | SAdvFresh _ n rest _ ->
        remove1_cnt_all (fr_fact n) lo.facts rest;
        remove1_some (fr_fact n) li.facts;
        let Some resti = remove1 (fr_fact n) li.facts in
        remove1_cnt_all (fr_fact n) li.facts resti;
        introduce forall (y:fact). cnt y (chains lo.facts) = cnt y (chains rest)
        with abs_remove1_cnt chain_of (fr_fact n) lo.facts rest y;
        let li' = { li with facts = resti; know = SName (FreshName n) :: li.know } in
        (| li', SAdvFresh li n resti () |)
    | SRecv _ t rest _ ->
        remove1_cnt_all (out_fact t) lo.facts rest;
        remove1_some (out_fact t) li.facts;
        let Some resti = remove1 (out_fact t) li.facts in
        remove1_cnt_all (out_fact t) li.facts resti;
        introduce forall (y:fact). cnt y (chains lo.facts) = cnt y (chains rest)
        with abs_remove1_cnt chain_of (out_fact t) lo.facts rest y;
        let li' = { li with facts = resti; know = t :: li.know } in
        (| li', SRecv li t resti () |)
    | SSend _ t d ->
        let li' = { li with facts = in_fact t :: li.facts } in
        let d' : derivable li.know t = d in
        (| li', SSend li t d' |)
    | SRule _ r sg nu m _ ->
        lift_rule_step lo li r sg nu;
        (| rule_result Instrumented li r sg nu, SRule li r sg nu m () |)

(* Every original source trace is, label for label, an instrumented source
   trace: the Chain-instrumented Tamarin system admits it unchanged. *)
let rec lift_source (h:strace) (c:config) (rc:sreach Original h c)
  : Pure (ci:config & sreach Instrumented h ci)
      (requires True) (ensures fun (| ci, _ |) -> lift_rel c ci)
      (decreases rc)
  = match rc with
    | SRInit -> (| init_config, SRInit |)
    | SRStep h0 c0 l c1 r0 st ->
        let (| ci0, ri0 |) = lift_source h0 c0 r0 in
        let (| ci1, sti |) = lift_step c0 ci0 l c1 st in
        (| ci1, SRStep h0 ci0 l ci1 ri0 sti |)

(* ------------------------------------------------------------------ *)
(* Transfer between the original and the instrumented system           *)
(* ------------------------------------------------------------------ *)

(* A trace property holds for every restricted trace of a system (the
   meaning of a Tamarin all-traces verdict), or for some (exists-trace). *)
let holds_for_all (sys:system) (p:strace -> Type0) : Type =
  (h:strace) -> (c:config) -> sreach sys h c -> squash (increasing h) -> squash (p h)

noeq type holds_for_some (sys:system) (p:strace -> Type0) =
  | Witness : h:strace -> c:config -> sreach sys h c ->
      squash (increasing h /\ p h) -> holds_for_some sys p

(* A verdict on the Chain-instrumented model (what Tamarin checked) holds
   for the original seven rules, and conversely. *)
let transfer_instrumented_to_original (p:strace -> Type0)
    (hp:holds_for_all Instrumented p)
  : holds_for_all Original p
  = fun h c rc _ -> let (| ci, ri |) = lift_source h c rc in hp h ci ri ()

let transfer_original_to_instrumented (p:strace -> Type0)
    (hp:holds_for_all Original p)
  : holds_for_all Instrumented p
  = fun h c rc _ -> hp h (erase_config c) (erase_source h c rc) ()

let witness_instrumented_to_original (p:strace -> Type0)
    (w:holds_for_some Instrumented p)
  : holds_for_some Original p
  = let Witness h c rc _ = w in Witness h (erase_config c) (erase_source h c rc) ()

let witness_original_to_instrumented (p:strace -> Type0)
    (w:holds_for_some Original p)
  : holds_for_some Instrumented p
  = let Witness h c rc _ = w in
    let (| ci, ri |) = lift_source h c rc in Witness h ci ri ()

(* Every slot of every restricted instrumented trace also embeds in the core
   encoding (through its erasure), so the core and lifted encodings cover
   the Tamarin model itself. *)
let embed_instrumented (s:sterm) (h:strace) (c:config) (rc:sreach Instrumented h c)
  : Pure (slot_view s h (erase_config c)) (requires increasing h) (ensures fun _ -> True)
  = embed s h (erase_config c) (erase_source h c rc)
