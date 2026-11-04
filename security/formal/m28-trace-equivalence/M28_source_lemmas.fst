module M28_source_lemmas

(* The remaining four universal M28 lemmas on source traces:
   application_requires_prior_durable_journal,
   cleanup_requires_prior_durable_vault, commit_uses_snapshot_generation and
   each_transaction_applies_at_most_once.  Each is proved on the core encoding
   (history and counting invariants of [reach_core]) and carried to the
   source through the P2b projection; the existential ones use the backward
   index map and the fact that generation fields of reachable source states
   are generation terms, on which [to_gen] is injective.  Together with
   M28_source_bridge this proves all eight universal lemmas for both source
   systems; M28_source_witness gives the two exists-trace lemmas. *)

open M28TraceEquivalence
open M28_source_terms
open M28_source_semantics
open M28_slot_projection
open M28_source_bridge

module L = FStar.List.Tot

(* ------------------------------------------------------------------ *)
(* Core history invariants                                             *)
(* ------------------------------------------------------------------ *)

let occurs_snoc (t:ctrace) (e:cevent)
  : Lemma (forall (k:nat) (e':cevent). k < trace_len t ==>
             occurs_at (Snoc t e) k e' = occurs_at t k e')
  = ()

let rec split_memP (#a:eqtype) (l:list a) (x:a) (r:list a) (sp:split l x r)
  : Lemma (ensures L.memP x l /\ (forall (y:a). L.memP y r ==> L.memP y l))
          (decreases sp)
  = match sp with
    | SplitHere _ _ -> ()
    | SplitThere _ _ _ _ sp' -> split_memP _ x _ sp'

let journal_seen (t:ctrace) (tx:sterm) (g:gen) (n pl:sterm) : Type0 =
  exists (k:nat) (o:sterm). k < trace_len t /\ occurs_at t k (EJournal tx g o n pl) = true

let vault_seen (t:ctrace) (tx:sterm) (g:gen) (n pl:sterm) : Type0 =
  exists (k:nat). k < trace_len t /\ occurs_at t k (EVault tx g n pl) = true

let lift_journal_seen (t0:ctrace) (e:cevent) (tx:sterm) (g:gen) (n pl:sterm)
  : Lemma (requires journal_seen t0 tx g n pl) (ensures journal_seen (Snoc t0 e) tx g n pl)
  = eliminate exists (k:nat) (o:sterm).
      k < trace_len t0 /\ occurs_at t0 k (EJournal tx g o n pl) = true
    returns journal_seen (Snoc t0 e) tx g n pl
    with _. begin
      occurs_snoc t0 e;
      introduce exists (k':nat) (o':sterm).
        k' < trace_len (Snoc t0 e) /\ occurs_at (Snoc t0 e) k' (EJournal tx g o' n pl) = true
      with k o and ()
    end

let lift_vault_seen (t0:ctrace) (e:cevent) (tx:sterm) (g:gen) (n pl:sterm)
  : Lemma (requires vault_seen t0 tx g n pl) (ensures vault_seen (Snoc t0 e) tx g n pl)
  = eliminate exists (k:nat).
      k < trace_len t0 /\ occurs_at t0 k (EVault tx g n pl) = true
    returns vault_seen (Snoc t0 e) tx g n pl
    with _. begin
      occurs_snoc t0 e;
      introduce exists (k':nat).
        k' < trace_len (Snoc t0 e) /\ occurs_at (Snoc t0 e) k' (EVault tx g n pl) = true
      with k and ()
    end

let new_journal_seen (t0:ctrace) (tx:sterm) (g:gen) (o n pl:sterm)
  : Lemma (journal_seen (Snoc t0 (EJournal tx g o n pl)) tx g n pl)
  = eq_event_refl (EJournal #sterm #sterm #sterm tx g o n pl);
    introduce exists (k:nat) (o':sterm).
      k < trace_len (Snoc t0 (EJournal tx g o n pl))
      /\ occurs_at (Snoc t0 (EJournal tx g o n pl)) k (EJournal tx g o' n pl) = true
    with (trace_len t0) o and ()

let new_vault_seen (t0:ctrace) (tx:sterm) (g:gen) (n pl:sterm)
  : Lemma (vault_seen (Snoc t0 (EVault tx g n pl)) tx g n pl)
  = eq_event_refl (EVault #sterm #sterm #sterm tx g n pl);
    introduce exists (k:nat).
      k < trace_len (Snoc t0 (EVault tx g n pl))
      /\ occurs_at (Snoc t0 (EVault tx g n pl)) k (EVault tx g n pl) = true
    with (trace_len t0) and ()

let phase_seen (t:ctrace) (ph:cphase) : Type0 =
  match ph with
  | Clean _ _ _ _ -> True
  | Pending tx g n pl _ _ -> journal_seen t tx g n pl
  | Applied tx g p i _ _ -> journal_seen t tx g p i /\ vault_seen t tx g p i

let lift_phase_seen (t0:ctrace) (e:cevent) (ph:cphase)
  : Lemma (requires phase_seen t0 ph) (ensures phase_seen (Snoc t0 e) ph)
  = match ph with
    | Clean _ _ _ _ -> ()
    | Pending tx g n pl _ _ -> lift_journal_seen t0 e tx g n pl
    | Applied tx g p i _ _ -> lift_journal_seen t0 e tx g p i; lift_vault_seen t0 e tx g p i

let rec reach_phase_hist (#r0 #item:sterm) (t:ctrace) (c:cstate)
    (r:reach_core proper_subterm r0 item t c)
  : Lemma (ensures phase_seen t c.ph) (decreases r)
  = match r with
    | RCInit -> ()
    | RCSnoc t0 c0 e c1 r0' st ->
        reach_phase_hist t0 c0 r0';
        (match st with
         | CReadSnapshot _ _ _ _ _ _ -> lift_phase_seen t0 e c0.ph
         | CPersistJournal _ tx g p vr vp n pl _ _ _ _ ->
             new_journal_seen t0 tx (GS g) p n pl
         | CPersistVault _ tx g n pl vr vp _ ->
             lift_journal_seen t0 e tx g n pl;
             new_vault_seen t0 tx g n pl
         | CClearJournal _ _ _ _ _ _ _ _ -> ()
         | CCrash _ _ -> lift_phase_seen t0 e c0.ph
         | COpenVault _ _ _ _ _ _ -> lift_phase_seen t0 e c0.ph)

let rec reach_snap_hist (#r0 #item:sterm) (t:ctrace) (c:cstate)
    (r:reach_core proper_subterm r0 item t c) (tx:sterm) (g:gen) (p:sterm)
  : Lemma (requires L.memP (tx, g, p) c.snaps)
          (ensures exists (k:nat). k < trace_len t /\ occurs_at t k (ESnapshotRead tx g p) = true)
          (decreases r)
  = match r with
    | RCInit -> ()
    | RCSnoc t0 c0 e c1 r0' st ->
        occurs_snoc t0 e;
        eq_event_refl e;
        (match st with
         | CReadSnapshot _ tx' g' p' _ _ ->
             if (tx, g, p) = (tx', g', p') then
               assert (occurs_at t (trace_len t0) (ESnapshotRead tx g p) = true)
             else reach_snap_hist t0 c0 r0' tx g p
         | CPersistJournal cc tx' g' p' _ _ _ _ rest _ sp _ ->
             split_memP cc.snaps (tx', g', p') rest sp;
             reach_snap_hist t0 c0 r0' tx g p
         | CPersistVault _ _ _ _ _ _ _ _ -> reach_snap_hist t0 c0 r0' tx g p
         | CClearJournal _ _ _ _ _ _ _ _ -> reach_snap_hist t0 c0 r0' tx g p
         | CCrash _ _ -> reach_snap_hist t0 c0 r0' tx g p
         | COpenVault _ _ _ _ _ _ -> reach_snap_hist t0 c0 r0' tx g p)

let rec vault_has_journal (#r0 #item:sterm) (t:ctrace) (c:cstate)
    (r:reach_core proper_subterm r0 item t c) (k:nat) (tx:sterm) (g:gen) (n pl:sterm)
  : Lemma (requires occurs_at t k (EVault tx g n pl) = true)
          (ensures exists (k':nat) (o:sterm). k' < k /\ occurs_at t k' (EJournal tx g o n pl) = true)
          (decreases r)
  = match r with
    | RCInit -> ()
    | RCSnoc t0 c0 e c1 r0' st ->
        occurs_snoc t0 e;
        if k = trace_len t0 then begin
          reach_phase_hist t0 c0 r0';
          match st with
          | CPersistVault _ tx' g' n' pl' _ _ _ ->
              eq_event_true (EVault #sterm #sterm #sterm tx g n pl)
                (EVault #sterm #sterm #sterm tx' g' n' pl')
          | _ -> ()
        end
        else begin
          occurs_at_bound t0 k (EVault tx g n pl);
          vault_has_journal t0 c0 r0' k tx g n pl
        end

let rec clear_has_vault (#r0 #item:sterm) (t:ctrace) (c:cstate)
    (r:reach_core proper_subterm r0 item t c) (k:nat) (tx:sterm) (g:gen) (p:sterm)
  : Lemma (requires occurs_at t k (EClear tx g p) = true)
          (ensures exists (k':nat) (pl:sterm). k' < k /\ occurs_at t k' (EVault tx g p pl) = true)
          (decreases r)
  = match r with
    | RCInit -> ()
    | RCSnoc t0 c0 e c1 r0' st ->
        occurs_snoc t0 e;
        if k = trace_len t0 then begin
          reach_phase_hist t0 c0 r0';
          match st with
          | CClearJournal _ tx' g' p' _ _ _ _ ->
              eq_event_true (EClear #sterm #sterm #sterm tx g p)
                (EClear #sterm #sterm #sterm tx' g' p')
          | _ -> ()
        end
        else begin
          occurs_at_bound t0 k (EClear tx g p);
          clear_has_vault t0 c0 r0' k tx g p
        end

let rec journal_has_read (#r0 #item:sterm) (t:ctrace) (c:cstate)
    (r:reach_core proper_subterm r0 item t c) (k:nat) (tx:sterm) (g:gen) (o n pl:sterm)
  : Lemma (requires occurs_at t k (EJournal tx (GS g) o n pl) = true)
          (ensures exists (k':nat). k' < k /\ occurs_at t k' (ESnapshotRead tx g o) = true)
          (decreases r)
  = match r with
    | RCInit -> ()
    | RCSnoc t0 c0 e c1 r0' st ->
        occurs_snoc t0 e;
        if k = trace_len t0 then begin
          match st with
          | CPersistJournal cc tx' g' p' _ _ n' pl' rest _ sp _ ->
              eq_event_true (EJournal #sterm #sterm #sterm tx (GS g) o n pl)
                (EJournal #sterm #sterm #sterm tx' (GS g') p' n' pl');
              split_memP cc.snaps (tx', g', p') rest sp;
              reach_snap_hist t0 c0 r0' tx g o
          | _ -> ()
        end
        else begin
          occurs_at_bound t0 k (EJournal tx (GS g) o n pl);
          journal_has_read t0 c0 r0' k tx g o n pl
        end

(* ------------------------------------------------------------------ *)
(* Core transaction counting                                           *)
(* ------------------------------------------------------------------ *)

let rec vcount (tx:sterm) (t:ctrace) : Tot nat (decreases t) =
  match t with
  | Nil -> 0
  | Snoc t' e ->
      vcount tx t' + (match e with EVault x _ _ _ -> if x = tx then 1 else 0 | _ -> 0)

let rec jcount_tx (tx:sterm) (t:ctrace) : Tot nat (decreases t) =
  match t with
  | Nil -> 0
  | Snoc t' e ->
      jcount_tx tx t' + (match e with EJournal x _ _ _ _ -> if x = tx then 1 else 0 | _ -> 0)

let rec scount (tx:sterm) (l:list (sterm & gen & sterm)) : Tot nat (decreases l) =
  match l with
  | [] -> 0
  | (x, _, _) :: r -> (if x = tx then 1 else 0) + scount tx r

let pend (tx:sterm) (ph:cphase) : nat =
  match ph with
  | Pending x _ _ _ _ _ -> if x = tx then 1 else 0
  | _ -> 0

let tx_inv (t:ctrace) (c:cstate) : Type0 =
  forall (tx:sterm).
    scount tx c.snaps + jcount_tx tx t = cnt tx c.used
    /\ vcount tx t + pend tx c.ph <= jcount_tx tx t
    /\ cnt tx c.used <= 1

let rec split_scount (l:list (sterm & gen & sterm)) (x:sterm & gen & sterm)
    (r:list (sterm & gen & sterm)) (sp:split l x r) (tx:sterm)
  : Lemma (ensures scount tx l = scount tx r + (let (a, _, _) = x in if a = tx then 1 else 0))
          (decreases sp)
  = match sp with
    | SplitHere _ _ -> ()
    | SplitThere _ _ _ _ sp' -> split_scount _ x _ sp' tx

let rec cnt_memP (#a:eqtype) (x:a) (l:list a)
  : Lemma (ensures cnt x l > 0 ==> L.memP x l) (decreases l)
  = match l with
    | [] -> ()
    | _ :: r -> cnt_memP x r

let rec reach_tx_inv (#r0 #item:sterm) (t:ctrace) (c:cstate)
    (r:reach_core proper_subterm r0 item t c)
  : Lemma (ensures tx_inv t c) (decreases r)
  = match r with
    | RCInit -> ()
    | RCSnoc t0 c0 e c1 r0' st ->
        reach_tx_inv t0 c0 r0';
        (match st with
         | CReadSnapshot _ tx' g p nf _ ->
             cnt_memP tx' c0.used;
             assert (cnt tx' c0.used = 0)
         | CPersistJournal cc tx' g p vr vp n pl rest _ sp _ ->
             introduce forall (tx:sterm). scount tx c0.snaps = scount tx rest
                                            + (if tx' = tx then 1 else 0)
             with split_scount cc.snaps (tx', g, p) rest sp tx
         | CPersistVault _ _ _ _ _ _ _ _ -> ()
         | CClearJournal _ _ _ _ _ _ _ _ -> ()
         | CCrash _ _ -> ()
         | COpenVault _ _ _ _ _ _ -> ())

let rec vcount_pos (t:ctrace) (k:nat) (tx:sterm) (g:gen) (n pl:sterm)
  : Lemma (requires occurs_at t k (EVault tx g n pl) = true)
          (ensures vcount tx t >= 1) (decreases t)
  = match t with
    | Nil -> ()
    | Snoc t' e ->
        if k = trace_len t' then
          eq_event_true (EVault #sterm #sterm #sterm tx g n pl) e
        else vcount_pos t' k tx g n pl

let rec vcount_two (t:ctrace) (i j:nat) (tx:sterm) (g1 g2:gen) (r1 r2 p1 p2:sterm)
  : Lemma (requires i < j /\ occurs_at t i (EVault tx g1 r1 p1) = true
                    /\ occurs_at t j (EVault tx g2 r2 p2) = true)
          (ensures vcount tx t >= 2) (decreases t)
  = match t with
    | Nil -> ()
    | Snoc t' e ->
        if j = trace_len t' then begin
          eq_event_true (EVault #sterm #sterm #sterm tx g2 r2 p2) e;
          vcount_pos t' i tx g1 r1 p1
        end
        else begin
          if i = trace_len t' then occurs_at_bound t' j (EVault tx g2 r2 p2)
          else vcount_two t' i j tx g1 g2 r1 r2 p1 p2
        end

(* ------------------------------------------------------------------ *)
(* Generation fields of reachable source states are generation terms   *)
(* ------------------------------------------------------------------ *)

let fact_gen_ok (f:fact) : bool =
  match f.f_sym, f.f_args with
  | F_ReadyGeneration, [_; g; _] -> is_gen_term g
  | F_Snapshot, [_; _; g; _] -> is_gen_term g
  | F_DiskClean, [_; g; _; _; _] -> is_gen_term g
  | F_DiskPending, [_; _; g; _; _; _; _] -> is_gen_term g
  | F_DiskApplied, [_; _; g; _; _; _; _] -> is_gen_term g
  | F_SnapshotRead, [_; _; g; _] -> is_gen_term g
  | F_JournalDurable, [_; _; g; _; _; _] -> is_gen_term g
  | F_VaultDurable, [_; _; g; _; _] -> is_gen_term g
  | F_JournalCleared, [_; _; g; _] -> is_gen_term g
  | F_Opened, [_; g; _; _; _] -> is_gen_term g
  | _ -> true

let rec gens_ok (l:list fact) : Tot bool (decreases l) =
  match l with
  | [] -> true
  | f :: r -> fact_gen_ok f && gens_ok r

let rec gens_ok_mem (l:list fact) (f:fact)
  : Lemma (requires gens_ok l = true /\ L.mem f l = true)
          (ensures fact_gen_ok f = true) (decreases l)
  = match l with
    | [] -> ()
    | x :: r -> if x = f then () else gens_ok_mem r f

let rec gens_ok_remove1 (f:fact) (l r:list fact)
  : Lemma (requires gens_ok l = true /\ remove1 f l == Some r)
          (ensures gens_ok r = true) (decreases l)
  = match l with
    | [] -> ()
    | x :: l' ->
        if x = f then ()
        else (match remove1 f l' with
              | Some r' -> gens_ok_remove1 f l' r'
              | None -> ())

let rec gens_ok_remove_all (fs l r:list fact)
  : Lemma (requires gens_ok l = true /\ remove_all fs l == Some r)
          (ensures gens_ok r = true) (decreases fs)
  = match fs with
    | [] -> ()
    | f :: fs' ->
        let Some l' = remove1 f l in
        gens_ok_remove1 f l l';
        gens_ok_remove_all fs' l' r

let rec gens_ok_append (l1 l2:list fact)
  : Lemma (ensures gens_ok (L.append l1 l2) = (gens_ok l1 && gens_ok l2)) (decreases l1)
  = match l1 with
    | [] -> ()
    | _ :: r -> gens_ok_append r l2

(* A rule instance enabled in a state with generation terms concludes and
   emits only generation terms. *)
let rule_gens (c:config) (r:rule_name) (sg:subst) (nu:fresh_subst)
  : Lemma (requires gens_ok c.facts = true /\ rule_enabled Original c r sg nu = true)
          (ensures gens_ok (rinst Original r sg nu).r_conclusions = true
                   /\ gens_ok (actions (LRule r sg nu)) = true)
  = shape_ok Original r sg nu;
    label_actions_shape r sg nu;
    enabled_rest Original c r sg nu;
    let fs = c.facts in
    match r with
    | R_Initialize -> ()
    | R_ReadSnapshot ->
        let f = f_ready (sg "slot") (sg "gen") (sg "pinned") in
        all_present_mem [f] fs f;
        gens_ok_mem fs f
    | R_PersistJournal ->
        let f = f_clean (sg "slot") (sg "gen") (sg "pinned") (sg "vrev") (sg "vpayload") in
        remove1_mem f fs (Some?.v (remove1 f fs));
        gens_ok_mem fs f
    | R_PersistVault ->
        let f = f_pending (sg "slot") (sg "tx") (sg "gen") (sg "next") (sg "payload")
                  (sg "vrev") (sg "vpayload") in
        remove1_mem f fs (Some?.v (remove1 f fs));
        gens_ok_mem fs f
    | R_ClearJournal ->
        let f = f_applied (sg "slot") (sg "tx") (sg "gen") (sg "pinned") (sg "intended")
                  (sg "vrev") (sg "vpayload") in
        remove1_mem f fs (Some?.v (remove1 f fs));
        gens_ok_mem fs f
    | R_Crash -> ()
    | R_OpenVault ->
        let f = f_clean (sg "slot") (sg "gen") (sg "pinned") (sg "revision") (sg "payload") in
        remove1_mem f fs (Some?.v (remove1 f fs));
        gens_ok_mem fs f

let rec actions_gens_ok (h:strace) : Type0 =
  match h with
  | TNil -> True
  | TSnoc h' l -> gens_ok (actions l) = true /\ actions_gens_ok h'

let rec reach_gens (h:strace) (c:config) (rc:sreach Original h c)
  : Lemma (ensures gens_ok c.facts = true /\ actions_gens_ok h) (decreases rc)
  = match rc with
    | SRInit -> ()
    | SRStep h0 c0 l c1 r0 st ->
        reach_gens h0 c0 r0;
        (match st with
         | SFresh _ _ _ -> ()
         | SAdvFresh _ n rest _ -> gens_ok_remove1 (fr_fact n) c0.facts rest
         | SRecv _ t rest _ -> gens_ok_remove1 (out_fact t) c0.facts rest
         | SSend _ _ _ -> ()
         | SRule _ r sg nu _ _ ->
             rule_gens c0 r sg nu;
             enabled_rest Original c0 r sg nu;
             let Some rest = remove_all (rule_linear Original r sg nu) c0.facts in
             gens_ok_remove_all (rule_linear Original r sg nu) c0.facts rest;
             gens_ok_append (rinst Original r sg nu).r_conclusions rest)

let rec action_gen_ok (h:strace) (i:nat) (f:fact)
  : Lemma (requires actions_gens_ok h /\ action_at h i f = true)
          (ensures fact_gen_ok f = true) (decreases h)
  = match h with
    | TNil -> ()
    | TSnoc h' l ->
        if i = slen h' then gens_ok_mem (actions l) f
        else action_gen_ok h' i f

(* ------------------------------------------------------------------ *)
(* Back from the projection to source actions                          *)
(* ------------------------------------------------------------------ *)

let nth_arg (f:fact) (k:nat) : sterm =
  match L.nth f.f_args k with
  | Some x -> x
  | None -> initial

let back_before (sl:sterm) (h:strace) (i j:nat)
  : Lemma (requires Some? (event_at sl h i) /\ Some? (event_at sl h j)
                    /\ pidx sl h j < pidx sl h i)
          (ensures j < i)
  = if j = i then () else if i < j then pidx_strict sl h i j else ()

let journal_shape (sl:sterm) (f:fact) (tx:sterm) (gg:gen) (o n pl:sterm)
  : Lemma (requires event_for sl f == Some (EJournal tx gg o n pl))
          (ensures f == a_journal_durable sl tx (nth_arg f 2) o n pl
                   /\ to_gen (nth_arg f 2) == gg)
  = match f.f_args with
    | [a0; a1; a2; a3; a4; a5] ->
        assert (nth_arg f 2 == a2);
        assert (f.f_sym = F_JournalDurable /\ f.f_persistent = false);
        assert (f == mk_fact F_JournalDurable false [a0; a1; a2; a3; a4; a5])
    | _ -> ()

let vault_shape (sl:sterm) (f:fact) (tx:sterm) (gg:gen) (n pl:sterm)
  : Lemma (requires event_for sl f == Some (EVault tx gg n pl))
          (ensures f == a_vault_durable sl tx (nth_arg f 2) n pl
                   /\ to_gen (nth_arg f 2) == gg)
  = match f.f_args with
    | [a0; a1; a2; a3; a4] ->
        assert (nth_arg f 2 == a2);
        assert (f.f_sym = F_VaultDurable /\ f.f_persistent = false);
        assert (f == mk_fact F_VaultDurable false [a0; a1; a2; a3; a4])
    | _ -> ()

let read_shape (sl:sterm) (f:fact) (tx:sterm) (gg:gen) (p:sterm)
  : Lemma (requires event_for sl f == Some (ESnapshotRead tx gg p))
          (ensures f == a_snapshot_read sl tx (nth_arg f 2) p
                   /\ to_gen (nth_arg f 2) == gg)
  = match f.f_args with
    | [a0; a1; a2; a3] ->
        assert (nth_arg f 2 == a2);
        assert (f.f_sym = F_SnapshotRead /\ f.f_persistent = false);
        assert (f == mk_fact F_SnapshotRead false [a0; a1; a2; a3])
    | _ -> ()

(* ------------------------------------------------------------------ *)
(* The four lemmas on source traces                                    *)
(* ------------------------------------------------------------------ *)

let vault_journal_at (h:strace) (c:config) (rc:sreach Original h c)
    (sl tx g rv pl:sterm) (i:nat)
  : Lemma (requires increasing h /\ action_at h i (a_vault_durable sl tx g rv pl) = true)
          (ensures exists (old:sterm) (j:nat).
                     action_at h j (a_journal_durable sl tx g old rv pl) = true /\ j < i)
  = let e = EVault tx (to_gen g) rv pl in
    slot_action_forward sl h i (a_vault_durable sl tx g rv pl) e;
    let (| item, st, r |) = embedded_reach sl h c rc (pidx sl h i) e in
    vault_has_journal (project sl h) st r (pidx sl h i) tx (to_gen g) rv pl;
    reach_gens h c rc;
    action_gen_ok h i (a_vault_durable sl tx g rv pl);
    eliminate exists (k:nat) (o:sterm).
      k < pidx sl h i /\ occurs_at (project sl h) k (EJournal tx (to_gen g) o rv pl) = true
    returns exists (old:sterm) (j:nat).
      action_at h j (a_journal_durable sl tx g old rv pl) = true /\ j < i
    with _. begin
      slot_event_backward sl h k (EJournal tx (to_gen g) o rv pl);
      eliminate exists (j:nat) (f:fact).
        action_at h j f = true /\ event_for sl f == Some (EJournal tx (to_gen g) o rv pl)
        /\ event_at sl h j == Some (EJournal tx (to_gen g) o rv pl) /\ pidx sl h j = k
      returns exists (old:sterm) (j:nat).
        action_at h j (a_journal_durable sl tx g old rv pl) = true /\ j < i
      with _. begin
        journal_shape sl f tx (to_gen g) o rv pl;
        action_gen_ok h j f;
        to_gen_injective (nth_arg f 2) g;
        back_before sl h i j;
        introduce exists (old:sterm) (j':nat).
          action_at h j' (a_journal_durable sl tx g old rv pl) = true /\ j' < i
        with o j and ()
      end
    end

let clear_vault_at (h:strace) (c:config) (rc:sreach Original h c)
    (sl tx g rv:sterm) (i:nat)
  : Lemma (requires increasing h /\ action_at h i (a_journal_cleared sl tx g rv) = true)
          (ensures exists (pl:sterm) (j:nat).
                     action_at h j (a_vault_durable sl tx g rv pl) = true /\ j < i)
  = let e = EClear tx (to_gen g) rv in
    slot_action_forward sl h i (a_journal_cleared sl tx g rv) e;
    let (| item, st, r |) = embedded_reach sl h c rc (pidx sl h i) e in
    clear_has_vault (project sl h) st r (pidx sl h i) tx (to_gen g) rv;
    reach_gens h c rc;
    action_gen_ok h i (a_journal_cleared sl tx g rv);
    eliminate exists (k:nat) (pl:sterm).
      k < pidx sl h i /\ occurs_at (project sl h) k (EVault tx (to_gen g) rv pl) = true
    returns exists (pl:sterm) (j:nat).
      action_at h j (a_vault_durable sl tx g rv pl) = true /\ j < i
    with _. begin
      slot_event_backward sl h k (EVault tx (to_gen g) rv pl);
      eliminate exists (j:nat) (f:fact).
        action_at h j f = true /\ event_for sl f == Some (EVault tx (to_gen g) rv pl)
        /\ event_at sl h j == Some (EVault tx (to_gen g) rv pl) /\ pidx sl h j = k
      returns exists (pl:sterm) (j:nat).
        action_at h j (a_vault_durable sl tx g rv pl) = true /\ j < i
      with _. begin
        vault_shape sl f tx (to_gen g) rv pl;
        action_gen_ok h j f;
        to_gen_injective (nth_arg f 2) g;
        back_before sl h i j;
        introduce exists (pl':sterm) (j':nat).
          action_at h j' (a_vault_durable sl tx g rv pl') = true /\ j' < i
        with pl j and ()
      end
    end

let journal_read_at (h:strace) (c:config) (rc:sreach Original h c)
    (sl tx g old nx pl:sterm) (i:nat)
  : Lemma (requires increasing h
                    /\ action_at h i (a_journal_durable sl tx (successor g) old nx pl) = true)
          (ensures exists (j:nat). action_at h j (a_snapshot_read sl tx g old) = true /\ j < i)
  = let e = EJournal tx (GS (to_gen g)) old nx pl in
    slot_action_forward sl h i (a_journal_durable sl tx (successor g) old nx pl) e;
    let (| item, st, r |) = embedded_reach sl h c rc (pidx sl h i) e in
    journal_has_read (project sl h) st r (pidx sl h i) tx (to_gen g) old nx pl;
    reach_gens h c rc;
    action_gen_ok h i (a_journal_durable sl tx (successor g) old nx pl);
    eliminate exists (k:nat).
      k < pidx sl h i /\ occurs_at (project sl h) k (ESnapshotRead tx (to_gen g) old) = true
    returns exists (j:nat). action_at h j (a_snapshot_read sl tx g old) = true /\ j < i
    with _. begin
      slot_event_backward sl h k (ESnapshotRead tx (to_gen g) old);
      eliminate exists (j:nat) (f:fact).
        action_at h j f = true /\ event_for sl f == Some (ESnapshotRead tx (to_gen g) old)
        /\ event_at sl h j == Some (ESnapshotRead tx (to_gen g) old) /\ pidx sl h j = k
      returns exists (j:nat). action_at h j (a_snapshot_read sl tx g old) = true /\ j < i
      with _. begin
        read_shape sl f tx (to_gen g) old;
        action_gen_ok h j f;
        to_gen_injective (nth_arg f 2) g;
        back_before sl h i j;
        introduce exists (j':nat). action_at h j' (a_snapshot_read sl tx g old) = true /\ j' < i
        with j and ()
      end
    end

let vault_once_at (h:strace) (c:config) (rc:sreach Original h c)
    (sl tx g1 g2 r1 r2 p1 p2:sterm) (i j:nat)
  : Lemma (requires increasing h
                    /\ action_at h i (a_vault_durable sl tx g1 r1 p1) = true
                    /\ action_at h j (a_vault_durable sl tx g2 r2 p2) = true)
          (ensures i = j)
  = let e1 = EVault tx (to_gen g1) r1 p1 in
    let e2 = EVault tx (to_gen g2) r2 p2 in
    slot_action_forward sl h i (a_vault_durable sl tx g1 r1 p1) e1;
    slot_action_forward sl h j (a_vault_durable sl tx g2 r2 p2) e2;
    let (| item, st, r |) = embedded_reach sl h c rc (pidx sl h i) e1 in
    reach_tx_inv (project sl h) st r;
    if i < j then begin
      pidx_strict sl h i j;
      vcount_two (project sl h) (pidx sl h i) (pidx sl h j) tx
        (to_gen g1) (to_gen g2) r1 r2 p1 p2
    end
    else if j < i then begin
      pidx_strict sl h j i;
      vcount_two (project sl h) (pidx sl h j) (pidx sl h i) tx
        (to_gen g2) (to_gen g1) r2 r1 p2 p1
    end
    else ()

let source_application_requires_prior_durable_journal (h:strace) (c:config)
    (rc:sreach Original h c)
  : Lemma (requires increasing h) (ensures application_requires_prior_durable_journal h)
  = introduce forall (sl tx g rv pl:sterm) (i:nat).
      action_at h i (a_vault_durable sl tx g rv pl) = true ==>
      (exists (old:sterm) (j:nat).
         action_at h j (a_journal_durable sl tx g old rv pl) = true /\ j < i)
    with introduce _ ==> _
    with _. vault_journal_at h c rc sl tx g rv pl i

let source_cleanup_requires_prior_durable_vault (h:strace) (c:config)
    (rc:sreach Original h c)
  : Lemma (requires increasing h) (ensures cleanup_requires_prior_durable_vault h)
  = introduce forall (sl tx g rv:sterm) (i:nat).
      action_at h i (a_journal_cleared sl tx g rv) = true ==>
      (exists (pl:sterm) (j:nat).
         action_at h j (a_vault_durable sl tx g rv pl) = true /\ j < i)
    with introduce _ ==> _
    with _. clear_vault_at h c rc sl tx g rv i

let source_commit_uses_snapshot_generation (h:strace) (c:config)
    (rc:sreach Original h c)
  : Lemma (requires increasing h) (ensures commit_uses_snapshot_generation h)
  = introduce forall (sl tx g old nx pl:sterm) (i:nat).
      action_at h i (a_journal_durable sl tx (successor g) old nx pl) = true ==>
      (exists (j:nat). action_at h j (a_snapshot_read sl tx g old) = true /\ j < i)
    with introduce _ ==> _
    with _. journal_read_at h c rc sl tx g old nx pl i

let source_each_transaction_applies_at_most_once (h:strace) (c:config)
    (rc:sreach Original h c)
  : Lemma (requires increasing h) (ensures each_transaction_applies_at_most_once h)
  = introduce forall (sl tx g1 g2 r1 r2 p1 p2:sterm) (i j:nat).
      action_at h i (a_vault_durable sl tx g1 r1 p1) = true
      /\ action_at h j (a_vault_durable sl tx g2 r2 p2) = true ==> i = j
    with introduce _ ==> _
    with _. vault_once_at h c rc sl tx g1 g2 r1 r2 p1 p2 i j

(* ------------------------------------------------------------------ *)
(* All eight universal M28 lemmas, for both source systems             *)
(* ------------------------------------------------------------------ *)

let original_universal_lemmas : holds_for_all Original m28_universal =
  fun h c rc _ ->
    source_open_has_matching_content_and_pin h c rc;
    source_application_requires_prior_durable_journal h c rc;
    source_cleanup_requires_prior_durable_vault h c rc;
    source_commit_uses_snapshot_generation h c rc;
    source_each_transaction_applies_at_most_once h c rc;
    source_pins_advance_on_every_commit h;
    source_committed_pins_never_decrease h c rc;
    source_a_generation_commits_at_most_once h c rc

(* The Chain-instrumented .spthy model, i.e. what Tamarin analyses. *)
let instrumented_universal_lemmas : holds_for_all Instrumented m28_universal =
  transfer_original_to_instrumented m28_universal original_universal_lemmas
