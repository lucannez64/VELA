module M28_slot_projection

(* P2b: projection of multi-slot M28 source traces to single-slot traces.

   [project s h] keeps, in order, the timepoints of the source trace [h] whose
   actions belong to slot [s], and maps each to the corresponding event of
   M28TraceEquivalence.  It is defined on the observable action trace only.
   [pidx s h i] is the position of timepoint #i in that projection.  The
   lemmas below show that the projection preserves exactly what the M28
   lemmas use: each slot action at #i appears in the projection at
   [pidx s h i] with the same fields, [pidx] is strictly monotone on slot
   timepoints (so order and equality of timepoints are reflected), and every
   projected event comes back from a source timepoint.

   [abs_core s c h] reads the single-slot core state of slot [s] from a
   source configuration.  The step lemmas show that a source step of another
   slot, or an attacker/Fresh step, leaves it unchanged and adds no event,
   and that a source step of slot [s] is the matching core step.  The
   hypotheses of those lemmas (one durable fact per initialized slot, fresh
   transaction names, the restriction) are discharged in M28_source_bridge
   from the P2c invariants. *)

open M28TraceEquivalence
open M28_source_terms
open M28_source_semantics

module L = FStar.List.Tot

type cevent = event sterm sterm sterm
type ctrace = trace sterm sterm sterm
type cstate = core sterm sterm sterm
type cphase = phase sterm sterm sterm

(* ------------------------------------------------------------------ *)
(* Generations                                                         *)
(* ------------------------------------------------------------------ *)

(* Generation terms are 'initial' and successor(...).  [to_gen] is total;
   it is injective on generation terms. *)
let rec to_gen (t:sterm) : Tot gen (decreases t) =
  match t with
  | SApp Successor a -> GS (to_gen a)
  | _ -> G0

let rec is_gen_term (t:sterm) : Tot bool (decreases t) =
  match t with
  | SName (PublicName p) -> p = "initial"
  | SApp Successor a -> is_gen_term a
  | _ -> false

let rec to_gen_injective (x y:sterm)
  : Lemma (requires is_gen_term x = true /\ is_gen_term y = true
                    /\ to_gen x = to_gen y)
          (ensures x = y) (decreases x)
  = match x, y with
    | SApp Successor x', SApp Successor y' -> to_gen_injective x' y'
    | _, _ -> ()

(* ------------------------------------------------------------------ *)
(* Facts of the M28 rules and the explicit rule instances              *)
(* ------------------------------------------------------------------ *)

let f_profile (s:sterm) : fact = mk_fact F_Profile true [s]
let f_ready (s g p:sterm) : fact = mk_fact F_ReadyGeneration true [s; g; p]
let f_clean (s g p vr vp:sterm) : fact =
  mk_fact F_DiskClean false [s; g; p; vr; vp]
let f_chain (s g p:sterm) : fact = mk_fact F_Chain false [s; g; p]
let f_snapshot (s tx g p:sterm) : fact = mk_fact F_Snapshot false [s; tx; g; p]
let f_pending (s tx g n pl vr vp:sterm) : fact =
  mk_fact F_DiskPending false [s; tx; g; n; pl; vr; vp]
let f_applied (s tx g p i vr vp:sterm) : fact =
  mk_fact F_DiskApplied false [s; tx; g; p; i; vr; vp]

let fresh_term (n:string) : sterm = SName (FreshName n)

type shape = {
  s_lin: list fact;
  s_pers: list fact;
  s_acts: list fact;
  s_concl: list fact;
}

let is_inst (sys:system) : bool = Instrumented? sys

(* The instance of each schema under (sg, nu), written out.  [shape_ok]
   checks it against the generic instantiation of the P2a schema. *)
let explicit_shape (sys:system) (r:rule_name) (sg:subst) (nu:fresh_subst)
  : shape
  = match r with
    | R_Initialize ->
        let sl = fresh_term (nu "slot") in
        let it = fresh_term (nu "item") in
        { s_lin = [fr_fact (nu "slot"); fr_fact (nu "item")];
          s_pers = [];
          s_acts = [a_initialized sl];
          s_concl =
            (if is_inst sys then
               [f_profile sl; f_ready sl initial initial;
                f_clean sl initial initial initial it;
                f_chain sl initial initial; out_fact sl]
             else
               [f_profile sl; f_ready sl initial initial;
                f_clean sl initial initial initial it; out_fact sl]) }
    | R_ReadSnapshot ->
        let tx = fresh_term (nu "tx") in
        { s_lin = [fr_fact (nu "tx")];
          s_pers = [f_ready (sg "slot") (sg "gen") (sg "pinned")];
          s_acts = [a_snapshot_read (sg "slot") tx (sg "gen") (sg "pinned")];
          s_concl = [f_snapshot (sg "slot") tx (sg "gen") (sg "pinned")] }
    | R_PersistJournal ->
        let s = sg "slot" in
        let g = sg "gen" in
        let p = sg "pinned" in
        let nr = sg "next_revision" in
        let pl = sg "payload" in
        { s_lin =
            (if is_inst sys then
               [f_clean s g p (sg "vrev") (sg "vpayload"); f_chain s g p;
                f_snapshot s (sg "tx") g p; in_fact (SPair nr pl)]
             else
               [f_clean s g p (sg "vrev") (sg "vpayload");
                f_snapshot s (sg "tx") g p; in_fact (SPair nr pl)]);
          s_pers = [];
          s_acts = [a_revision_increases p nr;
                    a_journal_durable s (sg "tx") (successor g) p nr pl];
          s_concl =
            (if is_inst sys then
               [f_pending s (sg "tx") (successor g) nr pl (sg "vrev") (sg "vpayload");
                f_chain s (successor g) nr]
             else
               [f_pending s (sg "tx") (successor g) nr pl (sg "vrev") (sg "vpayload")]) }
    | R_PersistVault ->
        let s = sg "slot" in
        { s_lin = [f_pending s (sg "tx") (sg "gen") (sg "next") (sg "payload")
                     (sg "vrev") (sg "vpayload")];
          s_pers = [];
          s_acts = [a_vault_durable s (sg "tx") (sg "gen") (sg "next") (sg "payload")];
          s_concl = [f_applied s (sg "tx") (sg "gen") (sg "next") (sg "payload")
                       (sg "next") (sg "payload")] }
    | R_ClearJournal ->
        let s = sg "slot" in
        let g = sg "gen" in
        let p = sg "pinned" in
        { s_lin =
            (if is_inst sys then
               [f_applied s (sg "tx") g p (sg "intended") (sg "vrev") (sg "vpayload");
                f_chain s g p]
             else
               [f_applied s (sg "tx") g p (sg "intended") (sg "vrev") (sg "vpayload")]);
          s_pers = [];
          s_acts = [a_journal_cleared s (sg "tx") g p];
          s_concl =
            (if is_inst sys then
               [f_clean s g p (sg "vrev") (sg "vpayload"); f_chain s g p;
                f_ready s g p]
             else
               [f_clean s g p (sg "vrev") (sg "vpayload"); f_ready s g p]) }
    | R_Crash ->
        { s_lin = []; s_pers = [f_profile (sg "slot")];
          s_acts = [a_crash (sg "slot")]; s_concl = [] }
    | R_OpenVault ->
        let f = f_clean (sg "slot") (sg "gen") (sg "pinned") (sg "revision")
                  (sg "payload") in
        { s_lin = [f]; s_pers = [];
          s_acts = [a_opened (sg "slot") (sg "gen") (sg "pinned") (sg "revision")
                      (sg "payload")];
          s_concl = [f] }

let matches_shape (sys:system) (r:rule_name) (sg:subst) (nu:fresh_subst)
  : Type0
  = rule_linear sys r sg nu == (explicit_shape sys r sg nu).s_lin
    /\ rule_persistent sys r sg nu == (explicit_shape sys r sg nu).s_pers
    /\ (rinst sys r sg nu).r_actions == (explicit_shape sys r sg nu).s_acts
    /\ (rinst sys r sg nu).r_conclusions == (explicit_shape sys r sg nu).s_concl

let shape_ok (sys:system) (r:rule_name) (sg:subst) (nu:fresh_subst)
  : Lemma (matches_shape sys r sg nu)
  = match sys, r with
    | Original, R_Initialize -> assert_norm (matches_shape Original R_Initialize sg nu)
    | Original, R_ReadSnapshot -> assert_norm (matches_shape Original R_ReadSnapshot sg nu)
    | Original, R_PersistJournal -> assert_norm (matches_shape Original R_PersistJournal sg nu)
    | Original, R_PersistVault -> assert_norm (matches_shape Original R_PersistVault sg nu)
    | Original, R_ClearJournal -> assert_norm (matches_shape Original R_ClearJournal sg nu)
    | Original, R_Crash -> assert_norm (matches_shape Original R_Crash sg nu)
    | Original, R_OpenVault -> assert_norm (matches_shape Original R_OpenVault sg nu)
    | Instrumented, R_Initialize -> assert_norm (matches_shape Instrumented R_Initialize sg nu)
    | Instrumented, R_ReadSnapshot -> assert_norm (matches_shape Instrumented R_ReadSnapshot sg nu)
    | Instrumented, R_PersistJournal -> assert_norm (matches_shape Instrumented R_PersistJournal sg nu)
    | Instrumented, R_PersistVault -> assert_norm (matches_shape Instrumented R_PersistVault sg nu)
    | Instrumented, R_ClearJournal -> assert_norm (matches_shape Instrumented R_ClearJournal sg nu)
    | Instrumented, R_Crash -> assert_norm (matches_shape Instrumented R_Crash sg nu)
    | Instrumented, R_OpenVault -> assert_norm (matches_shape Instrumented R_OpenVault sg nu)

let label_actions_shape (r:rule_name) (sg:subst) (nu:fresh_subst)
  : Lemma (actions (LRule r sg nu) == (explicit_shape Instrumented r sg nu).s_acts)
  = shape_ok Instrumented r sg nu

(* ------------------------------------------------------------------ *)
(* Action-to-event map                                                 *)
(* ------------------------------------------------------------------ *)

(* The slot and core event of one M28 action fact.  RevisionIncreases has
   no slot; its timepoint is carried by the JournalDurable action. *)
let action_event (f:fact) : option (sterm & cevent) =
  if f.f_persistent then None
  else match f.f_sym, f.f_args with
    | F_Initialized, [sl] -> Some (sl, EInitialized)
    | F_SnapshotRead, [sl; tx; g; p] -> Some (sl, ESnapshotRead tx (to_gen g) p)
    | F_JournalDurable, [sl; tx; g; o; n; p] -> Some (sl, EJournal tx (to_gen g) o n p)
    | F_VaultDurable, [sl; tx; g; n; p] -> Some (sl, EVault tx (to_gen g) n p)
    | F_JournalCleared, [sl; tx; g; p] -> Some (sl, EClear tx (to_gen g) p)
    | F_Crash, [sl] -> Some (sl, ECrash)
    | F_Opened, [sl; g; p; r; v] -> Some (sl, EOpened (to_gen g) p r v)
    | _ -> None

let event_for (s:sterm) (f:fact) : option cevent =
  match action_event f with
  | Some (sl, e) -> if sl = s then Some e else None
  | None -> None

(* The slot event of a timepoint: the last slot action of its action list.
   Every M28 rule has exactly one slot action. *)
let rec event_of (s:sterm) (acts:list fact) : Tot (option cevent) (decreases acts) =
  match acts with
  | [] -> None
  | f :: r ->
      (match event_of s r with
       | Some e -> Some e
       | None -> event_for s f)

let rec slot_actions (acts:list fact) : Tot nat (decreases acts) =
  match acts with
  | [] -> 0
  | f :: r -> (if Some? (action_event f) then 1 else 0) + slot_actions r

let rule_one_slot_action (r:rule_name) (sg:subst) (nu:fresh_subst)
  : Lemma (slot_actions (actions (LRule r sg nu)) = 1)
  = label_actions_shape r sg nu

let rec event_of_some_slot (s:sterm) (acts:list fact)
  : Lemma (requires Some? (event_of s acts))
          (ensures slot_actions acts >= 1) (decreases acts)
  = match acts with
    | [] -> ()
    | x :: r ->
        (match event_of s r with
         | Some _ -> event_of_some_slot s r
         | None -> ())

let rec event_of_mem (s:sterm) (acts:list fact) (f:fact) (e:cevent)
  : Lemma (requires L.mem f acts = true /\ event_for s f == Some e
                    /\ slot_actions acts <= 1)
          (ensures event_of s acts == Some e) (decreases acts)
  = match acts with
    | [] -> ()
    | x :: r ->
        if x = f then
          (match event_of s r with
           | Some _ -> event_of_some_slot s r
           | None -> ())
        else event_of_mem s r f e

let rec event_of_back (s:sterm) (acts:list fact) (e:cevent)
  : Lemma (requires event_of s acts == Some e)
          (ensures exists (f:fact). L.mem f acts = true /\ event_for s f == Some e)
          (decreases acts)
  = match acts with
    | [] -> ()
    | x :: r ->
        (match event_of s r with
         | Some _ -> event_of_back s r e
         | None -> ())

let actions_one_slot (l:label)
  : Lemma (slot_actions (actions l) <= 1)
  = match l with
    | LRule r sg nu -> rule_one_slot_action r sg nu
    | _ -> ()

(* ------------------------------------------------------------------ *)
(* The projection and its index map                                    *)
(* ------------------------------------------------------------------ *)

let rec event_at (s:sterm) (h:strace) (i:nat) : Tot (option cevent) (decreases h) =
  match h with
  | TNil -> None
  | TSnoc h' l -> if i = slen h' then event_of s (actions l) else event_at s h' i

let rec project (s:sterm) (h:strace) : Tot ctrace (decreases h) =
  match h with
  | TNil -> Nil
  | TSnoc h' l ->
      (match event_of s (actions l) with
       | Some e -> Snoc (project s h') e
       | None -> project s h')

let rec pidx (s:sterm) (h:strace) (i:nat) : Tot nat (decreases h) =
  match h with
  | TNil -> 0
  | TSnoc h' l -> if i = slen h' then trace_len (project s h') else pidx s h' i

let rec event_at_bound (s:sterm) (h:strace) (i:nat)
  : Lemma (requires Some? (event_at s h i)) (ensures i < slen h) (decreases h)
  = match h with
    | TNil -> ()
    | TSnoc h' _ -> if i = slen h' then () else event_at_bound s h' i

let eq_event_refl (e:cevent) : Lemma (eq_event e e = true) =
  match e with
  | EInitialized -> ()
  | ESnapshotRead _ _ _ -> ()
  | EJournal _ _ _ _ _ -> ()
  | EVault _ _ _ _ -> ()
  | EClear _ _ _ -> ()
  | ECrash -> ()
  | EOpened _ _ _ _ -> ()

(* A slot action at #i appears in the projection at position pidx i. *)
let rec project_forward (s:sterm) (h:strace) (i:nat) (e:cevent)
  : Lemma (requires event_at s h i == Some e)
          (ensures occurs_at (project s h) (pidx s h i) e = true
                   /\ pidx s h i < trace_len (project s h))
          (decreases h)
  = match h with
    | TNil -> ()
    | TSnoc h' l ->
        if i = slen h' then eq_event_refl e
        else begin
          event_at_bound s h' i;
          project_forward s h' i e;
          occurs_at_bound (project s h') (pidx s h' i) e
        end

(* pidx is strictly monotone on slot timepoints. *)
let rec pidx_strict (s:sterm) (h:strace) (i j:nat)
  : Lemma (requires Some? (event_at s h i) /\ Some? (event_at s h j) /\ i < j)
          (ensures pidx s h i < pidx s h j) (decreases h)
  = match h with
    | TNil -> ()
    | TSnoc h' l ->
        if j = slen h' then begin
          event_at_bound s h' i;
          project_forward s h' i (Some?.v (event_at s h' i))
        end
        else begin
          event_at_bound s h' j;
          pidx_strict s h' i j
        end

let pidx_injective (s:sterm) (h:strace) (i j:nat)
  : Lemma (requires Some? (event_at s h i) /\ Some? (event_at s h j)
                    /\ pidx s h i = pidx s h j)
          (ensures i = j)
  = if i < j then pidx_strict s h i j
    else if j < i then pidx_strict s h j i
    else ()

(* Every projected event comes from a source timepoint. *)
let rec project_backward (s:sterm) (h:strace) (k:nat) (e:cevent)
  : Lemma (requires occurs_at (project s h) k e = true)
          (ensures exists (i:nat). event_at s h i == Some e /\ pidx s h i = k)
          (decreases h)
  = match h with
    | TNil -> ()
    | TSnoc h' l ->
        (match event_of s (actions l) with
         | Some e' ->
             if k = trace_len (project s h') then eq_event_true e e'
             else begin
               project_backward s h' k e;
               introduce forall (i:nat).
                 (event_at s h' i == Some e /\ pidx s h' i = k) ==>
                 (event_at s h i == Some e /\ pidx s h i = k)
               with introduce _ ==> _
               with _. event_at_bound s h' i
             end
         | None ->
             project_backward s h' k e;
             introduce forall (i:nat).
               (event_at s h' i == Some e /\ pidx s h' i = k) ==>
               (event_at s h i == Some e /\ pidx s h i = k)
             with introduce _ ==> _
             with _. event_at_bound s h' i)

(* Action facts and timepoint events. *)
let rec action_event_at (s:sterm) (h:strace) (i:nat) (f:fact) (e:cevent)
  : Lemma (requires action_at h i f = true /\ event_for s f == Some e)
          (ensures event_at s h i == Some e) (decreases h)
  = match h with
    | TNil -> ()
    | TSnoc h' l ->
        if i = slen h' then begin
          actions_one_slot l;
          event_of_mem s (actions l) f e
        end
        else action_event_at s h' i f e

let rec event_at_action (s:sterm) (h:strace) (i:nat) (e:cevent)
  : Lemma (requires event_at s h i == Some e)
          (ensures exists (f:fact). action_at h i f = true /\ event_for s f == Some e)
          (decreases h)
  = match h with
    | TNil -> ()
    | TSnoc h' l ->
        if i = slen h' then event_of_back s (actions l) e
        else event_at_action s h' i e

(* The two directions in the form the lemma transfers use. *)
let slot_action_forward (s:sterm) (h:strace) (i:nat) (f:fact) (e:cevent)
  : Lemma (requires action_at h i f = true /\ event_for s f == Some e)
          (ensures occurs_at (project s h) (pidx s h i) e = true
                   /\ event_at s h i == Some e)
  = action_event_at s h i f e;
    project_forward s h i e

let slot_event_backward (s:sterm) (h:strace) (k:nat) (e:cevent)
  : Lemma (requires occurs_at (project s h) k e = true)
          (ensures exists (i:nat) (f:fact).
                     action_at h i f = true /\ event_for s f == Some e
                     /\ event_at s h i == Some e /\ pidx s h i = k)
  = project_backward s h k e;
    introduce forall (i:nat).
      (event_at s h i == Some e /\ pidx s h i = k) ==>
      (exists (f:fact). action_at h i f = true /\ event_for s f == Some e
                        /\ event_at s h i == Some e /\ pidx s h i = k)
    with introduce _ ==> _
    with _. event_at_action s h i e

(* ------------------------------------------------------------------ *)
(* State views of one slot                                             *)
(* ------------------------------------------------------------------ *)

let ready_view (s:sterm) (f:fact) : option (gen & sterm) =
  if f.f_sym = F_ReadyGeneration && f.f_persistent then
    (match f.f_args with
     | [sl; g; p] -> if sl = s then Some (to_gen g, p) else None
     | _ -> None)
  else None

let snap_view (s:sterm) (f:fact) : option (sterm & gen & sterm) =
  if f.f_sym = F_Snapshot && not f.f_persistent then
    (match f.f_args with
     | [sl; tx; g; p] -> if sl = s then Some (tx, to_gen g, p) else None
     | _ -> None)
  else None

let dur_view (s:sterm) (f:fact) : option cphase =
  if f.f_persistent then None
  else match f.f_sym, f.f_args with
    | F_DiskClean, [sl; g; p; vr; vp] ->
        if sl = s then Some (Clean (to_gen g) p vr vp) else None
    | F_DiskPending, [sl; tx; g; n; pl; vr; vp] ->
        if sl = s then Some (Pending tx (to_gen g) n pl vr vp) else None
    | F_DiskApplied, [sl; tx; g; p; i; vr; vp] ->
        if sl = s then Some (Applied tx (to_gen g) p i vr vp) else None
    | _ -> None

let profile_view (s:sterm) (f:fact) : option unit =
  if f.f_sym = F_Profile && f.f_persistent then
    (match f.f_args with
     | [sl] -> if sl = s then Some () else None
     | _ -> None)
  else None

let rec abs (#a:eqtype) (v:fact -> option a) (l:list fact)
  : Tot (list a) (decreases l)
  = match l with
    | [] -> []
    | f :: r ->
        (match v f with
         | Some x -> x :: abs v r
         | None -> abs v r)

let rec abs_append (#a:eqtype) (v:fact -> option a) (l1 l2:list fact)
  : Lemma (ensures abs v (L.append l1 l2) == L.append (abs v l1) (abs v l2))
          (decreases l1)
  = match l1 with
    | [] -> ()
    | _ :: r -> abs_append v r l2

let rec abs_remove1_none (#a:eqtype) (v:fact -> option a) (f:fact) (l r:list fact)
  : Lemma (requires remove1 f l == Some r /\ v f == None)
          (ensures abs v r == abs v l) (decreases l)
  = match l with
    | [] -> ()
    | x :: l' ->
        if x = f then ()
        else (match remove1 f l' with
              | Some r' -> abs_remove1_none v f l' r'
              | None -> ())

let rec abs_remove1_split (#a:eqtype) (v:fact -> option a) (f:fact)
    (l r:list fact) (x:a)
  : Pure (split (abs v l) x (abs v r))
      (requires remove1 f l == Some r /\ v f == Some x)
      (ensures fun _ -> True) (decreases l)
  = match l with
    | y :: l' ->
        if y = f then SplitHere x (abs v l')
        else begin
          let Some r' = remove1 f l' in
          let sp = abs_remove1_split v f l' r' x in
          match v y with
          | Some z -> SplitThere z x (abs v l') (abs v r') sp
          | None -> sp
        end

let rec abs_mem (#a:eqtype) (v:fact -> option a) (f:fact) (l:list fact) (x:a)
  : Lemma (requires L.mem f l = true /\ v f == Some x)
          (ensures L.memP x (abs v l)) (decreases l)
  = match l with
    | [] -> ()
    | y :: r -> if y = f then () else abs_mem v f r x

let split_single (#a:eqtype) (y x:a) (r:list a) (sp:split [y] x r)
  : Lemma (x == y /\ r == [])
  = match sp with
    | SplitHere _ _ -> ()
    | SplitThere _ _ _ _ sp' -> (match sp' with | SplitHere _ _ -> ())

let split_nil (#a:eqtype) (x:a) (r:list a) (sp:split [] x r)
  : Lemma False
  = match sp with | SplitHere _ _ -> ()

(* A fact belongs to no view of slot [s]. *)
let slot_free (s:sterm) (f:fact) : bool =
  None? (ready_view s f) && None? (snap_view s f) && None? (dur_view s f)
  && None? (profile_view s f)

let rec all_slot_free (s:sterm) (fs:list fact) : Tot bool (decreases fs) =
  match fs with
  | [] -> true
  | f :: r -> slot_free s f && all_slot_free s r

let rec abs_all_free (#a:eqtype) (v:fact -> option a) (fs:list fact)
  : Lemma (requires forall (f:fact). L.mem f fs = true ==> v f == None)
          (ensures abs v fs == []) (decreases fs)
  = match fs with
    | [] -> ()
    | _ :: r -> abs_all_free v r

let rec abs_remove_all_none (#a:eqtype) (v:fact -> option a) (fs l r:list fact)
  : Lemma (requires remove_all fs l == Some r
                    /\ (forall (f:fact). L.mem f fs = true ==> v f == None))
          (ensures abs v r == abs v l) (decreases fs)
  = match fs with
    | [] -> ()
    | f :: fs' ->
        let Some l' = remove1 f l in
        abs_remove1_none v f l l';
        abs_remove_all_none v fs' l' r

let rec all_slot_free_mem (s:sterm) (fs:list fact) (f:fact)
  : Lemma (requires all_slot_free s fs = true /\ L.mem f fs = true)
          (ensures slot_free s f = true) (decreases fs)
  = match fs with
    | [] -> ()
    | x :: r -> if x = f then () else all_slot_free_mem s r f

(* The core state of slot [s]: !ReadyGeneration pairs, Snapshot triples,
   SnapshotRead transaction names of the slot, and the durable phase. *)
let rec used_of (t:ctrace) : Tot (list sterm) (decreases t) =
  match t with
  | Nil -> []
  | Snoc t' e ->
      (match e with
       | ESnapshotRead tx _ _ -> tx :: used_of t'
       | _ -> used_of t')

let default_phase : cphase = Clean G0 initial initial initial

let the_phase (l:list cphase) : cphase =
  match l with
  | [ph] -> ph
  | _ -> default_phase

let abs_core (s:sterm) (c:config) (h:strace) : cstate =
  { opened = true;
    ready = abs (ready_view s) c.facts;
    snaps = abs (snap_view s) c.facts;
    used = used_of (project s h);
    ph = the_phase (abs (dur_view s) c.facts) }

(* Facts carried by the slot views are unchanged by removing and adding
   slot-free facts. *)
let views_same (s:sterm) (l l':list fact) : Type0 =
  abs (ready_view s) l' == abs (ready_view s) l
  /\ abs (snap_view s) l' == abs (snap_view s) l
  /\ abs (dur_view s) l' == abs (dur_view s) l
  /\ abs (profile_view s) l' == abs (profile_view s) l

let views_unchanged (s:sterm) (c c':config) : Type0 = views_same s c.facts c'.facts

let free_views_none (s:sterm) (fs:list fact)
  : Lemma (requires all_slot_free s fs = true)
          (ensures (forall (f:fact). L.mem f fs = true ==>
                      ready_view s f == None /\ snap_view s f == None
                      /\ dur_view s f == None /\ profile_view s f == None))
  = introduce forall (f:fact). L.mem f fs = true ==>
      ready_view s f == None /\ snap_view s f == None
      /\ dur_view s f == None /\ profile_view s f == None
    with introduce _ ==> _
    with _. all_slot_free_mem s fs f

let rewrite_free (s:sterm) (lin concl:list fact) (l r:list fact)
  : Lemma (requires remove_all lin l == Some r
                    /\ all_slot_free s lin = true /\ all_slot_free s concl = true)
          (ensures views_same s l (L.append concl r))
  = free_views_none s lin;
    free_views_none s concl;
    abs_remove_all_none (ready_view s) lin l r;
    abs_remove_all_none (snap_view s) lin l r;
    abs_remove_all_none (dur_view s) lin l r;
    abs_remove_all_none (profile_view s) lin l r;
    abs_append (ready_view s) concl r;
    abs_append (snap_view s) concl r;
    abs_append (dur_view s) concl r;
    abs_append (profile_view s) concl r;
    abs_all_free (ready_view s) concl;
    abs_all_free (snap_view s) concl;
    abs_all_free (dur_view s) concl;
    abs_all_free (profile_view s) concl

(* ------------------------------------------------------------------ *)
(* Non-interference: other slots and attacker steps                    *)
(* ------------------------------------------------------------------ *)

let rule_slot (r:rule_name) (sg:subst) (nu:fresh_subst) : sterm =
  match r with
  | R_Initialize -> fresh_term (nu "slot")
  | _ -> sg "slot"

(* Every fact and the slot action of a rule instance belong to the rule's
   slot; for any other slot the instance is invisible. *)
let other_slot_free (sys:system) (r:rule_name) (sg:subst) (nu:fresh_subst)
    (s:sterm)
  : Lemma (requires rule_slot r sg nu <> s)
          (ensures all_slot_free s (rule_linear sys r sg nu) = true
                   /\ all_slot_free s (rinst sys r sg nu).r_conclusions = true
                   /\ event_of s (actions (LRule r sg nu)) == None)
  = shape_ok sys r sg nu;
    label_actions_shape r sg nu

let other_slot_step (sys:system) (s:sterm) (c:config) (r:rule_name)
    (sg:subst) (nu:fresh_subst)
  : Lemma (requires rule_slot r sg nu <> s /\ rule_enabled sys c r sg nu = true)
          (ensures views_unchanged s c (rule_result sys c r sg nu)
                   /\ event_of s (actions (LRule r sg nu)) == None)
  = other_slot_free sys r sg nu s;
    let Some rest = remove_all (rule_linear sys r sg nu) c.facts in
    rewrite_free s (rule_linear sys r sg nu) (rinst sys r sg nu).r_conclusions
      c.facts rest

(* Fresh, ifresh, irecv and isend touch only Fr, In and Out facts. *)
let attacker_step_views (sys:system) (s:sterm) (c:config) (l:label)
    (c':config) (st:sstep sys c l c')
  : Lemma (requires ~(LRule? l))
          (ensures views_unchanged s c c' /\ event_of s (actions l) == None)
  = match st with
    | SFresh _ n _ -> ()
    | SAdvFresh _ n rest _ ->
        rewrite_free s [fr_fact n] [] c.facts rest
    | SRecv _ t rest _ ->
        rewrite_free s [out_fact t] [] c.facts rest
    | SSend _ t _ -> ()

let abs_core_unchanged (s:sterm) (c c':config) (h:strace) (l:label)
  : Lemma (requires views_unchanged s c c' /\ event_of s (actions l) == None)
          (ensures abs_core s c' (TSnoc h l) == abs_core s c h)
  = ()

(* ------------------------------------------------------------------ *)
(* Same-slot steps are core steps                                      *)
(* ------------------------------------------------------------------ *)

let split_one (#a:eqtype) (l:list a) (x:a) (r:list a) (sp:split l x r)
  : Lemma (requires L.length l = 1) (ensures l == [x] /\ r == [])
  = match sp with
    | SplitHere _ _ -> ()
    | SplitThere _ _ l' _ sp' -> split_nil #a x _ sp'

let enabled_rest (sys:system) (c:config) (r:rule_name) (sg:subst) (nu:fresh_subst)
  : Lemma (requires rule_enabled sys c r sg nu = true)
          (ensures Some? (remove_all (rule_linear sys r sg nu) c.facts)
                   /\ (rule_result sys c r sg nu).facts
                      == L.append (rinst sys r sg nu).r_conclusions
                           (Some?.v (remove_all (rule_linear sys r sg nu) c.facts))
                   /\ all_present (rule_persistent sys r sg nu) c.facts = true
                   /\ (rule_result sys c r sg nu).drawn == c.drawn
                   /\ (rule_result sys c r sg nu).know == c.know)
  = ()

let rec all_present_mem (ps l:list fact) (p:fact)
  : Lemma (requires all_present ps l = true /\ L.mem p ps = true)
          (ensures L.mem p l = true) (decreases ps)
  = match ps with
    | [] -> ()
    | x :: r -> if x = p then () else all_present_mem r l p

(* The result type of a same-slot step: the matching core event and step,
   and one durable fact afterwards. *)
let same_slot_result (s:sterm) (h:strace) (c:config) (r:rule_name)
    (sg:subst) (nu:fresh_subst) : Type
  = e:cevent
    & step_core proper_subterm (abs_core s c h) e
        (abs_core s (rule_result Original c r sg nu) (TSnoc h (LRule r sg nu)))
    & squash (event_of s (actions (LRule r sg nu)) == Some e
              /\ L.length (abs (dur_view s) (rule_result Original c r sg nu).facts) = 1)

let coerce_step (#c #c1 #c2:cstate) (#e:cevent)
    (st:step_core proper_subterm c e c1) (pf:squash (c1 == c2))
  : step_core proper_subterm c e c2
  = st

(* A proof term for a true boolean. *)
let bproof (b:bool) (_:squash (b = true)) : b2t b =
  FStar.Squash.join_squash (FStar.Squash.get_proof (b2t b))

(* A proof term for a negated membership, from the boolean test. *)
let not_memP_of_mem (#a:eqtype) (x:a) (l:list a) (h:squash (L.mem x l = false))
  : ~(L.memP x l)
  = FStar.List.Tot.Properties.mem_memP x l;
    FStar.Squash.return_squash #(L.memP x l -> GTot Prims.l_False)
      (fun (m:L.memP x l) -> (let r : Prims.l_False = () in r))

(* A proof term for membership, from the propositional fact. *)
let rec memP_proof (#a:eqtype) (x:a) (l:list a)
  : Pure (L.memP x l) (requires L.memP x l) (ensures fun _ -> True) (decreases l)
  = match l with
    | y :: q ->
        if x = y then
          FStar.Squash.return_squash #(Prims.sum (x == y) (L.memP x q))
            (Prims.Left (FStar.Squash.return_squash #(Prims.equals x y) Prims.Refl))
        else
          FStar.Squash.return_squash #(Prims.sum (x == y) (L.memP x q))
            (Prims.Right (memP_proof x q))

let read_snapshot_same_slot (s:sterm) (h:strace) (c:config) (sg:subst)
    (nu:fresh_subst)
    (en:squash (rule_enabled Original c R_ReadSnapshot sg nu = true))
    (sl:squash (sg "slot" == s))
    (one:squash (L.length (abs (dur_view s) c.facts) = 1))
    (fresh:squash (L.mem (fresh_term (nu "tx")) (used_of (project s h)) = false))
  : same_slot_result s h c R_ReadSnapshot sg nu
  = shape_ok Original R_ReadSnapshot sg nu;
    label_actions_shape R_ReadSnapshot sg nu;
    enabled_rest Original c R_ReadSnapshot sg nu;
    let g = sg "gen" in
    let p = sg "pinned" in
    let tx = fresh_term (nu "tx") in
    let frf = fr_fact (nu "tx") in
    let rgf = f_ready s g p in
    let snf = f_snapshot s tx g p in
    let fs = c.facts in
    let Some l1 = remove1 frf fs in
    all_present_mem [rgf] fs rgf;
    abs_mem (ready_view s) rgf fs (to_gen g, p);
    abs_remove1_none (ready_view s) frf fs l1;
    abs_remove1_none (snap_view s) frf fs l1;
    abs_remove1_none (dur_view s) frf fs l1;
    let cs = abs_core s c h in
    let st = CReadSnapshot cs tx (to_gen g) p (not_memP_of_mem tx cs.used fresh)
               (memP_proof (to_gen g, p) cs.ready) in
    let c' = rule_result Original c R_ReadSnapshot sg nu in
    assert (c'.facts == snf :: l1);
    let st' = coerce_step st () in
    (| ESnapshotRead tx (to_gen g) p, st', () |)

let persist_journal_same_slot (s:sterm) (h:strace) (c:config) (sg:subst)
    (nu:fresh_subst)
    (en:squash (rule_enabled Original c R_PersistJournal sg nu = true))
    (sl:squash (sg "slot" == s))
    (one:squash (L.length (abs (dur_view s) c.facts) = 1))
    (inc:squash (proper_subterm (sg "pinned") (sg "next_revision") = true))
  : same_slot_result s h c R_PersistJournal sg nu
  = shape_ok Original R_PersistJournal sg nu;
    label_actions_shape R_PersistJournal sg nu;
    enabled_rest Original c R_PersistJournal sg nu;
    let g = sg "gen" in
    let p = sg "pinned" in
    let vr = sg "vrev" in
    let vp = sg "vpayload" in
    let tx = sg "tx" in
    let nr = sg "next_revision" in
    let pl = sg "payload" in
    let dcf = f_clean s g p vr vp in
    let snf = f_snapshot s tx g p in
    let inf = in_fact (SPair nr pl) in
    let dpf = f_pending s tx (successor g) nr pl vr vp in
    let fs = c.facts in
    let Some l1 = remove1 dcf fs in
    let Some l2 = remove1 snf l1 in
    let Some l3 = remove1 inf l2 in
    let ph0 = Clean (to_gen g) p vr vp in
    let spd = abs_remove1_split (dur_view s) dcf fs l1 ph0 in
    split_one (abs (dur_view s) fs) ph0 (abs (dur_view s) l1) spd;
    abs_remove1_none (dur_view s) snf l1 l2;
    abs_remove1_none (dur_view s) inf l2 l3;
    abs_remove1_none (snap_view s) dcf fs l1;
    let x = (tx, to_gen g, p) in
    let sps = abs_remove1_split (snap_view s) snf l1 l2 x in
    abs_remove1_none (snap_view s) inf l2 l3;
    abs_remove1_none (ready_view s) dcf fs l1;
    abs_remove1_none (ready_view s) snf l1 l2;
    abs_remove1_none (ready_view s) inf l2 l3;
    let cs = abs_core s c h in
    let sps' : split cs.snaps x (abs (snap_view s) l2) = sps in
    assert (abs (dur_view s) fs == [ph0]);
    assert (cs.ph == ph0);
    let st = CPersistJournal cs tx (to_gen g) p vr vp nr pl
               (abs (snap_view s) l2) (bproof (cs.ph = Clean (to_gen g) p vr vp) ())
               sps' (bproof (proper_subterm p nr) ()) in
    let c' = rule_result Original c R_PersistJournal sg nu in
    assert (c'.facts == dpf :: l3);
    let st' = coerce_step st () in
    (| EJournal tx (GS (to_gen g)) p nr pl, st', () |)

let persist_vault_same_slot (s:sterm) (h:strace) (c:config) (sg:subst)
    (nu:fresh_subst)
    (en:squash (rule_enabled Original c R_PersistVault sg nu = true))
    (sl:squash (sg "slot" == s))
    (one:squash (L.length (abs (dur_view s) c.facts) = 1))
  : same_slot_result s h c R_PersistVault sg nu
  = shape_ok Original R_PersistVault sg nu;
    label_actions_shape R_PersistVault sg nu;
    enabled_rest Original c R_PersistVault sg nu;
    let tx = sg "tx" in
    let g = sg "gen" in
    let n = sg "next" in
    let pl = sg "payload" in
    let vr = sg "vrev" in
    let vp = sg "vpayload" in
    let dpf = f_pending s tx g n pl vr vp in
    let daf = f_applied s tx g n pl n pl in
    let fs = c.facts in
    let Some l1 = remove1 dpf fs in
    let ph0 = Pending tx (to_gen g) n pl vr vp in
    let spd = abs_remove1_split (dur_view s) dpf fs l1 ph0 in
    split_one (abs (dur_view s) fs) ph0 (abs (dur_view s) l1) spd;
    abs_remove1_none (snap_view s) dpf fs l1;
    abs_remove1_none (ready_view s) dpf fs l1;
    let cs = abs_core s c h in
    let st = CPersistVault cs tx (to_gen g) n pl vr vp
               (bproof (cs.ph = Pending tx (to_gen g) n pl vr vp) ()) in
    let c' = rule_result Original c R_PersistVault sg nu in
    assert (c'.facts == daf :: l1);
    let st' = coerce_step st () in
    (| EVault tx (to_gen g) n pl, st', () |)

let clear_journal_same_slot (s:sterm) (h:strace) (c:config) (sg:subst)
    (nu:fresh_subst)
    (en:squash (rule_enabled Original c R_ClearJournal sg nu = true))
    (sl:squash (sg "slot" == s))
    (one:squash (L.length (abs (dur_view s) c.facts) = 1))
  : same_slot_result s h c R_ClearJournal sg nu
  = shape_ok Original R_ClearJournal sg nu;
    label_actions_shape R_ClearJournal sg nu;
    enabled_rest Original c R_ClearJournal sg nu;
    let tx = sg "tx" in
    let g = sg "gen" in
    let p = sg "pinned" in
    let i = sg "intended" in
    let vr = sg "vrev" in
    let vp = sg "vpayload" in
    let daf = f_applied s tx g p i vr vp in
    let dcf = f_clean s g p vr vp in
    let rgf = f_ready s g p in
    let fs = c.facts in
    let Some l1 = remove1 daf fs in
    let ph0 = Applied tx (to_gen g) p i vr vp in
    let spd = abs_remove1_split (dur_view s) daf fs l1 ph0 in
    split_one (abs (dur_view s) fs) ph0 (abs (dur_view s) l1) spd;
    abs_remove1_none (snap_view s) daf fs l1;
    abs_remove1_none (ready_view s) daf fs l1;
    let cs = abs_core s c h in
    let st = CClearJournal cs tx (to_gen g) p i vr vp
               (bproof (cs.ph = Applied tx (to_gen g) p i vr vp) ()) in
    let c' = rule_result Original c R_ClearJournal sg nu in
    assert (c'.facts == dcf :: rgf :: l1);
    let st' = coerce_step st () in
    (| EClear tx (to_gen g) p, st', () |)

let crash_same_slot (s:sterm) (h:strace) (c:config) (sg:subst)
    (nu:fresh_subst)
    (en:squash (rule_enabled Original c R_Crash sg nu = true))
    (sl:squash (sg "slot" == s))
    (one:squash (L.length (abs (dur_view s) c.facts) = 1))
  : same_slot_result s h c R_Crash sg nu
  = shape_ok Original R_Crash sg nu;
    label_actions_shape R_Crash sg nu;
    enabled_rest Original c R_Crash sg nu;
    let cs = abs_core s c h in
    let st = CCrash cs (bproof (cs.opened = true) ()) in
    let c' = rule_result Original c R_Crash sg nu in
    assert (c'.facts == c.facts);
    let st' = coerce_step st () in
    (| ECrash, st', () |)

let open_vault_same_slot (s:sterm) (h:strace) (c:config) (sg:subst)
    (nu:fresh_subst)
    (en:squash (rule_enabled Original c R_OpenVault sg nu = true))
    (sl:squash (sg "slot" == s))
    (one:squash (L.length (abs (dur_view s) c.facts) = 1))
  : same_slot_result s h c R_OpenVault sg nu
  = shape_ok Original R_OpenVault sg nu;
    label_actions_shape R_OpenVault sg nu;
    enabled_rest Original c R_OpenVault sg nu;
    let g = sg "gen" in
    let p = sg "pinned" in
    let rv = sg "revision" in
    let pl = sg "payload" in
    let dcf = f_clean s g p rv pl in
    let fs = c.facts in
    let Some l1 = remove1 dcf fs in
    let ph0 = Clean (to_gen g) p rv pl in
    let spd = abs_remove1_split (dur_view s) dcf fs l1 ph0 in
    split_one (abs (dur_view s) fs) ph0 (abs (dur_view s) l1) spd;
    abs_remove1_none (snap_view s) dcf fs l1;
    abs_remove1_none (ready_view s) dcf fs l1;
    let cs = abs_core s c h in
    let st = COpenVault cs (to_gen g) p rv pl
               (bproof (cs.ph = Clean (to_gen g) p rv pl) ()) in
    let c' = rule_result Original c R_OpenVault sg nu in
    assert (c'.facts == dcf :: l1);
    let st' = coerce_step st () in
    (| EOpened (to_gen g) p rv pl, st', () |)

(* Initialize of a slot with no facts yet starts the core trace. *)
let initialize_same_slot (s:sterm) (h:strace) (c:config) (sg:subst)
    (nu:fresh_subst)
  : Lemma (requires rule_enabled Original c R_Initialize sg nu = true
                    /\ fresh_term (nu "slot") == s
                    /\ project s h == Nil
                    /\ abs (ready_view s) c.facts == []
                    /\ abs (snap_view s) c.facts == []
                    /\ abs (dur_view s) c.facts == [])
          (ensures
             abs_core s (rule_result Original c R_Initialize sg nu)
               (TSnoc h (LRule R_Initialize sg nu))
             == init_core initial (fresh_term (nu "item"))
             /\ project s (TSnoc h (LRule R_Initialize sg nu))
                == Snoc Nil EInitialized
             /\ L.length (abs (dur_view s)
                  (rule_result Original c R_Initialize sg nu).facts) = 1)
  = shape_ok Original R_Initialize sg nu;
    label_actions_shape R_Initialize sg nu;
    enabled_rest Original c R_Initialize sg nu;
    let fs = c.facts in
    let Some l1 = remove1 (fr_fact (nu "slot")) fs in
    let Some l2 = remove1 (fr_fact (nu "item")) l1 in
    abs_remove1_none (ready_view s) (fr_fact (nu "slot")) fs l1;
    abs_remove1_none (ready_view s) (fr_fact (nu "item")) l1 l2;
    abs_remove1_none (snap_view s) (fr_fact (nu "slot")) fs l1;
    abs_remove1_none (snap_view s) (fr_fact (nu "item")) l1 l2;
    abs_remove1_none (dur_view s) (fr_fact (nu "slot")) fs l1;
    abs_remove1_none (dur_view s) (fr_fact (nu "item")) l1 l2

(* A rule of a slot with no facts yet, other than Initialize, is disabled. *)
let uninit_disabled (s:sterm) (c:config) (r:rule_name) (sg:subst)
    (nu:fresh_subst)
  : Lemma (requires rule_enabled Original c r sg nu = true
                    /\ rule_slot r sg nu == s /\ r <> R_Initialize
                    /\ abs (ready_view s) c.facts == []
                    /\ abs (dur_view s) c.facts == []
                    /\ abs (profile_view s) c.facts == [])
          (ensures False)
  = shape_ok Original r sg nu;
    enabled_rest Original c r sg nu;
    let fs = c.facts in
    match r with
    | R_ReadSnapshot ->
        let rgf = f_ready s (sg "gen") (sg "pinned") in
        all_present_mem [rgf] fs rgf;
        abs_mem (ready_view s) rgf fs (to_gen (sg "gen"), sg "pinned")
    | R_PersistJournal ->
        let f = f_clean s (sg "gen") (sg "pinned") (sg "vrev") (sg "vpayload") in
        remove1_mem f fs (Some?.v (remove1 f fs));
        abs_mem (dur_view s) f fs
          (Clean (to_gen (sg "gen")) (sg "pinned") (sg "vrev") (sg "vpayload"))
    | R_PersistVault ->
        let f = f_pending s (sg "tx") (sg "gen") (sg "next") (sg "payload")
                  (sg "vrev") (sg "vpayload") in
        remove1_mem f fs (Some?.v (remove1 f fs));
        abs_mem (dur_view s) f fs
          (Pending (sg "tx") (to_gen (sg "gen")) (sg "next") (sg "payload")
             (sg "vrev") (sg "vpayload"))
    | R_ClearJournal ->
        let f = f_applied s (sg "tx") (sg "gen") (sg "pinned") (sg "intended")
                  (sg "vrev") (sg "vpayload") in
        remove1_mem f fs (Some?.v (remove1 f fs));
        abs_mem (dur_view s) f fs
          (Applied (sg "tx") (to_gen (sg "gen")) (sg "pinned") (sg "intended")
             (sg "vrev") (sg "vpayload"))
    | R_Crash ->
        let f = f_profile s in
        all_present_mem [f] fs f;
        abs_mem (profile_view s) f fs ()
    | R_OpenVault ->
        let f = f_clean s (sg "gen") (sg "pinned") (sg "revision") (sg "payload") in
        remove1_mem f fs (Some?.v (remove1 f fs));
        abs_mem (dur_view s) f fs
          (Clean (to_gen (sg "gen")) (sg "pinned") (sg "revision") (sg "payload"))
