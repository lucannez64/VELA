module M28_source_terms

(* P2a: source-term representation for the M28 share-journal model.

   This module transcribes the term algebra, facts and seven rule instances of
   security/formal/m28_share_journal.spthy, defines Tamarin's strict-subterm
   order on that algebra, and proves the order laws and well-foundedness.  It
   then embeds the unary revision fragment 'initial'/successor(...) into the
   concrete term type of M28TraceEquivalence, proves the embedding injective,
   and proves that the source order is exactly the encoded order on that
   fragment.  That discharges the strict-order record premise for the unary
   successor revisions (the generation chain, and pins that lie in the same
   fragment).  Adversary-supplied pins outside the fragment are represented in
   [sterm] but are not mapped to the core type.

   Scope.  The .spthy declares `functions: successor/1` and no `equations:`
   block; the only builtin term constructor used is Tamarin's pairing
   `<_,_>` (in `In(<next_revision, payload>)`).  This module therefore models
   the free term algebra over public names, fresh names, rule variables,
   successor/1 and pairs, with no equational theory.  The full algebra is
   represented in [sterm]; only the 'initial'/successor fragment is mapped to
   M28TraceEquivalence.term, because that core type has no name or pair
   constructors.  In particular, an adversary-supplied `next_revision` is an
   arbitrary [sterm], not necessarily a revision term.  Global freshness
   (`Fr`), input derivability (`In`) and multi-slot projection remain outside
   this module (plan steps P2b/P2c). *)

open M28TraceEquivalence

(* ------------------------------------------------------------------ *)
(* Source terms                                                        *)
(* ------------------------------------------------------------------ *)

(* Tamarin names: public names are written 'name' and fresh names ~name. *)
type name =
  | PublicName : string -> name
  | FreshName : string -> name

(* The .spthy contains exactly one declared function symbol:

       functions: successor/1

   `successor` is unary.  Tamarin's builtin pairing is the only other term
   constructor M28 uses. *)
type fn_symbol =
  | Successor

let fn_arity (f:fn_symbol) : Tot nat =
  match f with
  | Successor -> 1

(* Source terms: rule variables, names, successor applications and pairs. *)
type sterm =
  | SVar : string -> sterm
  | SName : name -> sterm
  | SApp : fn_symbol -> sterm -> sterm
  | SPair : sterm -> sterm -> sterm

let variable (s:string) : sterm = SVar s
let public_name (s:string) : sterm = SName (PublicName s)
let fresh_name (s:string) : sterm = SName (FreshName s)
let initial : sterm = public_name "initial"
let successor (t:sterm) : sterm = SApp Successor t
let tuple (a:sterm) (b:sterm) : sterm = SPair a b

let rec sterm_size (t:sterm) : Tot nat (decreases t) =
  match t with
  | SVar _ -> 0
  | SName _ -> 0
  | SApp _ a -> 1 + sterm_size a
  | SPair a b -> 1 + sterm_size a + sterm_size b

(* Tamarin's strict subterm order t << u: t occurs properly below u.  This is
   the ordering used by the Increasing restriction and by
   committed_pins_never_decrease. *)
let rec proper_subterm (x:sterm) (y:sterm) : Tot bool (decreases y) =
  match y with
  | SVar _ -> false
  | SName _ -> false
  | SApp _ a -> if x = a then true else proper_subterm x a
  | SPair a b ->
      if x = a then true
      else if x = b then true
      else proper_subterm x a || proper_subterm x b

let rec proper_subterm_size (x:sterm) (y:sterm)
  : Lemma (requires proper_subterm x y = true)
          (ensures sterm_size x < sterm_size y)
          (decreases y)
  = match y with
    | SVar _ -> ()
    | SName _ -> ()
    | SApp _ a ->
        if x = a then ()
        else proper_subterm_size x a
    | SPair a b ->
        if x = a then ()
        else if x = b then ()
        else if proper_subterm x a then proper_subterm_size x a
        else proper_subterm_size x b

let rec proper_subterm_trans (x:sterm) (y:sterm) (z:sterm)
  : Lemma (requires proper_subterm x y = true /\ proper_subterm y z = true)
          (ensures proper_subterm x z = true)
          (decreases z)
  = match z with
    | SVar _ -> ()
    | SName _ -> ()
    | SApp _ a ->
        if y = a then ()
        else proper_subterm_trans x y a
    | SPair a b ->
        if y = a then ()
        else if y = b then ()
        else if proper_subterm y a then proper_subterm_trans x y a
        else proper_subterm_trans x y b

let proper_subterm_irrefl (x:sterm)
  : Lemma (proper_subterm x x = false)
  = if proper_subterm x x then (proper_subterm_size x x; assert False) else ()

(* Type-valued form of the order, for well-foundedness. *)
let proper_subterm_t (x:sterm) (y:sterm) : Type =
  proper_subterm x y = true

(* Inductive accessibility and well-foundedness, defined locally.  (The
   FStar.WellFounded library module is avoided because checking it emits
   warning 242 under --cache_off, which the journal gate treats as failure.
   This is the standard accessibility predicate, not a weakened statement.) *)
noeq type acc_subterm : sterm -> Type =
  | AccSubtermIntro :
      (x:sterm) ->
      (step:(y:sterm -> proper_subterm_t y x -> acc_subterm y)) ->
      acc_subterm x

let well_founded_subterm : Type = (x:sterm) -> acc_subterm x

(* Well-foundedness, from the strict decrease of sterm_size. *)
let rec subterm_accessible (y:sterm)
  : Tot (acc_subterm y) (decreases (sterm_size y))
  = AccSubtermIntro y
      (fun (x:sterm) (hx:proper_subterm_t x y) ->
        proper_subterm_size x y;
        subterm_accessible x)

let subterm_well_founded : well_founded_subterm =
  fun (x:sterm) -> subterm_accessible x

(* ------------------------------------------------------------------ *)
(* Facts and the seven M28 rule instances                              *)
(* ------------------------------------------------------------------ *)

(* Fact symbols with their arities, read from m28_share_journal.spthy. *)
type fact_symbol =
  | F_Fr
  | F_Profile
  | F_ReadyGeneration
  | F_DiskClean
  | F_Chain
  | F_Out
  | F_Snapshot
  | F_In
  | F_DiskPending
  | F_DiskApplied
  | F_Initialized
  | F_SnapshotRead
  | F_RevisionIncreases
  | F_JournalDurable
  | F_VaultDurable
  | F_JournalCleared
  | F_Crash
  | F_Opened

let fact_arity (s:fact_symbol) : Tot nat =
  match s with
  | F_Fr -> 1
  | F_Profile -> 1
  | F_ReadyGeneration -> 3
  | F_DiskClean -> 5
  | F_Chain -> 3
  | F_Out -> 1
  | F_Snapshot -> 4
  | F_In -> 1
  | F_DiskPending -> 7
  | F_DiskApplied -> 7
  | F_Initialized -> 1
  | F_SnapshotRead -> 4
  | F_RevisionIncreases -> 2
  | F_JournalDurable -> 6
  | F_VaultDurable -> 5
  | F_JournalCleared -> 4
  | F_Crash -> 1
  | F_Opened -> 5

(* A fact is a symbol, its persistence annotation (!) and its term arguments.
   Facts form multisets in Tamarin; a rule side is represented by a list, so
   duplicate occurrences are retained. *)
type fact = {
  f_sym : fact_symbol;
  f_persistent : bool;
  f_args : list sterm;
}

type fact_multiset = list fact

type rule_name =
  | R_Initialize
  | R_ReadSnapshot
  | R_PersistJournal
  | R_PersistVault
  | R_ClearJournal
  | R_Crash
  | R_OpenVault

type rule_instance = {
  r_name : rule_name;
  r_premises : fact_multiset;
  r_actions : fact_multiset;
  r_conclusions : fact_multiset;
}

let mk_fact (s:fact_symbol) (persistent:bool) (args:list sterm) : fact =
  { f_sym = s; f_persistent = persistent; f_args = args }

let rec list_length (#a:Type) (xs:list a) : Tot nat (decreases xs) =
  match xs with
  | [] -> 0
  | _ :: rest -> 1 + list_length rest

let fact_arity_ok (f:fact) : bool =
  list_length f.f_args = fact_arity f.f_sym

let rec facts_arity_ok (fs:list fact) : Tot bool (decreases fs) =
  match fs with
  | [] -> true
  | f :: rest -> fact_arity_ok f && facts_arity_ok rest

(* Initialize: [ Fr(~slot), Fr(~item) ] --[ Initialized(~slot) ]->
     [ !Profile(~slot), !ReadyGeneration(~slot,'initial','initial'),
       DiskClean(~slot,'initial','initial','initial',~item),
       Chain(~slot,'initial','initial'), Out(~slot) ] *)
let initialize_rule : rule_instance = {
  r_name = R_Initialize;
  r_premises = [
    mk_fact F_Fr false [fresh_name "slot"];
    mk_fact F_Fr false [fresh_name "item"] ];
  r_actions = [
    mk_fact F_Initialized false [fresh_name "slot"] ];
  r_conclusions = [
    mk_fact F_Profile true [fresh_name "slot"];
    mk_fact F_ReadyGeneration true [fresh_name "slot"; initial; initial];
    mk_fact F_DiskClean false
      [fresh_name "slot"; initial; initial; initial; fresh_name "item"];
    mk_fact F_Chain false [fresh_name "slot"; initial; initial];
    mk_fact F_Out false [fresh_name "slot"] ];
}

(* ReadSnapshot: [ !ReadyGeneration(slot,gen,pinned), Fr(~tx) ]
     --[ SnapshotRead(slot,~tx,gen,pinned) ]->
     [ Snapshot(slot,~tx,gen,pinned) ] *)
let read_snapshot_rule : rule_instance = {
  r_name = R_ReadSnapshot;
  r_premises = [
    mk_fact F_ReadyGeneration true
      [variable "slot"; variable "gen"; variable "pinned"];
    mk_fact F_Fr false [fresh_name "tx"] ];
  r_actions = [
    mk_fact F_SnapshotRead false
      [variable "slot"; fresh_name "tx"; variable "gen"; variable "pinned"] ];
  r_conclusions = [
    mk_fact F_Snapshot false
      [variable "slot"; fresh_name "tx"; variable "gen"; variable "pinned"] ];
}

(* PersistJournal:
     [ DiskClean(slot,gen,pinned,vrev,vpayload), Chain(slot,gen,pinned),
       Snapshot(slot,tx,gen,pinned), In(<next_revision,payload>) ]
     --[ RevisionIncreases(pinned,next_revision),
         JournalDurable(slot,tx,successor(gen),pinned,next_revision,payload) ]->
     [ DiskPending(slot,tx,successor(gen),next_revision,payload,vrev,vpayload),
       Chain(slot,successor(gen),next_revision) ] *)
let persist_journal_rule : rule_instance = {
  r_name = R_PersistJournal;
  r_premises = [
    mk_fact F_DiskClean false
      [variable "slot"; variable "gen"; variable "pinned";
       variable "vrev"; variable "vpayload"];
    mk_fact F_Chain false
      [variable "slot"; variable "gen"; variable "pinned"];
    mk_fact F_Snapshot false
      [variable "slot"; variable "tx"; variable "gen"; variable "pinned"];
    mk_fact F_In false
      [tuple (variable "next_revision") (variable "payload")] ];
  r_actions = [
    mk_fact F_RevisionIncreases false
      [variable "pinned"; variable "next_revision"];
    mk_fact F_JournalDurable false
      [variable "slot"; variable "tx"; successor (variable "gen");
       variable "pinned"; variable "next_revision"; variable "payload"] ];
  r_conclusions = [
    mk_fact F_DiskPending false
      [variable "slot"; variable "tx"; successor (variable "gen");
       variable "next_revision"; variable "payload"; variable "vrev";
       variable "vpayload"];
    mk_fact F_Chain false
      [variable "slot"; successor (variable "gen"); variable "next_revision"] ];
}

(* PersistVault:
     [ DiskPending(slot,tx,gen,next,payload,vrev,vpayload) ]
     --[ VaultDurable(slot,tx,gen,next,payload) ]->
     [ DiskApplied(slot,tx,gen,next,payload,next,payload) ] *)
let persist_vault_rule : rule_instance = {
  r_name = R_PersistVault;
  r_premises = [
    mk_fact F_DiskPending false
      [variable "slot"; variable "tx"; variable "gen"; variable "next";
       variable "payload"; variable "vrev"; variable "vpayload"] ];
  r_actions = [
    mk_fact F_VaultDurable false
      [variable "slot"; variable "tx"; variable "gen"; variable "next";
       variable "payload"] ];
  r_conclusions = [
    mk_fact F_DiskApplied false
      [variable "slot"; variable "tx"; variable "gen"; variable "next";
       variable "payload"; variable "next"; variable "payload"] ];
}

(* ClearJournal:
     [ DiskApplied(slot,tx,gen,pinned,intended,vrev,vpayload),
       Chain(slot,gen,pinned) ]
     --[ JournalCleared(slot,tx,gen,pinned) ]->
     [ DiskClean(slot,gen,pinned,vrev,vpayload), Chain(slot,gen,pinned),
       !ReadyGeneration(slot,gen,pinned) ] *)
let clear_journal_rule : rule_instance = {
  r_name = R_ClearJournal;
  r_premises = [
    mk_fact F_DiskApplied false
      [variable "slot"; variable "tx"; variable "gen"; variable "pinned";
       variable "intended"; variable "vrev"; variable "vpayload"];
    mk_fact F_Chain false
      [variable "slot"; variable "gen"; variable "pinned"] ];
  r_actions = [
    mk_fact F_JournalCleared false
      [variable "slot"; variable "tx"; variable "gen"; variable "pinned"] ];
  r_conclusions = [
    mk_fact F_DiskClean false
      [variable "slot"; variable "gen"; variable "pinned";
       variable "vrev"; variable "vpayload"];
    mk_fact F_Chain false
      [variable "slot"; variable "gen"; variable "pinned"];
    mk_fact F_ReadyGeneration true
      [variable "slot"; variable "gen"; variable "pinned"] ];
}

(* Crash: [ !Profile(slot) ] --[ Crash(slot) ]-> [] *)
let crash_rule : rule_instance = {
  r_name = R_Crash;
  r_premises = [
    mk_fact F_Profile true [variable "slot"] ];
  r_actions = [
    mk_fact F_Crash false [variable "slot"] ];
  r_conclusions = [];
}

(* OpenVault:
     [ DiskClean(slot,gen,pinned,revision,payload) ]
     --[ Opened(slot,gen,pinned,revision,payload) ]->
     [ DiskClean(slot,gen,pinned,revision,payload) ] *)
let open_vault_rule : rule_instance = {
  r_name = R_OpenVault;
  r_premises = [
    mk_fact F_DiskClean false
      [variable "slot"; variable "gen"; variable "pinned";
       variable "revision"; variable "payload"] ];
  r_actions = [
    mk_fact F_Opened false
      [variable "slot"; variable "gen"; variable "pinned";
       variable "revision"; variable "payload"] ];
  r_conclusions = [
    mk_fact F_DiskClean false
      [variable "slot"; variable "gen"; variable "pinned";
       variable "revision"; variable "payload"] ];
}

let m28_rule (r:rule_name) : rule_instance =
  match r with
  | R_Initialize -> initialize_rule
  | R_ReadSnapshot -> read_snapshot_rule
  | R_PersistJournal -> persist_journal_rule
  | R_PersistVault -> persist_vault_rule
  | R_ClearJournal -> clear_journal_rule
  | R_Crash -> crash_rule
  | R_OpenVault -> open_vault_rule

(* Source drift check: every fact in every transcribed rule instance has the
   arity declared by [fact_arity].  This is not a parser proof. *)
let m28_rule_arities (r:rule_name)
  : Lemma (facts_arity_ok (m28_rule r).r_premises
           /\ facts_arity_ok (m28_rule r).r_actions
           /\ facts_arity_ok (m28_rule r).r_conclusions)
  = match r with
    | R_Initialize -> ()
    | R_ReadSnapshot -> ()
    | R_PersistJournal -> ()
    | R_PersistVault -> ()
    | R_ClearJournal -> ()
    | R_Crash -> ()
    | R_OpenVault -> ()

(* ------------------------------------------------------------------ *)
(* The revision fragment and the encoding into M28TraceEquivalence     *)
(* ------------------------------------------------------------------ *)

(* The unary fragment used by M28's generations (and by the concrete two-commit
   witness's pins): 'initial' and finite iterations of successor/1.  A
   PersistJournal input next_revision is an arbitrary term, so not every pin is
   in this fragment. *)
type source_revision =
  | RevInitial
  | RevSuccessor of source_revision

let rec source_revision_to_term (r:source_revision) : Tot sterm (decreases r) =
  match r with
  | RevInitial -> initial
  | RevSuccessor r' -> successor (source_revision_to_term r')

let rec encode_revision (r:source_revision)
  : Tot M28TraceEquivalence.term (decreases r)
  = match r with
    | RevInitial -> M28TraceEquivalence.TInit
    | RevSuccessor r' ->
        M28TraceEquivalence.TSucc (encode_revision r')

let rec decode_revision (t:M28TraceEquivalence.term)
  : Tot source_revision (decreases t)
  = match t with
    | M28TraceEquivalence.TInit -> RevInitial
    | M28TraceEquivalence.TSucc t' ->
        RevSuccessor (decode_revision t')

let rec decode_encode_revision (r:source_revision)
  : Lemma (ensures decode_revision (encode_revision r) = r)
          (decreases r)
  = match r with
    | RevInitial -> ()
    | RevSuccessor r' -> decode_encode_revision r'

let encode_revision_injective (x:source_revision) (y:source_revision)
  : Lemma (requires encode_revision x = encode_revision y)
          (ensures x = y)
  = decode_encode_revision x;
    decode_encode_revision y

let rec source_revision_to_term_injective (x:source_revision) (y:source_revision)
  : Lemma (requires source_revision_to_term x = source_revision_to_term y)
          (ensures x = y)
          (decreases x)
  = match x with
    | RevInitial ->
        (match y with
         | RevInitial -> ()
         | RevSuccessor _ -> ())
    | RevSuccessor x' ->
        (match y with
         | RevInitial -> ()
         | RevSuccessor y' -> source_revision_to_term_injective x' y')

(* The source-to-source embedding and the core embedding agree. *)
let rec core_to_source_term (t:M28TraceEquivalence.term)
  : Tot sterm (decreases t)
  = match t with
    | M28TraceEquivalence.TInit -> initial
    | M28TraceEquivalence.TSucc t' ->
        successor (core_to_source_term t')

let rec source_revision_to_term_is_core (r:source_revision)
  : Lemma (ensures source_revision_to_term r = core_to_source_term (encode_revision r))
          (decreases r)
  = match r with
    | RevInitial -> ()
    | RevSuccessor r' -> source_revision_to_term_is_core r'

let rec core_to_source_term_injective (x:M28TraceEquivalence.term)
                                       (y:M28TraceEquivalence.term)
  : Lemma (requires core_to_source_term x = core_to_source_term y)
          (ensures x = y)
          (decreases x)
  = match x with
    | M28TraceEquivalence.TInit ->
        (match y with
         | M28TraceEquivalence.TInit -> ()
         | M28TraceEquivalence.TSucc _ -> ())
    | M28TraceEquivalence.TSucc x' ->
        (match y with
         | M28TraceEquivalence.TInit -> ()
         | M28TraceEquivalence.TSucc y' ->
             core_to_source_term_injective x' y')

(* The two equality decisions agree on the core image. *)
let core_term_eq_iff (x:M28TraceEquivalence.term)
                     (y:M28TraceEquivalence.term)
  : Lemma ((x = y) = (core_to_source_term x = core_to_source_term y))
  = if x = y then ()
    else if core_to_source_term x = core_to_source_term y then
      (core_to_source_term_injective x y; assert False)
    else ()

(* [proper_subterm] on the source representation is exactly the core module's
   [subterm] on the encoded image. *)
let rec core_subterm_matches (x:M28TraceEquivalence.term)
                             (y:M28TraceEquivalence.term)
  : Lemma (ensures M28TraceEquivalence.subterm x y
           = proper_subterm (core_to_source_term x) (core_to_source_term y))
          (decreases y)
  = match y with
    | M28TraceEquivalence.TInit -> ()
    | M28TraceEquivalence.TSucc y' ->
        core_term_eq_iff x y';
        core_subterm_matches x y'

(* The source order on revisions. *)
let source_order (x:source_revision) (y:source_revision) : bool =
  proper_subterm (source_revision_to_term x) (source_revision_to_term y)

let source_order_matches_core (x:source_revision) (y:source_revision)
  : Lemma (source_order x y
           = M28TraceEquivalence.subterm (encode_revision x) (encode_revision y))
  = source_revision_to_term_is_core x;
    source_revision_to_term_is_core y;
    core_subterm_matches (encode_revision x) (encode_revision y)

(* The existing concrete order record [term_order] is exactly the image of the
   source order on this fragment.  This is the strict-order record premise
   discharged for unary successor revisions. *)
let source_order_matches_term_order (x:source_revision) (y:source_revision)
  : Lemma (source_order x y
           = M28TraceEquivalence.term_order.lt
               (encode_revision x) (encode_revision y))
  = source_order_matches_core x y

let source_order_trans (x:source_revision) (y:source_revision) (z:source_revision)
  : Lemma (requires source_order x y = true /\ source_order y z = true)
          (ensures source_order x z = true)
  = proper_subterm_trans
      (source_revision_to_term x)
      (source_revision_to_term y)
      (source_revision_to_term z)

let source_order_irrefl (x:source_revision)
  : Lemma (source_order x x = false)
  = proper_subterm_irrefl (source_revision_to_term x)

let source_revision_order : strict_order source_revision = {
  lt = source_order;
  lt_trans = (fun x y z -> source_order_trans x y z);
  lt_irrefl = (fun x -> source_order_irrefl x);
}

(* Well-foundedness transfers from [proper_subterm] along the embedding. *)
let source_order_t (x:source_revision) (y:source_revision) : Type =
  source_order x y = true

noeq type acc_source_revision : source_revision -> Type =
  | AccSourceRevisionIntro :
      (x:source_revision) ->
      (step:(y:source_revision -> source_order_t y x -> acc_source_revision y)) ->
      acc_source_revision x

let well_founded_source_order : Type =
  (x:source_revision) -> acc_source_revision x

let source_revision_size (r:source_revision) : nat =
  sterm_size (source_revision_to_term r)

let rec source_revision_accessible (y:source_revision)
  : Tot (acc_source_revision y) (decreases (source_revision_size y))
  = AccSourceRevisionIntro y
      (fun (x:source_revision) (hx:source_order_t x y) ->
        proper_subterm_size
          (source_revision_to_term x)
          (source_revision_to_term y);
        source_revision_accessible x)

let source_order_wf : well_founded_source_order =
  fun (x:source_revision) -> source_revision_accessible x

(* ------------------------------------------------------------------ *)
(* Partial translation of arbitrary source terms                      *)
(* ------------------------------------------------------------------ *)

(* Only the 'initial'/successor fragment has an image in the core term type.
   The function returns None for every name, pair, variable or other
   application, so its domain is explicit.  It is used to state injectivity
   for all source terms that do have an image, not only the [source_revision]
   spelling. *)
let rec encode_source_term (t:sterm)
  : Tot (option M28TraceEquivalence.term) (decreases t)
  = match t with
    | SName (PublicName s) ->
        if s = "initial" then Some M28TraceEquivalence.TInit else None
    | SApp Successor t' ->
        (match encode_source_term t' with
         | Some c -> Some (M28TraceEquivalence.TSucc c)
         | None -> None)
    | _ -> None

let rec encode_source_term_revision (r:source_revision)
  : Lemma (ensures encode_source_term (source_revision_to_term r)
           = Some (encode_revision r))
          (decreases r)
  = match r with
    | RevInitial -> ()
    | RevSuccessor r' -> encode_source_term_revision r'

let rec encode_source_term_injective (x:sterm) (y:sterm)
  : Lemma (requires encode_source_term x = encode_source_term y
                    /\ encode_source_term x <> None)
          (ensures x = y)
          (decreases x)
  = match x with
    | SName (PublicName sx) ->
        if sx = "initial" then
          (match y with
           | SName (PublicName sy) -> ()
           | _ -> ())
        else ()
    | SApp Successor x' ->
        (match encode_source_term x' with
         | Some cx ->
             (match y with
              | SApp Successor y' ->
                  (match encode_source_term y' with
                   | Some cy -> encode_source_term_injective x' y'
                   | None -> ())
              | _ -> ())
         | None -> ())
    | _ -> ()

(* In particular, two source terms that both have an image and encode to the
   same core term are equal. *)
let encode_source_term_same_image (x:sterm) (y:sterm)
  : Lemma (requires encode_source_term x = encode_source_term y
                    /\ encode_source_term x <> None)
          (ensures x = y)
  = encode_source_term_injective x y
