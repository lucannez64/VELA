module M28_source_semantics

(* P2c: a Tamarin-style multiset-rewriting semantics for M28, with attacker
   derivability for In facts and Tamarin's global freshness of Fr names.

   The semantics is driven by the P2a rule schemas [M28_source_terms.m28_rule]:
   a protocol step instantiates one schema with a ground substitution and
   rewrites the state exactly as Tamarin does (linear premises are consumed,
   persistent premises must be present, conclusions are added, actions are
   recorded at the step's timepoint).  The builtin Tamarin rules are separate
   steps:

     Fresh   [] --[]-> [Fr(~n)]            (n globally unused)
     ifresh  [Fr(~n)] --[]-> [!KU(~n)]      (LAdvFresh)
     irecv   [Out(x)] --[]-> [!KD(x)]       (LRecv)
     isend   [!KU(x)] --[K(x)]-> [In(x)]    (LSend, x derivable)

   Attacker knowledge is the list [know] of received outputs and attacker
   fresh names; the !KU/!KD message-deduction rules are the inductive
   [derivable].  M28 has no equations beyond Tamarin's builtin pairing, so
   messages are the free terms over names, successor/1, fst/1, snd/1 and
   pairing in normal form (no fst/snd applied to a pair).  The K action of
   isend is not recorded: no M28 lemma or restriction mentions K.

   Two rule systems share this semantics: [Instrumented] uses the P2a
   transcription of the .spthy (with the Chain ghost fact) and [Original]
   erases every Chain fact from it, which is the seven-rule model of commit
   b8221e7.

   What is trusted: that these definitions are Tamarin's semantics for M28
   (multiset rewriting modulo the pairing equations, the builtin rules above,
   restriction filtering, and the reading of trace formulas below), and that
   the P2a schemas are the .spthy rules (checked syntactically by
   check-m28-transcription.py).  Nothing here is assumed inside F*. *)

open M28_source_terms

module L = FStar.List.Tot

(* ------------------------------------------------------------------ *)
(* Counting multisets                                                  *)
(* ------------------------------------------------------------------ *)

let rec cnt (#a:eqtype) (x:a) (l:list a) : Tot nat (decreases l) =
  match l with
  | [] -> 0
  | y :: r -> (if y = x then 1 else 0) + cnt x r

let rec cnt_append (#a:eqtype) (x:a) (l1 l2:list a)
  : Lemma (ensures cnt x (L.append l1 l2) = cnt x l1 + cnt x l2)
          (decreases l1)
  = match l1 with
    | [] -> ()
    | _ :: r -> cnt_append x r l2

let rec mem_cnt (#a:eqtype) (x:a) (l:list a)
  : Lemma (ensures L.mem x l = (cnt x l > 0)) (decreases l)
  = match l with
    | [] -> ()
    | _ :: r -> mem_cnt x r

(* ------------------------------------------------------------------ *)
(* Messages and instantiation                                          *)
(* ------------------------------------------------------------------ *)

(* A Tamarin message: a ground term in normal form modulo
   fst(<x,y>) = x and snd(<x,y>) = y. *)
let rec message (t:sterm) : Tot bool (decreases t) =
  match t with
  | SVar _ -> false
  | SName _ -> true
  | SApp Successor a -> message a
  | SApp Fst a -> message a && not (SPair? a)
  | SApp Snd a -> message a && not (SPair? a)
  | SPair a b -> message a && message b

(* Message variables and fresh variables of a rule.  A schema term
   SName (FreshName x) is the fresh-sorted variable ~x; it is instantiated
   with the fresh name [nu x].  Public names are constants. *)
type subst = string -> sterm
type fresh_subst = string -> string

let rec inst (sg:subst) (nu:fresh_subst) (t:sterm) : Tot sterm (decreases t) =
  match t with
  | SVar x -> sg x
  | SName (PublicName p) -> SName (PublicName p)
  | SName (FreshName x) -> SName (FreshName (nu x))
  | SApp f a -> SApp f (inst sg nu a)
  | SPair a b -> SPair (inst sg nu a) (inst sg nu b)

let rec inst_args (sg:subst) (nu:fresh_subst) (ts:list sterm)
  : Tot (list sterm) (decreases ts)
  = match ts with
    | [] -> []
    | t :: r -> inst sg nu t :: inst_args sg nu r

let inst_fact (sg:subst) (nu:fresh_subst) (f:fact) : fact =
  { f_sym = f.f_sym; f_persistent = f.f_persistent;
    f_args = inst_args sg nu f.f_args }

let rec inst_facts (sg:subst) (nu:fresh_subst) (fs:list fact)
  : Tot (list fact) (decreases fs)
  = match fs with
    | [] -> []
    | f :: r -> inst_fact sg nu f :: inst_facts sg nu r

let inst_rule (sg:subst) (nu:fresh_subst) (ri:rule_instance) : rule_instance =
  { r_name = ri.r_name;
    r_premises = inst_facts sg nu ri.r_premises;
    r_actions = inst_facts sg nu ri.r_actions;
    r_conclusions = inst_facts sg nu ri.r_conclusions }

(* A Tamarin rule instance is ground: every variable is a message. *)
let message_subst (sg:subst) : Type0 = forall (x:string). message (sg x) = true

(* ------------------------------------------------------------------ *)
(* The two rule systems                                                *)
(* ------------------------------------------------------------------ *)

let rec erase (fs:list fact) : Tot (list fact) (decreases fs) =
  match fs with
  | [] -> []
  | f :: r -> if f.f_sym = F_Chain then erase r else f :: erase r

let erase_rule (ri:rule_instance) : rule_instance =
  { r_name = ri.r_name;
    r_premises = erase ri.r_premises;
    r_actions = erase ri.r_actions;
    r_conclusions = erase ri.r_conclusions }

(* The original seven rules: the .spthy rules without the Chain ghost. *)
let original_rule (r:rule_name) : rule_instance = erase_rule (m28_rule r)

type system =
  | Original
  | Instrumented

let rule_of (sys:system) (r:rule_name) : rule_instance =
  match sys with
  | Instrumented -> m28_rule r
  | Original -> original_rule r

let rinst (sys:system) (r:rule_name) (sg:subst) (nu:fresh_subst)
  : rule_instance
  = inst_rule sg nu (rule_of sys r)

(* ------------------------------------------------------------------ *)
(* Multiset rewriting                                                  *)
(* ------------------------------------------------------------------ *)

let fr_fact (n:string) : fact = mk_fact F_Fr false [SName (FreshName n)]
let in_fact (t:sterm) : fact = mk_fact F_In false [t]
let out_fact (t:sterm) : fact = mk_fact F_Out false [t]

(* Remove one occurrence. *)
let rec remove1 (f:fact) (l:list fact) : Tot (option (list fact)) (decreases l) =
  match l with
  | [] -> None
  | x :: r ->
      if x = f then Some r
      else (match remove1 f r with
            | Some r' -> Some (x :: r')
            | None -> None)

(* Remove one occurrence of each element of [fs], with multiplicity. *)
let rec remove_all (fs:list fact) (l:list fact)
  : Tot (option (list fact)) (decreases fs)
  = match fs with
    | [] -> Some l
    | f :: r ->
        (match remove1 f l with
         | None -> None
         | Some l' -> remove_all r l')

let rec linear (fs:list fact) : Tot (list fact) (decreases fs) =
  match fs with
  | [] -> []
  | f :: r -> if f.f_persistent then linear r else f :: linear r

let rec persistent (fs:list fact) : Tot (list fact) (decreases fs) =
  match fs with
  | [] -> []
  | f :: r -> if f.f_persistent then f :: persistent r else persistent r

let rec all_present (ps:list fact) (l:list fact) : Tot bool (decreases ps) =
  match ps with
  | [] -> true
  | p :: r -> L.mem p l && all_present r l

let rec remove1_cnt (f g:fact) (l r:list fact)
  : Lemma (requires remove1 f l == Some r)
          (ensures cnt g l = cnt g r + (if f = g then 1 else 0))
          (decreases l)
  = match l with
    | [] -> ()
    | x :: l' ->
        if x = f then ()
        else (match remove1 f l' with
              | Some r' -> remove1_cnt f g l' r'
              | None -> ())

let remove1_cnt_all (f:fact) (l r:list fact)
  : Lemma (requires remove1 f l == Some r)
          (ensures forall (g:fact). cnt g l = cnt g r + (if f = g then 1 else 0))
  = introduce forall (g:fact). cnt g l = cnt g r + (if f = g then 1 else 0)
    with remove1_cnt f g l r

let rec remove_all_cnt (fs:list fact) (g:fact) (l r:list fact)
  : Lemma (requires remove_all fs l == Some r)
          (ensures cnt g l = cnt g r + cnt g fs)
          (decreases fs)
  = match fs with
    | [] -> ()
    | f :: fs' ->
        (match remove1 f l with
         | Some l' -> remove1_cnt f g l l'; remove_all_cnt fs' g l' r
         | None -> ())

let remove_all_cnt_all (fs:list fact) (l r:list fact)
  : Lemma (requires remove_all fs l == Some r)
          (ensures forall (g:fact). cnt g l = cnt g r + cnt g fs)
  = introduce forall (g:fact). cnt g l = cnt g r + cnt g fs
    with remove_all_cnt fs g l r

let rec remove1_some (f:fact) (l:list fact)
  : Lemma (requires cnt f l > 0) (ensures Some? (remove1 f l)) (decreases l)
  = match l with
    | [] -> ()
    | x :: r -> if x = f then () else remove1_some f r

let rec remove_all_some (fs:list fact) (l:list fact)
  : Lemma (requires forall (g:fact). cnt g fs <= cnt g l)
          (ensures Some? (remove_all fs l))
          (decreases fs)
  = match fs with
    | [] -> ()
    | f :: fs' ->
        remove1_some f l;
        let Some l' = remove1 f l in
        remove1_cnt_all f l l';
        remove_all_some fs' l'

let remove1_mem (f:fact) (l r:list fact)
  : Lemma (requires remove1 f l == Some r) (ensures L.mem f l)
  = remove1_cnt f f l r; mem_cnt f l

(* ------------------------------------------------------------------ *)
(* Attacker derivability (P2c)                                          *)
(* ------------------------------------------------------------------ *)

(* Tamarin's message deduction for M28's signature: known terms, public
   names, pair construction and projection, and application of the public
   unary symbols when the result is a message (so fst/snd are applied by
   construction only to non-pairs; on a pair they reduce, which is DFst /
   DSnd). *)
noeq type derivable (know:list sterm) : sterm -> Type =
  | DKnown : t:sterm -> squash (L.mem t know = true) -> derivable know t
  | DPublic : p:string -> derivable know (SName (PublicName p))
  | DPair : a:sterm -> b:sterm -> derivable know a -> derivable know b ->
      derivable know (SPair a b)
  | DFst : a:sterm -> b:sterm -> derivable know (SPair a b) -> derivable know a
  | DSnd : a:sterm -> b:sterm -> derivable know (SPair a b) -> derivable know b
  | DApp : f:fn_symbol -> a:sterm -> derivable know a ->
      squash (message (SApp f a) = true) -> derivable know (SApp f a)

(* Knowledge only grows, so derivations survive it. *)
let rec derivable_mono (k1 k2:list sterm)
    (sub:squash (forall (t:sterm). L.mem t k1 = true ==> L.mem t k2 = true))
    (t:sterm) (d:derivable k1 t)
  : Tot (derivable k2 t) (decreases d)
  = match d with
    | DKnown t' _ -> DKnown t' ()
    | DPublic p -> DPublic p
    | DPair a b da db ->
        DPair a b (derivable_mono k1 k2 sub a da) (derivable_mono k1 k2 sub b db)
    | DFst a b dp -> DFst a b (derivable_mono k1 k2 sub (SPair a b) dp)
    | DSnd a b dp -> DSnd a b (derivable_mono k1 k2 sub (SPair a b) dp)
    | DApp f a da m -> DApp f a (derivable_mono k1 k2 sub a da) m

let rec all_messages (know:list sterm) : Tot bool (decreases know) =
  match know with
  | [] -> true
  | t :: r -> message t && all_messages r

let rec all_messages_mem (know:list sterm) (t:sterm)
  : Lemma (requires all_messages know = true /\ L.mem t know = true)
          (ensures message t = true) (decreases know)
  = match know with
    | [] -> ()
    | x :: r -> if x = t then () else all_messages_mem r t

(* Every derivable term is a message when the knowledge is. *)
let rec derivable_message (know:list sterm) (t:sterm) (d:derivable know t)
  : Lemma (requires all_messages know = true)
          (ensures message t = true) (decreases d)
  = match d with
    | DKnown t' _ -> all_messages_mem know t'
    | DPublic _ -> ()
    | DPair a b da db -> derivable_message know a da; derivable_message know b db
    | DFst a b dp -> derivable_message know (SPair a b) dp
    | DSnd a b dp -> derivable_message know (SPair a b) dp
    | DApp f a da _ -> ()

(* Fresh-name confinement: a derivable term only contains fresh names that
   already occur in the knowledge.  This is the property that makes the
   source In facts strictly smaller than the encoding's arbitrary inputs. *)
let rec occurs_fresh (n:string) (t:sterm) : Tot bool (decreases t) =
  match t with
  | SVar _ -> false
  | SName (FreshName m) -> m = n
  | SName (PublicName _) -> false
  | SApp _ a -> occurs_fresh n a
  | SPair a b -> occurs_fresh n a || occurs_fresh n b

let rec known_fresh (n:string) (know:list sterm) : Tot bool (decreases know) =
  match know with
  | [] -> false
  | k :: r -> occurs_fresh n k || known_fresh n r

let rec known_fresh_mem (n:string) (know:list sterm) (t:sterm)
  : Lemma (requires L.mem t know = true /\ occurs_fresh n t = true)
          (ensures known_fresh n know = true) (decreases know)
  = match know with
    | [] -> ()
    | x :: r -> if x = t then () else known_fresh_mem n r t

let rec derivable_fresh_confined (know:list sterm) (t:sterm)
    (d:derivable know t) (n:string)
  : Lemma (requires occurs_fresh n t = true)
          (ensures known_fresh n know = true) (decreases d)
  = match d with
    | DKnown t' _ -> known_fresh_mem n know t'
    | DPublic _ -> ()
    | DPair a b da db ->
        if occurs_fresh n a then derivable_fresh_confined know a da n
        else derivable_fresh_confined know b db n
    | DFst a b dp -> derivable_fresh_confined know (SPair a b) dp n
    | DSnd a b dp -> derivable_fresh_confined know (SPair a b) dp n
    | DApp f a da _ -> derivable_fresh_confined know a da n

(* A fresh name that the attacker has not learned is not derivable, nor is
   any term containing it. *)
let fresh_name_secret (know:list sterm) (n:string) (t:sterm)
    (d:derivable know t)
  : Lemma (requires known_fresh n know = false /\ occurs_fresh n t = true)
          (ensures False)
  = derivable_fresh_confined know t d n

(* ------------------------------------------------------------------ *)
(* Configurations, labels, steps and traces                           *)
(* ------------------------------------------------------------------ *)

(* [facts] is the multiset of linear and persistent facts, [drawn] the fresh
   names created by Fresh so far, and [know] the attacker knowledge. *)
type config = {
  facts: list fact;
  drawn: list string;
  know: list sterm;
}

let init_config : config = { facts = []; drawn = []; know = [] }

noeq type label =
  | LFresh : n:string -> label
  | LAdvFresh : n:string -> label
  | LRecv : t:sterm -> label
  | LSend : t:sterm -> label
  | LRule : r:rule_name -> sg:subst -> nu:fresh_subst -> label

let rule_linear (sys:system) (r:rule_name) (sg:subst) (nu:fresh_subst)
  : list fact
  = linear (rinst sys r sg nu).r_premises

let rule_persistent (sys:system) (r:rule_name) (sg:subst) (nu:fresh_subst)
  : list fact
  = persistent (rinst sys r sg nu).r_premises

let rule_enabled (sys:system) (c:config) (r:rule_name) (sg:subst)
    (nu:fresh_subst) : bool
  = Some? (remove_all (rule_linear sys r sg nu) c.facts)
    && all_present (rule_persistent sys r sg nu) c.facts

let rule_result (sys:system) (c:config) (r:rule_name) (sg:subst)
    (nu:fresh_subst) : config
  = match remove_all (rule_linear sys r sg nu) c.facts with
    | Some rest ->
        { c with facts = L.append (rinst sys r sg nu).r_conclusions rest }
    | None -> c

noeq type sstep (sys:system) : config -> label -> config -> Type =
  | SFresh :
      c:config -> n:string ->
      squash (L.mem n c.drawn = false) ->
      sstep sys c (LFresh n)
        ({ c with facts = fr_fact n :: c.facts; drawn = n :: c.drawn })
  | SAdvFresh :
      c:config -> n:string -> rest:list fact ->
      squash (remove1 (fr_fact n) c.facts == Some rest) ->
      sstep sys c (LAdvFresh n)
        ({ c with facts = rest; know = SName (FreshName n) :: c.know })
  | SRecv :
      c:config -> t:sterm -> rest:list fact ->
      squash (remove1 (out_fact t) c.facts == Some rest) ->
      sstep sys c (LRecv t) ({ c with facts = rest; know = t :: c.know })
  | SSend :
      c:config -> t:sterm -> derivable c.know t ->
      sstep sys c (LSend t) ({ c with facts = in_fact t :: c.facts })
  | SRule :
      c:config -> r:rule_name -> sg:subst -> nu:fresh_subst ->
      squash (message_subst sg) ->
      squash (rule_enabled sys c r sg nu = true) ->
      sstep sys c (LRule r sg nu) (rule_result sys c r sg nu)

noeq type strace =
  | TNil : strace
  | TSnoc : strace -> label -> strace

noeq type sreach (sys:system) : strace -> config -> Type =
  | SRInit : sreach sys TNil init_config
  | SRStep :
      h:strace -> c:config -> l:label -> c':config ->
      sreach sys h c -> sstep sys c l c' ->
      sreach sys (TSnoc h l) c'

(* ------------------------------------------------------------------ *)
(* Actions, timepoints and the restriction                            *)
(* ------------------------------------------------------------------ *)

let label_actions (sys:system) (l:label) : list fact =
  match l with
  | LRule r sg nu -> (rinst sys r sg nu).r_actions
  | _ -> []

(* No action of any schema is a Chain fact, so both systems emit the same
   actions for the same label. *)
let rec has_sym (s:fact_symbol) (fs:list fact) : Tot bool (decreases fs) =
  match fs with
  | [] -> false
  | f :: r -> f.f_sym = s || has_sym s r

let rec erase_no_chain (fs:list fact)
  : Lemma (requires has_sym F_Chain fs = false) (ensures erase fs == fs)
          (decreases fs)
  = match fs with
    | [] -> ()
    | _ :: r -> erase_no_chain r

let schema_actions_no_chain (r:rule_name)
  : Lemma (has_sym F_Chain (m28_rule r).r_actions = false)
  = match r with
    | R_Initialize -> assert_norm (has_sym F_Chain (m28_rule R_Initialize).r_actions = false)
    | R_ReadSnapshot -> assert_norm (has_sym F_Chain (m28_rule R_ReadSnapshot).r_actions = false)
    | R_PersistJournal -> assert_norm (has_sym F_Chain (m28_rule R_PersistJournal).r_actions = false)
    | R_PersistVault -> assert_norm (has_sym F_Chain (m28_rule R_PersistVault).r_actions = false)
    | R_ClearJournal -> assert_norm (has_sym F_Chain (m28_rule R_ClearJournal).r_actions = false)
    | R_Crash -> assert_norm (has_sym F_Chain (m28_rule R_Crash).r_actions = false)
    | R_OpenVault -> assert_norm (has_sym F_Chain (m28_rule R_OpenVault).r_actions = false)

let actions_agree (l:label)
  : Lemma (label_actions Original l == label_actions Instrumented l)
  = match l with
    | LRule r sg nu ->
        schema_actions_no_chain r;
        erase_no_chain (m28_rule r).r_actions
    | _ -> ()

(* The observable actions of a label, the same in both systems. *)
let actions (l:label) : list fact = label_actions Instrumented l

let rec slen (h:strace) : Tot nat (decreases h) =
  match h with
  | TNil -> 0
  | TSnoc h' _ -> slen h' + 1

(* [action_at h i f]: action [f] occurs at timepoint #i (counted from 0). *)
let rec action_at (h:strace) (i:nat) (f:fact) : Tot bool (decreases h) =
  match h with
  | TNil -> false
  | TSnoc h' l -> if i = slen h' then L.mem f (actions l) else action_at h' i f

let rec action_at_bound (h:strace) (i:nat) (f:fact)
  : Lemma (requires action_at h i f = true) (ensures i < slen h) (decreases h)
  = match h with
    | TNil -> ()
    | TSnoc h' _ -> if i = slen h' then () else action_at_bound h' i f

(* Action facts used by the M28 lemmas. *)
let a_initialized (s:sterm) : fact = mk_fact F_Initialized false [s]
let a_snapshot_read (s tx g p:sterm) : fact =
  mk_fact F_SnapshotRead false [s; tx; g; p]
let a_revision_increases (o n:sterm) : fact =
  mk_fact F_RevisionIncreases false [o; n]
let a_journal_durable (s tx g o n p:sterm) : fact =
  mk_fact F_JournalDurable false [s; tx; g; o; n; p]
let a_vault_durable (s tx g n p:sterm) : fact =
  mk_fact F_VaultDurable false [s; tx; g; n; p]
let a_journal_cleared (s tx g p:sterm) : fact =
  mk_fact F_JournalCleared false [s; tx; g; p]
let a_crash (s:sterm) : fact = mk_fact F_Crash false [s]
let a_opened (s g p r v:sterm) : fact = mk_fact F_Opened false [s; g; p; r; v]

(* restriction Increasing:
     "All old next #i. RevisionIncreases(old, next) @ #i ==> old << next" *)
let increasing (h:strace) : Type0 =
  forall (i:nat) (o n:sterm).
    action_at h i (a_revision_increases o n) = true ==> proper_subterm o n = true

let increasing_prefix (h:strace) (l:label)
  : Lemma (requires increasing (TSnoc h l)) (ensures increasing h)
  = introduce forall (i:nat) (o n:sterm).
      action_at h i (a_revision_increases o n) = true ==> proper_subterm o n = true
    with introduce _ ==> _
    with _. begin
      action_at_bound h i (a_revision_increases o n);
      assert (action_at (TSnoc h l) i (a_revision_increases o n) = true)
    end

(* ------------------------------------------------------------------ *)
(* Global freshness (P2c)                                               *)
(* ------------------------------------------------------------------ *)

let fr_name_of (f:fact) : option string =
  if f.f_sym = F_Fr && not f.f_persistent then
    (match f.f_args with
     | [SName (FreshName n)] -> Some n
     | _ -> None)
  else None

let fr_name_of_fact (f:fact) (n:string)
  : Lemma ((fr_name_of f = Some n) = (f = fr_fact n))
  = ()

let rec fr_names (fs:list fact) : Tot (list string) (decreases fs) =
  match fs with
  | [] -> []
  | f :: r ->
      (match fr_name_of f with
       | Some n -> n :: fr_names r
       | None -> fr_names r)

let rec cnt_fr_names (n:string) (fs:list fact)
  : Lemma (ensures cnt (fr_fact n) fs = cnt n (fr_names fs)) (decreases fs)
  = match fs with
    | [] -> ()
    | f :: r -> fr_name_of_fact f n; cnt_fr_names n r

(* Fresh names consumed by each step: by attacker ifresh, or by the linear
   Fr premises of a protocol rule. *)
let label_consumed (sys:system) (l:label) : list string =
  match l with
  | LAdvFresh n -> [n]
  | LRule r sg nu -> fr_names (rule_linear sys r sg nu)
  | _ -> []

let rec consumed (sys:system) (h:strace) : Tot (list string) (decreases h) =
  match h with
  | TNil -> []
  | TSnoc h' l -> L.append (label_consumed sys l) (consumed sys h')

(* No schema concludes an Fr fact; only the Fresh rule creates them. *)
let rec has_sym_inst (s:fact_symbol) (sg:subst) (nu:fresh_subst) (fs:list fact)
  : Lemma (ensures has_sym s (inst_facts sg nu fs) = has_sym s fs) (decreases fs)
  = match fs with
    | [] -> ()
    | _ :: r -> has_sym_inst s sg nu r

let rec has_sym_erase (s:fact_symbol) (fs:list fact)
  : Lemma (requires has_sym s fs = false) (ensures has_sym s (erase fs) = false)
          (decreases fs)
  = match fs with
    | [] -> ()
    | _ :: r -> has_sym_erase s r

let rec no_sym_cnt (f:fact) (fs:list fact)
  : Lemma (requires has_sym f.f_sym fs = false) (ensures cnt f fs = 0)
          (decreases fs)
  = match fs with
    | [] -> ()
    | _ :: r -> no_sym_cnt f r

let schema_conclusions_no_fr (r:rule_name)
  : Lemma (has_sym F_Fr (m28_rule r).r_conclusions = false)
  = match r with
    | R_Initialize -> assert_norm (has_sym F_Fr (m28_rule R_Initialize).r_conclusions = false)
    | R_ReadSnapshot -> assert_norm (has_sym F_Fr (m28_rule R_ReadSnapshot).r_conclusions = false)
    | R_PersistJournal -> assert_norm (has_sym F_Fr (m28_rule R_PersistJournal).r_conclusions = false)
    | R_PersistVault -> assert_norm (has_sym F_Fr (m28_rule R_PersistVault).r_conclusions = false)
    | R_ClearJournal -> assert_norm (has_sym F_Fr (m28_rule R_ClearJournal).r_conclusions = false)
    | R_Crash -> assert_norm (has_sym F_Fr (m28_rule R_Crash).r_conclusions = false)
    | R_OpenVault -> assert_norm (has_sym F_Fr (m28_rule R_OpenVault).r_conclusions = false)

let conclusions_no_fr (sys:system) (r:rule_name) (sg:subst) (nu:fresh_subst)
    (n:string)
  : Lemma (cnt (fr_fact n) (rinst sys r sg nu).r_conclusions = 0)
  = schema_conclusions_no_fr r;
    (match sys with
     | Instrumented -> has_sym_inst F_Fr sg nu (m28_rule r).r_conclusions
     | Original ->
         has_sym_erase F_Fr (m28_rule r).r_conclusions;
         has_sym_inst F_Fr sg nu (erase (m28_rule r).r_conclusions));
    no_sym_cnt (fr_fact n) (rinst sys r sg nu).r_conclusions

(* Tamarin's global uniqueness of fresh names, as a counting invariant:
   every drawn name is either still an unconsumed Fr fact or has been
   consumed exactly once, and no name is drawn twice. *)
let fresh_inv (sys:system) (h:strace) (c:config) : Type0 =
  forall (n:string).
    cnt (fr_fact n) c.facts + cnt n (consumed sys h) = cnt n c.drawn
    /\ cnt n c.drawn <= 1

let step_fresh_inv (sys:system) (h:strace) (c:config) (l:label) (c':config)
    (st:sstep sys c l c')
  : Lemma (requires fresh_inv sys h c) (ensures fresh_inv sys (TSnoc h l) c')
  = match st with
    | SFresh _ n _ -> mem_cnt n c.drawn
    | SAdvFresh _ n rest _ -> remove1_cnt_all (fr_fact n) c.facts rest
    | SRecv _ t rest _ -> remove1_cnt_all (out_fact t) c.facts rest
    | SSend _ _ _ -> ()
    | SRule _ r sg nu _ _ ->
        let lin = rule_linear sys r sg nu in
        let concl = (rinst sys r sg nu).r_conclusions in
        let Some rest = remove_all lin c.facts in
        introduce forall (n:string).
          cnt (fr_fact n) c'.facts + cnt n (consumed sys (TSnoc h l))
            = cnt n c'.drawn
          /\ cnt n c'.drawn <= 1
        with begin
          cnt_append (fr_fact n) concl rest;
          conclusions_no_fr sys r sg nu n;
          remove_all_cnt lin (fr_fact n) c.facts rest;
          cnt_fr_names n lin;
          cnt_append n (fr_names lin) (consumed sys h)
        end

let rec global_freshness (sys:system) (h:strace) (c:config)
    (rc:sreach sys h c)
  : Lemma (ensures fresh_inv sys h c) (decreases rc)
  = match rc with
    | SRInit -> ()
    | SRStep h0 c0 l c1 r0 st ->
        global_freshness sys h0 c0 r0;
        step_fresh_inv sys h0 c0 l c1 st

(* Corollaries in the form the bridge uses. *)
let consumed_at_most_once (sys:system) (h:strace) (c:config)
    (rc:sreach sys h c) (n:string)
  : Lemma (cnt n (consumed sys h) <= 1)
  = global_freshness sys h c rc

let fr_fact_unconsumed (sys:system) (h:strace) (c:config)
    (rc:sreach sys h c) (n:string)
  : Lemma (requires L.mem (fr_fact n) c.facts = true)
          (ensures L.mem n (consumed sys h) = false)
  = global_freshness sys h c rc;
    mem_cnt (fr_fact n) c.facts;
    mem_cnt n (consumed sys h)

let consumed_was_drawn (sys:system) (h:strace) (c:config)
    (rc:sreach sys h c) (n:string)
  : Lemma (requires L.mem n (consumed sys h) = true)
          (ensures L.mem n c.drawn = true)
  = global_freshness sys h c rc;
    mem_cnt n (consumed sys h);
    mem_cnt n c.drawn
