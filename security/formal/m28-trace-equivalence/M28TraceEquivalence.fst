module M28TraceEquivalence

open FStar.Squash

(* Machine-checked conservative-extension proof for the M28 share-journal
   model.

   The reference system is the original seven-rule model (commit b8221e7):
   Initialize, ReadSnapshot, PersistJournal, PersistVault, ClearJournal,
   Crash and OpenVault, with no Chain fact.

   The lifted system is the instrumented model used by the Tamarin proofs:
   it adds a linear Chain(slot, generation, pin) fact to Initialize,
   PersistJournal and ClearJournal.  Its only rule differences are the Chain
   premise in PersistJournal and ClearJournal and the Chain conclusion in
   Initialize, PersistJournal and ClearJournal.

   This module proves equivalence of two typed, initialized, single-slot
   transition encodings. The parameter [lt] is arbitrary. The step and
   reachable-trace maps preserve the same encoded event list; transfer
   functions are schemas taking a proof of the lifted predicate as input
   ([hp] is never discharged here).

   On the encoded event traces it also defines and proves the two all-pairs
   goals: under an explicit strict-order record for revisions, every earlier
   ClearJournal pin is strictly below every later one, and every generation
   occurs in at most one EJournal event.  Generation uniqueness is
   order-independent.  A concrete unary free-term proper-subterm instance and
   a two-commit reachability witness are checked below.

   Source correspondence is not established here. In particular, the
   encodings omit attacker In/Out derivability, model transaction non-reuse
   only per slot, and do not check the untyped-term or multi-slot embeddings.
   The fixed initialized single-slot types are not the .spthy semantics:
   global Fr/cross-slot freshness and the single-sort Tamarin term algebra are
   not represented.  Arbitrary revision/payload inputs over-approximate In
   derivability; they are not asserted to be exactly the source rules, and the
   encoded initial secret can appear as a payload even though the source never
   sends it.  The concrete [term_order] is only the encoded unary free-term
   instance, not the full Tamarin subterm algebra or a source embedding.
   Applying a Tamarin verdict still needs both directed embeddings described in
   README.md.  Nothing here implies that checking these F* theorems proves the
   actual Tamarin model. *)

type gen =
  | G0
  | GS of gen

type phase (rev:eqtype) (tx:eqtype) (msg:eqtype) =
  | Clean : gen -> rev -> rev -> msg -> phase rev tx msg
  | Pending : tx -> gen -> rev -> msg -> rev -> msg -> phase rev tx msg
  | Applied : tx -> gen -> rev -> msg -> rev -> msg -> phase rev tx msg

type event (rev:eqtype) (tx:eqtype) (msg:eqtype) =
  | EInitialized
  | ESnapshotRead : tx -> gen -> rev -> event rev tx msg
  | EJournal : tx -> gen -> rev -> rev -> msg -> event rev tx msg
  | EVault : tx -> gen -> rev -> msg -> event rev tx msg
  | EClear : tx -> gen -> rev -> event rev tx msg
  | ECrash
  | EOpened : gen -> rev -> rev -> msg -> event rev tx msg

(* A non-Chain state of the original model.  [ready] is !ReadyGeneration,
   [snaps] is the multiset of linear Snapshot facts, [used] tracks the fresh
   transaction identifiers consumed by ReadSnapshot, [opened] is !Profile.
   The durable product state is [ph]. *)
type core (rev:eqtype) (tx:eqtype) (msg:eqtype) = {
  opened: bool;
  ready: list (gen * rev);
  snaps: list (tx * gen * rev);
  used: list tx;
  ph: phase rev tx msg;
}

(* Split one occurrence out of the linear Snapshot multiset. *)
noeq type split (#a:Type) : list a -> a -> list a -> Type =
  | SplitHere : (x:a) -> (rest:list a) -> split (x::rest) x rest
  | SplitThere :
      (x:a) -> (y:a) -> (l:list a) -> (rest:list a) ->
      split l y rest -> split (x::l) y rest

(* The original transition relation, containing exactly the seven rules.
   [lt] is the Increasing restriction's strict-increase predicate. *)
noeq type step_core
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt: rev -> rev -> bool)
  : core rev tx msg -> event rev tx msg -> core rev tx msg -> Type =

  | CReadSnapshot :
      (c:core rev tx msg) -> (tx':tx) -> (g:gen) -> (p:rev) ->
      ~(FStar.List.Tot.memP tx' c.used) ->
      FStar.List.Tot.memP (g, p) c.ready ->
      step_core lt c (ESnapshotRead tx' g p)
        ({ c with used = tx' :: c.used; snaps = (tx', g, p) :: c.snaps })

  | CPersistJournal :
      (c:core rev tx msg) -> (tx':tx) -> (g:gen) -> (p:rev) ->
      (vrev:rev) -> (vpayload:msg) -> (next:rev) -> (payload:msg) ->
      (rest:list (tx * gen * rev)) ->
      c.ph = Clean g p vrev vpayload ->
      split c.snaps (tx', g, p) rest ->
      lt p next = true ->
      step_core lt c (EJournal tx' (GS g) p next payload)
        ({ c with ph = Pending tx' (GS g) next payload vrev vpayload;
                  snaps = rest })

  | CPersistVault :
      (c:core rev tx msg) -> (tx':tx) -> (g:gen) -> (next:rev) ->
      (payload:msg) -> (vrev:rev) -> (vpayload:msg) ->
      c.ph = Pending tx' g next payload vrev vpayload ->
      step_core lt c (EVault tx' g next payload)
        ({ c with ph = Applied tx' g next payload next payload })

  | CClearJournal :
      (c:core rev tx msg) -> (tx':tx) -> (g:gen) -> (p:rev) ->
      (intended:msg) -> (vrev:rev) -> (vpayload:msg) ->
      c.ph = Applied tx' g p intended vrev vpayload ->
      step_core lt c (EClear tx' g p)
        ({ c with ph = Clean g p vrev vpayload;
                  ready = (g, p) :: c.ready })

  | CCrash :
      (c:core rev tx msg) ->
      c.opened = true ->
      step_core lt c ECrash c

  | COpenVault :
      (c:core rev tx msg) -> (g:gen) -> (p:rev) ->
      (revision:rev) -> (payload:msg) ->
      c.ph = Clean g p revision payload ->
      step_core lt c (EOpened g p revision payload) c

(* The lifted state adds the linear Chain pair. *)
type lifted (rev:eqtype) (tx:eqtype) (msg:eqtype) = {
  base: core rev tx msg;
  chain: gen * rev;
}

(* The functional value of Chain on a durable phase. *)
let chain_of_phase (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (ph:phase rev tx msg) : gen * rev =
  match ph with
  | Clean g p _ _ -> (g, p)
  | Pending _ g next _ _ _ -> (g, next)
  | Applied _ g p _ _ _ -> (g, p)

(* Well-formedness: the linear Chain pair is exactly the pair determined by
   the durable phase.  [wf] is the state-invariant form of the Chain
   premise: together with the rule's durable-phase equation it is equivalent
   to the literal premise Chain(slot, generation, pin) (see
   lift_chain_premise_clean and lift_chain_premise_applied below). *)
let wf (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (s:lifted rev tx msg) : Type =
  s.chain = chain_of_phase s.base.ph

(* The unique lift of an original state. *)
let lift_state (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (c:core rev tx msg) : lifted rev tx msg =
  { base = c; chain = chain_of_phase c.ph }

(* Lifted transition relation: the original rules plus exactly the Chain
   premise/conclusion differences. *)
noeq type step_lift
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt: rev -> rev -> bool)
  : lifted rev tx msg -> event rev tx msg -> lifted rev tx msg -> Type =

  | LReadSnapshot :
      (s:lifted rev tx msg) -> (tx':tx) -> (g:gen) -> (p:rev) ->
      ~(FStar.List.Tot.memP tx' s.base.used) ->
      FStar.List.Tot.memP (g, p) s.base.ready ->
      step_lift lt s (ESnapshotRead tx' g p)
        ({ s with base = { s.base with
                            used = tx' :: s.base.used;
                            snaps = (tx', g, p) :: s.base.snaps } })

  | LPersistJournal :
      (s:lifted rev tx msg) -> (tx':tx) -> (g:gen) -> (p:rev) ->
      (vrev:rev) -> (vpayload:msg) -> (next:rev) -> (payload:msg) ->
      (rest:list (tx * gen * rev)) ->
      s.chain = (g, p) ->
      s.base.ph = Clean g p vrev vpayload ->
      split s.base.snaps (tx', g, p) rest ->
      lt p next = true ->
      step_lift lt s (EJournal tx' (GS g) p next payload)
        ({ s with base = { s.base with
                            ph = Pending tx' (GS g) next payload vrev vpayload;
                            snaps = rest };
                  chain = (GS g, next) })

  | LPersistVault :
      (s:lifted rev tx msg) -> (tx':tx) -> (g:gen) -> (next:rev) ->
      (payload:msg) -> (vrev:rev) -> (vpayload:msg) ->
      s.base.ph = Pending tx' g next payload vrev vpayload ->
      step_lift lt s (EVault tx' g next payload)
        ({ s with base = { s.base with
                            ph = Applied tx' g next payload next payload } })

  | LClearJournal :
      (s:lifted rev tx msg) -> (tx':tx) -> (g:gen) -> (p:rev) ->
      (intended:msg) -> (vrev:rev) -> (vpayload:msg) ->
      s.chain = (g, p) ->
      s.base.ph = Applied tx' g p intended vrev vpayload ->
      step_lift lt s (EClear tx' g p)
        ({ s with base = { s.base with
                            ph = Clean g p vrev vpayload;
                            ready = (g, p) :: s.base.ready };
                  chain = (g, p) })

  | LCrash :
      (s:lifted rev tx msg) ->
      s.base.opened = true ->
      step_lift lt s ECrash s

  | LOpenVault :
      (s:lifted rev tx msg) -> (g:gen) -> (p:rev) ->
      (revision:rev) -> (payload:msg) ->
      s.base.ph = Clean g p revision payload ->
      step_lift lt s (EOpened g p revision payload) s

(* Initial states.  The 'initial' revision and the initial vault item are
   parameters; both models receive the same values. *)
let init_phase (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (r0:rev) (item:msg) : phase rev tx msg =
  Clean G0 r0 r0 item

let init_core (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (r0:rev) (item:msg) : core rev tx msg =
  { opened = true;
    ready = [(G0, r0)];
    snaps = [];
    used = [];
    ph = init_phase r0 item }

let init_lifted (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (r0:rev) (item:msg) : lifted rev tx msg =
  { base = init_core r0 item; chain = (G0, r0) }

(* Event traces are snoc lists, so the last event is syntactically the last
   transition. *)
noeq type trace (rev:eqtype) (tx:eqtype) (msg:eqtype) =
  | Nil : trace rev tx msg
  | Snoc : trace rev tx msg -> event rev tx msg -> trace rev tx msg

noeq type reach_core
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt:rev -> rev -> bool) (r0:rev) (item:msg)
  : trace rev tx msg -> core rev tx msg -> Type =

  | RCInit :
      reach_core #rev #tx #msg lt r0 item
        (Snoc #rev #tx #msg (Nil #rev #tx #msg) (EInitialized #rev #tx #msg))
        (init_core #rev #tx #msg r0 item)

  | RCSnoc :
      (h:trace rev tx msg) -> (c:core rev tx msg) ->
      (e:event rev tx msg) -> (c':core rev tx msg) ->
      reach_core lt r0 item h c ->
      step_core lt c e c' ->
      reach_core lt r0 item (Snoc h e) c'

noeq type reach_lift
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt:rev -> rev -> bool) (r0:rev) (item:msg)
  : trace rev tx msg -> lifted rev tx msg -> Type =

  | RLInit :
      reach_lift #rev #tx #msg lt r0 item
        (Snoc #rev #tx #msg (Nil #rev #tx #msg) (EInitialized #rev #tx #msg))
        (init_lifted #rev #tx #msg r0 item)

  | RLSnoc :
      (h:trace rev tx msg) -> (s:lifted rev tx msg) ->
      (e:event rev tx msg) -> (s':lifted rev tx msg) ->
      reach_lift lt r0 item h s ->
      step_lift lt s e s' ->
      reach_lift lt r0 item (Snoc h e) s'


let wf_init (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (r0:rev) (item:msg)
  : Lemma (wf (init_lifted r0 item)) = ()

(* Every lifted transition preserves the invariants and projects to the
   corresponding original transition. *)
let step_lift_preserves_wf
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt:rev -> rev -> bool)
  (s s':lifted rev tx msg) (e:event rev tx msg)
  (st:step_lift lt s e s')
  : Lemma (requires wf s) (ensures wf s')
  = match st with
    | LReadSnapshot _ _ _ _ _ _ -> ()
    | LPersistJournal _ _ _ _ _ _ _ _ _ _ _ _ _ -> ()
    | LPersistVault _ _ _ _ _ _ _ _ -> ()
    | LClearJournal _ _ _ _ _ _ _ _ _ -> ()
    | LCrash _ _ -> ()
    | LOpenVault _ _ _ _ _ _ -> ()

let step_lift_projects
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt:rev -> rev -> bool)
  (s s':lifted rev tx msg) (e:event rev tx msg)
  (st:step_lift lt s e s')
  : step_core lt s.base e s'.base
  = match st with
    | LReadSnapshot c tx' g p nf mem -> CReadSnapshot c.base tx' g p nf mem
    | LPersistJournal c tx' g p vrev vpayload next payload rest _ ph sp inc ->
        CPersistJournal c.base tx' g p vrev vpayload next payload rest
          ph sp inc
    | LPersistVault c tx' g next payload vrev vpayload ph ->
        CPersistVault c.base tx' g next payload vrev vpayload ph
    | LClearJournal c tx' g p intended vrev vpayload _ ph ->
        CClearJournal c.base tx' g p intended vrev vpayload ph
    | LCrash c op -> CCrash c.base op
    | LOpenVault c g p revision payload ph ->
        COpenVault c.base g p revision payload ph

(* Chain values of concrete durable phases, used to discharge the lifted
   premises from the original rule premises. *)
let chain_clean
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (ph:phase rev tx msg) (g:gen) (r:rev) (vrev:rev) (vpayload:msg)
  (h:ph = Clean g r vrev vpayload)
  : Lemma (chain_of_phase ph = (g, r)) = ()

let chain_applied
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (ph:phase rev tx msg) (txv:tx) (g:gen) (r:rev)
  (intended:msg) (vrev:rev) (vpayload:msg)
  (h:ph = Applied txv g r intended vrev vpayload)
  : Lemma (chain_of_phase ph = (g, r)) = ()

(* Every original transition lifts to exactly one lifted transition from the
   unique lift of its source to the unique lift of its target.  The lifted
   Chain premise is the original durable-phase equation, so no transition is
   enabled or disabled by the instrumentation. *)
let step_core_to_lift
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt:rev -> rev -> bool)
  (c c':core rev tx msg) (e:event rev tx msg)
  (st:step_core lt c e c')
  : step_lift lt (lift_state c) e (lift_state c')
  = match st with
    | CReadSnapshot c tx' g p nf mem ->
        LReadSnapshot (lift_state c) tx' g p nf mem
    | CPersistJournal c tx' g p vrev vpayload next payload rest ph sp inc ->
        LPersistJournal (lift_state c) tx' g p vrev vpayload next payload
          rest
          (join_squash (get_proof ((lift_state c).chain = (g, p))))
          ph sp inc
    | CPersistVault c tx' g next payload vrev vpayload ph ->
        LPersistVault (lift_state c) tx' g next payload vrev vpayload ph
    | CClearJournal c tx' g p intended vrev vpayload ph ->
        LClearJournal (lift_state c) tx' g p intended vrev vpayload
          (join_squash (get_proof ((lift_state c).chain = (g, p))))
          ph
    | CCrash c op -> LCrash (lift_state c) op
    | COpenVault c g p revision payload ph ->
        LOpenVault (lift_state c) g p revision payload ph

(* The wf premise used in the lifted encodings is equivalent to the literal
   Chain premise of the instrumented Tamarin rules. *)
let lift_chain_premise_clean
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (s:lifted rev tx msg) (g:gen) (p:rev) (vrev:rev) (vpayload:msg)
  (w:wf s) (ph:s.base.ph = Clean g p vrev vpayload)
  : Lemma (s.chain = (g, p)) = ()

let lift_chain_premise_clean_converse
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (s:lifted rev tx msg) (g:gen) (p:rev) (vrev:rev) (vpayload:msg)
  (ch:s.chain = (g, p)) (ph:s.base.ph = Clean g p vrev vpayload)
  : Lemma (wf s) = ()

let lift_chain_premise_applied
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (s:lifted rev tx msg) (txv:tx) (g:gen) (p:rev)
  (intended:msg) (vrev:rev) (vpayload:msg)
  (w:wf s) (ph:s.base.ph = Applied txv g p intended vrev vpayload)
  : Lemma (s.chain = (g, p)) = ()

let lift_chain_premise_applied_converse
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (s:lifted rev tx msg) (txv:tx) (g:gen) (p:rev)
  (intended:msg) (vrev:rev) (vpayload:msg)
  (ch:s.chain = (g, p)) (ph:s.base.ph = Applied txv g p intended vrev vpayload)
  : Lemma (wf s) = ()

(* Every reachable original trace lifts, event for event, to a reachable
   lifted trace. *)
let rec reach_core_lifts
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt:rev -> rev -> bool) (r0:rev) (item:msg)
  (h:trace rev tx msg) (c:core rev tx msg)
  (r:reach_core lt r0 item h c)
  : Tot (reach_lift lt r0 item h (lift_state c))
    (decreases r)
  = match r with
    | RCInit -> RLInit
    | RCSnoc h c e c' rprev st ->
        RLSnoc h (lift_state c) e (lift_state c')
          (reach_core_lifts lt r0 item h c rprev)
          (step_core_to_lift lt c c' e st)

(* Every reachable lifted trace projects, event for event, to a reachable
   original trace. *)
let rec reach_lift_projects
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt:rev -> rev -> bool) (r0:rev) (item:msg)
  (h:trace rev tx msg) (s:lifted rev tx msg)
  (r:reach_lift lt r0 item h s)
  : Tot (reach_core lt r0 item h s.base)
    (decreases r)
  = match r with
    | RLInit -> RCInit
    | RLSnoc h s e s' rprev st ->
        RCSnoc h s.base e s'.base
          (reach_lift_projects lt r0 item h s rprev)
          (step_lift_projects lt s s' e st)

(* Any event-trace predicate proved for the lifted system holds for the
   original system, and conversely.  This is the machine-checked transfer
   step that replaces the manual "projection/lifting" argument: the two
   all-pairs lemmas are predicates over the emitted action events, and the
   event traces are identical in both directions. *)
let transfer_lifted_to_original
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt:rev -> rev -> bool) (r0:rev) (item:msg)
  (p:trace rev tx msg -> Type)
  (hp:(h:trace rev tx msg) -> (s:lifted rev tx msg) ->
      reach_lift lt r0 item h s -> p h)
  (h:trace rev tx msg) (c:core rev tx msg)
  (r:reach_core lt r0 item h c)
  : p h
  = hp h (lift_state c) (reach_core_lifts lt r0 item h c r)

let transfer_original_to_lifted
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt:rev -> rev -> bool) (r0:rev) (item:msg)
  (p:trace rev tx msg -> Type)
  (hp:(h:trace rev tx msg) -> (c:core rev tx msg) ->
      reach_core lt r0 item h c -> p h)
  (h:trace rev tx msg) (s:lifted rev tx msg)
  (r:reach_lift lt r0 item h s)
  : p h
  = hp h s.base (reach_lift_projects lt r0 item h s r)

(* Every reachable lifted state satisfies the Chain invariant.  Together with
   lift_chain_premise_clean / lift_chain_premise_applied this shows that the
   wf premises above are exactly the literal Chain premises of the Tamarin
   rules on reachable states. *)
let rec reach_lift_wf
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt:rev -> rev -> bool) (r0:rev) (item:msg)
  (h:trace rev tx msg) (s:lifted rev tx msg)
  (r:reach_lift lt r0 item h s)
  : Lemma (ensures (wf s)) (decreases r)
  = match r with
    | RLInit -> ()
    | RLSnoc h s e s' rprev st ->
        reach_lift_wf lt r0 item h s rprev;
        step_lift_preserves_wf lt s s' e st

(* ================================================================== *)
(* Indexed action occurrences and the all-pairs goals.                *)
(* ================================================================== *)

(* Chronological length of a snoc trace. *)
let rec trace_len (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (h:trace rev tx msg)
  : Tot nat (decreases h)
  = match h with
    | Nil -> 0
    | Snoc h' _ -> trace_len h' + 1

(* Number of EJournal events in a trace. *)
let rec jcount (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (h:trace rev tx msg)
  : Tot nat (decreases h)
  = match h with
    | Nil -> 0
    | Snoc h' e ->
        jcount h' + (match e with EJournal _ _ _ _ _ -> 1 | _ -> 0)

let is_journal (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (e:event rev tx msg)
  : Tot bool
  = match e with
    | EJournal _ _ _ _ _ -> true
    | _ -> false

(* Structural equality on events.  It is a plain function so that the
   occurrence predicate below computes by reduction on concrete events. *)
let eq_event (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (x:event rev tx msg) (y:event rev tx msg)
  : Tot bool
  = match x, y with
    | EInitialized, EInitialized -> true
    | ESnapshotRead t1 g1 p1, ESnapshotRead t2 g2 p2 ->
        (t1 = t2) && (g1 = g2) && (p1 = p2)
    | EJournal t1 g1 o1 n1 p1, EJournal t2 g2 o2 n2 p2 ->
        (t1 = t2) && (g1 = g2) && (o1 = o2) && (n1 = n2) && (p1 = p2)
    | EVault t1 g1 r1 p1, EVault t2 g2 r2 p2 ->
        (t1 = t2) && (g1 = g2) && (r1 = r2) && (p1 = p2)
    | EClear t1 g1 p1, EClear t2 g2 p2 ->
        (t1 = t2) && (g1 = g2) && (p1 = p2)
    | ECrash, ECrash -> true
    | EOpened g1 p1 r1 v1, EOpened g2 p2 r2 v2 ->
        (g1 = g2) && (p1 = p2) && (r1 = r2) && (v1 = v2)
    | _, _ -> false

(* [eq_event] reflects propositional equality. *)
let eq_event_true
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (x:event rev tx msg) (y:event rev tx msg)
  : Lemma (requires eq_event x y = true) (ensures x = y)
  = match x with
    | EInitialized -> (match y with | EInitialized -> () | _ -> ())
    | ESnapshotRead _ _ _ ->
        (match y with | ESnapshotRead _ _ _ -> () | _ -> ())
    | EJournal _ _ _ _ _ ->
        (match y with | EJournal _ _ _ _ _ -> () | _ -> ())
    | EVault _ _ _ _ ->
        (match y with | EVault _ _ _ _ -> () | _ -> ())
    | EClear _ _ _ ->
        (match y with | EClear _ _ _ -> () | _ -> ())
    | ECrash -> (match y with | ECrash -> () | _ -> ())
    | EOpened _ _ _ _ ->
        (match y with | EOpened _ _ _ _ -> () | _ -> ())

(* Indexed occurrence predicate on a snoc trace.  Index [i] is the timepoint
   number, counting from zero.  Appending an event leaves all earlier
   indices unchanged and puts the new event at index [trace_len h]. *)
let rec occurs_at (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (h:trace rev tx msg) (i:nat) (e:event rev tx msg)
  : Tot bool (decreases h)
  = match h with
    | Nil -> false
    | Snoc h' e' ->
        if i = trace_len h' then eq_event e e'
        else occurs_at h' i e

(* Number of EJournal events strictly before timepoint [i]. *)
let rec jcount_before (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (h:trace rev tx msg) (i:nat)
  : Tot nat (decreases h)
  = match h with
    | Nil -> 0
    | Snoc h' e' ->
        if i = trace_len h' then jcount h'
        else jcount_before h' i

(* Every occurrence has an in-range timepoint. *)
let rec occurs_at_bound (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (h:trace rev tx msg) (i:nat) (e:event rev tx msg)
  : Lemma (requires occurs_at h i e = true)
          (ensures (i < trace_len h))
          (decreases h)
  = match h with
    | Nil -> ()
    | Snoc h' e' ->
        if i = trace_len h' then ()
        else occurs_at_bound h' i e

(* Generation depth: the number of GS constructors. *)
let rec gen_depth (g:gen) : Tot nat (decreases g) =
  match g with
  | G0 -> 0
  | GS g' -> 1 + gen_depth g'

let phase_gen (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (ph:phase rev tx msg)
  : Tot gen
  = match ph with
    | Clean g _ _ _ -> g
    | Pending _ g _ _ _ _ -> g
    | Applied _ g _ _ _ _ -> g

(* Invariant: the generation of the durable phase is exactly the number of
   journal events written so far. *)
let gen_count_inv (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (h:trace rev tx msg) (c:core rev tx msg)
  : Type
  = gen_depth (phase_gen c.ph) = jcount h

let rec reach_core_gen_count
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt:rev -> rev -> bool) (r0:rev) (item:msg)
  (h:trace rev tx msg) (c:core rev tx msg)
  (r:reach_core lt r0 item h c)
  : Lemma (ensures (gen_count_inv h c))
          (decreases r)
  = match r with
    | RCInit -> ()
    | RCSnoc h0 c0 e c' rprev st ->
        reach_core_gen_count lt r0 item h0 c0 rprev;
        (match st with
         | CReadSnapshot c1 tx' g p nf mem -> ()
         | CPersistJournal c1 tx' g p vrev vpayload next payload rest ph sp inc
           -> ()
         | CPersistVault c1 tx' g next payload vrev vpayload ph -> ()
         | CClearJournal c1 tx' g p intended vrev vpayload ph -> ()
         | CCrash c1 op -> ()
         | COpenVault c1 g p revision payload ph -> ())

(* Journal counts are bounded by the whole count, and strictly increase
   across a journal occurrence. *)
let rec jcount_before_bound
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (h:trace rev tx msg) (i:nat) (e:event rev tx msg)
  : Lemma (requires occurs_at h i e = true /\ is_journal e = true)
          (ensures (jcount_before h i + 1 <= jcount h))
          (decreases h)
  = match h with
    | Nil -> ()
    | Snoc h' e' ->
        if i = trace_len h' then eq_event_true #rev #tx #msg e e'
        else jcount_before_bound h' i e

let rec jcount_before_monotone
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (h:trace rev tx msg) (i:nat) (j:nat)
  (e1:event rev tx msg) (e2:event rev tx msg)
  : Lemma (requires i < j
                    /\ occurs_at h i e1 = true
                    /\ occurs_at h j e2 = true
                    /\ is_journal e1 = true)
          (ensures (jcount_before h i + 1 <= jcount_before h j))
          (decreases h)
  = match h with
    | Nil -> ()
    | Snoc h' e' ->
        if i = trace_len h' then occurs_at_bound (Snoc h' e') j e2
        else if j = trace_len h' then jcount_before_bound h' i e1
        else jcount_before_monotone h' i j e1 e2

(* Every journal occurrence emits a generation whose depth is one more than
   the number of journal events strictly before it. *)
let rec reach_core_journal_depth
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt:rev -> rev -> bool) (r0:rev) (item:msg)
  (h:trace rev tx msg) (c:core rev tx msg)
  (r:reach_core lt r0 item h c)
  (i:nat) (tx':tx) (g:gen) (old:rev) (next:rev) (payload:msg)
  : Lemma (requires occurs_at h i (EJournal tx' g old next payload) = true)
          (ensures (gen_depth g = jcount_before h i + 1))
          (decreases r)
  = match r with
    | RCInit -> ()
    | RCSnoc h0 c0 e c' rprev st ->
        reach_core_gen_count lt r0 item h0 c0 rprev;
        if i = trace_len h0 then
          (match st with
           | CPersistJournal c1 tx0 g0 p0 vrev vpayload next0 payload0
               rest ph sp inc ->
               eq_event_true #rev #tx #msg
                 (EJournal tx' g old next payload)
                 (EJournal tx0 (GS g0) p0 next0 payload0)
           | _ -> ())
        else
          reach_core_journal_depth lt r0 item h0 c0 rprev
            i tx' g old next payload

(* The exact all-pairs generation goal, packaged as a logical formula. *)
let journal_generation_at_most_once
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (h:trace rev tx msg)
  : Type
  = forall (i j:nat) (tx1 tx2:tx) (g:gen)
      (old1 old2 next1 next2:rev) (payload1 payload2:msg).
      occurs_at h i (EJournal tx1 g old1 next1 payload1) = true ->
      occurs_at h j (EJournal tx2 g old2 next2 payload2) = true ->
      i = j

(* Parametric form: for every pair of same-generation journal occurrences,
   the timepoints are equal. *)
let reach_core_journal_unique
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt:rev -> rev -> bool) (r0:rev) (item:msg)
  (h:trace rev tx msg) (c:core rev tx msg)
  (r:reach_core lt r0 item h c)
  (i j:nat) (tx1 tx2:tx) (g:gen)
  (old1 old2 next1 next2:rev) (payload1 payload2:msg)
  : Lemma (requires occurs_at h i (EJournal tx1 g old1 next1 payload1) = true
                    /\ occurs_at h j (EJournal tx2 g old2 next2 payload2) = true)
          (ensures (i = j))
  = reach_core_journal_depth lt r0 item h c r
      i tx1 g old1 next1 payload1;
    reach_core_journal_depth lt r0 item h c r
      j tx2 g old2 next2 payload2;
    if i < j then (
      jcount_before_monotone h i j
        (EJournal tx1 g old1 next1 payload1)
        (EJournal tx2 g old2 next2 payload2);
      assert False
    ) else if j < i then (
      jcount_before_monotone h j i
        (EJournal tx2 g old2 next2 payload2)
        (EJournal tx1 g old1 next1 payload1);
      assert False
    ) else ()

(* ================================================================== *)
(* Revision order laws and the all-pairs pin goal.                    *)
(* ================================================================== *)

(* The security statement needs a genuine strict order on revisions; the
   transition relation only stores its decision procedure [lt].  The record
   below pairs [lt] with the transitivity and irreflexivity proofs the
   argument uses.  Nothing is asserted about an arbitrary [lt]. *)
noeq type strict_order (a:eqtype) = {
  lt: a -> a -> bool;
  lt_trans :
    (x:a) -> (y:a) -> (z:a) ->
    Lemma (requires (lt x y = true /\ lt y z = true))
          (ensures (lt x z = true));
  lt_irrefl : (x:a) -> Lemma (lt x x = false);
}

(* Reflexive closure of the strict order, decided as a boolean. *)
let le_b (#a:eqtype) (o:strict_order a) (x:a) (y:a) : bool =
  (x = y) || o.lt x y

let le_b_of_lt (#a:eqtype) (o:strict_order a) (x:a) (y:a)
  : Lemma (requires o.lt x y = true) (ensures le_b o x y = true)
  = ()

(* A value below the current pin stays below the next pin. *)
let le_lt_trans (#a:eqtype) (o:strict_order a) (x:a) (y:a) (z:a)
  : Lemma (requires le_b o x y = true /\ o.lt y z = true)
          (ensures o.lt x z = true)
  = if x = y then () else o.lt_trans x y z

(* Exact all-pairs goal for JournalCleared events, packaged as a logical
   formula. *)
let clear_pins_strictly_increase
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (o:strict_order rev) (h:trace rev tx msg)
  : Type
  = forall (i j:nat) (tx1 tx2:tx) (g1 g2:gen) (p1 p2:rev).
      i < j ->
      occurs_at h i (EClear tx1 g1 p1) = true ->
      occurs_at h j (EClear tx2 g2 p2) = true ->
      o.lt p1 p2 = true

(* The pin of the durable product state. *)
let phase_pin (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (ph:phase rev tx msg)
  : Tot rev
  = match ph with
    | Clean _ p _ _ -> p
    | Pending _ _ next _ _ _ -> next
    | Applied _ _ next _ _ _ -> next

(* Strictness flag of the durable phase: [false] in Clean, [true] while a
   commit is Pending or Applied. *)
let is_strict_phase (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
    (ph:phase rev tx msg)
  : Tot bool
  = match ph with
    | Clean _ _ _ _ -> false
    | Pending _ _ _ _ _ _ -> true
    | Applied _ _ _ _ _ _ -> true

(* In every reachable state, each earlier clear pin is at most the current
   pin in Clean and strictly below it in Pending/Applied. *)
let rec reach_core_pin_bound
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (o:strict_order rev) (r0:rev) (item:msg)
  (h:trace rev tx msg) (c:core rev tx msg)
  (r:reach_core o.lt r0 item h c)
  (i:nat) (tx':tx) (g:gen) (p':rev)
  : Lemma (requires occurs_at h i (EClear tx' g p') = true)
          (ensures
            (if is_strict_phase c.ph
             then o.lt p' (phase_pin c.ph) = true
             else le_b o p' (phase_pin c.ph) = true))
          (decreases r)
  = match r with
    | RCInit -> ()
    | RCSnoc h0 c0 e c' rprev st ->
        (match st with
         | CReadSnapshot c1 tx0 g0 p0 nf mem ->
             if i = trace_len h0 then ()
             else reach_core_pin_bound o r0 item h0 c0 rprev i tx' g p'
         | CPersistJournal c1 tx0 g0 p0 vrev vpayload next0 payload0
             rest ph sp inc ->
             if i = trace_len h0 then ()
             else
               (reach_core_pin_bound o r0 item h0 c0 rprev i tx' g p';
                le_lt_trans o p' p0 next0)
         | CPersistVault c1 tx0 g0 next0 payload0 vrev vpayload ph ->
             if i = trace_len h0 then ()
             else reach_core_pin_bound o r0 item h0 c0 rprev i tx' g p'
         | CClearJournal c1 tx0 g0 p0 intended vrev vpayload ph ->
             if i = trace_len h0 then
               eq_event_true #rev #tx #msg (EClear tx' g p') (EClear tx0 g0 p0)
             else
               (reach_core_pin_bound o r0 item h0 c0 rprev i tx' g p';
                le_b_of_lt o p' p0)
         | CCrash c1 op ->
             if i = trace_len h0 then ()
             else reach_core_pin_bound o r0 item h0 c0 rprev i tx' g p'
         | COpenVault c1 g0 p0 revision payload0 ph ->
             if i = trace_len h0 then ()
             else reach_core_pin_bound o r0 item h0 c0 rprev i tx' g p')

(* Parametric all-pairs pin goal: for every ordered pair of clears in a
   reachable trace, the earlier pin is strictly below the later pin. *)
let rec reach_core_clear_pins_strict
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (o:strict_order rev) (r0:rev) (item:msg)
  (h:trace rev tx msg) (c:core rev tx msg)
  (r:reach_core o.lt r0 item h c)
  (i j:nat) (tx1 tx2:tx) (g1 g2:gen) (p1 p2:rev)
  : Lemma (requires i < j
                    /\ occurs_at h i (EClear tx1 g1 p1) = true
                    /\ occurs_at h j (EClear tx2 g2 p2) = true)
          (ensures (o.lt p1 p2 = true))
          (decreases r)
  = match r with
    | RCInit -> ()
    | RCSnoc h0 c0 e c' rprev st ->
        (match st with
         | CReadSnapshot c1 tx0 g0 p0 nf mem ->
             if j = trace_len h0 then ()
             else if i = trace_len h0 then
               occurs_at_bound (Snoc h0 (ESnapshotRead tx0 g0 p0)) j
                 (EClear tx2 g2 p2)
             else reach_core_clear_pins_strict o r0 item h0 c0 rprev
                    i j tx1 tx2 g1 g2 p1 p2
         | CPersistJournal c1 tx0 g0 p0 vrev vpayload next0 payload0
             rest ph sp inc ->
             if j = trace_len h0 then ()
             else if i = trace_len h0 then
               occurs_at_bound
                 (Snoc h0 (EJournal tx0 (GS g0) p0 next0 payload0)) j
                 (EClear tx2 g2 p2)
             else reach_core_clear_pins_strict o r0 item h0 c0 rprev
                    i j tx1 tx2 g1 g2 p1 p2
         | CPersistVault c1 tx0 g0 next0 payload0 vrev vpayload ph ->
             if j = trace_len h0 then ()
             else if i = trace_len h0 then
               occurs_at_bound
                 (Snoc h0 (EVault tx0 g0 next0 payload0)) j
                 (EClear tx2 g2 p2)
             else reach_core_clear_pins_strict o r0 item h0 c0 rprev
                    i j tx1 tx2 g1 g2 p1 p2
         | CClearJournal c1 tx0 g0 p0 intended vrev vpayload ph ->
             if j = trace_len h0 then
               (reach_core_pin_bound o r0 item h0 c0 rprev i tx1 g1 p1;
                eq_event_true #rev #tx #msg (EClear tx2 g2 p2) (EClear tx0 g0 p0))
             else if i = trace_len h0 then
               occurs_at_bound (Snoc h0 (EClear tx0 g0 p0)) j
                 (EClear tx2 g2 p2)
             else reach_core_clear_pins_strict o r0 item h0 c0 rprev
                    i j tx1 tx2 g1 g2 p1 p2
         | CCrash c1 op ->
             if j = trace_len h0 then ()
             else if i = trace_len h0 then
               occurs_at_bound (Snoc h0 ECrash) j (EClear tx2 g2 p2)
             else reach_core_clear_pins_strict o r0 item h0 c0 rprev
                    i j tx1 tx2 g1 g2 p1 p2
         | COpenVault c1 g0 p0 revision payload0 ph ->
             if j = trace_len h0 then ()
             else if i = trace_len h0 then
               occurs_at_bound
                 (Snoc h0 (EOpened g0 p0 revision payload0)) j
                 (EClear tx2 g2 p2)
             else reach_core_clear_pins_strict o r0 item h0 c0 rprev
                    i j tx1 tx2 g1 g2 p1 p2)

(* The lifted encoding has the same event trace, so the goal transfers. *)
let reach_lift_clear_pins_strict
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (o:strict_order rev) (r0:rev) (item:msg)
  (h:trace rev tx msg) (s:lifted rev tx msg)
  (r:reach_lift o.lt r0 item h s)
  (i j:nat) (tx1 tx2:tx) (g1 g2:gen) (p1 p2:rev)
  : Lemma (requires i < j
                    /\ occurs_at h i (EClear tx1 g1 p1) = true
                    /\ occurs_at h j (EClear tx2 g2 p2) = true)
          (ensures (o.lt p1 p2 = true))
  = reach_core_clear_pins_strict o r0 item h s.base
      (reach_lift_projects o.lt r0 item h s r)
      i j tx1 tx2 g1 g2 p1 p2;
    ()

(* The lifted encoding satisfies the generation goal as well. *)
let reach_lift_journal_unique
  (#rev:eqtype) (#tx:eqtype) (#msg:eqtype)
  (lt:rev -> rev -> bool) (r0:rev) (item:msg)
  (h:trace rev tx msg) (s:lifted rev tx msg)
  (r:reach_lift lt r0 item h s)
  (i j:nat) (tx1 tx2:tx) (g:gen)
  (old1 old2 next1 next2:rev) (payload1 payload2:msg)
  : Lemma (requires occurs_at h i (EJournal tx1 g old1 next1 payload1) = true
                    /\ occurs_at h j (EJournal tx2 g old2 next2 payload2) = true)
          (ensures (i = j))
  = reach_core_journal_unique lt r0 item h s.base
      (reach_lift_projects lt r0 item h s r)
      i j tx1 tx2 g old1 old2 next1 next2 payload1 payload2;
    ()

(* ================================================================== *)
(* Concrete revision term order and a two-commit reachability witness. *)
(* ================================================================== *)

(* The concrete revision instance used by the witness below: the unary free
   term algebra generated by 'initial' and successor, with proper subterm as
   the strict order.  This instantiates the encoded revision parameter only;
   it is not the full Tamarin subterm algebra and not a source embedding. *)
type term =
  | TInit
  | TSucc of term

let rec subterm (x:term) (y:term) : Tot bool (decreases y) =
  match y with
  | TInit -> false
  | TSucc y' -> if x = y' then true else subterm x y'

let rec term_size (t:term) : Tot nat (decreases t) =
  match t with
  | TInit -> 0
  | TSucc t' -> 1 + term_size t'

let rec subterm_size (x:term) (y:term)
  : Lemma (requires subterm x y = true)
          (ensures (term_size x < term_size y))
          (decreases y)
  = match y with
    | TInit -> ()
    | TSucc y' -> if x = y' then () else subterm_size x y'

let rec subterm_trans (x:term) (y:term) (z:term)
  : Lemma (requires subterm x y = true /\ subterm y z = true)
          (ensures (subterm x z = true))
          (decreases z)
  = match z with
    | TInit -> ()
    | TSucc z' ->
        if y = z' then () else subterm_trans x y z'

let subterm_irrefl (x:term) : Lemma (subterm x x = false) =
  if subterm x x then (subterm_size x x; assert False) else ()

let term_order : strict_order term = {
  lt = subterm;
  lt_trans = (fun x y z -> subterm_trans x y z);
  lt_irrefl = (fun x -> subterm_irrefl x);
}

(* Explicit proof terms for the two linear-list premises.  [memP x []]
   reduces to [False]; [memP x (x :: rest)] starts with a reflexivity
   disjunct.  Both are ordinary terms, not retained assumptions. *)
let not_memP_nil (#a:Type) (x:a)
  : ~(FStar.List.Tot.memP x [])
  = FStar.Squash.return_squash
      #(FStar.List.Tot.memP x [] -> GTot Prims.l_False)
      (fun (h:FStar.List.Tot.memP x []) ->
        (let h' : Prims.l_False = h in h'))

let memP_head (#a:Type) (x:a) (rest:list a)
  : FStar.List.Tot.memP x (x :: rest)
  = FStar.Squash.return_squash
      #(Prims.sum (x == x) (FStar.List.Tot.memP x rest))
      (Prims.Left
        (FStar.Squash.return_squash #(Prims.equals x x) Prims.Refl))

let eq_refl (#a:eqtype) (x:a) : (x = x) =
  FStar.Squash.return_squash Prims.Refl

let w_nf_0 : ~(FStar.List.Tot.memP 0 []) = not_memP_nil 0

let w_mem_0
  : FStar.List.Tot.memP (G0, TInit) [(G0, TInit)] =
  memP_head (G0, TInit) []

let w_mem_1
  : FStar.List.Tot.memP (GS G0, TSucc TInit)
      ((GS G0, TSucc TInit) :: [(G0, TInit)]) =
  memP_head (GS G0, TSucc TInit) [(G0, TInit)]

(* The two-commit trace.  Timepoints: 0 Initialized, 1 SnapshotRead,
   2 Journal, 3 Vault, 4 Clear, 5 SnapshotRead, 6 Journal, 7 Vault,
   8 Clear. *)
let w_init : core term nat nat = init_core TInit 0

let w_t1 : trace term nat nat = Snoc Nil EInitialized

let w_read1 : event term nat nat = ESnapshotRead 0 G0 TInit

let w_c1 : core term nat nat =
  { w_init with used = [0]; snaps = [(0, G0, TInit)] }

let w_s1 : step_core subterm w_init w_read1 w_c1 =
  CReadSnapshot w_init 0 G0 TInit w_nf_0 w_mem_0

let w_t2 : trace term nat nat = Snoc w_t1 w_read1

let w_r2 : reach_core subterm TInit 0 w_t2 w_c1 =
  RCSnoc w_t1 w_init w_read1 w_c1 RCInit w_s1

let w_j1 : event term nat nat =
  EJournal 0 (GS G0) TInit (TSucc TInit) 1

let w_c2 : core term nat nat =
  { w_c1 with
    ph = Pending 0 (GS G0) (TSucc TInit) 1 TInit 0;
    snaps = [] }

let w_s2 : step_core subterm w_c1 w_j1 w_c2 =
  CPersistJournal w_c1 0 G0 TInit TInit 0 (TSucc TInit) 1 []
    (eq_refl w_c1.ph) (SplitHere (0, G0, TInit) [])
    (eq_refl (subterm TInit (TSucc TInit)))

let w_t3 : trace term nat nat = Snoc w_t2 w_j1

let w_r3 : reach_core subterm TInit 0 w_t3 w_c2 =
  RCSnoc w_t2 w_c1 w_j1 w_c2 w_r2 w_s2

let w_v1 : event term nat nat =
  EVault 0 (GS G0) (TSucc TInit) 1

let w_c3 : core term nat nat =
  { w_c2 with ph = Applied 0 (GS G0) (TSucc TInit) 1 (TSucc TInit) 1 }

let w_s3 : step_core subterm w_c2 w_v1 w_c3 =
  CPersistVault w_c2 0 (GS G0) (TSucc TInit) 1 TInit 0
    (eq_refl w_c2.ph)

let w_t4 : trace term nat nat = Snoc w_t3 w_v1

let w_r4 : reach_core subterm TInit 0 w_t4 w_c3 =
  RCSnoc w_t3 w_c2 w_v1 w_c3 w_r3 w_s3

let w_k1 : event term nat nat =
  EClear 0 (GS G0) (TSucc TInit)

let w_c4 : core term nat nat =
  { w_c3 with
    ph = Clean (GS G0) (TSucc TInit) (TSucc TInit) 1;
    ready = (GS G0, TSucc TInit) :: w_c3.ready }

let w_nf_1 : ~(FStar.List.Tot.memP 1 w_c4.used) =
  FStar.Squash.return_squash
    #(FStar.List.Tot.memP 1 w_c4.used -> GTot Prims.l_False)
    (fun (h:FStar.List.Tot.memP 1 w_c4.used) ->
      (let h' : Prims.l_False = h in h'))

let w_s4 : step_core subterm w_c3 w_k1 w_c4 =
  CClearJournal w_c3 0 (GS G0) (TSucc TInit) 1 (TSucc TInit) 1
    (eq_refl w_c3.ph)

let w_t5 : trace term nat nat = Snoc w_t4 w_k1

let w_r5 : reach_core subterm TInit 0 w_t5 w_c4 =
  RCSnoc w_t4 w_c3 w_k1 w_c4 w_r4 w_s4

let w_read2 : event term nat nat =
  ESnapshotRead 1 (GS G0) (TSucc TInit)

let w_c5 : core term nat nat =
  { w_c4 with
    used = [1; 0];
    snaps = [(1, GS G0, TSucc TInit)] }

let w_s5 : step_core subterm w_c4 w_read2 w_c5 =
  CReadSnapshot w_c4 1 (GS G0) (TSucc TInit) w_nf_1 w_mem_1

let w_t6 : trace term nat nat = Snoc w_t5 w_read2

let w_r6 : reach_core subterm TInit 0 w_t6 w_c5 =
  RCSnoc w_t5 w_c4 w_read2 w_c5 w_r5 w_s5

let w_j2 : event term nat nat =
  EJournal 1 (GS (GS G0)) (TSucc TInit) (TSucc (TSucc TInit)) 2

let w_c6 : core term nat nat =
  { w_c5 with
    ph = Pending 1 (GS (GS G0)) (TSucc (TSucc TInit)) 2 (TSucc TInit) 1;
    snaps = [] }

let w_s6 : step_core subterm w_c5 w_j2 w_c6 =
  CPersistJournal w_c5 1 (GS G0) (TSucc TInit) (TSucc TInit) 1
    (TSucc (TSucc TInit)) 2 []
    (eq_refl w_c5.ph) (SplitHere (1, GS G0, TSucc TInit) [])
    (eq_refl (subterm (TSucc TInit) (TSucc (TSucc TInit))))

let w_t7 : trace term nat nat = Snoc w_t6 w_j2

let w_r7 : reach_core subterm TInit 0 w_t7 w_c6 =
  RCSnoc w_t6 w_c5 w_j2 w_c6 w_r6 w_s6

let w_v2 : event term nat nat =
  EVault 1 (GS (GS G0)) (TSucc (TSucc TInit)) 2

let w_c7 : core term nat nat =
  { w_c6 with
    ph = Applied 1 (GS (GS G0)) (TSucc (TSucc TInit)) 2
           (TSucc (TSucc TInit)) 2 }

let w_s7 : step_core subterm w_c6 w_v2 w_c7 =
  CPersistVault w_c6 1 (GS (GS G0)) (TSucc (TSucc TInit)) 2 (TSucc TInit) 1
    (eq_refl w_c6.ph)

let w_t8 : trace term nat nat = Snoc w_t7 w_v2

let w_r8 : reach_core subterm TInit 0 w_t8 w_c7 =
  RCSnoc w_t7 w_c6 w_v2 w_c7 w_r7 w_s7

let w_k2 : event term nat nat =
  EClear 1 (GS (GS G0)) (TSucc (TSucc TInit))

let w_c8 : core term nat nat =
  { w_c7 with
    ph = Clean (GS (GS G0)) (TSucc (TSucc TInit)) (TSucc (TSucc TInit)) 2;
    ready =
      (GS (GS G0), TSucc (TSucc TInit)) :: w_c7.ready }

let w_s8 : step_core subterm w_c7 w_k2 w_c8 =
  CClearJournal w_c7 1 (GS (GS G0)) (TSucc (TSucc TInit)) 2
    (TSucc (TSucc TInit)) 2 (eq_refl w_c7.ph)

let w_t9 : trace term nat nat = Snoc w_t8 w_k2

let two_commits_reach : reach_core subterm TInit 0 w_t9 w_c8 =
  RCSnoc w_t8 w_c7 w_k2 w_c8 w_r8 w_s8

(* The same trace in the lifted encoding, obtained through the checked
   projection/lifting equivalence. *)
let two_commits_reach_lift
  : reach_lift subterm TInit 0 w_t9 (lift_state w_c8)
  = reach_core_lifts #term #nat #nat subterm TInit 0 w_t9 w_c8
      two_commits_reach

(* The bodies of [clear_pins_strictly_increase term_order w_t9] and
   [journal_generation_at_most_once w_t9], specialized to the witness trace.
   These are not new assumptions: they call the checked parametric theorems. *)
let two_commits_clear_goal
  (i j:nat) (tx1 tx2:nat) (g1 g2:gen) (p1 p2:term)
  : Lemma (requires i < j
                    /\ occurs_at w_t9 i (EClear tx1 g1 p1) = true
                    /\ occurs_at w_t9 j (EClear tx2 g2 p2) = true)
          (ensures (term_order.lt p1 p2 = true))
  = reach_core_clear_pins_strict #term #nat #nat term_order TInit 0 w_t9 w_c8
      two_commits_reach i j tx1 tx2 g1 g2 p1 p2

let two_commits_journal_goal
  (i j:nat) (tx1 tx2:nat) (g:gen)
  (old1 old2 next1 next2:term) (payload1 payload2:nat)
  : Lemma (requires occurs_at w_t9 i (EJournal tx1 g old1 next1 payload1) = true
                    /\ occurs_at w_t9 j (EJournal tx2 g old2 next2 payload2) = true)
          (ensures (i = j))
  = reach_core_journal_unique #term #nat #nat subterm TInit 0 w_t9 w_c8
      two_commits_reach i j tx1 tx2 g old1 old2 next1 next2 payload1 payload2

let two_commits_lift_clear_goal
  (i j:nat) (tx1 tx2:nat) (g1 g2:gen) (p1 p2:term)
  : Lemma (requires i < j
                    /\ occurs_at w_t9 i (EClear tx1 g1 p1) = true
                    /\ occurs_at w_t9 j (EClear tx2 g2 p2) = true)
          (ensures (term_order.lt p1 p2 = true))
  = reach_lift_clear_pins_strict #term #nat #nat term_order TInit 0 w_t9
      (lift_state w_c8) two_commits_reach_lift i j tx1 tx2 g1 g2 p1 p2

let two_commits_lift_journal_goal
  (i j:nat) (tx1 tx2:nat) (g:gen)
  (old1 old2 next1 next2:term) (payload1 payload2:nat)
  : Lemma (requires occurs_at w_t9 i (EJournal tx1 g old1 next1 payload1) = true
                    /\ occurs_at w_t9 j (EJournal tx2 g old2 next2 payload2) = true)
          (ensures (i = j))
  = reach_lift_journal_unique #term #nat #nat subterm TInit 0 w_t9
      (lift_state w_c8) two_commits_reach_lift
      i j tx1 tx2 g old1 old2 next1 next2 payload1 payload2

(* Concrete non-vacuity: the witness has two journals at timepoints 2 and 6
   with generations GS G0 and GS (GS G0), and two clears at timepoints 4 and
   8 whose pins strictly increase. The pin theorems are instantiated at
   distinct indices 4 < 8. The journal uniqueness theorems are instantiated
   reflexively at 2 = 2: the two distinct journals have different generations,
   and a same-generation pair at distinct indices is forbidden. *)
let two_commits_ordered (u:unit)
  : Lemma
      (term_order.lt (TSucc TInit) (TSucc (TSucc TInit)) = true
       /\ occurs_at w_t9 2
            (EJournal 0 (GS G0) TInit (TSucc TInit) 1) = true
       /\ occurs_at w_t9 6
            (EJournal 1 (GS (GS G0)) (TSucc TInit) (TSucc (TSucc TInit)) 2) = true
       /\ occurs_at w_t9 4 (EClear 0 (GS G0) (TSucc TInit)) = true
       /\ occurs_at w_t9 8
            (EClear 1 (GS (GS G0)) (TSucc (TSucc TInit))) = true
       /\ gen_depth (GS G0) = 1
       /\ gen_depth (GS (GS G0)) = 2)
  = assert (occurs_at w_t9 2
              (EJournal 0 (GS G0) TInit (TSucc TInit) 1) = true);
    assert (occurs_at w_t9 6
              (EJournal 1 (GS (GS G0)) (TSucc TInit)
                (TSucc (TSucc TInit)) 2) = true);
    assert (occurs_at w_t9 4 (EClear 0 (GS G0) (TSucc TInit)) = true);
    assert (occurs_at w_t9 8
              (EClear 1 (GS (GS G0)) (TSucc (TSucc TInit))) = true);
    reach_core_journal_depth #term #nat #nat subterm TInit 0 w_t9 w_c8
      two_commits_reach 2 0 (GS G0) TInit (TSucc TInit) 1;
    reach_core_journal_depth #term #nat #nat subterm TInit 0 w_t9 w_c8
      two_commits_reach 6 1 (GS (GS G0)) (TSucc TInit)
      (TSucc (TSucc TInit)) 2;
    two_commits_journal_goal 2 2 0 0 (GS G0)
      TInit TInit (TSucc TInit) (TSucc TInit) 1 1;
    two_commits_lift_journal_goal 2 2 0 0 (GS G0)
      TInit TInit (TSucc TInit) (TSucc TInit) 1 1;
    reach_core_clear_pins_strict #term #nat #nat term_order TInit 0 w_t9 w_c8
      two_commits_reach
      4 8 0 1 (GS G0) (GS (GS G0)) (TSucc TInit) (TSucc (TSucc TInit));
    reach_lift_clear_pins_strict #term #nat #nat term_order TInit 0 w_t9
      (lift_state w_c8) two_commits_reach_lift
      4 8 0 1 (GS G0) (GS (GS G0)) (TSucc TInit) (TSucc (TSucc TInit));
    ()
