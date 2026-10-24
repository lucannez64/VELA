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
   functions are schemas taking a proof of the lifted predicate as input.
   No all-pairs security goal is defined or proved in this module.

   Source correspondence is not established here. In particular, the
   encodings omit attacker In/Out derivability, model transaction non-reuse
   only per slot, and do not check the untyped-term or multi-slot embeddings.
   Applying a Tamarin verdict still needs both directed embeddings described
   in README.md. Arbitrary revision/payload inputs over-approximate In
   derivability; they are not asserted to be exactly the source rules. *)

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
   [snaps] is the multiset of linear Snapshot facts, [used] tracks per-slot
   transaction non-reuse (not global freshness), [opened] is !Profile.
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

(* A predicate over the encoded traces transfers given an input proof [hp].
   This is a schema, not a proof of either all-pairs goal. No Tamarin verdict
   or source embedding is supplied by this module. *)
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
