module Vela_client_share_journal
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// Durable phase of the share journal. The phase is not serialized: a store
/// with no pending items decodes as `Clean`, a store with pending items decodes
/// as `Pending` (whether or not the vault write already happened).
type t_JournalPhase =
  | JournalPhase_Clean : t_JournalPhase
  | JournalPhase_Pending : t_JournalPhase
  | JournalPhase_Applied : t_JournalPhase

/// One pending vault-item change, reduced to the facts the journal phase
/// machine needs. The shell keeps the actual items; this is its stable id and
/// whether a `before` image existed.
type t_PendingItem = {
  f_id:u64;
  f_had_before:bool
}

let impl_8: Core_models.Clone.t_Clone t_PendingItem =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// One pinned received share, reduced to the M28 pin facts: a slot (one
/// received lineage) and its committed revision.
type t_SharePin = {
  f_slot:u64;
  f_revision:u64
}

let impl_14: Core_models.Clone.t_Clone t_SharePin =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// The durable journal content: generation, pending items and pins.
type t_JournalImage = {
  f_generation:u64;
  f_pending:Alloc.Vec.t_Vec t_PendingItem Alloc.Alloc.t_Global;
  f_pins:Alloc.Vec.t_Vec t_SharePin Alloc.Alloc.t_Global
}

let impl_20: Core_models.Clone.t_Clone t_JournalImage =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// The journal's current state.
type t_JournalState = {
  f_generation:u64;
  f_phase:t_JournalPhase;
  f_pending:Alloc.Vec.t_Vec t_PendingItem Alloc.Alloc.t_Global;
  f_pins:Alloc.Vec.t_Vec t_SharePin Alloc.Alloc.t_Global
}

/// A filesystem write the shell must perform, in order.
type t_JournalEffect =
  | JournalEffect_WriteJournal : t_JournalImage -> t_JournalEffect
  | JournalEffect_WriteVault : t_JournalEffect
  | JournalEffect_ClearJournal : t_JournalImage -> t_JournalEffect

/// The observations and requests the shell feeds to [`step`].
type t_JournalEvent =
  | JournalEvent_ReadSnapshot {
    f_generation:u64;
    f_pending:Alloc.Vec.t_Vec t_PendingItem Alloc.Alloc.t_Global;
    f_pins:Alloc.Vec.t_Vec t_SharePin Alloc.Alloc.t_Global
  }: t_JournalEvent
  | JournalEvent_PersistJournal {
    f_snapshot_generation:u64;
    f_pending:Alloc.Vec.t_Vec t_PendingItem Alloc.Alloc.t_Global;
    f_pins:Alloc.Vec.t_Vec t_SharePin Alloc.Alloc.t_Global
  }: t_JournalEvent
  | JournalEvent_ReArm : t_JournalEvent
  | JournalEvent_ApplyToVault : t_JournalEvent
  | JournalEvent_Clear : t_JournalEvent
  | JournalEvent_Crash : t_JournalEvent
  | JournalEvent_Recover : t_JournalEvent

/// Result of one step: the next state and the effects to perform in order.
type t_JournalStep = {
  f_state:t_JournalState;
  f_effects:Alloc.Vec.t_Vec t_JournalEffect Alloc.Alloc.t_Global
}

/// A canonical item-commit plan: the four effects in the order M28 requires.
/// The shell performs [`CommitEffects::into_effects`] in field order.
type t_CommitEffects = {
  f_persist:t_JournalEffect;
  f_rearm:t_JournalEffect;
  f_vault:t_JournalEffect;
  f_clear:t_JournalEffect
}

/// The image a journal write would publish for this state.
let impl_JournalState__image (self: t_JournalState) : t_JournalImage =
  {
    f_generation = self.f_generation;
    f_pending
    =
    Core_models.Clone.f_clone #(Alloc.Vec.t_Vec t_PendingItem Alloc.Alloc.t_Global)
      #FStar.Tactics.Typeclasses.solve
      self.f_pending;
    f_pins
    =
    Core_models.Clone.f_clone #(Alloc.Vec.t_Vec t_SharePin Alloc.Alloc.t_Global)
      #FStar.Tactics.Typeclasses.solve
      self.f_pins
  }
  <:
  t_JournalImage

/// The image a clear write publishes: same generation and pins, no pending.
let impl_JournalState__cleared_image (self: t_JournalState) : t_JournalImage =
  {
    f_generation = self.f_generation;
    f_pending = Alloc.Vec.impl__new #t_PendingItem ();
    f_pins
    =
    Core_models.Clone.f_clone #(Alloc.Vec.t_Vec t_SharePin Alloc.Alloc.t_Global)
      #FStar.Tactics.Typeclasses.solve
      self.f_pins
  }
  <:
  t_JournalImage

/// A phase is well formed when pending items exist exactly in a non-clean
/// phase. A store cannot persist `Applied`; it decodes as `Pending`.
let state_is_well_formed (state: t_JournalState) : bool =
  if Alloc.Vec.impl_1__is_empty #t_PendingItem #Alloc.Alloc.t_Global state.f_pending
  then
    match state.f_phase <: t_JournalPhase with
    | JournalPhase_Clean  -> true
    | _ -> false
  else
    ~.(match state.f_phase <: t_JournalPhase with
      | JournalPhase_Clean  -> true
      | _ -> false)

let phase_for (pending: t_Slice t_PendingItem) : t_JournalPhase =
  if Core_models.Slice.impl__is_empty #t_PendingItem pending
  then JournalPhase_Clean <: t_JournalPhase
  else JournalPhase_Pending <: t_JournalPhase

/// The generation a successful commit publishes. Saturating at `u64::MAX`
/// keeps the pure function total; `commit_is_authorized` refuses that point, so
/// the saturated value is never used for a real write.
let next_generation (generation: u64) : u64 =
  if generation =. Core_models.Num.impl_u64__MAX then generation else generation +! mk_u64 1

/// The commit-authorization check shared by [`step`] and [`plan_commit`]: the
/// freshly read disk journal is clean and still at the snapshot generation,
/// and the generation has room to advance. This is the M28
/// `ReadSnapshot`/`PersistJournal` guard plus the code's generation equality.
let commit_is_authorized (state: t_JournalState) (snapshot_generation: u64) : bool =
  (match state.f_phase <: t_JournalPhase with
    | JournalPhase_Clean  -> true
    | _ -> false) &&
  Alloc.Vec.impl_1__is_empty #t_PendingItem #Alloc.Alloc.t_Global state.f_pending &&
  state.f_generation =. snapshot_generation &&
  state.f_generation <. Core_models.Num.impl_u64__MAX

/// Postcondition of [`step`]: the generation never decreases and a well-formed
/// input stays well formed.
let step_result_is_sound (state: t_JournalState) (result: t_JournalStep) : bool =
  result.f_state.f_generation >=. state.f_generation &&
  (~.(state_is_well_formed state <: bool) || state_is_well_formed result.f_state)

/// Every effect of an item commit: journal persistence, re-arm, vault, clear.
/// The generation is the one the persist step produced; clear keeps it.
let commit_effects_match_spec
      (prior: t_JournalState)
      (snapshot_generation: u64)
      (pending: t_Slice t_PendingItem)
      (pins: t_Slice t_SharePin)
      (effects: t_CommitEffects)
    : bool =
  let generation:u64 = next_generation prior.f_generation in
  prior.f_generation <. Core_models.Num.impl_u64__MAX &&
  commit_is_authorized prior snapshot_generation &&
  ~.(Core_models.Slice.impl__is_empty #t_PendingItem pending <: bool) &&
  (match effects.f_persist <: t_JournalEffect with
    | JournalEffect_WriteJournal image ->
      image.f_generation =. generation &&
      ~.(Alloc.Vec.impl_1__is_empty #t_PendingItem #Alloc.Alloc.t_Global image.f_pending <: bool) &&
      (Alloc.Vec.impl_1__len #t_SharePin #Alloc.Alloc.t_Global image.f_pins <: usize) =.
      (Core_models.Slice.impl__len #t_SharePin pins <: usize)
    | _ -> false) &&
  (match effects.f_rearm <: t_JournalEffect with
    | JournalEffect_WriteJournal image ->
      image.f_generation =. generation &&
      ~.(Alloc.Vec.impl_1__is_empty #t_PendingItem #Alloc.Alloc.t_Global image.f_pending <: bool) &&
      (Alloc.Vec.impl_1__len #t_SharePin #Alloc.Alloc.t_Global image.f_pins <: usize) =.
      (Core_models.Slice.impl__len #t_SharePin pins <: usize)
    | _ -> false) &&
  (match effects.f_vault <: t_JournalEffect with
    | JournalEffect_WriteVault  -> true
    | _ -> false) &&
  (match effects.f_clear <: t_JournalEffect with
    | JournalEffect_ClearJournal image ->
      image.f_generation =. generation &&
      Alloc.Vec.impl_1__is_empty #t_PendingItem #Alloc.Alloc.t_Global image.f_pending &&
      (Alloc.Vec.impl_1__len #t_SharePin #Alloc.Alloc.t_Global image.f_pins <: usize) =.
      (Core_models.Slice.impl__len #t_SharePin pins <: usize)
    | _ -> false)

/// A planned commit: the cleared state after the four effects and the effects.
type t_CommitPlan = {
  f_state:t_JournalState;
  f_effects:t_CommitEffects
}

/// Plan the canonical item commit for a clean journal and snapshot. Returns
/// `None` when the commit is refused (stale snapshot, pending record, or an
/// exhausted generation), matching [`step`]\'s `PersistJournal` decision.
let plan_commit
      (state: t_JournalState)
      (snapshot_generation: u64)
      (pending: Alloc.Vec.t_Vec t_PendingItem Alloc.Alloc.t_Global)
      (pins: Alloc.Vec.t_Vec t_SharePin Alloc.Alloc.t_Global)
    : Prims.Pure (Core_models.Option.t_Option t_CommitPlan)
      Prims.l_True
      (ensures
        fun result ->
          let result:Core_models.Option.t_Option t_CommitPlan = result in
          match result <: Core_models.Option.t_Option t_CommitPlan with
          | Core_models.Option.Option_Some plan ->
            commit_effects_match_spec state
              snapshot_generation
              (Alloc.Vec.impl_1__as_slice pending <: t_Slice t_PendingItem)
              (Alloc.Vec.impl_1__as_slice pins <: t_Slice t_SharePin)
              plan.f_effects &&
            plan.f_state.f_generation =. (next_generation state.f_generation <: u64) &&
            (match plan.f_state.f_phase <: t_JournalPhase with
              | JournalPhase_Clean  -> true
              | _ -> false) &&
            Alloc.Vec.impl_1__is_empty #t_PendingItem #Alloc.Alloc.t_Global plan.f_state.f_pending
          | Core_models.Option.Option_None  ->
            ~.(commit_is_authorized state snapshot_generation <: bool) ||
            Alloc.Vec.impl_1__is_empty #t_PendingItem #Alloc.Alloc.t_Global pending) =
  if
    ~.(commit_is_authorized state snapshot_generation <: bool) ||
    Alloc.Vec.impl_1__is_empty #t_PendingItem #Alloc.Alloc.t_Global pending
  then Core_models.Option.Option_None <: Core_models.Option.t_Option t_CommitPlan
  else
    let generation:u64 = next_generation state.f_generation in
    let image:t_JournalImage =
      {
        f_generation = generation;
        f_pending
        =
        Core_models.Clone.f_clone #(Alloc.Vec.t_Vec t_PendingItem Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          pending;
        f_pins
        =
        Core_models.Clone.f_clone #(Alloc.Vec.t_Vec t_SharePin Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          pins
      }
      <:
      t_JournalImage
    in
    let effects:t_CommitEffects =
      {
        f_persist
        =
        JournalEffect_WriteJournal
        (Core_models.Clone.f_clone #t_JournalImage #FStar.Tactics.Typeclasses.solve image)
        <:
        t_JournalEffect;
        f_rearm = JournalEffect_WriteJournal image <: t_JournalEffect;
        f_vault = JournalEffect_WriteVault <: t_JournalEffect;
        f_clear
        =
        JournalEffect_ClearJournal
        ({
            f_generation = generation;
            f_pending = Alloc.Vec.impl__new #t_PendingItem ();
            f_pins
            =
            Core_models.Clone.f_clone #(Alloc.Vec.t_Vec t_SharePin Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              pins
          }
          <:
          t_JournalImage)
        <:
        t_JournalEffect
      }
      <:
      t_CommitEffects
    in
    Core_models.Option.Option_Some
    ({
        f_state
        =
        {
          f_generation = generation;
          f_phase = JournalPhase_Clean <: t_JournalPhase;
          f_pending = Alloc.Vec.impl__new #t_PendingItem ();
          f_pins = pins
        }
        <:
        t_JournalState;
        f_effects = effects
      }
      <:
      t_CommitPlan)
    <:
    Core_models.Option.t_Option t_CommitPlan

/// A helper for the gate: `true` when `effects` is exactly the canonical item
/// commit order: journal, re-arm, vault, clear.
let effects_are_commit_ordered (effects: t_Slice t_JournalEffect) : bool =
  (Core_models.Slice.impl__len #t_JournalEffect effects <: usize) =. mk_usize 4 &&
  (match effects.[ mk_usize 0 ] <: t_JournalEffect with
    | JournalEffect_WriteJournal _ -> true
    | _ -> false) &&
  (match effects.[ mk_usize 1 ] <: t_JournalEffect with
    | JournalEffect_WriteJournal _ -> true
    | _ -> false) &&
  (match effects.[ mk_usize 2 ] <: t_JournalEffect with
    | JournalEffect_WriteVault  -> true
    | _ -> false) &&
  (match effects.[ mk_usize 3 ] <: t_JournalEffect with
    | JournalEffect_ClearJournal _ -> true
    | _ -> false)

/// A helper for the gate: `true` when `effects` is exactly the canonical
/// recovery order: journal, vault, clear.
let effects_are_recovery_ordered (effects: t_Slice t_JournalEffect) : bool =
  (Core_models.Slice.impl__len #t_JournalEffect effects <: usize) =. mk_usize 3 &&
  (match effects.[ mk_usize 0 ] <: t_JournalEffect with
    | JournalEffect_WriteJournal _ -> true
    | _ -> false) &&
  (match effects.[ mk_usize 1 ] <: t_JournalEffect with
    | JournalEffect_WriteVault  -> true
    | _ -> false) &&
  (match effects.[ mk_usize 2 ] <: t_JournalEffect with
    | JournalEffect_ClearJournal _ -> true
    | _ -> false)

/// Postcondition of [`plan_recovery`]: the generation is preserved and the
/// effects are exactly journal, vault, clear when a pending record exists.
let recovery_plan_matches_spec (state: t_JournalState) (result: t_JournalStep) : bool =
  result.f_state.f_generation =. state.f_generation &&
  Alloc.Vec.impl_1__is_empty #t_PendingItem #Alloc.Alloc.t_Global result.f_state.f_pending &&
  (if Alloc.Vec.impl_1__is_empty #t_PendingItem #Alloc.Alloc.t_Global state.f_pending
    then Alloc.Vec.impl_1__is_empty #t_JournalEffect #Alloc.Alloc.t_Global result.f_effects
    else
      effects_are_recovery_ordered (Alloc.Vec.impl_1__as_slice result.f_effects
          <:
          t_Slice t_JournalEffect))

/// The canonical recovery plan for a readable journal state: a pending record
/// is re-armed, applied and cleared; a clean journal plans nothing.
let plan_recovery (state: t_JournalState)
    : Prims.Pure t_JournalStep
      Prims.l_True
      (ensures
        fun result ->
          let result:t_JournalStep = result in
          recovery_plan_matches_spec state result) =
  if Alloc.Vec.impl_1__is_empty #t_PendingItem #Alloc.Alloc.t_Global state.f_pending
  then
    {
      f_state = { state with f_phase = JournalPhase_Clean <: t_JournalPhase } <: t_JournalState;
      f_effects = Alloc.Vec.impl__new #t_JournalEffect ()
    }
    <:
    t_JournalStep
  else
    let pending_image:t_JournalImage = impl_JournalState__image state in
    let cleared_image:t_JournalImage = impl_JournalState__cleared_image state in
    let clean:t_JournalState =
      {
        f_generation = state.f_generation;
        f_phase = JournalPhase_Clean <: t_JournalPhase;
        f_pending = Alloc.Vec.impl__new #t_PendingItem ();
        f_pins = state.f_pins
      }
      <:
      t_JournalState
    in
    {
      f_state = clean;
      f_effects
      =
      Alloc.Slice.impl__into_vec #t_JournalEffect
        #Alloc.Alloc.t_Global
        ((let list =
              [
                JournalEffect_WriteJournal pending_image <: t_JournalEffect;
                JournalEffect_WriteVault <: t_JournalEffect;
                JournalEffect_ClearJournal cleared_image <: t_JournalEffect
              ]
            in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
            Rust_primitives.Hax.array_of_list 3 list)
          <:
          t_Slice t_JournalEffect)
    }
    <:
    t_JournalStep

/// The total journal transition relation.
/// Events that do not match the current phase (including every event on a
/// clean journal except `PersistJournal`/`ReadSnapshot`) are ignored: the
/// state is returned unchanged and the effect list is empty.
let step (state: t_JournalState) (event: t_JournalEvent)
    : Prims.Pure t_JournalStep
      Prims.l_True
      (ensures
        fun result ->
          let result:t_JournalStep = result in
          step_result_is_sound state result) =
  match event <: t_JournalEvent with
  | JournalEvent_ReadSnapshot { f_generation = generation ; f_pending = pending ; f_pins = pins } ->
    if generation <. state.f_generation
    then { f_state = state; f_effects = Alloc.Vec.impl__new #t_JournalEffect () } <: t_JournalStep
    else
      let phase:t_JournalPhase =
        phase_for (Alloc.Vec.impl_1__as_slice pending <: t_Slice t_PendingItem)
      in
      {
        f_state
        =
        { f_generation = generation; f_phase = phase; f_pending = pending; f_pins = pins }
        <:
        t_JournalState;
        f_effects = Alloc.Vec.impl__new #t_JournalEffect ()
      }
      <:
      t_JournalStep
  | JournalEvent_PersistJournal
    { f_snapshot_generation = snapshot_generation ; f_pending = pending ; f_pins = pins } ->
    if commit_is_authorized state snapshot_generation
    then
      let generation:u64 = next_generation state.f_generation in
      let image:t_JournalImage =
        {
          f_generation = generation;
          f_pending
          =
          Core_models.Clone.f_clone #(Alloc.Vec.t_Vec t_PendingItem Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            pending;
          f_pins
          =
          Core_models.Clone.f_clone #(Alloc.Vec.t_Vec t_SharePin Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            pins
        }
        <:
        t_JournalImage
      in
      let next:t_JournalState =
        {
          f_generation = generation;
          f_phase = phase_for (Alloc.Vec.impl_1__as_slice pending <: t_Slice t_PendingItem);
          f_pending = pending;
          f_pins = pins
        }
        <:
        t_JournalState
      in
      {
        f_state = next;
        f_effects
        =
        Alloc.Slice.impl__into_vec #t_JournalEffect
          #Alloc.Alloc.t_Global
          ((let list = [JournalEffect_WriteJournal image <: t_JournalEffect] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
            <:
            t_Slice t_JournalEffect)
      }
      <:
      t_JournalStep
    else { f_state = state; f_effects = Alloc.Vec.impl__new #t_JournalEffect () } <: t_JournalStep
  | JournalEvent_ReArm  ->
    if
      match state.f_phase <: t_JournalPhase with
      | JournalPhase_Pending  -> true
      | _ -> false
    then
      let image:t_JournalImage = impl_JournalState__image state in
      {
        f_state = state;
        f_effects
        =
        Alloc.Slice.impl__into_vec #t_JournalEffect
          #Alloc.Alloc.t_Global
          ((let list = [JournalEffect_WriteJournal image <: t_JournalEffect] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
            <:
            t_Slice t_JournalEffect)
      }
      <:
      t_JournalStep
    else { f_state = state; f_effects = Alloc.Vec.impl__new #t_JournalEffect () } <: t_JournalStep
  | JournalEvent_ApplyToVault  ->
    if
      match state.f_phase <: t_JournalPhase with
      | JournalPhase_Pending  -> true
      | _ -> false
    then
      {
        f_state = { state with f_phase = JournalPhase_Applied <: t_JournalPhase } <: t_JournalState;
        f_effects
        =
        Alloc.Slice.impl__into_vec #t_JournalEffect
          #Alloc.Alloc.t_Global
          ((let list = [JournalEffect_WriteVault <: t_JournalEffect] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
            <:
            t_Slice t_JournalEffect)
      }
      <:
      t_JournalStep
    else { f_state = state; f_effects = Alloc.Vec.impl__new #t_JournalEffect () } <: t_JournalStep
  | JournalEvent_Clear  ->
    if Alloc.Vec.impl_1__is_empty #t_PendingItem #Alloc.Alloc.t_Global state.f_pending
    then { f_state = state; f_effects = Alloc.Vec.impl__new #t_JournalEffect () } <: t_JournalStep
    else
      let image:t_JournalImage = impl_JournalState__cleared_image state in
      {
        f_state
        =
        {
          state with
          f_phase = JournalPhase_Clean <: t_JournalPhase;
          f_pending = Alloc.Vec.impl__new #t_PendingItem ()
        }
        <:
        t_JournalState;
        f_effects
        =
        Alloc.Slice.impl__into_vec #t_JournalEffect
          #Alloc.Alloc.t_Global
          ((let list = [JournalEffect_ClearJournal image <: t_JournalEffect] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
            <:
            t_Slice t_JournalEffect)
      }
      <:
      t_JournalStep
  | JournalEvent_Crash  ->
    { f_state = state; f_effects = Alloc.Vec.impl__new #t_JournalEffect () } <: t_JournalStep
  | JournalEvent_Recover  -> plan_recovery state

/// The clear step, exposed with its generation-preservation postcondition.
let clear_step (state: t_JournalState)
    : Prims.Pure t_JournalStep
      Prims.l_True
      (ensures
        fun result ->
          let result:t_JournalStep = result in
          result.f_state.f_generation =. state.f_generation) =
  step state (JournalEvent_Clear <: t_JournalEvent)
