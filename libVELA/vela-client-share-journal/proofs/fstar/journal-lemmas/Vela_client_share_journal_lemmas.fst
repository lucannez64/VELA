module Vela_client_share_journal_lemmas

/// Hand-written restatement of the four P3a obligations against the extracted
/// step function. No proof escape is used; F* checks each lemma.
///
/// Scope: the durable phase machine only. The shell owns the read, the AEAD
/// codec, `write_secret_file`, the vault item policy and the test fault
/// injection points; those stay outside both this module and the crate.

open Core_models
open Vela_client_share_journal

/// `step` has no precondition and returns a value for every state and event.
let step_is_total (state: t_JournalState) (event: t_JournalEvent)
  : Tot t_JournalStep = step state event

/// The generation is monotone across every single step.
let generation_never_decreases (state: t_JournalState) (event: t_JournalEvent)
  : Lemma ((step state event).f_state.f_generation >=. state.f_generation) = ()

/// `Clear` reuses the generation instead of advancing it (P1 finding 1).
let clear_keeps_generation (state: t_JournalState)
  : Lemma ((clear_step state).f_state.f_generation =. state.f_generation) = ()

/// An accepted item commit plans exactly journal, re-arm, vault, clear, and
/// the clear image keeps the generation the persist image wrote.
let commit_effects_are_journal_vault_clear
      (state: t_JournalState)
      (snapshot_generation: u64)
      (pending: Alloc.Vec.t_Vec t_PendingItem Alloc.Alloc.t_Global)
      (pins: Alloc.Vec.t_Vec t_SharePin Alloc.Alloc.t_Global)
  : Lemma
    (match plan_commit state snapshot_generation pending pins with
     | Core_models.Option.Option_Some plan ->
       (match plan.f_effects.f_persist <: t_JournalEffect with
        | JournalEffect_WriteJournal image ->
          (match plan.f_effects.f_rearm <: t_JournalEffect with
           | JournalEffect_WriteJournal rearm -> rearm.f_generation =. image.f_generation
           | _ -> false)
        | _ -> false) /\
       (match plan.f_effects.f_vault <: t_JournalEffect with
        | JournalEffect_WriteVault  -> true
        | _ -> false) /\
       (match plan.f_effects.f_clear <: t_JournalEffect with
        | JournalEffect_ClearJournal image ->
          image.f_generation =. plan.f_state.f_generation
        | _ -> false)
     | Core_models.Option.Option_None  -> true) = ()

/// A readable pending journal recovers with exactly journal, vault, clear, and
/// the generation is preserved.
let recovery_effects_are_journal_vault_clear (state: t_JournalState)
  : Lemma
    (Alloc.Vec.impl_1__is_empty #t_PendingItem #Alloc.Alloc.t_Global state.f_pending \/
     effects_are_recovery_ordered
       (Alloc.Vec.impl_1__as_slice #t_JournalEffect #Alloc.Alloc.t_Global
          (plan_recovery state).f_effects)) = ()
