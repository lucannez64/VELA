//! Pure journal step for the desktop share commit (Tamarin model M28).
//!
//! The encrypted `shares.enc` file is the write-ahead journal of a share
//! commit: it publishes the advanced generation, the new pins and the pending
//! vault items in one atomic replacement, *before* `vault.enc` changes.
//! `desktopVELA/vela-desktop-core/src/sharing.rs` reads and writes those files;
//! this crate owns the durable phase machine between the two writes:
//!
//! ```text
//!   Clean --PersistJournal--> Pending --ApplyToVault--> Applied --Clear--> Clean
//!                                \--ReArm (stutter)----/      \--Clear-----/
//! ```
//!
//! [`step`] is total: every state and every event has a result, and an event
//! that is not valid in the current phase is a no-op with no effects. The
//! event carries the observations the effectful shell made (generations,
//! pending items, pins); the returned [`JournalEffect`] list is exactly the
//! filesystem writes the shell must perform, in order. Nothing here reads the
//! clock, the filesystem or a random source.
//!
//! The mapping to M28 (`security/formal/m28_share_journal.spthy`) is:
//!
//! * `PersistJournal` = `PersistJournal` (one durable journal replacement),
//! * `ReArm` = the code's idempotent same-content rewrite of a pending journal
//!   (not an M28 step; a required stutter, see P1 findings),
//! * `ApplyToVault` = `PersistVault`,
//! * `Clear` = `ClearJournal` (generation is preserved, never incremented),
//! * `Crash`/`Recover` = `Crash` plus the startup recovery path,
//! * `ReadSnapshot` = `ReadSnapshot`/`OpenVault` snapshot acquisition.
//!
//! One M28 slot projects onto one received-share lineage; that projection and
//! the pin ordering relation are P3b work, not assumed here.

/// Durable phase of the share journal. The phase is not serialized: a store
/// with no pending items decodes as `Clean`, a store with pending items decodes
/// as `Pending` (whether or not the vault write already happened).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalPhase {
    /// No pending record: the journal and the vault agree.
    Clean,
    /// The journal (pin + pending items) is durable; the vault is still old.
    Pending,
    /// The vault write was requested; the journal clear has not happened yet.
    Applied,
}

/// One pending vault-item change, reduced to the facts the journal phase
/// machine needs. The shell keeps the actual items; this is its stable id and
/// whether a `before` image existed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingItem {
    pub id: u64,
    pub had_before: bool,
}

/// One pinned received share, reduced to the M28 pin facts: a slot (one
/// received lineage) and its committed revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharePin {
    pub slot: u64,
    pub revision: u64,
}

/// The durable journal content: generation, pending items and pins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalImage {
    pub generation: u64,
    pub pending: Vec<PendingItem>,
    pub pins: Vec<SharePin>,
}

/// The journal's current state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalState {
    pub generation: u64,
    pub phase: JournalPhase,
    pub pending: Vec<PendingItem>,
    pub pins: Vec<SharePin>,
}

/// A filesystem write the shell must perform, in order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalEffect {
    /// Replace `shares.enc` with this image (journal persistence or re-arm).
    WriteJournal(JournalImage),
    /// Apply the pending items to the in-memory vault, then replace `vault.enc`.
    WriteVault,
    /// Replace `shares.enc` with the clear image (same generation, no pending).
    ClearJournal(JournalImage),
}

/// The observations and requests the shell feeds to [`step`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalEvent {
    /// Adopt a snapshot read from disk. A snapshot older than the current
    /// generation is stale and ignored; a pending record decodes as `Pending`.
    ReadSnapshot {
        generation: u64,
        pending: Vec<PendingItem>,
        pins: Vec<SharePin>,
    },
    /// Request a commit from the snapshot the caller loaded earlier. The state
    /// is the freshly read disk journal; `snapshot_generation` is the
    /// generation that snapshot carried, and `pending`/`pins` are the new
    /// content the caller wants to publish.
    PersistJournal {
        snapshot_generation: u64,
        pending: Vec<PendingItem>,
        pins: Vec<SharePin>,
    },
    /// Re-write the pending journal unchanged before touching the vault. This
    /// is the durability re-arm required by an uncertain previous write.
    ReArm,
    /// Ask the shell to apply the pending items and replace the vault.
    ApplyToVault,
    /// Clear the pending record. The generation is preserved.
    Clear,
    /// Process death or power loss: durable files are unchanged.
    Crash,
    /// Startup recovery: plan the writes that finish a visible pending record.
    Recover,
}

/// Result of one step: the next state and the effects to perform in order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalStep {
    pub state: JournalState,
    pub effects: Vec<JournalEffect>,
}

/// A canonical item-commit plan: the four effects in the order M28 requires.
/// The shell performs [`CommitEffects::into_effects`] in field order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitEffects {
    /// 1. Journal persistence (new generation, pins and pending items).
    pub persist: JournalEffect,
    /// 2. Durability re-arm (same image, same generation).
    pub rearm: JournalEffect,
    /// 3. Vault replacement.
    pub vault: JournalEffect,
    /// 4. Journal clear (same generation, no pending items).
    pub clear: JournalEffect,
}

impl CommitEffects {
    /// The effect list in execution order.
    pub fn into_effects(self) -> Vec<JournalEffect> {
        vec![self.persist, self.rearm, self.vault, self.clear]
    }
}

impl JournalState {
    /// A clean state with the given generation and pins.
    pub fn clean(generation: u64, pins: Vec<SharePin>) -> Self {
        Self {
            generation,
            phase: JournalPhase::Clean,
            pending: Vec::new(),
            pins,
        }
    }

    /// The image a journal write would publish for this state.
    pub fn image(&self) -> JournalImage {
        JournalImage {
            generation: self.generation,
            pending: self.pending.clone(),
            pins: self.pins.clone(),
        }
    }

    /// The image a clear write publishes: same generation and pins, no pending.
    pub fn cleared_image(&self) -> JournalImage {
        JournalImage {
            generation: self.generation,
            pending: Vec::new(),
            pins: self.pins.clone(),
        }
    }
}

/// A phase is well formed when pending items exist exactly in a non-clean
/// phase. A store cannot persist `Applied`; it decodes as `Pending`.
pub fn state_is_well_formed(state: &JournalState) -> bool {
    if state.pending.is_empty() {
        matches!(state.phase, JournalPhase::Clean)
    } else {
        !matches!(state.phase, JournalPhase::Clean)
    }
}

fn phase_for(pending: &[PendingItem]) -> JournalPhase {
    if pending.is_empty() {
        JournalPhase::Clean
    } else {
        JournalPhase::Pending
    }
}

/// The generation a successful commit publishes. Saturating at `u64::MAX`
/// keeps the pure function total; `commit_is_authorized` refuses that point, so
/// the saturated value is never used for a real write.
pub fn next_generation(generation: u64) -> u64 {
    if generation == u64::MAX {
        generation
    } else {
        generation + 1
    }
}

/// The commit-authorization check shared by [`step`] and [`plan_commit`]: the
/// freshly read disk journal is clean and still at the snapshot generation,
/// and the generation has room to advance. This is the M28
/// `ReadSnapshot`/`PersistJournal` guard plus the code's generation equality.
pub fn commit_is_authorized(state: &JournalState, snapshot_generation: u64) -> bool {
    matches!(state.phase, JournalPhase::Clean)
        && state.pending.is_empty()
        && state.generation == snapshot_generation
        && state.generation < u64::MAX
}

/// Postcondition of [`step`]: the generation never decreases and a well-formed
/// input stays well formed.
pub fn step_result_is_sound(state: &JournalState, result: &JournalStep) -> bool {
    result.state.generation >= state.generation
        && (!state_is_well_formed(state) || state_is_well_formed(&result.state))
}

/// The total journal transition relation.
///
/// Events that do not match the current phase (including every event on a
/// clean journal except `PersistJournal`/`ReadSnapshot`) are ignored: the
/// state is returned unchanged and the effect list is empty.
#[cfg_attr(hax, hax_lib::ensures(|result| step_result_is_sound(&state, &result)))]
pub fn step(state: JournalState, event: JournalEvent) -> JournalStep {
    match event {
        JournalEvent::ReadSnapshot {
            generation,
            pending,
            pins,
        } => {
            // A read cannot rewind the state machine. An older image belongs to
            // a different (external) writer and the commit guard will reject it.
            if generation < state.generation {
                JournalStep {
                    state,
                    effects: Vec::new(),
                }
            } else {
                let phase = phase_for(&pending);
                JournalStep {
                    state: JournalState {
                        generation,
                        phase,
                        pending,
                        pins,
                    },
                    effects: Vec::new(),
                }
            }
        }
        JournalEvent::PersistJournal {
            snapshot_generation,
            pending,
            pins,
        } => {
            if commit_is_authorized(&state, snapshot_generation) {
                let generation = next_generation(state.generation);
                let image = JournalImage {
                    generation,
                    pending: pending.clone(),
                    pins: pins.clone(),
                };
                let next = JournalState {
                    generation,
                    phase: phase_for(&pending),
                    pending,
                    pins,
                };
                JournalStep {
                    state: next,
                    effects: vec![JournalEffect::WriteJournal(image)],
                }
            } else {
                JournalStep {
                    state,
                    effects: Vec::new(),
                }
            }
        }
        JournalEvent::ReArm => {
            if matches!(state.phase, JournalPhase::Pending) {
                let image = state.image();
                JournalStep {
                    state,
                    effects: vec![JournalEffect::WriteJournal(image)],
                }
            } else {
                JournalStep {
                    state,
                    effects: Vec::new(),
                }
            }
        }
        JournalEvent::ApplyToVault => {
            if matches!(state.phase, JournalPhase::Pending) {
                JournalStep {
                    state: JournalState {
                        phase: JournalPhase::Applied,
                        ..state
                    },
                    effects: vec![JournalEffect::WriteVault],
                }
            } else {
                JournalStep {
                    state,
                    effects: Vec::new(),
                }
            }
        }
        JournalEvent::Clear => {
            if state.pending.is_empty() {
                JournalStep {
                    state,
                    effects: Vec::new(),
                }
            } else {
                let image = state.cleared_image();
                JournalStep {
                    state: JournalState {
                        phase: JournalPhase::Clean,
                        pending: Vec::new(),
                        ..state
                    },
                    effects: vec![JournalEffect::ClearJournal(image)],
                }
            }
        }
        JournalEvent::Crash => JournalStep {
            state,
            effects: Vec::new(),
        },
        JournalEvent::Recover => plan_recovery(state),
    }
}

/// Every effect of an item commit: journal persistence, re-arm, vault, clear.
/// The generation is the one the persist step produced; clear keeps it.
pub fn commit_effects_match_spec(
    prior: &JournalState,
    snapshot_generation: u64,
    pending: &[PendingItem],
    pins: &[SharePin],
    effects: &CommitEffects,
) -> bool {
    let generation = next_generation(prior.generation);
    prior.generation < u64::MAX
        && commit_is_authorized(prior, snapshot_generation)
        && !pending.is_empty()
        && match &effects.persist {
            JournalEffect::WriteJournal(image) => {
                image.generation == generation
                    && !image.pending.is_empty()
                    && image.pins.len() == pins.len()
            }
            _ => false,
        }
        && match &effects.rearm {
            JournalEffect::WriteJournal(image) => {
                image.generation == generation
                    && !image.pending.is_empty()
                    && image.pins.len() == pins.len()
            }
            _ => false,
        }
        && matches!(effects.vault, JournalEffect::WriteVault)
        && match &effects.clear {
            JournalEffect::ClearJournal(image) => {
                image.generation == generation
                    && image.pending.is_empty()
                    && image.pins.len() == pins.len()
            }
            _ => false,
        }
}

/// Plan the canonical item commit for a clean journal and snapshot. Returns
/// `None` when the commit is refused (stale snapshot, pending record, or an
/// exhausted generation), matching [`step`]'s `PersistJournal` decision.
#[cfg_attr(hax, hax_lib::ensures(|result| match result {
    Some(plan) => commit_effects_match_spec(&state, snapshot_generation, &pending, &pins, &plan.effects)
        && plan.state.generation == next_generation(state.generation)
        && matches!(plan.state.phase, JournalPhase::Clean)
        && plan.state.pending.is_empty(),
    None => !commit_is_authorized(&state, snapshot_generation) || pending.is_empty(),
}))]
pub fn plan_commit(
    state: JournalState,
    snapshot_generation: u64,
    pending: Vec<PendingItem>,
    pins: Vec<SharePin>,
) -> Option<CommitPlan> {
    if !commit_is_authorized(&state, snapshot_generation) || pending.is_empty() {
        return None;
    }
    let generation = next_generation(state.generation);
    let image = JournalImage {
        generation,
        pending: pending.clone(),
        pins: pins.clone(),
    };
    let effects = CommitEffects {
        persist: JournalEffect::WriteJournal(image.clone()),
        rearm: JournalEffect::WriteJournal(image),
        vault: JournalEffect::WriteVault,
        clear: JournalEffect::ClearJournal(JournalImage {
            generation,
            pending: Vec::new(),
            pins: pins.clone(),
        }),
    };
    Some(CommitPlan {
        state: JournalState {
            generation,
            phase: JournalPhase::Clean,
            pending: Vec::new(),
            pins,
        },
        effects,
    })
}

/// A planned commit: the cleared state after the four effects and the effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitPlan {
    pub state: JournalState,
    pub effects: CommitEffects,
}

/// Postcondition of [`plan_recovery`]: the generation is preserved and the
/// effects are exactly journal, vault, clear when a pending record exists.
pub fn recovery_plan_matches_spec(state: &JournalState, result: &JournalStep) -> bool {
    result.state.generation == state.generation
        && result.state.pending.is_empty()
        && if state.pending.is_empty() {
            result.effects.is_empty()
        } else {
            effects_are_recovery_ordered(&result.effects)
        }
}

/// The canonical recovery plan for a readable journal state: a pending record
/// is re-armed, applied and cleared; a clean journal plans nothing.
#[cfg_attr(hax, hax_lib::ensures(|result| recovery_plan_matches_spec(&state, &result)))]
pub fn plan_recovery(state: JournalState) -> JournalStep {
    if state.pending.is_empty() {
        JournalStep {
            state: JournalState {
                phase: JournalPhase::Clean,
                ..state
            },
            effects: Vec::new(),
        }
    } else {
        // Re-arm, apply, clear: the startup path for every readable pending
        // record, including an uncertain previous write.
        let pending_image = state.image();
        let cleared_image = state.cleared_image();
        let clean = JournalState {
            generation: state.generation,
            phase: JournalPhase::Clean,
            pending: Vec::new(),
            pins: state.pins,
        };
        JournalStep {
            state: clean,
            effects: vec![
                JournalEffect::WriteJournal(pending_image),
                JournalEffect::WriteVault,
                JournalEffect::ClearJournal(cleared_image),
            ],
        }
    }
}

/// The clear step, exposed with its generation-preservation postcondition.
#[cfg_attr(hax, hax_lib::ensures(|result| result.state.generation == state.generation))]
pub fn clear_step(state: JournalState) -> JournalStep {
    step(state, JournalEvent::Clear)
}

/// A helper for the gate: `true` when `effects` is exactly the canonical item
/// commit order: journal, re-arm, vault, clear.
pub fn effects_are_commit_ordered(effects: &[JournalEffect]) -> bool {
    effects.len() == 4
        && matches!(effects[0], JournalEffect::WriteJournal(_))
        && matches!(effects[1], JournalEffect::WriteJournal(_))
        && matches!(effects[2], JournalEffect::WriteVault)
        && matches!(effects[3], JournalEffect::ClearJournal(_))
}

/// A helper for the gate: `true` when `effects` is exactly the canonical
/// recovery order: journal, vault, clear.
pub fn effects_are_recovery_ordered(effects: &[JournalEffect]) -> bool {
    effects.len() == 3
        && matches!(effects[0], JournalEffect::WriteJournal(_))
        && matches!(effects[1], JournalEffect::WriteVault)
        && matches!(effects[2], JournalEffect::ClearJournal(_))
}
