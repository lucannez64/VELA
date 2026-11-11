//! Pure journal-step coverage: every phase, the rejection paths, effect order
//! and the generation invariants. These tests mirror the F* gate's statements.

use vela_client_share_journal::*;

fn pending(id: u64, had_before: bool) -> PendingItem {
    PendingItem { id, had_before }
}

fn pin(slot: u64, revision: u64) -> SharePin {
    SharePin { slot, revision }
}

fn states() -> Vec<JournalState> {
    vec![
        JournalState {
            generation: 0,
            phase: JournalPhase::Clean,
            pending: Vec::new(),
            pins: vec![pin(0, 1)],
        },
        JournalState {
            generation: 7,
            phase: JournalPhase::Clean,
            pending: Vec::new(),
            pins: vec![pin(0, 2), pin(1, 9)],
        },
        JournalState {
            generation: 7,
            phase: JournalPhase::Pending,
            pending: vec![pending(0, true)],
            pins: vec![pin(0, 3)],
        },
        JournalState {
            generation: 7,
            phase: JournalPhase::Applied,
            pending: vec![pending(0, false)],
            pins: vec![pin(0, 3)],
        },
        JournalState {
            generation: u64::MAX,
            phase: JournalPhase::Clean,
            pending: Vec::new(),
            pins: Vec::new(),
        },
    ]
}

fn events() -> Vec<JournalEvent> {
    vec![
        JournalEvent::ReadSnapshot {
            generation: 2,
            pending: vec![pending(0, false)],
            pins: vec![pin(0, 1)],
        },
        JournalEvent::ReadSnapshot {
            generation: 99,
            pending: Vec::new(),
            pins: vec![pin(0, 2)],
        },
        JournalEvent::PersistJournal {
            snapshot_generation: 7,
            pending: vec![pending(0, true)],
            pins: vec![pin(0, 4)],
        },
        JournalEvent::PersistJournal {
            snapshot_generation: 6,
            pending: vec![pending(0, true)],
            pins: Vec::new(),
        },
        JournalEvent::ReArm,
        JournalEvent::ApplyToVault,
        JournalEvent::Clear,
        JournalEvent::Crash,
        JournalEvent::Recover,
    ]
}

#[test]
fn step_is_total_and_keeps_the_generation_monotone() {
    for state in states() {
        for event in events() {
            let result = step(state.clone(), event);
            assert!(
                result.state.generation >= state.generation,
                "{state:?} -> {result:?}"
            );
            assert!(step_result_is_sound(&state, &result));
            if state_is_well_formed(&state) {
                assert!(state_is_well_formed(&result.state), "{result:?}");
            }
        }
    }
}

#[test]
fn clear_keeps_the_generation() {
    for state in states() {
        let result = clear_step(state.clone());
        assert_eq!(result.state.generation, state.generation);
        assert_eq!(result.state.phase, JournalPhase::Clean);
        assert!(result.state.pending.is_empty());
        if state.pending.is_empty() {
            assert!(result.effects.is_empty());
        } else {
            assert!(matches!(
                result.effects.as_slice(),
                [JournalEffect::ClearJournal(image)] if image.generation == state.generation
            ));
        }
    }
}

#[test]
fn commit_effects_are_journal_before_vault_before_clear() {
    let state = JournalState {
        generation: 4,
        phase: JournalPhase::Clean,
        pending: Vec::new(),
        pins: vec![pin(0, 2)],
    };
    let plan = plan_commit(state.clone(), 4, vec![pending(0, true)], vec![pin(0, 3)])
        .expect("authorized commit");
    assert!(commit_effects_match_spec(
        &state,
        4,
        &[pending(0, true)],
        &[pin(0, 3)],
        &plan.effects,
    ));
    let effects = plan.effects.clone().into_effects();
    assert!(effects_are_commit_ordered(&effects));
    match effects.as_slice() {
        [JournalEffect::WriteJournal(persist), JournalEffect::WriteJournal(rearm), JournalEffect::WriteVault, JournalEffect::ClearJournal(clear)] =>
        {
            assert_eq!(persist.generation, 5);
            assert_eq!(rearm.generation, 5);
            assert_eq!(clear.generation, 5);
            assert!(clear.pending.is_empty());
        }
        other => panic!("unexpected effects: {other:?}"),
    }
    assert_eq!(plan.state.generation, 5);
    assert_eq!(plan.state.phase, JournalPhase::Clean);
    assert!(plan.state.pending.is_empty());
}

#[test]
fn commit_rejects_stale_pending_and_exhausted_generations() {
    let clean = JournalState {
        generation: 4,
        phase: JournalPhase::Clean,
        pending: Vec::new(),
        pins: Vec::new(),
    };
    assert!(plan_commit(clean.clone(), 3, vec![pending(0, false)], Vec::new()).is_none());
    let pending_state = JournalState {
        generation: 4,
        phase: JournalPhase::Pending,
        pending: vec![pending(0, false)],
        pins: Vec::new(),
    };
    assert!(plan_commit(pending_state, 4, vec![pending(1, false)], Vec::new()).is_none());
    let exhausted = JournalState {
        generation: u64::MAX,
        ..clean.clone()
    };
    assert!(plan_commit(exhausted, u64::MAX, vec![pending(0, false)], Vec::new()).is_none());
    // A rejected step is a no-op.
    let result = step(
        clean,
        JournalEvent::PersistJournal {
            snapshot_generation: 3,
            pending: vec![pending(0, false)],
            pins: Vec::new(),
        },
    );
    assert!(result.effects.is_empty());
    assert_eq!(result.state.generation, 4);
}

#[test]
fn metadata_only_commit_writes_only_the_journal() {
    let state = JournalState {
        generation: 2,
        phase: JournalPhase::Clean,
        pending: Vec::new(),
        pins: Vec::new(),
    };
    let result = step(
        state,
        JournalEvent::PersistJournal {
            snapshot_generation: 2,
            pending: Vec::new(),
            pins: Vec::new(),
        },
    );
    assert_eq!(result.state.generation, 3);
    assert_eq!(result.state.phase, JournalPhase::Clean);
    assert!(matches!(
        result.effects.as_slice(),
        [JournalEffect::WriteJournal(image)] if image.generation == 3 && image.pending.is_empty()
    ));
}

#[test]
fn recovery_plans_journal_before_vault_before_clear() {
    let state = JournalState {
        generation: 9,
        phase: JournalPhase::Pending,
        pending: vec![pending(0, true)],
        pins: vec![pin(0, 4)],
    };
    let result = plan_recovery(state.clone());
    assert!(effects_are_recovery_ordered(&result.effects));
    assert_eq!(result.state.generation, state.generation);
    assert_eq!(result.state.phase, JournalPhase::Clean);
    assert!(result.state.pending.is_empty());
    // A clean journal plans no write at all.
    let clean = JournalState {
        generation: 9,
        phase: JournalPhase::Clean,
        pending: Vec::new(),
        pins: vec![pin(0, 4)],
    };
    assert!(plan_recovery(clean).effects.is_empty());
}

#[test]
fn read_snapshot_decodes_a_pending_record_and_never_rewinds() {
    let clean = JournalState {
        generation: 5,
        phase: JournalPhase::Clean,
        pending: Vec::new(),
        pins: Vec::new(),
    };
    let pending_read = step(
        clean.clone(),
        JournalEvent::ReadSnapshot {
            generation: 6,
            pending: vec![pending(0, false)],
            pins: vec![pin(0, 1)],
        },
    );
    assert_eq!(pending_read.state.generation, 6);
    assert_eq!(pending_read.state.phase, JournalPhase::Pending);
    assert!(pending_read.effects.is_empty());
    let stale = step(
        clean.clone(),
        JournalEvent::ReadSnapshot {
            generation: 4,
            pending: vec![pending(0, true)],
            pins: Vec::new(),
        },
    );
    assert_eq!(stale.state, clean);
    assert!(stale.effects.is_empty());
}

#[test]
fn crash_leaves_the_durable_state_unchanged() {
    let state = JournalState {
        generation: 3,
        phase: JournalPhase::Pending,
        pending: vec![pending(0, true)],
        pins: Vec::new(),
    };
    let result = step(state.clone(), JournalEvent::Crash);
    assert_eq!(result.state, state);
    assert!(result.effects.is_empty());
}
