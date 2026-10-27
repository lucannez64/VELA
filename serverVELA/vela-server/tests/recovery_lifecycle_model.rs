//! Exhaustive bounded refinement checks for the M14 recovery policy.

use vela_recovery_policy::{
    credential_update_decision_matches_spec, enrollment_is_authorized, initiation_is_authorized,
    plan_credential_update, plan_enrollment, plan_initiation, plan_recovery, plan_registration,
    recovery_is_authorized, registration_is_authorized, CredentialUpdateFacts, EnrollmentDecision,
    EnrollmentFacts, InitiateDecision, InitiateFacts, RecoverDecision, RecoverFacts, RecoveryPhase,
    RegistrationDecision, RegistrationFacts,
};

const PHASES: [RecoveryPhase; 7] = [
    RecoveryPhase::Unavailable,
    RecoveryPhase::Ready,
    RecoveryPhase::ChallengePending,
    RecoveryPhase::GrantIssued,
    RecoveryPhase::Completed,
    RecoveryPhase::Revoked,
    RecoveryPhase::Expired,
];
const EPOCHS: [i64; 4] = [-1, 0, 1, 2];

fn bit(mask: u16, index: u16) -> bool {
    mask & (1 << index) != 0
}

#[test]
fn every_bounded_initiation_and_registration_matches_m14() {
    for phase in PHASES {
        for mask in 0..32 {
            let facts = InitiateFacts {
                phase,
                account_exists: bit(mask, 0),
                share_present: bit(mask, 1),
                credential_present: bit(mask, 2),
                attempt_id_fresh: bit(mask, 3),
                ttl_positive: bit(mask, 4),
            };
            assert_eq!(
                matches!(plan_initiation(facts), InitiateDecision::Start(_)),
                initiation_is_authorized(facts)
            );
        }
    }

    for mask in 0..64 {
        let facts = RegistrationFacts {
            device_scope: bit(mask, 0),
            account_matches: bit(mask, 1),
            challenge_pending: bit(mask, 2),
            challenge_consumed: bit(mask, 3),
            credential_valid: bit(mask, 4),
            credential_unique: bit(mask, 5),
        };
        assert_eq!(
            matches!(plan_registration(facts), RegistrationDecision::Register(_)),
            registration_is_authorized(facts)
        );
    }
}

#[test]
fn every_bounded_share_release_and_credential_update_matches_m14() {
    for phase in PHASES {
        for epoch in EPOCHS {
            for mask in 0..256 {
                let facts = RecoverFacts {
                    phase,
                    user_matches: bit(mask, 0),
                    attempt_matches: bit(mask, 1),
                    challenge_consumed: bit(mask, 2),
                    credential_matches_current: bit(mask, 3),
                    assertion_valid: bit(mask, 4),
                    user_verified: bit(mask, 5),
                    share_present: bit(mask, 6),
                    account_epoch_active: bit(mask, 7),
                    epoch,
                };
                assert_eq!(
                    matches!(plan_recovery(facts), RecoverDecision::Release(_)),
                    recovery_is_authorized(facts),
                    "recovery mismatch for {facts:?}"
                );
            }
        }
    }

    for mask in 0..8 {
        let facts = CredentialUpdateFacts {
            assertion_valid: bit(mask, 0),
            credential_matches_current: bit(mask, 1),
            needs_update: bit(mask, 2),
        };
        let decision = plan_credential_update(facts);
        assert!(credential_update_decision_matches_spec(facts, decision));
    }
}

#[test]
fn every_bounded_recovered_device_enrollment_matches_m14() {
    for phase in PHASES {
        for grant_epoch in EPOCHS {
            for account_epoch in EPOCHS {
                for mask in 0..512 {
                    let facts = EnrollmentFacts {
                        phase,
                        account_present: bit(mask, 8),
                        user_matches: bit(mask, 0),
                        grant_live: bit(mask, 1),
                        grant_consumed: bit(mask, 2),
                        credential_matches_current: bit(mask, 3),
                        possession_grant: bit(mask, 4),
                        possession_hash_present: bit(mask, 5),
                        public_keys_valid: bit(mask, 6),
                        account_epoch_active: bit(mask, 7),
                        grant_epoch,
                        account_epoch,
                    };
                    assert_eq!(
                        matches!(plan_enrollment(facts), EnrollmentDecision::Enroll(_)),
                        enrollment_is_authorized(facts),
                        "enrollment mismatch for {facts:?}"
                    );
                }
            }
        }
    }
}

// ── Bounded conformance of the extracted recovery-share lifecycle driver ────

mod share_lifecycle {
    use vela_recovery_policy::recovery_share_driver::{
        begin_share_lifecycle, step_share_lifecycle, DeleteUpdateObservation,
        FinalizeAccountObservation, FinalizeUpdateObservation, ReadObservation, ShareActorObservation,
        ShareEffect, ShareEvent, ShareFailure, ShareOperation, ShareRequestObservation,
        StageAccountObservation, StageUpdateObservation,
    };

    #[derive(Clone, Copy, Debug)]
    pub enum Command {
        Stage(i64),
        Finalize(i64),
        Delete,
        Read,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Outcome {
        Success,
        Rekeyed,
        Conflict,
        ShareMissing,
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Model {
        pub epoch: i64,
        pub rotation: bool,
        pub active: Option<(i64, i64)>,
        pub pending: Option<(i64, i64)>,
    }

    impl Model {
        pub fn new() -> Self {
            Self {
                epoch: 1,
                rotation: false,
                active: None,
                pending: None,
            }
        }

        pub fn reference(&mut self, command: Command) -> Outcome {
            match command {
                Command::Stage(split) => {
                    if self.rotation {
                        Outcome::Rekeyed
                    } else if self.active == Some((self.epoch, split)) {
                        // The exact post-finalization delivery retry is
                        // idempotent; a different split cannot overwrite it.
                        Outcome::Success
                    } else if self.active.is_some() {
                        Outcome::Conflict
                    } else {
                        self.pending = Some((self.epoch, split));
                        Outcome::Success
                    }
                }
                Command::Finalize(split) => {
                    if self.rotation {
                        Outcome::Rekeyed
                    } else if self.active == Some((self.epoch, split)) {
                        Outcome::Success
                    } else if self.active.is_some() {
                        Outcome::Conflict
                    } else if self.pending == Some((self.epoch, split)) {
                        self.active = self.pending;
                        self.pending = None;
                        Outcome::Success
                    } else {
                        Outcome::Conflict
                    }
                }
                Command::Delete => {
                    if self.rotation {
                        Outcome::Rekeyed
                    } else {
                        self.active = None;
                        self.pending = None;
                        Outcome::Success
                    }
                }
                Command::Read => {
                    if self.active.is_some() {
                        Outcome::Success
                    } else {
                        Outcome::ShareMissing
                    }
                }
            }
        }

        /// Runs the extracted driver against this model's guarded updates.
        pub fn run_driver(&mut self, command: Command) -> Outcome {
            let (operation, split) = match command {
                Command::Stage(split) => (ShareOperation::Stage, split),
                Command::Finalize(split) => (ShareOperation::Finalize, split),
                Command::Delete => (ShareOperation::Delete, 0),
                Command::Read => (ShareOperation::Read, 0),
            };
            let request = ShareRequestObservation {
                operation,
                actor: ShareActorObservation {
                    authenticated: true,
                    device_active: true,
                    scoped_to_session_account: true,
                },
                declared_epoch: self.epoch,
                split_id_present: true,
                share_present: true,
                device_authority: true,
                split,
            };
            let mut transition = begin_share_lifecycle(request);
            for _ in 0..3 {
                let event = match transition.effect {
                    ShareEffect::StageShare(permit) => {
                        let staged = !self.rotation
                            && self.epoch == permit.epoch()
                            && self.active.is_none();
                        if staged {
                            self.pending = Some((permit.epoch(), permit.split()));
                            ShareEvent::StageUpdate(StageUpdateObservation::Staged)
                        } else {
                            ShareEvent::StageUpdate(StageUpdateObservation::NotStaged)
                        }
                    }
                    ShareEffect::StageQueryAccount => {
                        let matches = self
                            .active
                            .map(|(epoch, id)| epoch == self.epoch && id == split)
                            .unwrap_or(false);
                        ShareEvent::StageAccount(StageAccountObservation {
                            account_present: true,
                            stored_epoch: Some(self.epoch),
                            rotation_active: self.rotation,
                            active_share_matches: matches,
                            active_split_matches: matches,
                        })
                    }
                    ShareEffect::PromoteStagedSplit(permit) => {
                        let promoted = !self.rotation
                            && self.epoch == permit.epoch()
                            && self.active.is_none()
                            && self.pending == Some((permit.epoch(), permit.split()));
                        if promoted {
                            self.active = self.pending;
                            self.pending = None;
                            ShareEvent::FinalizeUpdate(FinalizeUpdateObservation::Promoted)
                        } else {
                            ShareEvent::FinalizeUpdate(FinalizeUpdateObservation::NotPromoted)
                        }
                    }
                    ShareEffect::FinalizeQueryAccount => {
                        let matches = self
                            .active
                            .map(|(epoch, id)| epoch == self.epoch && id == split)
                            .unwrap_or(false);
                        ShareEvent::FinalizeAccount(FinalizeAccountObservation {
                            account_present: true,
                            stored_epoch: Some(self.epoch),
                            rotation_active: self.rotation,
                            active_split_matches: matches,
                        })
                    }
                    ShareEffect::DeleteShare(permit) => {
                        let deleted = !self.rotation && self.epoch == permit.epoch();
                        if deleted {
                            self.active = None;
                            self.pending = None;
                            ShareEvent::DeleteUpdate(DeleteUpdateObservation::Deleted)
                        } else {
                            ShareEvent::DeleteUpdate(DeleteUpdateObservation::NotDeleted)
                        }
                    }
                    ShareEffect::ReadShare => ShareEvent::ReadObserved(ReadObservation {
                        account_present: true,
                        share_present: self.active.is_some(),
                    }),
                    ShareEffect::Complete | ShareEffect::Fail(_) | ShareEffect::Idle => break,
                };
                transition = step_share_lifecycle(transition.driver, event);
            }
            match transition.effect {
                ShareEffect::Complete => Outcome::Success,
                ShareEffect::Fail(ShareFailure::Rekeyed) => Outcome::Rekeyed,
                ShareEffect::Fail(ShareFailure::Conflict) => Outcome::Conflict,
                ShareEffect::Fail(ShareFailure::ShareMissing) => Outcome::ShareMissing,
                other => panic!("unexpected lifecycle verdict: {other:?}"),
            }
        }
    }

    fn alphabet() -> Vec<Command> {
        use Command::*;
        vec![Stage(7), Stage(8), Finalize(7), Delete, Read]
    }

    fn sequences(depth: usize) -> Vec<Vec<Command>> {
        let alphabet = alphabet();
        let mut all = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..depth {
            let mut next = Vec::new();
            for prefix in &frontier {
                for command in &alphabet {
                    let mut sequence = prefix.clone();
                    sequence.push(*command);
                    next.push(sequence);
                }
            }
            all.extend(next.iter().cloned());
            frontier = next;
        }
        all
    }

    #[test]
    fn every_bounded_lifecycle_trace_matches_the_share_state_model() {
        let mut steps = 0usize;
        for trace in sequences(3) {
            let mut reference = Model::new();
            let mut driver = Model::new();
            for (step, command) in trace.iter().enumerate() {
                let expected = reference.reference(*command);
                let actual = driver.run_driver(*command);
                assert_eq!(
                    actual, expected,
                    "outcome mismatch at step {step} of {trace:?}"
                );
                assert_eq!(
                    driver, reference,
                    "share state mismatch at step {step} of {trace:?}"
                );
                steps += 1;
            }
        }
        assert!(steps > 100);
    }

    #[test]
    fn freezing_blocks_every_lifecycle_operation() {
        let mut model = Model::new();
        model.pending = Some((1, 7));
        model.active = Some((1, 7));
        model.rotation = true;
        for command in [Command::Stage(8), Command::Finalize(7), Command::Delete] {
            let before = model;
            assert_eq!(model.run_driver(command), Outcome::Rekeyed, "{command:?}");
            assert_eq!(model, before, "{command:?} mutated the frozen share state");
        }
        // A read is not a vault mutation and keeps returning the live share.
        assert_eq!(model.run_driver(Command::Read), Outcome::Success);
    }

    #[test]
    fn delete_removes_share_and_pending_together() {
        let mut model = Model::new();
        model.pending = Some((1, 7));
        assert_eq!(model.run_driver(Command::Delete), Outcome::Success);
        assert!(model.active.is_none());
        assert!(model.pending.is_none());
    }
}
