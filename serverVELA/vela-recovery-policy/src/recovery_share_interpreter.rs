//! The one loop that connects the four recovery-share handlers to their driver.
//!
//! `PUT /recovery/share`, `POST /recovery/share/finalize`,
//! `DELETE /recovery/share` and `GET /recovery/share` do not call the driver by
//! hand. Each handler expands [`recovery_share_interpreter!`](crate::recovery_share_interpreter),
//! the same macro this module expands into the synchronous
//! [`run_share_lifecycle`] that hax extracts and F* checks. The proofs show, for
//! every executor implementation, that
//!
//! - an executor method is called only for the effect the driver has just
//!   emitted, in the order emitted, and returns the observation kind that
//!   effect expects;
//! - a failed effect stops the loop before any later effect, and the handler
//!   renders the recorded error unchanged;
//! - the loop stops at the first terminal effect and performs nothing after it;
//! - the final driver is the driver's `run_share_lifecycle` over the
//!   observations the executor actually returned, so every per-request
//!   lifecycle theorem holds for the real handler.
//!
//! The server's expansions differ only by `.await` after each executor call.

use crate::interpreter_support::executor_trait;
use crate::recovery_share_driver::{
    DeleteUpdateObservation, FinalizeAccountObservation, FinalizeUpdateObservation,
    ReadObservation, ShareDeletePermit, ShareEffect, ShareFinalizePermit,
    ShareStagePermit, ShareTransition, StageAccountObservation, StageUpdateObservation,
};

/// Most effects one lifecycle request performs: the update/read, an account
/// inspection after a zero-row update, and the verdict turn.
pub const RECOVERY_SHARE_MAX_EFFECTS: usize = 3;

/// The driver has decided: nothing more may be performed.
pub fn share_lifecycle_effect_is_terminal(effect: ShareEffect) -> bool {
    matches!(
        effect,
        ShareEffect::Complete | ShareEffect::Fail(_) | ShareEffect::Idle
    )
}

/// What the loop invariant keeps: the driver state and the effect it is about
/// to perform agree with each other.
pub fn share_lifecycle_transition_is_sound(transition: ShareTransition) -> bool {
    crate::recovery_share_driver::share_lifecycle_state_is_sound(transition.driver)
        && crate::recovery_share_driver::share_lifecycle_effect_is_sound(
            transition.driver,
            transition.effect,
        )
}

executor_trait! {
    /// The I/O behind every non-terminal lifecycle effect. Each handler
    /// implements the method for its own operation; the others refuse with
    /// `None` (the driver never emits them, but the trait stays total and
    /// panic-free). `None` aborts the request with the error the executor
    /// recorded.
    pub trait RecoveryShareIo {
        fn stage_share(&mut self, permit: ShareStagePermit) -> Option<StageUpdateObservation>;
        fn stage_query_account(&mut self) -> Option<StageAccountObservation>;
        fn promote_staged_split(&mut self, permit: ShareFinalizePermit) -> Option<FinalizeUpdateObservation>;
        fn finalize_query_account(&mut self) -> Option<FinalizeAccountObservation>;
        fn delete_share(&mut self, permit: ShareDeletePermit) -> Option<DeleteUpdateObservation>;
        fn read_share(&mut self) -> Option<ReadObservation>;
    }
}

/// The lifecycle interpreter body, shared verbatim by [`run_share_lifecycle`]
/// and the async handlers. `$io` names a mutable executor; pass `await` as the
/// last argument to await each executor call.
#[macro_export]
macro_rules! recovery_share_interpreter {
    ($io:ident, $request:expr $(, $aw:ident)?) => {{
        use $crate::recovery_share_driver::{
            begin_share_lifecycle as __begin, step_share_lifecycle as __step,
            ShareEffect as __E, ShareEvent as __V,
        };
        let mut transition = __begin($request);
        let mut aborted = false;
        for _ in 0..$crate::recovery_share_interpreter::RECOVERY_SHARE_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::recovery_share_interpreter::share_lifecycle_transition_is_sound(transition)
            });
            if !aborted {
                transition = match transition.effect {
                    __E::StageShare(permit) => match $io.stage_share(permit)$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::StageUpdate(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::StageQueryAccount => match $io.stage_query_account()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::StageAccount(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::PromoteStagedSplit(permit) => {
                        match $io.promote_staged_split(permit)$(.$aw)? {
                            Some(observation) => {
                                __step(transition.driver, __V::FinalizeUpdate(observation))
                            }
                            None => {
                                aborted = true;
                                transition
                            }
                        }
                    }
                    __E::FinalizeQueryAccount => match $io.finalize_query_account()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::FinalizeAccount(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::DeleteShare(permit) => match $io.delete_share(permit)$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::DeleteUpdate(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    __E::ReadShare => match $io.read_share()$(.$aw)? {
                        Some(observation) => {
                            __step(transition.driver, __V::ReadObserved(observation))
                        }
                        None => {
                            aborted = true;
                            transition
                        }
                    },
                    // The driver has decided: perform nothing, keep the verdict.
                    __E::Complete | __E::Fail(_) | __E::Idle => transition,
                };
            }
        }
        if aborted { None } else { Some(transition) }
    }};
}

/// The synchronous expansion of [`recovery_share_interpreter!`]: the artifact
/// hax extracts and F* checks.
pub fn run_share_lifecycle<Io: RecoveryShareIo>(
    io: &mut Io,
    request: crate::recovery_share_driver::ShareRequestObservation,
) -> Option<ShareTransition> {
    crate::recovery_share_interpreter!(io, request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_share_driver::{
        begin_share_lifecycle, step_share_lifecycle, ShareActorObservation, ShareEvent,
        ShareFailure, ShareOperation, ShareRequestObservation,
    };

    struct Scripted {
        /// Outcome kind per call index (0 = primary success, 1 = zero-row, 2 =
        /// observed failure).
        script: Vec<u8>,
        calls: Vec<ShareEffect>,
        events: Vec<ShareEvent>,
        abort_at: Option<usize>,
    }

    impl Scripted {
        fn record(&mut self, effect: ShareEffect) -> Option<u8> {
            let index = self.calls.len();
            self.calls.push(effect);
            if self.abort_at == Some(index) {
                return None;
            }
            Some(self.script.get(index).copied().unwrap_or(0))
        }
    }

    impl RecoveryShareIo for Scripted {
        fn stage_share(&mut self, permit: ShareStagePermit) -> Option<StageUpdateObservation> {
            let kind = self.record(ShareEffect::StageShare(permit))?;
            let observation = if kind == 0 {
                StageUpdateObservation::Staged
            } else {
                StageUpdateObservation::NotStaged
            };
            self.events.push(ShareEvent::StageUpdate(observation));
            Some(observation)
        }

        fn stage_query_account(&mut self) -> Option<StageAccountObservation> {
            let kind = self.record(ShareEffect::StageQueryAccount)?;
            let observation = if kind == 2 {
                StageAccountObservation {
                    account_present: false,
                    stored_epoch: None,
                    rotation_active: false,
                    active_share_matches: false,
                    active_split_matches: false,
                }
            } else if kind == 1 {
                StageAccountObservation {
                    account_present: true,
                    stored_epoch: Some(1),
                    rotation_active: true,
                    active_share_matches: false,
                    active_split_matches: false,
                }
            } else {
                StageAccountObservation {
                    account_present: true,
                    stored_epoch: Some(1),
                    rotation_active: false,
                    active_share_matches: true,
                    active_split_matches: true,
                }
            };
            self.events.push(ShareEvent::StageAccount(observation));
            Some(observation)
        }

        fn promote_staged_split(
            &mut self,
            permit: ShareFinalizePermit,
        ) -> Option<FinalizeUpdateObservation> {
            let kind = self.record(ShareEffect::PromoteStagedSplit(permit))?;
            let observation = if kind == 0 {
                FinalizeUpdateObservation::Promoted
            } else {
                FinalizeUpdateObservation::NotPromoted
            };
            self.events.push(ShareEvent::FinalizeUpdate(observation));
            Some(observation)
        }

        fn finalize_query_account(&mut self) -> Option<FinalizeAccountObservation> {
            let kind = self.record(ShareEffect::FinalizeQueryAccount)?;
            let observation = if kind == 2 {
                FinalizeAccountObservation {
                    account_present: false,
                    stored_epoch: None,
                    rotation_active: false,
                    active_split_matches: false,
                }
            } else if kind == 1 {
                FinalizeAccountObservation {
                    account_present: true,
                    stored_epoch: Some(1),
                    rotation_active: false,
                    active_split_matches: false,
                }
            } else if kind == 3 {
                FinalizeAccountObservation {
                    account_present: true,
                    stored_epoch: Some(2),
                    rotation_active: false,
                    active_split_matches: false,
                }
            } else {
                FinalizeAccountObservation {
                    account_present: true,
                    stored_epoch: Some(1),
                    rotation_active: false,
                    active_split_matches: true,
                }
            };
            self.events.push(ShareEvent::FinalizeAccount(observation));
            Some(observation)
        }

        fn delete_share(&mut self, permit: ShareDeletePermit) -> Option<DeleteUpdateObservation> {
            let kind = self.record(ShareEffect::DeleteShare(permit))?;
            let observation = if kind == 0 {
                DeleteUpdateObservation::Deleted
            } else {
                DeleteUpdateObservation::NotDeleted
            };
            self.events.push(ShareEvent::DeleteUpdate(observation));
            Some(observation)
        }

        fn read_share(&mut self) -> Option<ReadObservation> {
            let kind = self.record(ShareEffect::ReadShare)?;
            let observation = ReadObservation {
                account_present: kind != 2,
                share_present: kind == 0,
            };
            self.events.push(ShareEvent::ReadObserved(observation));
            Some(observation)
        }
    }

    fn actor() -> ShareActorObservation {
        ShareActorObservation {
            authenticated: true,
            device_active: true,
            scoped_to_session_account: true,
        }
    }

    fn request(operation: ShareOperation) -> ShareRequestObservation {
        ShareRequestObservation {
            operation,
            actor: actor(),
            declared_epoch: 1,
            split_id_present: true,
            share_present: true,
            device_authority: true,
            split: 7,
        }
    }

    fn check(
        operation: ShareOperation,
        script: Vec<u8>,
        abort_at: Option<usize>,
    ) -> Option<ShareEffect> {
        let request = request(operation);
        let mut io = Scripted { script, calls: vec![], events: vec![], abort_at };
        let result = run_share_lifecycle(&mut io, request);
        let mut t = begin_share_lifecycle(request);
        for (index, call) in io.calls.iter().enumerate() {
            if abort_at == Some(index) {
                break;
            }
            assert_eq!(*call, t.effect, "call was not the emitted effect");
            assert!(!share_lifecycle_effect_is_terminal(t.effect));
            t = step_share_lifecycle(t.driver, io.events[index]);
        }
        assert!(io.calls.len() <= RECOVERY_SHARE_MAX_EFFECTS);
        if abort_at.is_some() {
            assert!(result.is_none());
            return None;
        }
        let result = result.expect("no abort, so a verdict must be reached");
        assert_eq!(t, result);
        assert!(share_lifecycle_effect_is_terminal(result.effect));
        Some(result.effect)
    }

    #[test]
    fn every_operation_performs_exactly_the_driver_effects() {
        assert_eq!(
            check(ShareOperation::Stage, vec![0], None),
            Some(ShareEffect::Complete)
        );
        assert_eq!(
            check(ShareOperation::Stage, vec![1, 0], None),
            Some(ShareEffect::Complete)
        );
        assert!(matches!(
            check(ShareOperation::Stage, vec![1, 1], None),
            Some(ShareEffect::Fail(ShareFailure::Rekeyed))
        ));
        assert!(matches!(
            check(ShareOperation::Stage, vec![1, 2], None),
            Some(ShareEffect::Fail(ShareFailure::AccountMissing))
        ));
        assert_eq!(
            check(ShareOperation::Finalize, vec![0], None),
            Some(ShareEffect::Complete)
        );
        assert_eq!(
            check(ShareOperation::Finalize, vec![1, 0], None),
            Some(ShareEffect::Complete)
        );
        assert!(matches!(
            check(ShareOperation::Finalize, vec![1, 1], None),
            Some(ShareEffect::Fail(ShareFailure::Conflict))
        ));
        assert!(matches!(
            check(ShareOperation::Finalize, vec![1, 3], None),
            Some(ShareEffect::Fail(ShareFailure::Rekeyed))
        ));
        assert_eq!(
            check(ShareOperation::Delete, vec![0], None),
            Some(ShareEffect::Complete)
        );
        assert!(matches!(
            check(ShareOperation::Delete, vec![1], None),
            Some(ShareEffect::Fail(ShareFailure::Rekeyed))
        ));
        assert_eq!(
            check(ShareOperation::Read, vec![0], None),
            Some(ShareEffect::Complete)
        );
        assert!(matches!(
            check(ShareOperation::Read, vec![1], None),
            Some(ShareEffect::Fail(ShareFailure::ShareMissing))
        ));
        for operation in [
            ShareOperation::Stage,
            ShareOperation::Finalize,
            ShareOperation::Delete,
            ShareOperation::Read,
        ] {
            assert_eq!(check(operation, vec![0; 3], Some(0)), None);
        }
        // A zero-row start performs a second effect; aborting it is visible too.
        assert_eq!(check(ShareOperation::Stage, vec![1, 0], Some(1)), None);
        assert_eq!(check(ShareOperation::Finalize, vec![1, 0], Some(1)), None);
    }
}
