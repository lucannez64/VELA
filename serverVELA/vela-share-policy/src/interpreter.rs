//! The one loop that connects the sharing handlers to their driver.
//!
//! The handlers do not call the sharing driver by hand. Each expands
//! [`share_interpreter!`](crate::interpreter), the same macro this module
//! expands into the synchronous [`run_share`]. hax extracts `run_share` and F*
//! proves, for every [`ShareIo`] implementation, that
//!
//! - an executor method is called only for the effect the driver has just
//!   emitted, in the order emitted, with that effect's permit argument, and
//!   each method returns the observation kind that effect expects (the types
//!   allow nothing else);
//! - the loop stops at the first terminal effect and performs nothing after it;
//! - the final driver is `run_from_*` for the observations the executor
//!   actually returned, so every per-request sharing theorem holds for the real
//!   handler.
//!
//! The server's expansions differ only by `.await` after each executor call.
//! What stays outside the proof is each executor method: that it runs the I/O
//! its name describes and reports the outcome honestly.
//!
//! Every request kind shares the driver's single [`ShareEffect`] type, so one
//! executor trait and one loop macro cover all five. The caller supplies the
//! request's begin transition; the loop only performs the effects that
//! transition leads to.

use crate::driver::{
    CleanupObservation, EkDeviceObservation, InboxDeletePermit,
    LinkUpdatePermit, RowsObservation, SendInsertPermit, SendResultObservation, ShareEffect,
    ShareTransition,
};
use crate::{EkRegistrationPermit, LinkMutationObservation};

/// Most effects one request performs: observe the linked row, revoke it and
/// clean up its pending inbox row.
pub const SHARE_MAX_EFFECTS: usize = 3;

/// The driver has decided: nothing more may be performed.
pub fn share_effect_is_terminal(effect: ShareEffect) -> bool {
    matches!(
        effect,
        ShareEffect::Complete | ShareEffect::Fail(_) | ShareEffect::Idle
    )
}

/// Declares an executor trait from one list of method signatures. Under hax
/// every method gets `requires(true)` (the proof assumes nothing about the
/// executor); ordinary builds get the same trait without the attributes, so
/// `hax-lib` stays a hax-only dependency.
macro_rules! executor_trait {
    (
        $(#[$doc:meta])*
        pub trait $name:ident {
            $(fn $method:ident(&mut self $(, $arg:ident: $ty:ty)*) -> $ret:ty;)*
        }
    ) => {
        $(#[$doc])*
        #[cfg(hax)]
        #[hax_lib::attributes]
        pub trait $name {
            $(
                #[hax_lib::requires(true)]
                fn $method(&mut self $(, $arg: $ty)*) -> $ret;
            )*
        }

        $(#[$doc])*
        #[cfg(not(hax))]
        pub trait $name {
            $(fn $method(&mut self $(, $arg: $ty)*) -> $ret;)*
        }
    };
}

executor_trait! {
    /// The I/O behind each non-terminal effect. Each method returns only the
    /// observation its effect expects.
    pub trait ShareIo {
        fn observe_link(&mut self) -> LinkMutationObservation;
        fn observe_device(&mut self) -> EkDeviceObservation;
        fn insert_capsule(&mut self, permit: SendInsertPermit) -> SendResultObservation;
        fn update_linked_item(&mut self, permit: LinkUpdatePermit) -> RowsObservation;
        fn revoke_linked_item(&mut self) -> RowsObservation;
        fn delete_linked_inbox(&mut self) -> CleanupObservation;
        fn delete_inbox_item(&mut self, permit: InboxDeletePermit) -> RowsObservation;
        fn update_share_ek(&mut self, permit: EkRegistrationPermit) -> RowsObservation;
    }
}

/// The interpreter body, shared verbatim by [`run_share`] and the async
/// handlers. `$io` names a mutable executor; pass `await` as the last argument
/// to await each executor call. `$start` is the request's begin transition.
#[macro_export]
macro_rules! share_interpreter {
    ($io:ident, $start:expr $(, $aw:ident)?) => {{
        use $crate::driver::{step as __step, ShareEffect as __E, ShareEvent as __V};
        let mut transition = $start;
        for _ in 0..$crate::interpreter::SHARE_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::driver::share_state_is_sound(transition.driver)
            });
            transition = match transition.effect {
                __E::ObserveLink => {
                    __step(transition.driver, __V::LinkObserved($io.observe_link()$(.$aw)?))
                }
                __E::ObserveDevice => {
                    __step(transition.driver, __V::EkObserved($io.observe_device()$(.$aw)?))
                }
                __E::InsertCapsule(permit) => __step(
                    transition.driver,
                    __V::SendResult($io.insert_capsule(permit)$(.$aw)?),
                ),
                __E::UpdateLinkedItem(permit) => __step(
                    transition.driver,
                    __V::Mutated($io.update_linked_item(permit)$(.$aw)?),
                ),
                __E::RevokeLinkedItem => __step(
                    transition.driver,
                    __V::Mutated($io.revoke_linked_item()$(.$aw)?),
                ),
                __E::DeleteLinkedInbox => __step(
                    transition.driver,
                    __V::Cleaned($io.delete_linked_inbox()$(.$aw)?),
                ),
                __E::DeleteInboxItem(permit) => __step(
                    transition.driver,
                    __V::Mutated($io.delete_inbox_item(permit)$(.$aw)?),
                ),
                __E::UpdateShareEk(permit) => __step(
                    transition.driver,
                    __V::Mutated($io.update_share_ek(permit)$(.$aw)?),
                ),
                // The driver has decided: perform nothing, keep the verdict.
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`share_interpreter!`]: the artifact hax
/// extracts and F* checks.
#[cfg_attr(hax, hax_lib::requires(crate::driver::share_state_is_sound(start.driver)))]
pub fn run_share<Io: ShareIo>(io: &mut Io, start: ShareTransition) -> ShareTransition {
    crate::share_interpreter!(io, start)
}

// ── Request entry points ───────────────────────────────────────────────────
//
// The handlers call these instead of the driver's `begin_*` functions, so the
// only driver transition a handler can reach is the proved loop. Each is the
// driver's own begin decision, unchanged.

pub fn start_send(observation: crate::driver::SendRequestObservation) -> ShareTransition {
    crate::driver::begin_send(observation)
}

pub fn start_link_update(
    observation: crate::driver::LinkUpdateStartObservation,
) -> ShareTransition {
    crate::driver::begin_link_update(observation)
}

pub fn start_link_revoke() -> ShareTransition {
    crate::driver::begin_link_revoke()
}

pub fn start_inbox_delete() -> ShareTransition {
    crate::driver::begin_inbox_delete()
}

pub fn start_ek_registration(
    observation: crate::driver::EkRegistrationStartObservation,
) -> ShareTransition {
    crate::driver::begin_ek_registration(observation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{
        begin_ek_registration, begin_inbox_delete, begin_link_revoke, begin_link_update,
        begin_send, step, EkRegistrationStartObservation, LinkUpdateStartObservation,
        SendRequestObservation, ShareEvent, ShareFailure,
    };
    use crate::{EkRegistrationObservation, SendObservation, SHARE_EK_LEN};

    /// Plays a fixed script of outcomes and records every call.
    struct Scripted {
        /// Which outcome to return for the n-th call (0 = the success kind,
        /// 1.. = the other observation kinds).
        script: Vec<u8>,
        calls: Vec<ShareEffect>,
        events: Vec<ShareEvent>,
    }

    impl Scripted {
        fn pick(&mut self) -> u8 {
            let n = self.calls.len() - 1;
            self.script.get(n).copied().unwrap_or(0)
        }
        fn record(&mut self, effect: ShareEffect) -> u8 {
            self.calls.push(effect);
            self.pick()
        }
        fn rows(pick: u8) -> RowsObservation {
            RowsObservation {
                rows: if pick % 2 == 0 { 1 } else { 0 },
            }
        }
        fn link_kind(&self, pick: u8) -> LinkMutationObservation {
            // Revoke/update: 0 = live sender-owned row, 1 = missing.
            if pick % 2 == 0 {
                LinkMutationObservation {
                    item_present: true,
                    caller_matches_sender: true,
                    item_not_revoked: true,
                }
            } else {
                LinkMutationObservation {
                    item_present: false,
                    caller_matches_sender: false,
                    item_not_revoked: false,
                }
            }
        }
    }

    impl ShareIo for Scripted {
        fn observe_link(&mut self) -> LinkMutationObservation {
            let pick = self.record(ShareEffect::ObserveLink);
            let o = self.link_kind(pick);
            self.events.push(ShareEvent::LinkObserved(o));
            o
        }
        fn observe_device(&mut self) -> EkDeviceObservation {
            let pick = self.record(ShareEffect::ObserveDevice);
            let registration = EkRegistrationObservation {
                ek_len: SHARE_EK_LEN,
                signature_verified: pick % 2 == 0,
                device_row_present: true,
                device_user_matches: true,
                device_active: true,
                signed_at_is_fresher: true,
                binding_exists: false,
            };
            let o = EkDeviceObservation {
                registration,
                stored_identity_vk_decode_failed: false,
                signature_decode_failed: false,
            };
            self.events.push(ShareEvent::EkObserved(o));
            o
        }
        fn insert_capsule(&mut self, permit: SendInsertPermit) -> SendResultObservation {
            let o = [
                SendResultObservation::Committed,
                SendResultObservation::StorageFailed,
                SendResultObservation::CommitConflict,
            ][(self.record(ShareEffect::InsertCapsule(permit)) % 3) as usize];
            self.events.push(ShareEvent::SendResult(o));
            o
        }
        fn update_linked_item(&mut self, permit: LinkUpdatePermit) -> RowsObservation {
            let o = Self::rows(self.record(ShareEffect::UpdateLinkedItem(permit)));
            self.events.push(ShareEvent::Mutated(o));
            o
        }
        fn revoke_linked_item(&mut self) -> RowsObservation {
            let o = Self::rows(self.record(ShareEffect::RevokeLinkedItem));
            self.events.push(ShareEvent::Mutated(o));
            o
        }
        fn delete_linked_inbox(&mut self) -> CleanupObservation {
            let pick = self.record(ShareEffect::DeleteLinkedInbox);
            let o = CleanupObservation {
                storage_failed: pick % 2 == 1,
            };
            self.events.push(ShareEvent::Cleaned(o));
            o
        }
        fn delete_inbox_item(&mut self, permit: InboxDeletePermit) -> RowsObservation {
            let o = Self::rows(self.record(ShareEffect::DeleteInboxItem(permit)));
            self.events.push(ShareEvent::Mutated(o));
            o
        }
        fn update_share_ek(&mut self, permit: EkRegistrationPermit) -> RowsObservation {
            let o = Self::rows(self.record(ShareEffect::UpdateShareEk(permit)));
            self.events.push(ShareEvent::Mutated(o));
            o
        }
    }

    fn check(start: ShareTransition, script: Vec<u8>) -> ShareEffect {
        let mut io = Scripted {
            script,
            calls: vec![],
            events: vec![],
        };
        let result = run_share(&mut io, start);
        let mut t = start;
        for (i, event) in io.events.iter().enumerate() {
            assert_eq!(io.calls[i], t.effect, "call {i} was not the emitted effect");
            assert!(!share_effect_is_terminal(t.effect));
            t = step(t.driver, *event);
        }
        assert_eq!(t, result, "interpreter result differs from the replayed driver");
        assert!(
            share_effect_is_terminal(result.effect),
            "no verdict within {SHARE_MAX_EFFECTS} effects"
        );
        assert!(io.calls.len() <= SHARE_MAX_EFFECTS);
        result.effect
    }

    fn send_start() -> ShareTransition {
        begin_send(SendRequestObservation {
            policy: SendObservation {
                session_user_id_present: true,
                recipient_has_share_ek: true,
                capsule_len: 16,
                existing_inbox_bytes: 0,
            },
            decode_failed: false,
            inbox_count: 0,
            pair_bytes: 0,
        })
    }

    fn ek_start() -> ShareTransition {
        begin_ek_registration(EkRegistrationStartObservation {
            ek_decode_failed: false,
            ek_len: SHARE_EK_LEN,
            signed_at_not_canonical: false,
            signed_at_unparseable: false,
            signed_at_future: false,
        })
    }

    fn ceremonies() -> Vec<(&'static str, ShareTransition)> {
        vec![
            ("send", send_start()),
            (
                "update",
                begin_link_update(LinkUpdateStartObservation {
                    decode_failed: false,
                    capsule_len: 16,
                }),
            ),
            ("revoke", begin_link_revoke()),
            ("inbox", begin_inbox_delete()),
            ("ek", ek_start()),
        ]
    }

    #[test]
    fn interpreter_performs_exactly_the_driver_effects_for_every_outcome() {
        for (name, start) in ceremonies() {
            assert_eq!(
                check(start, vec![0u8; SHARE_MAX_EFFECTS]),
                ShareEffect::Complete,
                "{name}: success script"
            );
            for position in 0..SHARE_MAX_EFFECTS {
                for script_kind in 1..=3u8 {
                    let mut script = vec![0u8; SHARE_MAX_EFFECTS];
                    script[position] = script_kind;
                    check(start, script);
                }
            }
        }
    }

    #[test]
    fn a_refused_send_performs_nothing() {
        let start = begin_send(SendRequestObservation {
            policy: SendObservation {
                session_user_id_present: true,
                recipient_has_share_ek: false,
                capsule_len: 16,
                existing_inbox_bytes: 0,
            },
            decode_failed: false,
            inbox_count: 0,
            pair_bytes: 0,
        });
        let mut io = Scripted {
            script: vec![],
            calls: vec![],
            events: vec![],
        };
        let result = run_share(&mut io, start);
        assert!(io.calls.is_empty());
        assert!(matches!(result.effect, ShareEffect::Fail(_)));
        assert_eq!(result.effect, ShareEffect::Fail(ShareFailure::RecipientUnavailable));
    }

    #[test]
    fn a_missing_linked_row_performs_no_mutation() {
        let start = begin_link_revoke();
        let mut io = Scripted {
            script: vec![1],
            calls: vec![],
            events: vec![],
        };
        let result = run_share(&mut io, start);
        assert_eq!(io.calls.len(), 1);
        assert_eq!(
            result.effect,
            ShareEffect::Fail(ShareFailure::LinkNotFound)
        );
    }

    #[test]
    fn a_committed_revoke_cleans_up_exactly_once() {
        for cleanup_kind in [0u8, 1u8] {
            let start = begin_link_revoke();
            let mut io = Scripted {
                script: vec![0, 0, cleanup_kind],
                calls: vec![],
                events: vec![],
            };
            let result = run_share(&mut io, start);
            assert_eq!(io.calls.len(), 3);
            assert_eq!(result.effect, ShareEffect::Complete);
            assert!(result.driver.revoked && result.driver.cleanup_issued);
        }
    }
}
