//! The one loop that connects the device-pairing handlers to their driver.
//!
//! The handlers do not call the ceremony driver by hand. Each expands
//! [`pairing_interpreter!`](crate::pairing_interpreter), the same macro this
//! module expands into the synchronous [`run_pairing`]. hax extracts
//! `run_pairing` and F* proves, for every [`PairingIo`] implementation, that
//!
//! - an executor method is called only for the effect the driver has just
//!   emitted, in the order emitted, and each method returns the observation
//!   kind that effect expects (the types allow nothing else);
//! - the loop stops at the first terminal effect and performs nothing after it;
//! - the final driver is `run_from_*` for the observations the executor
//!   actually returned, so every per-request pairing theorem holds for the real
//!   handler.
//!
//! The server's expansions differ only by `.await` after each executor call.
//! What stays outside the proof is each executor method: that it runs the I/O
//! its name describes and reports the outcome honestly.
//!
//! Every ceremony shares the driver's single [`PairingEffect`] type, so one
//! executor trait and one loop macro cover all six. The caller supplies the
//! ceremony's begin transition; the loop only performs the effects that
//! transition leads to.

use crate::ClaimObservation;
use crate::pairing_driver::{
    ClaimReadObservation, ClaimWriteObservation,
    CompletionAccountObservation, CompletionPreflightObservation, DeviceGrantObservation,
    DeviceInsertObservation, PairingEffect, PairingTransition, RedeemObservation,
    ResultReadObservation, StoreObservation, TakeObservation,
};

/// Most effects one request performs: the account preflight, the verified
/// preflight, the destructive take, the guarded insert and the result write.
pub const PAIRING_MAX_EFFECTS: usize = 5;

/// The driver has decided: nothing more may be performed.
pub fn pairing_effect_is_terminal(effect: PairingEffect) -> bool {
    matches!(
        effect,
        PairingEffect::Complete
            | PairingEffect::ReturnResult(_)
            | PairingEffect::Fail(_)
            | PairingEffect::RestoreAndFail(_)
            | PairingEffect::Idle
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
    pub trait PairingIo {
        fn store_package(&mut self) -> StoreObservation;
        fn redeem_package(&mut self) -> RedeemObservation;
        fn store_grant(&mut self) -> StoreObservation;
        fn check_claim(&mut self) -> ClaimObservation;
        fn write_claim(&mut self) -> ClaimWriteObservation;
        fn check_account(&mut self) -> CompletionAccountObservation;
        fn prepare_completion(&mut self) -> CompletionPreflightObservation;
        fn take_ceremony(&mut self) -> TakeObservation;
        fn insert_device(&mut self) -> DeviceInsertObservation;
        fn write_result(&mut self) -> StoreObservation;
        fn read_result(&mut self) -> ResultReadObservation;
        fn read_claim(&mut self) -> ClaimReadObservation;
        fn read_enrolled_device(&mut self) -> DeviceGrantObservation;
    }
}

/// The interpreter body, shared verbatim by [`run_pairing`] and the async
/// handlers. `$io` names a mutable executor; pass `await` as the last argument
/// to await each executor call. `$start` is the ceremony's begin transition.
#[macro_export]
macro_rules! pairing_interpreter {
    ($io:ident, $start:expr $(, $aw:ident)?) => {{
        use $crate::pairing_driver::{step as __step, PairingEffect as __E, PairingEvent as __V};
        let mut transition = $start;
        for _ in 0..$crate::pairing_interpreter::PAIRING_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::pairing_driver::pairing_state_is_sound(transition.driver)
            });
            transition = match transition.effect {
                __E::StorePackage => __step(
                    transition.driver,
                    __V::PackageWritten($io.store_package()$(.$aw)?),
                ),
                __E::RedeemPackage => __step(
                    transition.driver,
                    __V::PackageRedeemed($io.redeem_package()$(.$aw)?),
                ),
                __E::StoreGrant => {
                    __step(transition.driver, __V::GrantWritten($io.store_grant()$(.$aw)?))
                }
                __E::CheckClaim => {
                    __step(transition.driver, __V::ClaimChecked($io.check_claim()$(.$aw)?))
                }
                __E::WriteClaim => {
                    __step(transition.driver, __V::ClaimWritten($io.write_claim()$(.$aw)?))
                }
                __E::CheckAccount => __step(
                    transition.driver,
                    __V::AccountChecked($io.check_account()$(.$aw)?),
                ),
                __E::PrepareCompletion => __step(
                    transition.driver,
                    __V::CompletionReady($io.prepare_completion()$(.$aw)?),
                ),
                __E::TakeCeremony => __step(
                    transition.driver,
                    __V::CeremonyTaken($io.take_ceremony()$(.$aw)?),
                ),
                __E::InsertDevice => __step(
                    transition.driver,
                    __V::DeviceInserted($io.insert_device()$(.$aw)?),
                ),
                __E::WriteResult => {
                    __step(transition.driver, __V::ResultWritten($io.write_result()$(.$aw)?))
                }
                __E::ReadResult => {
                    __step(transition.driver, __V::ResultRead($io.read_result()$(.$aw)?))
                }
                __E::ReadClaim => {
                    __step(transition.driver, __V::ClaimRead($io.read_claim()$(.$aw)?))
                }
                __E::ReadEnrolledDevice => __step(
                    transition.driver,
                    __V::EnrolledDeviceRead($io.read_enrolled_device()$(.$aw)?),
                ),
                // The driver has decided: perform nothing, keep the verdict.
                __E::Complete
                | __E::ReturnResult(_)
                | __E::Fail(_)
                | __E::RestoreAndFail(_)
                | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`pairing_interpreter!`]: the artifact hax
/// extracts and F* checks.
#[cfg_attr(hax, hax_lib::requires(crate::pairing_driver::pairing_state_is_sound(start.driver)))]
pub fn run_pairing<Io: PairingIo>(io: &mut Io, start: PairingTransition) -> PairingTransition {
    crate::pairing_interpreter!(io, start)
}

// ── Ceremony entry points ──────────────────────────────────────────────────
//
// The handlers call these instead of the driver's `begin_*` functions, so the
// only driver transition a handler can reach is the proved loop. Each is the
// driver's own begin decision, unchanged.

pub fn start_store_package(
    observation: crate::pairing_driver::PackageStoreObservation,
) -> PairingTransition {
    crate::pairing_driver::begin_store_package(observation)
}

pub fn start_redeem_package(
    observation: crate::pairing_driver::PackageTokenObservation,
) -> PairingTransition {
    crate::pairing_driver::begin_redeem_package(observation)
}

pub fn start_open_grant(
    observation: crate::OpenObservation,
) -> PairingTransition {
    crate::pairing_driver::begin_open_grant(observation)
}

pub fn start_claim(grant_live: bool) -> PairingTransition {
    crate::pairing_driver::begin_claim(grant_live)
}

pub fn start_completion(
    grant: crate::pairing_driver::GrantObservation,
) -> PairingTransition {
    crate::pairing_driver::begin_completion(grant)
}

pub fn start_result() -> PairingTransition {
    crate::pairing_driver::begin_result()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing_driver::{
        begin_claim, begin_completion, begin_open_grant, begin_redeem_package, begin_result,
        begin_store_package, step, ClaimMaterialObservation, GrantObservation, OpenerObservation,
        PackageStoreObservation, PackageTokenObservation, PairingEvent, PairingFailure,
        SignatureObservation,
    };
    use crate::{OpenObservation, HYBRID_EK_LEN, HYBRID_VK_LEN};

    /// Plays a fixed script of outcomes and records every call.
    struct Scripted {
        /// Which outcome to return for the n-th call (0 = the success kind,
        /// 1.. = the other observation kinds in declaration order).
        script: Vec<u8>,
        calls: Vec<PairingEffect>,
        events: Vec<PairingEvent>,
    }

    impl Scripted {
        fn pick(&mut self) -> u8 {
            let n = self.calls.len() - 1;
            self.script.get(n).copied().unwrap_or(0)
        }
        fn record(&mut self, effect: PairingEffect) -> u8 {
            self.calls.push(effect);
            self.pick()
        }
        fn store_kind(pick: u8) -> StoreObservation {
            [StoreObservation::Stored, StoreObservation::Failed]
                [(pick % 2) as usize]
        }
        fn rows_kind(pick: u8) -> DeviceInsertObservation {
            [
                DeviceInsertObservation::Inserted,
                DeviceInsertObservation::Skipped,
                DeviceInsertObservation::Failed,
            ][(pick % 3) as usize]
        }
        fn claim_read_kind(pick: u8) -> ClaimReadObservation {
            match pick % 4 {
                0 => ClaimReadObservation::Claimed {
                    claimed_key_len: HYBRID_VK_LEN,
                    signature_verified: true,
                },
                1 => ClaimReadObservation::Claimed {
                    claimed_key_len: HYBRID_VK_LEN,
                    signature_verified: false,
                },
                2 => ClaimReadObservation::Absent,
                _ => ClaimReadObservation::Unreadable,
            }
        }
        fn result_read_kind(pick: u8) -> ResultReadObservation {
            match pick % 4 {
                0 => ResultReadObservation::Completed {
                    claimed_key_len: HYBRID_VK_LEN,
                    signature_verified: true,
                },
                1 => ResultReadObservation::Completed {
                    claimed_key_len: HYBRID_VK_LEN,
                    signature_verified: false,
                },
                2 => ResultReadObservation::Absent,
                _ => ResultReadObservation::Unreadable,
            }
        }
        fn device_grant_kind(pick: u8) -> DeviceGrantObservation {
            match pick % 4 {
                0 => DeviceGrantObservation::Enrolled {
                    claimed_key_len: HYBRID_VK_LEN,
                    signature_verified: true,
                },
                1 => DeviceGrantObservation::Enrolled {
                    claimed_key_len: HYBRID_VK_LEN,
                    signature_verified: false,
                },
                2 => DeviceGrantObservation::Absent,
                _ => DeviceGrantObservation::Unreadable,
            }
        }
        fn preflight_kind(pick: u8) -> CompletionPreflightObservation {
            let base = CompletionPreflightObservation {
                claim: ClaimMaterialObservation::Usable,
                capsule_valid: true,
                signature_field_valid: true,
                opener: OpenerObservation::Active,
                signature: SignatureObservation::Verified,
                account_epoch: 3,
                declared_epoch: 3,
                rotation_in_progress: false,
                account_epoch_active: true,
            };
            match pick % 6 {
                0 => base,
                1 => CompletionPreflightObservation {
                    claim: ClaimMaterialObservation::Missing,
                    ..base
                },
                2 => CompletionPreflightObservation {
                    signature: SignatureObservation::Failed,
                    ..base
                },
                3 => CompletionPreflightObservation {
                    opener: OpenerObservation::Inactive,
                    ..base
                },
                4 => CompletionPreflightObservation {
                    account_epoch_active: false,
                    ..base
                },
                _ => CompletionPreflightObservation {
                    capsule_valid: false,
                    ..base
                },
            }
        }
    }

    impl PairingIo for Scripted {
        fn store_package(&mut self) -> StoreObservation {
            let o = Self::store_kind(self.record(PairingEffect::StorePackage));
            self.events.push(PairingEvent::PackageWritten(o));
            o
        }
        fn redeem_package(&mut self) -> RedeemObservation {
            let o = [
                RedeemObservation::Present { utf8_valid: true },
                RedeemObservation::Missing,
                RedeemObservation::Present { utf8_valid: false },
            ][(self.record(PairingEffect::RedeemPackage) % 3) as usize];
            self.events.push(PairingEvent::PackageRedeemed(o));
            o
        }
        fn store_grant(&mut self) -> StoreObservation {
            let o = Self::store_kind(self.record(PairingEffect::StoreGrant));
            self.events.push(PairingEvent::GrantWritten(o));
            o
        }
        fn check_claim(&mut self) -> ClaimObservation {
            let pick = self.record(PairingEffect::CheckClaim) % 5;
            let o = match pick {
                0 => ClaimObservation {
                    grant_live: true,
                    claim_exists: false,
                    hybrid_ek_len: HYBRID_EK_LEN,
                    hybrid_vk_len: HYBRID_VK_LEN,
                },
                1 => ClaimObservation {
                    grant_live: true,
                    claim_exists: true,
                    hybrid_ek_len: HYBRID_EK_LEN,
                    hybrid_vk_len: HYBRID_VK_LEN,
                },
                2 => ClaimObservation {
                    grant_live: true,
                    claim_exists: false,
                    hybrid_ek_len: 0,
                    hybrid_vk_len: HYBRID_VK_LEN,
                },
                3 => ClaimObservation {
                    grant_live: true,
                    claim_exists: false,
                    hybrid_ek_len: HYBRID_EK_LEN,
                    hybrid_vk_len: 0,
                },
                _ => ClaimObservation {
                    grant_live: false,
                    claim_exists: false,
                    hybrid_ek_len: HYBRID_EK_LEN,
                    hybrid_vk_len: HYBRID_VK_LEN,
                },
            };
            self.events.push(PairingEvent::ClaimChecked(o));
            o
        }
        fn write_claim(&mut self) -> ClaimWriteObservation {
            let o = [
                ClaimWriteObservation::Inserted,
                ClaimWriteObservation::GuardMissing,
                ClaimWriteObservation::KeyExists,
            ][(self.record(PairingEffect::WriteClaim) % 3) as usize];
            self.events.push(PairingEvent::ClaimWritten(o));
            o
        }
        fn check_account(&mut self) -> CompletionAccountObservation {
            let o = match self.record(PairingEffect::CheckAccount) % 4 {
                0 => CompletionAccountObservation {
                    account_query_ok: true,
                    declared_epoch_positive: true,
                    rekey_permitted: true,
                },
                1 => CompletionAccountObservation {
                    account_query_ok: false,
                    declared_epoch_positive: true,
                    rekey_permitted: true,
                },
                2 => CompletionAccountObservation {
                    account_query_ok: true,
                    declared_epoch_positive: false,
                    rekey_permitted: true,
                },
                _ => CompletionAccountObservation {
                    account_query_ok: true,
                    declared_epoch_positive: true,
                    rekey_permitted: false,
                },
            };
            self.events.push(PairingEvent::AccountChecked(o));
            o
        }
        fn prepare_completion(&mut self) -> CompletionPreflightObservation {
            let o = Self::preflight_kind(self.record(PairingEffect::PrepareCompletion));
            self.events.push(PairingEvent::CompletionReady(o));
            o
        }
        fn take_ceremony(&mut self) -> TakeObservation {
            let o = [
                TakeObservation::Taken {
                    grant_matches: true,
                    claim_matches: true,
                },
                TakeObservation::Missing,
                TakeObservation::Taken {
                    grant_matches: true,
                    claim_matches: false,
                },
            ][(self.record(PairingEffect::TakeCeremony) % 3) as usize];
            self.events.push(PairingEvent::CeremonyTaken(o));
            o
        }
        fn insert_device(&mut self) -> DeviceInsertObservation {
            let o = Self::rows_kind(self.record(PairingEffect::InsertDevice));
            self.events.push(PairingEvent::DeviceInserted(o));
            o
        }
        fn write_result(&mut self) -> StoreObservation {
            let o = Self::store_kind(self.record(PairingEffect::WriteResult));
            self.events.push(PairingEvent::ResultWritten(o));
            o
        }
        fn read_result(&mut self) -> ResultReadObservation {
            let o = Self::result_read_kind(self.record(PairingEffect::ReadResult));
            self.events.push(PairingEvent::ResultRead(o));
            o
        }
        fn read_claim(&mut self) -> ClaimReadObservation {
            let o = Self::claim_read_kind(self.record(PairingEffect::ReadClaim));
            self.events.push(PairingEvent::ClaimRead(o));
            o
        }
        fn read_enrolled_device(&mut self) -> DeviceGrantObservation {
            let o = Self::device_grant_kind(self.record(PairingEffect::ReadEnrolledDevice));
            self.events.push(PairingEvent::EnrolledDeviceRead(o));
            o
        }
    }

    /// Replays the recorded events through the driver by hand and checks the
    /// interpreter called exactly the emitted effects, in order, and stopped
    /// at the verdict.
    fn check(start: PairingTransition, script: Vec<u8>) -> PairingEffect {
        let mut io = Scripted {
            script,
            calls: vec![],
            events: vec![],
        };
        let result = run_pairing(&mut io, start);
        let mut t = start;
        for (i, event) in io.events.iter().enumerate() {
            assert_eq!(io.calls[i], t.effect, "call {i} was not the emitted effect");
            assert!(!pairing_effect_is_terminal(t.effect));
            t = step(t.driver, *event);
        }
        assert_eq!(t, result, "interpreter result differs from the replayed driver");
        assert!(
            pairing_effect_is_terminal(result.effect),
            "no verdict within {PAIRING_MAX_EFFECTS} effects"
        );
        assert!(io.calls.len() <= PAIRING_MAX_EFFECTS);
        result.effect
    }

    fn ceremonies() -> Vec<(&'static str, PairingTransition)> {
        vec![
            (
                "store",
                begin_store_package(PackageStoreObservation {
                    token_valid: true,
                    ciphertext_len_valid: true,
                }),
            ),
            (
                "redeem",
                begin_redeem_package(PackageTokenObservation { token_valid: true }),
            ),
            (
                "open",
                begin_open_grant(OpenObservation {
                    scope_is_device: true,
                    user_id_present: true,
                    device_id_present: true,
                    ttl_secs: 300,
                }),
            ),
            ("claim", begin_claim(true)),
            (
                "completion",
                begin_completion(GrantObservation::Present {
                    user_matches: true,
                    opener_matches: true,
                }),
            ),
            ("result", begin_result()),
        ]
    }

    #[test]
    fn interpreter_performs_exactly_the_driver_effects_for_every_outcome() {
        for (name, start) in ceremonies() {
            assert_eq!(
                check(start, vec![0u8; PAIRING_MAX_EFFECTS]),
                if name == "result" {
                    PairingEffect::ReturnResult(crate::ResultKind::Enrolled)
                } else {
                    PairingEffect::Complete
                },
                "{name}: success script"
            );
            // One alternative observation at each position in turn, covering
            // every observation kind each effect has.
            for position in 0..PAIRING_MAX_EFFECTS {
                for kind in 1..=6u8 {
                    let mut script = vec![0u8; PAIRING_MAX_EFFECTS];
                    script[position] = kind;
                    check(start, script);
                }
            }
        }
    }

    #[test]
    fn a_terminal_begin_performs_nothing() {
        let starts = [
            begin_store_package(PackageStoreObservation {
                token_valid: false,
                ciphertext_len_valid: true,
            }),
            begin_redeem_package(PackageTokenObservation { token_valid: false }),
            begin_claim(false),
            begin_completion(GrantObservation::Absent),
        ];
        for start in starts {
            let mut io = Scripted {
                script: vec![],
                calls: vec![],
                events: vec![],
            };
            let result = run_pairing(&mut io, start);
            assert!(io.calls.is_empty());
            assert!(matches!(
                result.effect,
                PairingEffect::Fail(_) | PairingEffect::RestoreAndFail(_)
            ));
        }
    }

    #[test]
    fn a_completion_take_mismatch_restores_and_stops() {
        let start = begin_completion(GrantObservation::Present {
            user_matches: true,
            opener_matches: true,
        });
        let mut script = vec![0u8; PAIRING_MAX_EFFECTS];
        // CheckAccount success, PrepareCompletion success, take mismatch.
        script[2] = 2;
        let mut io = Scripted {
            script,
            calls: vec![],
            events: vec![],
        };
        let result = run_pairing(&mut io, start);
        assert!(matches!(
            result.effect,
            PairingEffect::RestoreAndFail(PairingFailure::CeremonyChanged)
        ));
        assert_eq!(io.calls.len(), 3);
        assert!(result.driver.restored && !result.driver.inserted);
    }

    #[test]
    fn an_ambiguous_insert_error_consumes_the_ceremony() {
        let start = begin_completion(GrantObservation::Present {
            user_matches: true,
            opener_matches: true,
        });
        let mut script = vec![0u8; PAIRING_MAX_EFFECTS];
        // CheckAccount success, PrepareCompletion success, take success,
        // guarded insert error (kind 2).
        script[3] = 2;
        let mut io = Scripted {
            script,
            calls: vec![],
            events: vec![],
        };
        let result = run_pairing(&mut io, start);
        assert!(matches!(
            result.effect,
            PairingEffect::Fail(PairingFailure::InsertStorage)
        ));
        assert!(result.driver.failed && !result.driver.restored);
        assert_eq!(io.calls.len(), 4);
    }
}
