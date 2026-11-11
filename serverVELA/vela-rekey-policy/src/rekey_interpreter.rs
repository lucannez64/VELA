//! The four loops that connect the rotation handlers to their driver.
//!
//! No handler calls the driver by hand. `post_start`, `post_capsules`,
//! `post_commit` and `post_abort` each expand one of the macros below, the same
//! macro text this module expands into the synchronous `run_start`,
//! `run_capsules`, `run_commit` and `run_abort`. hax extracts those functions
//! and F* proves, for every [`RekeyIo`] implementation:
//!
//! - the executor method for the effect the driver has just emitted is the one
//!   called, with that effect's argument (the capsule index), in the order
//!   emitted, and no method is called once the driver reached a verdict;
//! - the observations the executor returned form a list in which each
//!   observation answers the effect it was returned for, and the final driver
//!   is `run_from_* request observations`, so every per-request rotation
//!   theorem holds for the real handler;
//! - the driver always reaches a verdict within the loop budget;
//! - the loop preserves the driver's own state invariant.
//!
//! The server's expansion differs only by `.await` after each executor call.
//! What stays outside the proof is each executor method: that it runs the I/O
//! its name describes and reports the outcome honestly.

use crate::rekey_driver::{
    CapsuleObservation, CasObservation, CleanupObservation, InventoryObservation,
    ProbeObservation, RateLimitObservation, RekeyEffect, RekeyRequest, RekeyTransition,
    RollbackObservation, StateObservation, SweepObservation, TimeoutObservation,
    TransactionObservation,
};

/// Most effects any rotation request performs: pacing, state load, a timeout
/// rollback, the readiness probes, the freeze transaction, the inventory, the
/// freeze CAS, the cleanup, the transaction commit — or 64 capsule writes, or
/// the two completeness probes, the commit CAS, the sweep and the publication.
pub const START_MAX_EFFECTS: usize = 12;
pub const CAPSULES_MAX_EFFECTS: usize = 68;
pub const COMMIT_MAX_EFFECTS: usize = 10;
pub const ABORT_MAX_EFFECTS: usize = 4;
/// Largest of the four budgets, used by the scripted conformance tests.
pub const REKEY_MAX_EFFECTS: usize = 68;

/// The state invariant every loop keeps.
pub fn rekey_loop_is_sound(transition: RekeyTransition) -> bool {
    crate::rekey_driver::rekey_state_is_sound(transition.driver)
        && crate::rekey_driver::rekey_effect_is_sound(transition.driver, transition.effect)
}

/// The driver has decided: nothing more may be performed.
pub fn rekey_effect_is_terminal(effect: RekeyEffect) -> bool {
    matches!(
        effect,
        RekeyEffect::Complete
            | RekeyEffect::CompleteReplay
            | RekeyEffect::Fail(_)
            | RekeyEffect::Idle
    )
}

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
    /// The I/O behind each non-terminal rotation effect. Each method returns
    /// only the observation its effect expects.
    pub trait RekeyIo {
        fn rate_limit(&mut self) -> RateLimitObservation;
        fn load_state(&mut self) -> StateObservation;
        fn timeout_rollback(&mut self) -> TimeoutObservation;
        fn check_oram(&mut self) -> ProbeObservation;
        fn check_capable(&mut self) -> ProbeObservation;
        fn check_acknowledged(&mut self) -> ProbeObservation;
        fn begin_freeze_transaction(&mut self) -> TransactionObservation;
        fn read_inventory(&mut self) -> InventoryObservation;
        fn freeze_cas(&mut self, from_epoch: i64, to_epoch: i64) -> CasObservation;
        fn cleanup_chunks(&mut self, from_epoch: i64) -> CleanupObservation;
        fn commit_freeze_transaction(&mut self) -> TransactionObservation;
        fn write_capsule(&mut self, index: i64) -> CapsuleObservation;
        fn check_chunk_shadows(&mut self) -> ProbeObservation;
        fn check_device_capsules(&mut self) -> ProbeObservation;
        fn commit_cas(&mut self, from_epoch: i64, to_epoch: i64) -> CasObservation;
        fn sweep_old_chunks(&mut self, new_epoch: i64) -> SweepObservation;
        fn publish_epoch(&mut self, epoch: i64) -> ();
        fn rollback_attempt(&mut self, epoch: i64) -> RollbackObservation;
    }
}

/// The start handler's loop, shared verbatim by [`run_start`] and the async
/// handler. `$io` names a mutable executor; pass `await` as the last argument
/// to await each executor call.
#[macro_export]
macro_rules! rekey_start_interpreter {
    ($io:ident, $request:expr $(, $aw:ident)?) => {{
        use $crate::rekey_driver::{
            begin_start as __begin, rekey_step as __step, RekeyEffect as __E, RekeyEvent as __V,
        };
        let mut transition = __begin($request);
        for _ in 0..$crate::rekey_interpreter::START_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::rekey_interpreter::rekey_loop_is_sound(transition)
            });
            transition = match transition.effect {
                __E::RateLimit => {
                    __step(transition.driver, __V::RateLimit($io.rate_limit()$(.$aw)?))
                }
                __E::LoadState => {
                    __step(transition.driver, __V::State($io.load_state()$(.$aw)?))
                }
                __E::TimeoutRollback => {
                    __step(transition.driver, __V::Timeout($io.timeout_rollback()$(.$aw)?))
                }
                __E::CheckOram => __step(transition.driver, __V::Oram($io.check_oram()$(.$aw)?)),
                __E::CheckCapable => {
                    __step(transition.driver, __V::Capable($io.check_capable()$(.$aw)?))
                }
                __E::CheckAcknowledged => __step(
                    transition.driver,
                    __V::Acknowledged($io.check_acknowledged()$(.$aw)?),
                ),
                __E::BeginFreezeTransaction => __step(
                    transition.driver,
                    __V::Transaction($io.begin_freeze_transaction()$(.$aw)?),
                ),
                __E::ReadInventory => __step(
                    transition.driver,
                    __V::Inventory($io.read_inventory()$(.$aw)?),
                ),
                __E::FreezeCas => __step(
                    transition.driver,
                    __V::FreezeCas(
                        $io.freeze_cas(transition.driver.from_epoch, transition.driver.to_epoch)$(.$aw)?,
                    ),
                ),
                __E::CleanupChunks => __step(
                    transition.driver,
                    __V::Cleanup($io.cleanup_chunks(transition.driver.from_epoch)$(.$aw)?),
                ),
                __E::CommitFreezeTransaction => __step(
                    transition.driver,
                    __V::TxCommit($io.commit_freeze_transaction()$(.$aw)?),
                ),
                __E::WriteCapsule { index } => __step(
                    transition.driver,
                    __V::Capsule($io.write_capsule(index)$(.$aw)?),
                ),
                __E::CheckChunkShadows => __step(
                    transition.driver,
                    __V::Chunks($io.check_chunk_shadows()$(.$aw)?),
                ),
                __E::CheckDeviceCapsules => __step(
                    transition.driver,
                    __V::Devices($io.check_device_capsules()$(.$aw)?),
                ),
                __E::CommitCas => __step(
                    transition.driver,
                    __V::CommitCas(
                        $io.commit_cas(transition.driver.from_epoch, transition.driver.to_epoch)$(.$aw)?,
                    ),
                ),
                __E::SweepOldChunks => __step(
                    transition.driver,
                    __V::Sweep($io.sweep_old_chunks(transition.driver.to_epoch)$(.$aw)?),
                ),
                __E::PublishEpoch => {
                    $io.publish_epoch(transition.driver.to_epoch)$(.$aw)?;
                    __step(transition.driver, __V::Published)
                }
                __E::RollbackAttempt => __step(
                    transition.driver,
                    __V::Rollback($io.rollback_attempt(transition.driver.epoch)$(.$aw)?),
                ),
                __E::Complete | __E::CompleteReplay | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The capsules handler's loop.
#[macro_export]
macro_rules! rekey_capsules_interpreter {
    ($io:ident, $request:expr $(, $aw:ident)?) => {{
        use $crate::rekey_driver::{
            begin_capsules as __begin, rekey_step as __step, RekeyEffect as __E,
            RekeyEvent as __V,
        };
        let mut transition = __begin($request);
        for _ in 0..$crate::rekey_interpreter::CAPSULES_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::rekey_interpreter::rekey_loop_is_sound(transition)
            });
            transition = match transition.effect {
                __E::RateLimit => {
                    __step(transition.driver, __V::RateLimit($io.rate_limit()$(.$aw)?))
                }
                __E::LoadState => {
                    __step(transition.driver, __V::State($io.load_state()$(.$aw)?))
                }
                __E::TimeoutRollback => {
                    __step(transition.driver, __V::Timeout($io.timeout_rollback()$(.$aw)?))
                }
                __E::CheckOram => __step(transition.driver, __V::Oram($io.check_oram()$(.$aw)?)),
                __E::CheckCapable => {
                    __step(transition.driver, __V::Capable($io.check_capable()$(.$aw)?))
                }
                __E::CheckAcknowledged => __step(
                    transition.driver,
                    __V::Acknowledged($io.check_acknowledged()$(.$aw)?),
                ),
                __E::BeginFreezeTransaction => __step(
                    transition.driver,
                    __V::Transaction($io.begin_freeze_transaction()$(.$aw)?),
                ),
                __E::ReadInventory => __step(
                    transition.driver,
                    __V::Inventory($io.read_inventory()$(.$aw)?),
                ),
                __E::FreezeCas => __step(
                    transition.driver,
                    __V::FreezeCas(
                        $io.freeze_cas(transition.driver.from_epoch, transition.driver.to_epoch)$(.$aw)?,
                    ),
                ),
                __E::CleanupChunks => __step(
                    transition.driver,
                    __V::Cleanup($io.cleanup_chunks(transition.driver.from_epoch)$(.$aw)?),
                ),
                __E::CommitFreezeTransaction => __step(
                    transition.driver,
                    __V::TxCommit($io.commit_freeze_transaction()$(.$aw)?),
                ),
                __E::WriteCapsule { index } => __step(
                    transition.driver,
                    __V::Capsule($io.write_capsule(index)$(.$aw)?),
                ),
                __E::CheckChunkShadows => __step(
                    transition.driver,
                    __V::Chunks($io.check_chunk_shadows()$(.$aw)?),
                ),
                __E::CheckDeviceCapsules => __step(
                    transition.driver,
                    __V::Devices($io.check_device_capsules()$(.$aw)?),
                ),
                __E::CommitCas => __step(
                    transition.driver,
                    __V::CommitCas(
                        $io.commit_cas(transition.driver.from_epoch, transition.driver.to_epoch)$(.$aw)?,
                    ),
                ),
                __E::SweepOldChunks => __step(
                    transition.driver,
                    __V::Sweep($io.sweep_old_chunks(transition.driver.to_epoch)$(.$aw)?),
                ),
                __E::PublishEpoch => {
                    $io.publish_epoch(transition.driver.to_epoch)$(.$aw)?;
                    __step(transition.driver, __V::Published)
                }
                __E::RollbackAttempt => __step(
                    transition.driver,
                    __V::Rollback($io.rollback_attempt(transition.driver.epoch)$(.$aw)?),
                ),
                __E::Complete | __E::CompleteReplay | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The commit handler's loop.
#[macro_export]
macro_rules! rekey_commit_interpreter {
    ($io:ident, $request:expr $(, $aw:ident)?) => {{
        use $crate::rekey_driver::{
            begin_commit as __begin, rekey_step as __step, RekeyEffect as __E, RekeyEvent as __V,
        };
        let mut transition = __begin($request);
        for _ in 0..$crate::rekey_interpreter::COMMIT_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::rekey_interpreter::rekey_loop_is_sound(transition)
            });
            transition = match transition.effect {
                __E::RateLimit => {
                    __step(transition.driver, __V::RateLimit($io.rate_limit()$(.$aw)?))
                }
                __E::LoadState => {
                    __step(transition.driver, __V::State($io.load_state()$(.$aw)?))
                }
                __E::TimeoutRollback => {
                    __step(transition.driver, __V::Timeout($io.timeout_rollback()$(.$aw)?))
                }
                __E::CheckOram => __step(transition.driver, __V::Oram($io.check_oram()$(.$aw)?)),
                __E::CheckCapable => {
                    __step(transition.driver, __V::Capable($io.check_capable()$(.$aw)?))
                }
                __E::CheckAcknowledged => __step(
                    transition.driver,
                    __V::Acknowledged($io.check_acknowledged()$(.$aw)?),
                ),
                __E::BeginFreezeTransaction => __step(
                    transition.driver,
                    __V::Transaction($io.begin_freeze_transaction()$(.$aw)?),
                ),
                __E::ReadInventory => __step(
                    transition.driver,
                    __V::Inventory($io.read_inventory()$(.$aw)?),
                ),
                __E::FreezeCas => __step(
                    transition.driver,
                    __V::FreezeCas(
                        $io.freeze_cas(transition.driver.from_epoch, transition.driver.to_epoch)$(.$aw)?,
                    ),
                ),
                __E::CleanupChunks => __step(
                    transition.driver,
                    __V::Cleanup($io.cleanup_chunks(transition.driver.from_epoch)$(.$aw)?),
                ),
                __E::CommitFreezeTransaction => __step(
                    transition.driver,
                    __V::TxCommit($io.commit_freeze_transaction()$(.$aw)?),
                ),
                __E::WriteCapsule { index } => __step(
                    transition.driver,
                    __V::Capsule($io.write_capsule(index)$(.$aw)?),
                ),
                __E::CheckChunkShadows => __step(
                    transition.driver,
                    __V::Chunks($io.check_chunk_shadows()$(.$aw)?),
                ),
                __E::CheckDeviceCapsules => __step(
                    transition.driver,
                    __V::Devices($io.check_device_capsules()$(.$aw)?),
                ),
                __E::CommitCas => __step(
                    transition.driver,
                    __V::CommitCas(
                        $io.commit_cas(transition.driver.from_epoch, transition.driver.to_epoch)$(.$aw)?,
                    ),
                ),
                __E::SweepOldChunks => __step(
                    transition.driver,
                    __V::Sweep($io.sweep_old_chunks(transition.driver.to_epoch)$(.$aw)?),
                ),
                __E::PublishEpoch => {
                    $io.publish_epoch(transition.driver.to_epoch)$(.$aw)?;
                    __step(transition.driver, __V::Published)
                }
                __E::RollbackAttempt => __step(
                    transition.driver,
                    __V::Rollback($io.rollback_attempt(transition.driver.epoch)$(.$aw)?),
                ),
                __E::Complete | __E::CompleteReplay | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The abort handler's loop.
#[macro_export]
macro_rules! rekey_abort_interpreter {
    ($io:ident, $request:expr $(, $aw:ident)?) => {{
        use $crate::rekey_driver::{
            begin_abort as __begin, rekey_step as __step, RekeyEffect as __E, RekeyEvent as __V,
        };
        let mut transition = __begin($request);
        for _ in 0..$crate::rekey_interpreter::ABORT_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::rekey_interpreter::rekey_loop_is_sound(transition)
            });
            transition = match transition.effect {
                __E::RateLimit => {
                    __step(transition.driver, __V::RateLimit($io.rate_limit()$(.$aw)?))
                }
                __E::LoadState => {
                    __step(transition.driver, __V::State($io.load_state()$(.$aw)?))
                }
                __E::TimeoutRollback => {
                    __step(transition.driver, __V::Timeout($io.timeout_rollback()$(.$aw)?))
                }
                __E::CheckOram => __step(transition.driver, __V::Oram($io.check_oram()$(.$aw)?)),
                __E::CheckCapable => {
                    __step(transition.driver, __V::Capable($io.check_capable()$(.$aw)?))
                }
                __E::CheckAcknowledged => __step(
                    transition.driver,
                    __V::Acknowledged($io.check_acknowledged()$(.$aw)?),
                ),
                __E::BeginFreezeTransaction => __step(
                    transition.driver,
                    __V::Transaction($io.begin_freeze_transaction()$(.$aw)?),
                ),
                __E::ReadInventory => __step(
                    transition.driver,
                    __V::Inventory($io.read_inventory()$(.$aw)?),
                ),
                __E::FreezeCas => __step(
                    transition.driver,
                    __V::FreezeCas(
                        $io.freeze_cas(transition.driver.from_epoch, transition.driver.to_epoch)$(.$aw)?,
                    ),
                ),
                __E::CleanupChunks => __step(
                    transition.driver,
                    __V::Cleanup($io.cleanup_chunks(transition.driver.from_epoch)$(.$aw)?),
                ),
                __E::CommitFreezeTransaction => __step(
                    transition.driver,
                    __V::TxCommit($io.commit_freeze_transaction()$(.$aw)?),
                ),
                __E::WriteCapsule { index } => __step(
                    transition.driver,
                    __V::Capsule($io.write_capsule(index)$(.$aw)?),
                ),
                __E::CheckChunkShadows => __step(
                    transition.driver,
                    __V::Chunks($io.check_chunk_shadows()$(.$aw)?),
                ),
                __E::CheckDeviceCapsules => __step(
                    transition.driver,
                    __V::Devices($io.check_device_capsules()$(.$aw)?),
                ),
                __E::CommitCas => __step(
                    transition.driver,
                    __V::CommitCas(
                        $io.commit_cas(transition.driver.from_epoch, transition.driver.to_epoch)$(.$aw)?,
                    ),
                ),
                __E::SweepOldChunks => __step(
                    transition.driver,
                    __V::Sweep($io.sweep_old_chunks(transition.driver.to_epoch)$(.$aw)?),
                ),
                __E::PublishEpoch => {
                    $io.publish_epoch(transition.driver.to_epoch)$(.$aw)?;
                    __step(transition.driver, __V::Published)
                }
                __E::RollbackAttempt => __step(
                    transition.driver,
                    __V::Rollback($io.rollback_attempt(transition.driver.epoch)$(.$aw)?),
                ),
                __E::Complete | __E::CompleteReplay | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`rekey_start_interpreter!`].
pub fn run_start<Io: RekeyIo>(io: &mut Io, request: RekeyRequest) -> RekeyTransition {
    crate::rekey_start_interpreter!(io, request)
}

/// The synchronous expansion of [`rekey_capsules_interpreter!`].
pub fn run_capsules<Io: RekeyIo>(io: &mut Io, request: RekeyRequest) -> RekeyTransition {
    crate::rekey_capsules_interpreter!(io, request)
}

/// The synchronous expansion of [`rekey_commit_interpreter!`].
pub fn run_commit<Io: RekeyIo>(io: &mut Io, request: RekeyRequest) -> RekeyTransition {
    crate::rekey_commit_interpreter!(io, request)
}

/// The synchronous expansion of [`rekey_abort_interpreter!`].
pub fn run_abort<Io: RekeyIo>(io: &mut Io, request: RekeyRequest) -> RekeyTransition {
    crate::rekey_abort_interpreter!(io, request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rekey_driver::{
        begin_abort, begin_capsules, begin_commit, begin_start, rekey_step, RekeyEvent,
        RekeyFailure, RekeyStage,
    };

    struct Scripted {
        script: Vec<u8>,
        calls: Vec<RekeyEffect>,
        events: Vec<RekeyEvent>,
    }

    impl Scripted {
        fn new(script: Vec<u8>) -> Self {
            Scripted {
                script,
                calls: vec![],
                events: vec![],
            }
        }
        fn pick(&mut self) -> u8 {
            let n = self.calls.len() - 1;
            self.script.get(n).copied().unwrap_or(0)
        }
        fn record(&mut self, effect: RekeyEffect) -> u8 {
            self.calls.push(effect);
            self.pick()
        }
    }

    impl RekeyIo for Scripted {
        fn rate_limit(&mut self) -> RateLimitObservation {
            let n = self.record(RekeyEffect::RateLimit);
            let observation = if n == 0 {
                RateLimitObservation::Allowed
            } else {
                RateLimitObservation::Limited
            };
            self.events.push(RekeyEvent::RateLimit(observation));
            observation
        }
        fn load_state(&mut self) -> StateObservation {
            let n = self.record(RekeyEffect::LoadState);
            let observation = match n % 4 {
                0 => StateObservation::Loaded(active(1)),
                1 => StateObservation::Loaded(freezing(1)),
                2 => StateObservation::Loaded(freezing_expired(1)),
                _ => StateObservation::Storage,
            };
            self.events.push(RekeyEvent::State(observation));
            observation
        }
        fn timeout_rollback(&mut self) -> TimeoutObservation {
            let n = self.record(RekeyEffect::TimeoutRollback);
            let observation = match n % 3 {
                0 => TimeoutObservation::RolledBack,
                1 => TimeoutObservation::Raced(active(1)),
                _ => TimeoutObservation::Storage,
            };
            self.events.push(RekeyEvent::Timeout(observation));
            observation
        }
        fn check_oram(&mut self) -> ProbeObservation {
            self.probe(RekeyEffect::CheckOram, RekeyEvent::Oram)
        }
        fn check_capable(&mut self) -> ProbeObservation {
            self.probe(RekeyEffect::CheckCapable, RekeyEvent::Capable)
        }
        fn check_acknowledged(&mut self) -> ProbeObservation {
            self.probe(RekeyEffect::CheckAcknowledged, RekeyEvent::Acknowledged)
        }
        fn begin_freeze_transaction(&mut self) -> TransactionObservation {
            let n = self.record(RekeyEffect::BeginFreezeTransaction);
            let observation = if n % 2 == 0 {
                TransactionObservation::Committed
            } else {
                TransactionObservation::Failed
            };
            self.events.push(RekeyEvent::Transaction(observation));
            observation
        }
        fn read_inventory(&mut self) -> InventoryObservation {
            let n = self.record(RekeyEffect::ReadInventory);
            let observation = if n % 2 == 0 {
                InventoryObservation::Read
            } else {
                InventoryObservation::Failed
            };
            self.events.push(RekeyEvent::Inventory(observation));
            observation
        }
        fn freeze_cas(&mut self, _from: i64, _to: i64) -> CasObservation {
            let n = self.record(RekeyEffect::FreezeCas);
            let observation = match n % 3 {
                0 => CasObservation::Updated,
                1 => CasObservation::Skipped,
                _ => CasObservation::Storage,
            };
            self.events.push(RekeyEvent::FreezeCas(observation));
            observation
        }
        fn cleanup_chunks(&mut self, _from: i64) -> CleanupObservation {
            let n = self.record(RekeyEffect::CleanupChunks);
            let observation = if n % 2 == 0 {
                CleanupObservation::Done
            } else {
                CleanupObservation::Storage
            };
            self.events.push(RekeyEvent::Cleanup(observation));
            observation
        }
        fn commit_freeze_transaction(&mut self) -> TransactionObservation {
            let n = self.record(RekeyEffect::CommitFreezeTransaction);
            let observation = if n % 2 == 0 {
                TransactionObservation::Committed
            } else {
                TransactionObservation::Failed
            };
            self.events.push(RekeyEvent::TxCommit(observation));
            observation
        }
        fn write_capsule(&mut self, _index: i64) -> CapsuleObservation {
            let n = self.record(RekeyEffect::WriteCapsule { index: _index });
            let observation = match n % 4 {
                0 => CapsuleObservation::Stored,
                1 => CapsuleObservation::Invalid,
                2 => CapsuleObservation::NotTarget,
                _ => CapsuleObservation::Storage,
            };
            self.events.push(RekeyEvent::Capsule(observation));
            observation
        }
        fn check_chunk_shadows(&mut self) -> ProbeObservation {
            self.probe(RekeyEffect::CheckChunkShadows, RekeyEvent::Chunks)
        }
        fn check_device_capsules(&mut self) -> ProbeObservation {
            self.probe(RekeyEffect::CheckDeviceCapsules, RekeyEvent::Devices)
        }
        fn commit_cas(&mut self, _from: i64, _to: i64) -> CasObservation {
            let n = self.record(RekeyEffect::CommitCas);
            let observation = match n % 3 {
                0 => CasObservation::Updated,
                1 => CasObservation::Skipped,
                _ => CasObservation::Storage,
            };
            self.events.push(RekeyEvent::CommitCas(observation));
            observation
        }
        fn sweep_old_chunks(&mut self, _epoch: i64) -> SweepObservation {
            let n = self.record(RekeyEffect::SweepOldChunks);
            let observation = if n % 2 == 0 {
                SweepObservation::Done
            } else {
                SweepObservation::Failed
            };
            self.events.push(RekeyEvent::Sweep(observation));
            observation
        }
        fn publish_epoch(&mut self, _epoch: i64) {
            self.record(RekeyEffect::PublishEpoch);
            self.events.push(RekeyEvent::Published);
        }
        fn rollback_attempt(&mut self, _epoch: i64) -> RollbackObservation {
            let n = self.record(RekeyEffect::RollbackAttempt);
            let observation = match n % 3 {
                0 => RollbackObservation::RolledBack,
                1 => RollbackObservation::Raced,
                _ => RollbackObservation::Storage,
            };
            self.events.push(RekeyEvent::Rollback(observation));
            observation
        }
    }

    impl Scripted {
        fn probe(
            &mut self,
            effect: RekeyEffect,
            event: fn(ProbeObservation) -> RekeyEvent,
        ) -> ProbeObservation {
            let n = self.record(effect);
            let observation = match n % 3 {
                0 => ProbeObservation::Empty,
                1 => ProbeObservation::Found,
                _ => ProbeObservation::Storage,
            };
            self.events.push(event(observation));
            observation
        }
    }

    fn active(epoch: i64) -> crate::rekey_driver::KeyStateObs {
        crate::rekey_driver::KeyStateObs {
            epoch,
            freezing: false,
            starter_matches: false,
            rotation_id_present: false,
            header_present: false,
            header_matches: false,
            replay_target: None,
            replay_recorded: None,
            replay_id_matches: false,
            expired: false,
        }
    }

    fn freezing(epoch: i64) -> crate::rekey_driver::KeyStateObs {
        crate::rekey_driver::KeyStateObs {
            epoch,
            freezing: true,
            starter_matches: true,
            rotation_id_present: true,
            header_present: true,
            header_matches: true,
            replay_target: None,
            replay_recorded: None,
            replay_id_matches: false,
            expired: false,
        }
    }

    fn freezing_expired(epoch: i64) -> crate::rekey_driver::KeyStateObs {
        crate::rekey_driver::KeyStateObs {
            expired: true,
            ..freezing(epoch)
        }
    }

    fn request(capsules: i64) -> RekeyRequest {
        RekeyRequest {
            authenticated: true,
            device_scope: true,
            capsule_count: capsules,
        }
    }

    /// The state load is the second call; selecting kind 1 makes it return a
    /// freezing account, which every non-start entry point requires.
    fn freezing_script() -> Vec<u8> {
        let mut script = vec![0u8; REKEY_MAX_EFFECTS];
        script[1] = 1;
        script
    }

    fn check(
        request: RekeyRequest,
        script: Vec<u8>,
        begin: fn(RekeyRequest) -> RekeyTransition,
        run: fn(&mut Scripted, RekeyRequest) -> RekeyTransition,
    ) -> RekeyEffect {
        let mut io = Scripted::new(script);
        let result = run(&mut io, request);
        let mut t = begin(request);
        for (i, event) in io.events.iter().enumerate() {
            assert_eq!(io.calls[i], t.effect, "call {i} was not the emitted effect");
            assert!(
                !rekey_effect_is_terminal(t.effect),
                "call {i} was made after the verdict"
            );
            t = rekey_step(t.driver, *event);
        }
        assert_eq!(t, result, "interpreter result differs from the replayed driver");
        assert!(
            rekey_effect_is_terminal(result.effect),
            "no verdict within {REKEY_MAX_EFFECTS} effects"
        );
        assert_eq!(io.calls.len(), io.events.len());
        assert!(io.calls.len() <= REKEY_MAX_EFFECTS);
        result.effect
    }

    fn start_run(io: &mut Scripted, request: RekeyRequest) -> RekeyTransition {
        run_start(io, request)
    }
    fn capsules_run(io: &mut Scripted, request: RekeyRequest) -> RekeyTransition {
        run_capsules(io, request)
    }
    fn commit_run(io: &mut Scripted, request: RekeyRequest) -> RekeyTransition {
        run_commit(io, request)
    }
    fn abort_run(io: &mut Scripted, request: RekeyRequest) -> RekeyTransition {
        run_abort(io, request)
    }

    #[test]
    fn start_performs_exactly_the_driver_effects_for_every_outcome() {
        for position in 0..REKEY_MAX_EFFECTS {
            for kind in 0..4u8 {
                let mut script = vec![0u8; REKEY_MAX_EFFECTS];
                script[position] = kind;
                check(request(0), script, begin_start, start_run);
            }
        }
        assert_eq!(
            check(request(0), vec![0; REKEY_MAX_EFFECTS], begin_start, start_run),
            RekeyEffect::Complete
        );
    }

    #[test]
    fn capsules_perform_one_write_per_entry() {
        let result = check(request(3), freezing_script(), begin_capsules, capsules_run);
        assert_eq!(result, RekeyEffect::Complete);
        let mut io = Scripted::new(freezing_script());
        let result = run_capsules(&mut io, request(3));
        assert_eq!(
            io.calls
                .iter()
                .filter(|effect| matches!(effect, RekeyEffect::WriteCapsule { .. }))
                .count(),
            3
        );
        assert!(result.driver.capsules_complete);
    }

    #[test]
    fn commit_and_abort_reach_their_verdicts() {
        assert_eq!(
            check(request(0), freezing_script(), begin_commit, commit_run),
            RekeyEffect::Complete
        );
        assert_eq!(
            check(request(0), freezing_script(), begin_abort, abort_run),
            RekeyEffect::Complete
        );
        let mut io = Scripted::new(freezing_script());
        let result = run_commit(&mut io, request(0));
        assert_eq!(result.driver.stage, RekeyStage::Done);
        assert!(result.driver.committed);
        let mut io = Scripted::new(freezing_script());
        let result = run_abort(&mut io, request(0));
        assert!(result.driver.rolled_back && result.driver.active);
    }

    #[test]
    fn an_unauthenticated_or_web_request_performs_nothing() {
        for request in [
            RekeyRequest {
                authenticated: false,
                device_scope: true,
                capsule_count: 0,
            },
            RekeyRequest {
                authenticated: true,
                device_scope: false,
                capsule_count: 0,
            },
        ] {
            for (run, failure) in [
                (start_run as fn(&mut Scripted, RekeyRequest) -> RekeyTransition, RekeyFailure::Unauthenticated),
                (capsules_run, RekeyFailure::Unauthenticated),
                (commit_run, RekeyFailure::Unauthenticated),
                (abort_run, RekeyFailure::Unauthenticated),
            ] {
                let mut io = Scripted::new(vec![]);
                let result = run(&mut io, request);
                assert!(io.calls.is_empty());
                if !request.authenticated {
                    assert_eq!(result.effect, RekeyEffect::Fail(failure));
                } else {
                    assert_eq!(
                        result.effect,
                        RekeyEffect::Fail(RekeyFailure::WebSessionForbidden)
                    );
                }
            }
        }
    }
}
