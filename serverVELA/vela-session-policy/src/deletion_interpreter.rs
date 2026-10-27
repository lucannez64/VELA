//! The one loop that connects `DELETE /account` to its driver.
//!
//! The handler does not call the driver by hand. It expands
//! [`deletion_interpreter!`](crate::deletion_interpreter), the same macro this
//! module expands into the synchronous [`run_deletion`]. hax extracts
//! `run_deletion` and F* proves, for every [`DeletionIo`] implementation, that
//!
//! - an executor method is called only for the effect the driver has just
//!   emitted, in the order emitted, and each method returns the observation
//!   kind that effect expects (the types allow nothing else);
//! - the loop stops at the first terminal effect and performs nothing after it;
//! - the final driver is `run_from_actor actor events` for the observations the
//!   executor actually returned, so every per-request deletion theorem holds
//!   for the real handler.
//!
//! The server's expansion differs only by `.await` after each executor call.
//! What stays outside the proof is each executor method: that it runs the I/O
//! its name describes and reports the outcome honestly.

use crate::deletion_driver::{
    CommitObservation, DeletionActorObservation, DeletionEffect, DeletionTable,
    DeletionTransition, LockoutObservation, ScanObservation, TableDeleteObservation,
    TransactionObservation, UsersDeleteObservation,
};

/// Most effects one request performs: two scans, two lockouts, the transaction
/// begin, seven table deletes, the `users` delete and the commit.
pub const DELETION_MAX_EFFECTS: usize = 14;

/// The driver has decided: nothing more may be performed.
pub fn deletion_effect_is_terminal(effect: DeletionEffect) -> bool {
    matches!(
        effect,
        DeletionEffect::Complete | DeletionEffect::Fail(_) | DeletionEffect::Idle
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
    pub trait DeletionIo {
        fn scan_devices(&mut self) -> ScanObservation;
        fn lockout_devices(&mut self) -> LockoutObservation;
        fn scan_web_sessions(&mut self) -> ScanObservation;
        fn lockout_web_sessions(&mut self) -> LockoutObservation;
        fn begin_transaction(&mut self) -> TransactionObservation;
        fn delete_table(&mut self, table: DeletionTable) -> TableDeleteObservation;
        fn delete_users(&mut self) -> UsersDeleteObservation;
        fn commit(&mut self) -> CommitObservation;
    }
}

/// The interpreter body, shared verbatim by [`run_deletion`] and the async
/// handler. `$io` names a mutable executor; pass `await` as the last argument
/// to await each executor call.
#[macro_export]
macro_rules! deletion_interpreter {
    ($io:ident, $actor:expr $(, $aw:ident)?) => {{
        use $crate::deletion_driver::{step as __step, DeletionEffect as __E, DeletionEvent as __V};
        let mut transition = $crate::deletion_driver::begin_deletion($actor);
        for _ in 0..$crate::deletion_interpreter::DELETION_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::deletion_driver::deletion_state_is_sound(transition.driver)
            });
            transition = match transition.effect {
                __E::ScanDevices => {
                    __step(transition.driver, __V::DevicesScanned($io.scan_devices()$(.$aw)?))
                }
                __E::LockoutDevices => {
                    __step(transition.driver, __V::DeviceLockout($io.lockout_devices()$(.$aw)?))
                }
                __E::ScanWebSessions => __step(
                    transition.driver,
                    __V::WebSessionsScanned($io.scan_web_sessions()$(.$aw)?),
                ),
                __E::LockoutWebSessions => __step(
                    transition.driver,
                    __V::WebSessionLockout($io.lockout_web_sessions()$(.$aw)?),
                ),
                __E::BeginTransaction => {
                    __step(transition.driver, __V::Transaction($io.begin_transaction()$(.$aw)?))
                }
                __E::DeleteTable(table) => {
                    __step(transition.driver, __V::TableDeleted($io.delete_table(table)$(.$aw)?))
                }
                __E::DeleteUsers => {
                    __step(transition.driver, __V::UsersDeleted($io.delete_users()$(.$aw)?))
                }
                __E::CommitTransaction => {
                    __step(transition.driver, __V::Commit($io.commit()$(.$aw)?))
                }
                // The driver has decided: perform nothing, keep the verdict.
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`deletion_interpreter!`]: the artifact hax
/// extracts and F* checks.
pub fn run_deletion<Io: DeletionIo>(
    io: &mut Io,
    actor: DeletionActorObservation,
) -> DeletionTransition {
    crate::deletion_interpreter!(io, actor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deletion_driver::{begin_deletion, step, DeletionEvent};

    /// Plays a fixed script of outcomes and records every call.
    struct Scripted {
        /// Which outcome to return for the n-th call (0 = success, 1 = first
        /// failure kind, 2 = second failure kind where one exists).
        script: Vec<u8>,
        calls: Vec<DeletionEffect>,
        events: Vec<DeletionEvent>,
    }

    impl Scripted {
        fn pick(&mut self) -> u8 {
            let n = self.calls.len() - 1;
            self.script.get(n).copied().unwrap_or(0)
        }
        fn record(&mut self, effect: DeletionEffect) -> u8 {
            self.calls.push(effect);
            self.pick()
        }
    }

    impl DeletionIo for Scripted {
        fn scan_devices(&mut self) -> ScanObservation {
            let o = [ScanObservation::Rows, ScanObservation::QueryFailed]
                [(self.record(DeletionEffect::ScanDevices) % 2) as usize];
            self.events.push(DeletionEvent::DevicesScanned(o));
            o
        }
        fn lockout_devices(&mut self) -> LockoutObservation {
            let o = [LockoutObservation::Applied, LockoutObservation::StorageFailed]
                [(self.record(DeletionEffect::LockoutDevices) % 2) as usize];
            self.events.push(DeletionEvent::DeviceLockout(o));
            o
        }
        fn scan_web_sessions(&mut self) -> ScanObservation {
            let o = [ScanObservation::Rows, ScanObservation::QueryFailed]
                [(self.record(DeletionEffect::ScanWebSessions) % 2) as usize];
            self.events.push(DeletionEvent::WebSessionsScanned(o));
            o
        }
        fn lockout_web_sessions(&mut self) -> LockoutObservation {
            let o = [LockoutObservation::Applied, LockoutObservation::StorageFailed]
                [(self.record(DeletionEffect::LockoutWebSessions) % 2) as usize];
            self.events.push(DeletionEvent::WebSessionLockout(o));
            o
        }
        fn begin_transaction(&mut self) -> TransactionObservation {
            let o = [TransactionObservation::Begun, TransactionObservation::Failed]
                [(self.record(DeletionEffect::BeginTransaction) % 2) as usize];
            self.events.push(DeletionEvent::Transaction(o));
            o
        }
        fn delete_table(&mut self, table: DeletionTable) -> TableDeleteObservation {
            let o = [TableDeleteObservation::Deleted, TableDeleteObservation::Failed]
                [(self.record(DeletionEffect::DeleteTable(table)) % 2) as usize];
            self.events.push(DeletionEvent::TableDeleted(o));
            o
        }
        fn delete_users(&mut self) -> UsersDeleteObservation {
            let o = [
                UsersDeleteObservation::Deleted,
                UsersDeleteObservation::Absent,
                UsersDeleteObservation::Failed,
            ][(self.record(DeletionEffect::DeleteUsers) % 3) as usize];
            self.events.push(DeletionEvent::UsersDeleted(o));
            o
        }
        fn commit(&mut self) -> CommitObservation {
            let o = [CommitObservation::Committed, CommitObservation::Failed]
                [(self.record(DeletionEffect::CommitTransaction) % 2) as usize];
            self.events.push(DeletionEvent::Commit(o));
            o
        }
    }

    /// Replays the recorded events through the driver by hand and checks the
    /// interpreter called exactly the emitted effects, in order, and stopped
    /// at the verdict.
    fn check(actor: DeletionActorObservation, script: Vec<u8>) -> DeletionEffect {
        let mut io = Scripted { script, calls: vec![], events: vec![] };
        let result = run_deletion(&mut io, actor);
        let mut t = begin_deletion(actor);
        for (i, event) in io.events.iter().enumerate() {
            assert_eq!(io.calls[i], t.effect, "call {i} was not the emitted effect");
            assert!(!deletion_effect_is_terminal(t.effect));
            t = step(t.driver, *event);
        }
        assert_eq!(t, result, "interpreter result differs from the replayed driver");
        assert!(
            deletion_effect_is_terminal(result.effect),
            "no verdict within {DELETION_MAX_EFFECTS} effects"
        );
        assert!(io.calls.len() <= DELETION_MAX_EFFECTS);
        result.effect
    }

    fn actors() -> Vec<DeletionActorObservation> {
        let mut v = vec![];
        for a in [false, true] {
            for d in [false, true] {
                for s in [false, true] {
                    v.push(DeletionActorObservation {
                        authenticated: a,
                        device_active: d,
                        scoped_to_session_account: s,
                    });
                }
            }
        }
        v
    }

    #[test]
    fn interpreter_performs_exactly_the_driver_effects_for_every_outcome() {
        let ok = DeletionActorObservation {
            authenticated: true,
            device_active: true,
            scoped_to_session_account: true,
        };
        // Success everywhere, then one failure at each position in turn, with
        // each failure kind.
        let mut completes = 0;
        for position in 0..DELETION_MAX_EFFECTS {
            for kind in 1..=2u8 {
                let mut script = vec![0u8; DELETION_MAX_EFFECTS];
                script[position] = kind;
                if check(ok, script) == DeletionEffect::Complete {
                    completes += 1;
                }
            }
        }
        assert_eq!(check(ok, vec![0; DELETION_MAX_EFFECTS]), DeletionEffect::Complete);
        // Only an ignored lockout failure still completes.
        assert!(completes > 0);
        for actor in actors() {
            check(actor, vec![0; DELETION_MAX_EFFECTS]);
        }
    }

    #[test]
    fn a_refused_actor_performs_nothing() {
        for actor in actors() {
            if actor.authenticated && actor.device_active && actor.scoped_to_session_account {
                continue;
            }
            let mut io = Scripted { script: vec![], calls: vec![], events: vec![] };
            let result = run_deletion(&mut io, actor);
            assert!(io.calls.is_empty());
            assert!(matches!(result.effect, DeletionEffect::Fail(_)));
        }
    }
}
