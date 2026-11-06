//! The one loop that connects the one-off share-link handlers to their driver.
//!
//! The handlers do not call the send driver by hand. Each expands
//! [`send_interpreter!`](crate::send_interpreter), the same macro this module
//! expands into the synchronous [`run_send`]. hax extracts `run_send` and F*
//! proves, for every [`SendIo`] implementation, that
//!
//! - an executor method is called only for the effect the driver has just
//!   emitted, in the order emitted, and each method returns the observation
//!   kind that effect expects (the types allow nothing else);
//! - the loop stops at the first terminal effect and performs nothing after it;
//! - the final driver is `run_from_*` for the observations the executor
//!   actually returned, so every per-request send theorem holds for the real
//!   handler.
//!
//! The server's expansions differ only by `.await` after each executor call.
//! What stays outside the proof is each executor method: that it runs the I/O
//! its name describes and reports the outcome honestly.

use crate::send_driver::{
    ConsumeObservation, CreateObservation, CreatePermit, DeletePermit, ReadObservation,
    RemoveObservation, RowsObservation, SendEffect, SendTransition,
};

/// Most effects one fetch performs: consume, read, cleanup. Create and delete
/// perform one effect each.
pub const SEND_MAX_EFFECTS: usize = 3;

/// The driver has decided: nothing more may be performed.
pub fn send_effect_is_terminal(effect: SendEffect) -> bool {
    matches!(
        effect,
        SendEffect::CompleteCreate
            | SendEffect::CompleteFetch
            | SendEffect::CompleteDelete { .. }
            | SendEffect::Fail(_)
            | SendEffect::Idle
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
    /// observation its effect expects; the handler keeps the original error in
    /// its own slot.
    pub trait SendIo {
        fn insert_send(&mut self, permit: CreatePermit) -> RowsObservation;
        fn consume_view(&mut self) -> ConsumeObservation;
        fn read_send(&mut self) -> ReadObservation;
        fn remove_fetched(&mut self) -> RemoveObservation;
        fn delete_link(&mut self, permit: DeletePermit) -> RowsObservation;
    }
}

/// The interpreter body, shared verbatim by [`run_send`] and the async
/// handlers. `$io` names a mutable executor; pass `await` as the last argument
/// to await each executor call. `$start` is the request's begin transition.
#[macro_export]
macro_rules! send_interpreter {
    ($io:ident, $start:expr $(, $aw:ident)?) => {{
        use $crate::send_driver::{step as __step, SendEffect as __E, SendEvent as __V};
        let mut transition = $start;
        for _ in 0..$crate::send_interpreter::SEND_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::send_driver::send_state_is_sound(transition.driver)
            });
            transition = match transition.effect {
                __E::InsertSend(permit) => __step(
                    transition.driver,
                    __V::SendInserted($io.insert_send(permit)$(.$aw)?),
                ),
                __E::ConsumeView => {
                    __step(transition.driver, __V::ViewConsumed($io.consume_view()$(.$aw)?))
                }
                __E::ReadSend => {
                    __step(transition.driver, __V::SendRead($io.read_send()$(.$aw)?))
                }
                __E::RemoveFetched => {
                    __step(transition.driver, __V::SendRemoved($io.remove_fetched()$(.$aw)?))
                }
                __E::DeleteLink(permit) => __step(
                    transition.driver,
                    __V::SendDeleted($io.delete_link(permit)$(.$aw)?),
                ),
                // The driver has decided: perform nothing, keep the verdict.
                __E::CompleteCreate
                | __E::CompleteFetch
                | __E::CompleteDelete { .. }
                | __E::Fail(_)
                | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`send_interpreter!`]: the artifact hax
/// extracts and F* checks.
#[cfg_attr(hax, hax_lib::requires(crate::send_driver::send_state_is_sound(start.driver)))]
pub fn run_send<Io: SendIo>(io: &mut Io, start: SendTransition) -> SendTransition {
    crate::send_interpreter!(io, start)
}

// ── Request entry points ────────────────────────────────────────────────────
//
// Handlers call these instead of the driver's `begin_*` functions, so the only
// driver transition a handler can reach is the proved loop.

pub fn start_create(observation: CreateObservation) -> SendTransition {
    crate::send_driver::begin_create(observation)
}

pub fn start_fetch() -> SendTransition {
    crate::send_driver::begin_fetch()
}

pub fn start_delete(owner_present: bool) -> SendTransition {
    crate::send_driver::begin_delete(owner_present)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::send_driver::{begin_create, begin_delete, begin_fetch, step, SendEvent, SendFailure};

    fn kind(effect: SendEffect) -> u8 {
        match effect {
            SendEffect::InsertSend(_) => 0,
            SendEffect::ConsumeView => 1,
            SendEffect::ReadSend => 2,
            SendEffect::RemoveFetched => 3,
            SendEffect::DeleteLink(_) => 4,
            _ => 5,
        }
    }

    /// Plays a fixed script of outcomes and records every call.
    struct Scripted {
        script: Vec<u8>,
        calls: Vec<u8>,
        events: Vec<SendEvent>,
    }

    impl Scripted {
        fn pick(&mut self) -> u8 {
            let n = self.calls.len() - 1;
            self.script.get(n).copied().unwrap_or(0)
        }
        fn record(&mut self, effect: u8) -> u8 {
            self.calls.push(effect);
            self.pick()
        }
    }

    fn rows(pick: u8) -> RowsObservation {
        match pick % 3 {
            0 => RowsObservation {
                rows: 1,
                failed: false,
            },
            1 => RowsObservation {
                rows: 0,
                failed: false,
            },
            _ => RowsObservation {
                rows: 0,
                failed: true,
            },
        }
    }

    impl SendIo for Scripted {
        fn insert_send(&mut self, _permit: CreatePermit) -> RowsObservation {
            let o = rows(self.record(0));
            self.events.push(SendEvent::SendInserted(o));
            o
        }
        fn consume_view(&mut self) -> ConsumeObservation {
            let o = [
                ConsumeObservation::Consumed,
                ConsumeObservation::Unavailable,
                ConsumeObservation::Error,
            ][(self.record(1) % 3) as usize];
            self.events.push(SendEvent::ViewConsumed(o));
            o
        }
        fn read_send(&mut self) -> ReadObservation {
            let o = [
                ReadObservation::Payload { view_once: true },
                ReadObservation::Payload { view_once: false },
                ReadObservation::Missing,
                ReadObservation::Unreadable,
            ][(self.record(2) % 4) as usize];
            self.events.push(SendEvent::SendRead(o));
            o
        }
        fn remove_fetched(&mut self) -> RemoveObservation {
            let o = [true, false][(self.record(3) % 2) as usize];
            let o = RemoveObservation {
                removed: o,
                failed: !o,
            };
            self.events.push(SendEvent::SendRemoved(o));
            o
        }
        fn delete_link(&mut self, _permit: DeletePermit) -> RowsObservation {
            let o = rows(self.record(4));
            self.events.push(SendEvent::SendDeleted(o));
            o
        }
    }

    fn check(start: SendTransition, script: Vec<u8>) -> SendEffect {
        let mut io = Scripted {
            script,
            calls: vec![],
            events: vec![],
        };
        let result = run_send(&mut io, start);
        let mut t = start;
        for (i, event) in io.events.iter().enumerate() {
            assert_eq!(io.calls[i], kind(t.effect), "call {i} was not the emitted effect");
            assert!(!send_effect_is_terminal(t.effect));
            t = step(t.driver, *event);
            assert!(crate::send_driver::send_state_is_sound(t.driver));
        }
        assert_eq!(t, result, "interpreter result differs from the replayed driver");
        assert!(
            send_effect_is_terminal(result.effect),
            "no verdict within {SEND_MAX_EFFECTS} effects"
        );
        assert!(io.calls.len() <= SEND_MAX_EFFECTS);
        result.effect
    }

    fn create_obs() -> CreateObservation {
        CreateObservation {
            owner_present: true,
            ciphertext_decode_failed: false,
            ciphertext_len: 10,
            has_passphrase: false,
            kdf_salt_present: false,
            kdf_salt_decode_failed: false,
            kdf_salt_len: 0,
            has_ttl: false,
            ttl_secs: 0,
            has_max_views: false,
            max_views: 0,
            view_once: false,
        }
    }

    #[test]
    fn interpreter_performs_exactly_the_driver_effects_for_every_outcome() {
        let starts = [
            begin_create(create_obs()),
            begin_fetch(),
            begin_delete(true),
        ];
        for start in starts {
            for position in 0..SEND_MAX_EFFECTS {
                for kind in 0..=8u8 {
                    let mut script = vec![0u8; SEND_MAX_EFFECTS];
                    script[position] = kind;
                    check(start, script);
                }
            }
        }
    }

    #[test]
    fn a_rejected_create_performs_nothing() {
        let mut io = Scripted {
            script: vec![],
            calls: vec![],
            events: vec![],
        };
        let start = crate::send_interpreter::start_create(CreateObservation {
            owner_present: false,
            ..create_obs()
        });
        let result = run_send(&mut io, start);
        assert!(io.calls.is_empty());
        assert_eq!(result.effect, SendEffect::Fail(SendFailure::Unauthenticated));
    }

    #[test]
    fn a_view_once_fetch_calls_consume_read_and_remove_in_order() {
        let mut io = Scripted {
            script: vec![0, 0, 0],
            calls: vec![],
            events: vec![],
        };
        let result = run_send(&mut io, begin_fetch());
        assert_eq!(io.calls.len(), 3);
        assert_eq!(result.effect, SendEffect::CompleteFetch);
        assert!(result.driver.removed);
    }
}
