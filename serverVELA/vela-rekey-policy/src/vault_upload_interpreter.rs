//! The two loops that connect the vault chunk handlers to their drivers.
//!
//! Neither handler calls the upload or read driver by hand. Each expands
//! [`upload_interpreter!`](crate::upload_interpreter) or
//! [`read_interpreter!`](crate::read_interpreter), the same macros this module
//! expands into the synchronous [`run_upload`] and [`run_read`]. hax extracts
//! those functions and F* proves, for every executor implementation, that
//!
//! - the executor method for the effect the driver has just emitted is the one
//!   called, with that effect's argument (the write permit), in the order
//!   emitted, and no method is called once the driver reached a verdict;
//! - the observations the executor returned form a list in which each
//!   observation answers the effect it was returned for, and the final driver
//!   is `run_from_request request observations`, so every per-request upload and
//!   read theorem holds for the real handler;
//! - the driver always reaches a verdict within the loop budget (7 upload
//!   effects, 2 read effects);
//! - the loop preserves the driver's own state invariant.
//!
//! The server's expansion differs only by `.await` after each executor call.
//! What stays outside the proof is each executor method: that it runs the I/O
//! its name describes and reports the outcome honestly.
//!
//! Both drivers also have effects whose observation is a *lookup*: the shadow
//! attempt and the served read epoch. Their executor methods return `None` when
//! that lookup failed; the macro feeds the driver's dedicated storage-failure
//! event, so the verdict stays the driver's decision and the handler renders
//! the storage error it recorded.

use crate::vault_upload_driver::{
    ActivityObservation, QuotaObservation, ReadEffect, ReadEpochObservation,
    ReadLookupObservation, ReadRequest, ReadTransition, RecheckObservation, RekeyObservation,
    RereadObservation, UploadEffect, UploadRequest, UploadTransition, UploadWritePermit,
    WriteObservation,
};
use crate::AttemptAuthority;

/// Most effects one upload performs: resolve, shadow authority, quota, the
/// guarded write, the version read-back, the shadow-activity refresh and the
/// publication.
pub const UPLOAD_MAX_EFFECTS: usize = 7;

/// Most effects one read performs: the served epoch and the row lookup.
pub const READ_MAX_EFFECTS: usize = 2;

/// The state invariant the upload loop keeps: the driver's own soundness
/// predicate on the transition's driver. It is a named helper so the extracted
/// loop invariant need not project a record field from a tuple whose type is
/// still being inferred.
pub fn upload_loop_is_sound(transition: UploadTransition) -> bool {
    crate::vault_upload_driver::upload_state_is_sound(transition.driver)
        && crate::vault_upload_driver::upload_effect_is_sound(
            transition.driver,
            transition.effect,
        )
}

/// The state invariant the read loop keeps.
pub fn read_loop_is_sound(transition: ReadTransition) -> bool {
    crate::vault_upload_driver::read_state_is_sound(transition.driver)
        && crate::vault_upload_driver::read_effect_is_sound(transition.driver, transition.effect)
}

/// The driver has decided: nothing more may be performed.
pub fn upload_effect_is_terminal(effect: UploadEffect) -> bool {
    matches!(
        effect,
        UploadEffect::Complete | UploadEffect::Fail(_) | UploadEffect::Idle
    )
}

/// The driver has decided: nothing more may be performed.
pub fn read_effect_is_terminal(effect: ReadEffect) -> bool {
    matches!(
        effect,
        ReadEffect::Serve { .. } | ReadEffect::Fail(_) | ReadEffect::Idle
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
    /// The I/O behind each non-terminal upload effect. Each method returns only
    /// the observation its effect expects; `None` from a lookup method means
    /// that lookup failed and the handler kept its error.
    pub trait UploadIo {
        fn resolve_epoch(&mut self) -> RekeyObservation;
        fn authorize_shadow(&mut self) -> Option<AttemptAuthority>;
        fn enforce_quota(&mut self) -> QuotaObservation;
        fn guarded_write(&mut self, permit: UploadWritePermit) -> WriteObservation;
        fn recheck_state(&mut self) -> RecheckObservation;
        fn reread_version(&mut self) -> RereadObservation;
        fn record_shadow_activity(&mut self) -> ActivityObservation;
        fn publish(&mut self) -> ();
    }
}

executor_trait! {
    /// The I/O behind each non-terminal read effect.
    pub trait ReadIo {
        fn read_epoch(&mut self) -> Option<ReadEpochObservation>;
        fn lookup_chunk(&mut self) -> ReadLookupObservation;
    }
}

/// The upload interpreter body, shared verbatim by [`run_upload`] and the async
/// handler. `$io` names a mutable executor; pass `await` as the last argument
/// to await each executor call.
#[macro_export]
macro_rules! upload_interpreter {
    ($io:ident, $request:expr $(, $aw:ident)?) => {{
        use $crate::vault_upload_driver::{
            begin_upload, upload_step as __step, UploadEffect as __E, UploadEvent as __V,
        };
        let mut transition = begin_upload($request);
        for _ in 0..$crate::vault_upload_interpreter::UPLOAD_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::vault_upload_interpreter::upload_loop_is_sound(transition)
            });
            transition = match transition.effect {
                __E::ResolveEpoch => {
                    __step(transition.driver, __V::Rekey($io.resolve_epoch()$(.$aw)?))
                }
                __E::AuthorizeShadow => match $io.authorize_shadow()$(.$aw)? {
                    Some(authority) => __step(transition.driver, __V::Attempt(authority)),
                    None => __step(transition.driver, __V::AttemptStorage),
                },
                __E::EnforceQuota => {
                    __step(transition.driver, __V::Quota($io.enforce_quota()$(.$aw)?))
                }
                __E::Write(permit) => {
                    __step(transition.driver, __V::Write($io.guarded_write(permit)$(.$aw)?))
                }
                __E::RecheckState => {
                    __step(transition.driver, __V::Recheck($io.recheck_state()$(.$aw)?))
                }
                __E::RereadVersion => {
                    __step(transition.driver, __V::Reread($io.reread_version()$(.$aw)?))
                }
                __E::RecordShadowActivity => __step(
                    transition.driver,
                    __V::Activity($io.record_shadow_activity()$(.$aw)?),
                ),
                __E::Publish => {
                    $io.publish()$(.$aw)?;
                    __step(transition.driver, __V::Published)
                }
                // The driver has decided: perform nothing, keep the verdict.
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The read interpreter body, shared verbatim by [`run_read`] and the async
/// handler.
#[macro_export]
macro_rules! read_interpreter {
    ($io:ident, $request:expr $(, $aw:ident)?) => {{
        use $crate::vault_upload_driver::{
            begin_read, read_step as __step, ReadEffect as __E, ReadEvent as __V,
        };
        let mut transition = begin_read($request);
        for _ in 0..$crate::vault_upload_interpreter::READ_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::vault_upload_interpreter::read_loop_is_sound(transition)
            });
            transition = match transition.effect {
                __E::ReadEpoch => match $io.read_epoch()$(.$aw)? {
                    Some(observation) => __step(transition.driver, __V::Epoch(observation)),
                    None => __step(transition.driver, __V::EpochStorage),
                },
                __E::LookupChunk => {
                    __step(transition.driver, __V::Lookup($io.lookup_chunk()$(.$aw)?))
                }
                // The driver has decided: perform nothing, keep the verdict.
                __E::Serve { .. } | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`upload_interpreter!`]: the artifact hax
/// extracts and F* checks.
pub fn run_upload<Io: UploadIo>(io: &mut Io, request: UploadRequest) -> UploadTransition {
    crate::upload_interpreter!(io, request)
}

/// The synchronous expansion of [`read_interpreter!`].
pub fn run_read<Io: ReadIo>(io: &mut Io, request: ReadRequest) -> ReadTransition {
    crate::read_interpreter!(io, request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_upload_driver::{
        begin_read, begin_upload, read_step, upload_step, ReadFailure, UploadEvent, UploadFailure,
        UploadStage, UploadWriter, WriteIntent,
    };
    use crate::{AttemptAuthority, Phase};

    // ── Upload ─────────────────────────────────────────────────────────────

    /// Plays a fixed script of outcomes and records every call. The value at
    /// index `n` selects the outcome returned by the `n`-th call.
    struct ScriptedUpload {
        script: Vec<u8>,
        calls: Vec<UploadEffect>,
        events: Vec<UploadEvent>,
    }

    impl ScriptedUpload {
        fn new(script: Vec<u8>) -> Self {
            ScriptedUpload { script, calls: vec![], events: vec![] }
        }
        fn pick(&mut self) -> u8 {
            let n = self.calls.len() - 1;
            self.script.get(n).copied().unwrap_or(0)
        }
        fn record(&mut self, effect: UploadEffect) -> u8 {
            self.calls.push(effect);
            self.pick()
        }
    }

    impl UploadIo for ScriptedUpload {
        /// 0 = active epoch one, 1 = freezing epoch one, 2 = rejected.
        fn resolve_epoch(&mut self) -> RekeyObservation {
            let n = self.record(UploadEffect::ResolveEpoch);
            let observation = match n % 3 {
                0 => RekeyObservation::State { epoch: 1, phase: Phase::Active },
                1 => RekeyObservation::State { epoch: 1, phase: Phase::Freezing },
                _ => RekeyObservation::Rejected,
            };
            self.events.push(crate::vault_upload_driver::UploadEvent::Rekey(observation));
            observation
        }
        /// 0 = the starting device, 1 = wrong starter, 2 = no rotation id,
        /// 3 = the lookup failed.
        fn authorize_shadow(&mut self) -> Option<AttemptAuthority> {
            let n = self.record(UploadEffect::AuthorizeShadow);
            if n % 4 == 3 {
                self.events
                    .push(crate::vault_upload_driver::UploadEvent::AttemptStorage);
                return None;
            }
            let all = AttemptAuthority {
                device_scope: true,
                starter_matches: true,
                rotation_id_present: true,
                rotation_id_matches: true,
            };
            let authority = match n % 4 {
                0 => all,
                1 => AttemptAuthority { starter_matches: false, ..all },
                _ => AttemptAuthority { rotation_id_present: false, ..all },
            };
            self.events
                .push(crate::vault_upload_driver::UploadEvent::Attempt(authority));
            Some(authority)
        }
        fn enforce_quota(&mut self) -> QuotaObservation {
            let n = self.record(UploadEffect::EnforceQuota);
            let observation = [
                QuotaObservation::Allowed,
                QuotaObservation::Exceeded,
                QuotaObservation::StorageFailed,
            ][(n % 3) as usize];
            self.events
                .push(crate::vault_upload_driver::UploadEvent::Quota(observation));
            observation
        }
        fn guarded_write(&mut self, permit: UploadWritePermit) -> WriteObservation {
            let n = self.record(UploadEffect::Write(permit));
            let observation = [
                WriteObservation::Inserted,
                WriteObservation::Updated,
                WriteObservation::Existing,
                WriteObservation::Skipped,
                WriteObservation::Duplicate,
                WriteObservation::Failed,
            ][(n % 6) as usize];
            self.events
                .push(crate::vault_upload_driver::UploadEvent::Write(observation));
            observation
        }
        fn recheck_state(&mut self) -> RecheckObservation {
            let n = self.record(UploadEffect::RecheckState);
            let observation = [
                RecheckObservation::Unchanged,
                RecheckObservation::Changed,
                RecheckObservation::Failed,
            ][(n % 3) as usize];
            self.events
                .push(crate::vault_upload_driver::UploadEvent::Recheck(observation));
            observation
        }
        /// 0 = a version row, 1 = missing, 2 = the read failed.
        fn reread_version(&mut self) -> RereadObservation {
            let n = self.record(UploadEffect::RereadVersion);
            let observation = match n % 3 {
                0 => RereadObservation::Read { version: 4 },
                1 => RereadObservation::Missing,
                _ => RereadObservation::Failed,
            };
            self.events
                .push(crate::vault_upload_driver::UploadEvent::Reread(observation));
            observation
        }
        fn record_shadow_activity(&mut self) -> ActivityObservation {
            let n = self.record(UploadEffect::RecordShadowActivity);
            let observation = [
                ActivityObservation::Refreshed,
                ActivityObservation::Ended,
                ActivityObservation::Failed,
            ][(n % 3) as usize];
            self.events
                .push(crate::vault_upload_driver::UploadEvent::Activity(observation));
            observation
        }
        fn publish(&mut self) {
            self.calls.push(UploadEffect::Publish);
            self.events.push(crate::vault_upload_driver::UploadEvent::Published);
        }
    }

    fn device_request(intent: WriteIntent, declared: Option<i64>) -> UploadRequest {
        UploadRequest {
            writer: UploadWriter { authenticated: true, web: false, web_epoch: None },
            intent,
            declared_epoch: declared,
        }
    }

    fn web_request(epoch: i64, declared: Option<i64>) -> UploadRequest {
        UploadRequest {
            writer: UploadWriter { authenticated: true, web: true, web_epoch: Some(epoch) },
            intent: WriteIntent::Create,
            declared_epoch: declared,
        }
    }

    /// Replays the recorded events through the driver by hand and checks the
    /// interpreter called exactly the emitted effects, in order, and stopped at
    /// the verdict.
    fn check_upload(request: UploadRequest, script: Vec<u8>) -> UploadEffect {
        let mut io = ScriptedUpload::new(script);
        let result = run_upload(&mut io, request);
        let mut t = begin_upload(request);
        for (i, event) in io.events.iter().enumerate() {
            assert_eq!(io.calls[i], t.effect, "call {i} was not the emitted effect");
            assert!(
                !upload_effect_is_terminal(t.effect),
                "call {i} was made after the verdict"
            );
            t = upload_step(t.driver, *event);
        }
        assert_eq!(t, result, "interpreter result differs from the replayed driver");
        assert!(
            upload_effect_is_terminal(result.effect),
            "no verdict within {UPLOAD_MAX_EFFECTS} effects"
        );
        assert_eq!(io.calls.len(), io.events.len());
        assert!(io.calls.len() <= UPLOAD_MAX_EFFECTS);
        result.effect
    }

    #[test]
    fn upload_performs_exactly_the_driver_effects_for_every_outcome_kind() {
        // Every observation kind of every effect, at every position it can
        // occupy: success everywhere, then each alternative in turn.
        let requests = [
            device_request(WriteIntent::Create, Some(1)),
            device_request(WriteIntent::Replace { version: 3 }, Some(1)),
            device_request(WriteIntent::Create, Some(2)),
            web_request(1, Some(1)),
            web_request(1, Some(2)),
        ];
        for request in requests {
            for position in 0..UPLOAD_MAX_EFFECTS {
                for kind in 0..6u8 {
                    let mut script = vec![0u8; UPLOAD_MAX_EFFECTS];
                    script[position] = kind;
                    check_upload(request, script);
                }
            }
        }
        // All-default success: an active create and an active replace complete.
        for request in [
            device_request(WriteIntent::Create, Some(1)),
            device_request(WriteIntent::Replace { version: 3 }, Some(1)),
        ] {
            assert_eq!(
                check_upload(request, vec![0; UPLOAD_MAX_EFFECTS]),
                UploadEffect::Complete
            );
        }
        // A shadow create resolves the freezing route first (kind 1 at the
        // resolve position) and then completes without publishing.
        assert_eq!(
            check_upload(
                device_request(WriteIntent::Create, Some(2)),
                vec![1, 0, 0, 0, 0, 0, 0],
            ),
            UploadEffect::Complete
        );
    }

    #[test]
    fn the_longest_upload_path_uses_the_whole_budget_and_only_one_write() {
        // Freezing resolve (kind 1), authorised attempt, allowed quota, one
        // inserted row, a read-back, a refreshed activity, then publication.
        let mut io = ScriptedUpload::new(vec![1, 0, 0, 0, 0, 0, 0]);
        let result = run_upload(&mut io, device_request(WriteIntent::Create, Some(2)));
        assert_eq!(result.effect, UploadEffect::Complete);
        assert_eq!(io.calls.len(), UPLOAD_MAX_EFFECTS);
        assert_eq!(
            io.calls
                .iter()
                .filter(|effect| matches!(effect, UploadEffect::Write(_)))
                .count(),
            1
        );
        assert!(result.driver.shadow);
        assert!(result.driver.activity_done);
        assert!(!result.driver.published);
    }

    #[test]
    fn an_unauthenticated_upload_performs_nothing() {
        for request in [
            UploadRequest {
                writer: UploadWriter { authenticated: false, web: false, web_epoch: None },
                intent: WriteIntent::Create,
                declared_epoch: Some(1),
            },
            UploadRequest {
                writer: UploadWriter { authenticated: false, web: true, web_epoch: Some(1) },
                intent: WriteIntent::Create,
                declared_epoch: Some(1),
            },
        ] {
            let mut io = ScriptedUpload::new(vec![]);
            let result = run_upload(&mut io, request);
            assert!(io.calls.is_empty());
            assert_eq!(
                result.effect,
                UploadEffect::Fail(UploadFailure::Unauthenticated)
            );
        }
    }

    #[test]
    fn a_scripted_activity_failure_stops_at_the_verdict() {
        let mut io = ScriptedUpload::new(vec![1, 0, 0, 0, 0, 2, 0]);
        let result = run_upload(&mut io, device_request(WriteIntent::Create, Some(2)));
        assert_eq!(
            result.effect,
            UploadEffect::Fail(UploadFailure::ActivityStorage)
        );
        assert_eq!(result.driver.stage, UploadStage::Done);
        assert!(io.calls.len() <= UPLOAD_MAX_EFFECTS);
        assert!(!io.calls.contains(&UploadEffect::Publish));
    }

    // ── Read ───────────────────────────────────────────────────────────────

    struct ScriptedRead {
        /// `None` is the failed epoch lookup.
        epoch: Option<i64>,
        lookup: u8,
        calls: Vec<ReadEffect>,
        events: Vec<crate::vault_upload_driver::ReadEvent>,
    }

    impl ReadIo for ScriptedRead {
        fn read_epoch(&mut self) -> Option<ReadEpochObservation> {
            self.calls.push(ReadEffect::ReadEpoch);
            match self.epoch {
                Some(epoch) => {
                    let observation = ReadEpochObservation { epoch };
                    self.events
                        .push(crate::vault_upload_driver::ReadEvent::Epoch(observation));
                    Some(observation)
                }
                None => {
                    self.events
                        .push(crate::vault_upload_driver::ReadEvent::EpochStorage);
                    None
                }
            }
        }
        fn lookup_chunk(&mut self) -> ReadLookupObservation {
            self.calls.push(ReadEffect::LookupChunk);
            let observation = [
                ReadLookupObservation::Found {
                    account_matches: true,
                    epoch_matches: true,
                    version: 2,
                    lamport_clock: 7,
                },
                ReadLookupObservation::Found {
                    account_matches: false,
                    epoch_matches: true,
                    version: 2,
                    lamport_clock: 7,
                },
                ReadLookupObservation::Found {
                    account_matches: true,
                    epoch_matches: false,
                    version: 2,
                    lamport_clock: 7,
                },
                ReadLookupObservation::Missing,
                ReadLookupObservation::QueryFailed,
                ReadLookupObservation::Malformed,
            ][(self.lookup % 6) as usize];
            self.events
                .push(crate::vault_upload_driver::ReadEvent::Lookup(observation));
            observation
        }
    }

    fn check_read(epoch: Option<i64>, lookup: u8) -> ReadEffect {
        let mut io = ScriptedRead { epoch, lookup, calls: vec![], events: vec![] };
        let request = ReadRequest { authenticated: true };
        let result = run_read(&mut io, request);
        let mut t = begin_read(request);
        for (i, event) in io.events.iter().enumerate() {
            assert_eq!(io.calls[i], t.effect, "call {i} was not the emitted effect");
            assert!(!read_effect_is_terminal(t.effect));
            t = read_step(t.driver, *event);
        }
        assert_eq!(t, result);
        assert!(read_effect_is_terminal(result.effect));
        assert!(io.calls.len() <= READ_MAX_EFFECTS);
        result.effect
    }

    #[test]
    fn read_performs_exactly_the_driver_effects_for_every_lookup_outcome() {
        let mut serves = 0;
        let mut failures = 0;
        for epoch in [None, Some(0), Some(1), Some(4)] {
            for lookup in 0..6u8 {
                match check_read(epoch, lookup) {
                    ReadEffect::Serve { version, lamport_clock } => {
                        assert!(epoch.unwrap_or(0) >= 1);
                        assert_eq!(lookup, 0);
                        assert_eq!((version, lamport_clock), (2, 7));
                        serves += 1;
                    }
                    ReadEffect::Fail(_) => failures += 1,
                    other => panic!("non-terminal read verdict {other:?}"),
                }
            }
        }
        assert_eq!(serves, 2);
        assert_eq!(failures, 22);
    }

    #[test]
    fn an_unauthenticated_read_performs_nothing() {
        let mut io = ScriptedRead { epoch: Some(1), lookup: 0, calls: vec![], events: vec![] };
        let result = run_read(&mut io, ReadRequest { authenticated: false });
        assert!(io.calls.is_empty());
        assert_eq!(result.effect, ReadEffect::Fail(ReadFailure::Unauthenticated));
    }
}
