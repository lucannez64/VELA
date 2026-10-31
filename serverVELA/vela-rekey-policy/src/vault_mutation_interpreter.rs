//! The five loops that connect the remaining vault/device mutations to their
//! drivers.
//!
//! Each handler expands one of the macros below; this module expands the same
//! macro text into a synchronous `run_*` that hax extracts. F* proves, for
//! every executor implementation, that the loop calls exactly the executor
//! method for the effect the driver emitted, stops at the verdict, reaches it
//! within the budget and ends in the state the per-request driver theorems
//! cover.

use crate::vault_mutation_driver::{
    AckObservation, AttestObservation, BucketObservation, BucketRecheckObservation,
    CapsuleAckEffect, CapsuleAckRequest, CapsuleAckTransition, ChunkDeleteEffect,
    ChunkDeleteRequest, ChunkDeleteTransition, DeleteObservation, OramEffect, OramRequest,
    OramTransition, PendingObservation, QuotaObservation, RekeyCapableEffect,
    RekeyCapableRequest, RekeyCapableTransition, RouteObservation, SchemaEffect,
    SchemaObservation, SchemaRequest, SchemaTransition, SchemaWriteObservation,
    VersionObservation,
};

/// Most effects a chunk delete performs: schema, route, version, delete and
/// publication.
pub const CHUNK_DELETE_MAX_EFFECTS: usize = 5;

/// Most effects an ORAM path write performs: route, quota, one write and at
/// most one recheck per bucket (33 buckets), and the publication.
pub const ORAM_MAX_EFFECTS: usize = 69;

/// Most effects the schema activation performs.
pub const SCHEMA_MAX_EFFECTS: usize = 1;

/// Most effects a capsule acknowledgement performs: the clear and the pending
/// inspection.
pub const CAPSULE_ACK_MAX_EFFECTS: usize = 2;

/// Most effects a capability attestation performs.
pub const REKEY_CAPABLE_MAX_EFFECTS: usize = 1;

pub fn chunk_delete_loop_is_sound(transition: ChunkDeleteTransition) -> bool {
    crate::vault_mutation_driver::chunk_delete_state_is_sound(transition.driver)
        && crate::vault_mutation_driver::chunk_delete_effect_is_sound(
            transition.driver,
            transition.effect,
        )
}

pub fn oram_loop_is_sound(transition: OramTransition) -> bool {
    crate::vault_mutation_driver::oram_state_is_sound(transition.driver)
        && crate::vault_mutation_driver::oram_effect_is_sound(transition.driver, transition.effect)
}

pub fn schema_loop_is_sound(transition: SchemaTransition) -> bool {
    crate::vault_mutation_driver::schema_state_is_sound(transition.driver)
        && crate::vault_mutation_driver::schema_effect_is_sound(transition.driver, transition.effect)
}

pub fn capsule_ack_loop_is_sound(transition: CapsuleAckTransition) -> bool {
    crate::vault_mutation_driver::capsule_ack_state_is_sound(transition.driver)
        && crate::vault_mutation_driver::capsule_ack_effect_is_sound(
            transition.driver,
            transition.effect,
        )
}

pub fn rekey_capable_loop_is_sound(transition: RekeyCapableTransition) -> bool {
    crate::vault_mutation_driver::rekey_capable_state_is_sound(transition.driver)
        && crate::vault_mutation_driver::rekey_capable_effect_is_sound(
            transition.driver,
            transition.effect,
        )
}

pub fn chunk_delete_effect_is_terminal(effect: ChunkDeleteEffect) -> bool {
    matches!(
        effect,
        ChunkDeleteEffect::Complete | ChunkDeleteEffect::Fail(_) | ChunkDeleteEffect::Idle
    )
}

pub fn oram_effect_is_terminal(effect: OramEffect) -> bool {
    matches!(
        effect,
        OramEffect::Complete | OramEffect::Fail(_) | OramEffect::Idle
    )
}

pub fn schema_effect_is_terminal(effect: SchemaEffect) -> bool {
    matches!(
        effect,
        SchemaEffect::Complete | SchemaEffect::Fail(_) | SchemaEffect::Idle
    )
}

pub fn capsule_ack_effect_is_terminal(effect: CapsuleAckEffect) -> bool {
    matches!(
        effect,
        CapsuleAckEffect::Complete | CapsuleAckEffect::Fail(_) | CapsuleAckEffect::Idle
    )
}

pub fn rekey_capable_effect_is_terminal(effect: RekeyCapableEffect) -> bool {
    matches!(
        effect,
        RekeyCapableEffect::Complete | RekeyCapableEffect::Fail(_) | RekeyCapableEffect::Idle
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
    pub trait ChunkDeleteIo {
        fn check_schema(&mut self) -> SchemaObservation;
        fn resolve_epoch(&mut self) -> RouteObservation;
        fn read_version(&mut self) -> VersionObservation;
        fn delete_row(&mut self) -> DeleteObservation;
        fn publish(&mut self) -> ();
    }
}

executor_trait! {
    pub trait OramIo {
        fn resolve_path_epoch(&mut self) -> RouteObservation;
        fn enforce_quota(&mut self) -> QuotaObservation;
        fn write_bucket(&mut self, index: i64) -> BucketObservation;
        fn recheck_bucket(&mut self, index: i64) -> BucketRecheckObservation;
        fn publish_path(&mut self) -> ();
    }
}

executor_trait! {
    pub trait SchemaIo {
        fn write_floor(&mut self) -> SchemaWriteObservation;
    }
}

executor_trait! {
    pub trait CapsuleAckIo {
        fn acknowledge(&mut self) -> AckObservation;
        fn inspect_pending(&mut self) -> PendingObservation;
    }
}

executor_trait! {
    pub trait RekeyCapableIo {
        fn attest(&mut self) -> AttestObservation;
    }
}

#[macro_export]
macro_rules! chunk_delete_interpreter {
    ($io:ident, $request:expr $(, $aw:ident)?) => {{
        use $crate::vault_mutation_driver::{
            begin_chunk_delete as __begin, chunk_delete_step as __step,
            ChunkDeleteEffect as __E, ChunkDeleteEvent as __V,
        };
        let mut transition = __begin($request);
        for _ in 0..$crate::vault_mutation_interpreter::CHUNK_DELETE_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::vault_mutation_interpreter::chunk_delete_loop_is_sound(transition)
            });
            transition = match transition.effect {
                __E::CheckSchema => {
                    __step(transition.driver, __V::Schema($io.check_schema()$(.$aw)?))
                }
                __E::ResolveEpoch => {
                    __step(transition.driver, __V::Route($io.resolve_epoch()$(.$aw)?))
                }
                __E::ReadVersion => {
                    __step(transition.driver, __V::Version($io.read_version()$(.$aw)?))
                }
                __E::DeleteRow => {
                    __step(transition.driver, __V::Delete($io.delete_row()$(.$aw)?))
                }
                __E::Publish => {
                    $io.publish()$(.$aw)?;
                    __step(transition.driver, __V::Published)
                }
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

#[macro_export]
macro_rules! oram_interpreter {
    ($io:ident, $request:expr $(, $aw:ident)?) => {{
        use $crate::vault_mutation_driver::{
            begin_oram as __begin, oram_step as __step, OramEffect as __E, OramEvent as __V,
        };
        let mut transition = __begin($request);
        for _ in 0..$crate::vault_mutation_interpreter::ORAM_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::vault_mutation_interpreter::oram_loop_is_sound(transition)
            });
            transition = match transition.effect {
                __E::ResolveEpoch => {
                    __step(transition.driver, __V::Route($io.resolve_path_epoch()$(.$aw)?))
                }
                __E::EnforceQuota => {
                    __step(transition.driver, __V::Quota($io.enforce_quota()$(.$aw)?))
                }
                __E::WriteBucket { index } => __step(
                    transition.driver,
                    __V::Bucket($io.write_bucket(index)$(.$aw)?),
                ),
                __E::RecheckBucket { index } => __step(
                    transition.driver,
                    __V::Recheck($io.recheck_bucket(index)$(.$aw)?),
                ),
                __E::Publish => {
                    $io.publish_path()$(.$aw)?;
                    __step(transition.driver, __V::Published)
                }
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

#[macro_export]
macro_rules! schema_interpreter {
    ($io:ident, $request:expr $(, $aw:ident)?) => {{
        use $crate::vault_mutation_driver::{
            begin_schema as __begin, schema_step as __step, SchemaEffect as __E, SchemaEvent as __V,
        };
        let mut transition = __begin($request);
        for _ in 0..$crate::vault_mutation_interpreter::SCHEMA_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::vault_mutation_interpreter::schema_loop_is_sound(transition)
            });
            transition = match transition.effect {
                __E::WriteFloor => {
                    __step(transition.driver, __V::Write($io.write_floor()$(.$aw)?))
                }
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

#[macro_export]
macro_rules! capsule_ack_interpreter {
    ($io:ident, $request:expr $(, $aw:ident)?) => {{
        use $crate::vault_mutation_driver::{
            begin_capsule_ack as __begin, capsule_ack_step as __step, CapsuleAckEffect as __E,
            CapsuleAckEvent as __V,
        };
        let mut transition = __begin($request);
        for _ in 0..$crate::vault_mutation_interpreter::CAPSULE_ACK_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::vault_mutation_interpreter::capsule_ack_loop_is_sound(transition)
            });
            transition = match transition.effect {
                __E::Acknowledge => {
                    __step(transition.driver, __V::Ack($io.acknowledge()$(.$aw)?))
                }
                __E::InspectPending => {
                    __step(transition.driver, __V::Pending($io.inspect_pending()$(.$aw)?))
                }
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

#[macro_export]
macro_rules! rekey_capable_interpreter {
    ($io:ident, $request:expr $(, $aw:ident)?) => {{
        use $crate::vault_mutation_driver::{
            begin_rekey_capable as __begin, rekey_capable_step as __step,
            RekeyCapableEffect as __E, RekeyCapableEvent as __V,
        };
        let mut transition = __begin($request);
        for _ in 0..$crate::vault_mutation_interpreter::REKEY_CAPABLE_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::vault_mutation_interpreter::rekey_capable_loop_is_sound(transition)
            });
            transition = match transition.effect {
                __E::Attest => {
                    __step(transition.driver, __V::Attest($io.attest()$(.$aw)?))
                }
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

pub fn run_chunk_delete<Io: ChunkDeleteIo>(
    io: &mut Io,
    request: ChunkDeleteRequest,
) -> ChunkDeleteTransition {
    crate::chunk_delete_interpreter!(io, request)
}

pub fn run_oram<Io: OramIo>(io: &mut Io, request: OramRequest) -> OramTransition {
    crate::oram_interpreter!(io, request)
}

pub fn run_schema<Io: SchemaIo>(io: &mut Io, request: SchemaRequest) -> SchemaTransition {
    crate::schema_interpreter!(io, request)
}

pub fn run_capsule_ack<Io: CapsuleAckIo>(
    io: &mut Io,
    request: CapsuleAckRequest,
) -> CapsuleAckTransition {
    crate::capsule_ack_interpreter!(io, request)
}

pub fn run_rekey_capable<Io: RekeyCapableIo>(
    io: &mut Io,
    request: RekeyCapableRequest,
) -> RekeyCapableTransition {
    crate::rekey_capable_interpreter!(io, request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_mutation_driver::{
        begin_capsule_ack, begin_chunk_delete, begin_rekey_capable, begin_schema,
        capsule_ack_step, chunk_delete_step, rekey_capable_step, schema_step,
        CapsuleAckEvent, ChunkDeleteEvent, OramEvent, RekeyCapableEvent, SchemaEvent,
    };

    struct ChunkScript {
        script: Vec<u8>,
        calls: Vec<ChunkDeleteEffect>,
        events: Vec<ChunkDeleteEvent>,
    }

    impl ChunkDeleteIo for ChunkScript {
        fn check_schema(&mut self) -> SchemaObservation {
            let n = self.calls.len();
            self.calls.push(ChunkDeleteEffect::CheckSchema);
            let observation = [
                SchemaObservation::Allowed,
                SchemaObservation::Refused,
                SchemaObservation::Storage,
            ][self.script.get(n).copied().unwrap_or(0) as usize % 3];
            self.events.push(ChunkDeleteEvent::Schema(observation));
            observation
        }
        fn resolve_epoch(&mut self) -> RouteObservation {
            let n = self.calls.len();
            self.calls.push(ChunkDeleteEffect::ResolveEpoch);
            let observation = [
                RouteObservation::Active { epoch: 1 },
                RouteObservation::Freezing,
                RouteObservation::Rejected,
                RouteObservation::Storage,
            ][self.script.get(n).copied().unwrap_or(0) as usize % 4];
            self.events.push(ChunkDeleteEvent::Route(observation));
            observation
        }
        fn read_version(&mut self) -> VersionObservation {
            let n = self.calls.len();
            self.calls.push(ChunkDeleteEffect::ReadVersion);
            let observation = [
                VersionObservation::Found { version: 1 },
                VersionObservation::Missing,
                VersionObservation::Storage,
            ][self.script.get(n).copied().unwrap_or(0) as usize % 3];
            self.events.push(ChunkDeleteEvent::Version(observation));
            observation
        }
        fn delete_row(&mut self) -> DeleteObservation {
            let n = self.calls.len();
            self.calls.push(ChunkDeleteEffect::DeleteRow);
            let observation = [
                DeleteObservation::Deleted,
                DeleteObservation::Skipped,
                DeleteObservation::Storage,
            ][self.script.get(n).copied().unwrap_or(0) as usize % 3];
            self.events.push(ChunkDeleteEvent::Delete(observation));
            observation
        }
        fn publish(&mut self) {
            self.calls.push(ChunkDeleteEffect::Publish);
            self.events.push(ChunkDeleteEvent::Published);
        }
    }

    struct OramScript {
        script: Vec<u8>,
        calls: Vec<OramEffect>,
        events: Vec<OramEvent>,
    }

    impl OramIo for OramScript {
        fn resolve_path_epoch(&mut self) -> RouteObservation {
            let n = self.calls.len();
            self.calls.push(OramEffect::ResolveEpoch);
            let observation = [
                RouteObservation::Active { epoch: 1 },
                RouteObservation::Freezing,
                RouteObservation::Rejected,
                RouteObservation::Storage,
            ][self.script.get(n).copied().unwrap_or(0) as usize % 4];
            self.events.push(OramEvent::Route(observation));
            observation
        }
        fn enforce_quota(&mut self) -> QuotaObservation {
            let n = self.calls.len();
            self.calls.push(OramEffect::EnforceQuota);
            let observation = [
                QuotaObservation::Allowed,
                QuotaObservation::Exceeded,
                QuotaObservation::Storage,
            ][self.script.get(n).copied().unwrap_or(0) as usize % 3];
            self.events.push(OramEvent::Quota(observation));
            observation
        }
        fn write_bucket(&mut self, index: i64) -> BucketObservation {
            let n = self.calls.len();
            self.calls.push(OramEffect::WriteBucket { index });
            let observation = [
                BucketObservation::Written,
                BucketObservation::Invalid,
                BucketObservation::Existing,
                BucketObservation::Skipped,
                BucketObservation::Storage,
            ][self.script.get(n).copied().unwrap_or(0) as usize % 5];
            self.events.push(OramEvent::Bucket(observation));
            observation
        }
        fn recheck_bucket(&mut self, index: i64) -> BucketRecheckObservation {
            let n = self.calls.len();
            self.calls.push(OramEffect::RecheckBucket { index });
            let observation = [
                BucketRecheckObservation::Unchanged,
                BucketRecheckObservation::Changed,
                BucketRecheckObservation::Failed,
            ][self.script.get(n).copied().unwrap_or(0) as usize % 3];
            self.events.push(OramEvent::Recheck(observation));
            observation
        }
        fn publish_path(&mut self) {
            self.calls.push(OramEffect::Publish);
            self.events.push(OramEvent::Published);
        }
    }

    struct SchemaScript {
        script: Vec<u8>,
        calls: Vec<SchemaEffect>,
        events: Vec<SchemaEvent>,
    }

    impl SchemaIo for SchemaScript {
        fn write_floor(&mut self) -> SchemaWriteObservation {
            let n = self.calls.len();
            self.calls.push(SchemaEffect::WriteFloor);
            let observation = [
                SchemaWriteObservation::Written,
                SchemaWriteObservation::Storage,
            ][self.script.get(n).copied().unwrap_or(0) as usize % 2];
            self.events.push(SchemaEvent::Write(observation));
            observation
        }
    }

    struct AckScript {
        script: Vec<u8>,
        calls: Vec<CapsuleAckEffect>,
        events: Vec<CapsuleAckEvent>,
    }

    impl CapsuleAckIo for AckScript {
        fn acknowledge(&mut self) -> AckObservation {
            let n = self.calls.len();
            self.calls.push(CapsuleAckEffect::Acknowledge);
            let observation = [
                AckObservation::Cleared,
                AckObservation::Missed,
                AckObservation::Storage,
            ][self.script.get(n).copied().unwrap_or(0) as usize % 3];
            self.events.push(CapsuleAckEvent::Ack(observation));
            observation
        }
        fn inspect_pending(&mut self) -> PendingObservation {
            let n = self.calls.len();
            self.calls.push(CapsuleAckEffect::InspectPending);
            let observation = [
                PendingObservation::Replay,
                PendingObservation::Pending,
                PendingObservation::Missing,
                PendingObservation::Storage,
            ][self.script.get(n).copied().unwrap_or(0) as usize % 4];
            self.events.push(CapsuleAckEvent::Pending(observation));
            observation
        }
    }

    struct CapableScript {
        script: Vec<u8>,
        calls: Vec<RekeyCapableEffect>,
        events: Vec<RekeyCapableEvent>,
    }

    impl RekeyCapableIo for CapableScript {
        fn attest(&mut self) -> AttestObservation {
            let n = self.calls.len();
            self.calls.push(RekeyCapableEffect::Attest);
            let observation = [
                AttestObservation::Attested,
                AttestObservation::Missing,
                AttestObservation::Storage,
            ][self.script.get(n).copied().unwrap_or(0) as usize % 3];
            self.events.push(RekeyCapableEvent::Attest(observation));
            observation
        }
    }

    fn if_match_request() -> ChunkDeleteRequest {
        ChunkDeleteRequest {
            authenticated: true,
            web: false,
            web_epoch: None,
            if_match: 1,
        }
    }

    #[test]
    fn chunk_delete_interpreter_matches_the_driver_for_every_outcome() {
        for position in 0..CHUNK_DELETE_MAX_EFFECTS {
            for kind in 0..5u8 {
                let mut script = vec![0u8; CHUNK_DELETE_MAX_EFFECTS];
                script[position] = kind;
                let mut io = ChunkScript {
                    script,
                    calls: vec![],
                    events: vec![],
                };
                let result = run_chunk_delete(&mut io, if_match_request());
                let mut t = begin_chunk_delete(if_match_request());
                for (i, event) in io.events.iter().enumerate() {
                    assert_eq!(io.calls[i], t.effect);
                    assert!(!chunk_delete_effect_is_terminal(t.effect));
                    t = chunk_delete_step(t.driver, *event);
                }
                assert_eq!(t, result);
                assert!(chunk_delete_effect_is_terminal(result.effect));
            }
        }
    }

    #[test]
    fn oram_interpreter_writes_and_rechecks_in_order() {
        let mut script = vec![0u8; ORAM_MAX_EFFECTS];
        // Route active, quota allowed, bucket 0 update-miss (kind 3), recheck
        // unchanged (kind 0), bucket 1 written.
        script[2] = 3;
        let mut io = OramScript {
            script,
            calls: vec![],
            events: vec![],
        };
        let request = OramRequest {
            authenticated: true,
            web: false,
            web_epoch: None,
            bucket_count: 2,
            create_mask: 0,
        };
        let result = run_oram(&mut io, request);
        assert_eq!(result.effect, OramEffect::Fail(crate::vault_mutation_driver::OramFailure::VersionMismatch));
        assert_eq!(
            io.calls,
            vec![
                OramEffect::ResolveEpoch,
                OramEffect::EnforceQuota,
                OramEffect::WriteBucket { index: 0 },
                OramEffect::RecheckBucket { index: 0 },
            ]
        );
    }

    #[test]
    fn schema_capsule_and_capability_interpreters_match_their_drivers() {
        for kind in 0..2u8 {
            let mut io = SchemaScript {
                script: vec![kind],
                calls: vec![],
                events: vec![],
            };
            let request = SchemaRequest {
                authenticated: true,
                device_scope: true,
            };
            let result = run_schema(&mut io, request);
            let mut t = begin_schema(request);
            for (i, event) in io.events.iter().enumerate() {
                assert_eq!(io.calls[i], t.effect);
                t = schema_step(t.driver, *event);
            }
            assert_eq!(t, result);
        }
        for kind in 0..4u8 {
            let mut io = AckScript {
                script: vec![kind, kind],
                calls: vec![],
                events: vec![],
            };
            let request = CapsuleAckRequest {
                authenticated: true,
                device_scope: true,
            };
            let result = run_capsule_ack(&mut io, request);
            let mut t = begin_capsule_ack(request);
            for (i, event) in io.events.iter().enumerate() {
                assert_eq!(io.calls[i], t.effect);
                t = capsule_ack_step(t.driver, *event);
            }
            assert_eq!(t, result);
        }
        for kind in 0..3u8 {
            let mut io = CapableScript {
                script: vec![kind],
                calls: vec![],
                events: vec![],
            };
            let request = RekeyCapableRequest {
                authenticated: true,
                device_scope: true,
            };
            let result = run_rekey_capable(&mut io, request);
            let mut t = begin_rekey_capable(request);
            for (i, event) in io.events.iter().enumerate() {
                assert_eq!(io.calls[i], t.effect);
                t = rekey_capable_step(t.driver, *event);
            }
            assert_eq!(t, result);
        }
    }

    #[test]
    fn refused_requests_perform_no_effect() {
        let unauthenticated = ChunkDeleteRequest {
            authenticated: false,
            ..if_match_request()
        };
        let mut io = ChunkScript {
            script: vec![],
            calls: vec![],
            events: vec![],
        };
        assert!(matches!(
            run_chunk_delete(&mut io, unauthenticated).effect,
            ChunkDeleteEffect::Fail(_)
        ));
        assert!(io.calls.is_empty());

        let web = SchemaRequest {
            authenticated: true,
            device_scope: false,
        };
        let mut io = SchemaScript {
            script: vec![],
            calls: vec![],
            events: vec![],
        };
        assert!(matches!(
            run_schema(&mut io, web).effect,
            SchemaEffect::Fail(_)
        ));
        assert!(io.calls.is_empty());
    }
}
