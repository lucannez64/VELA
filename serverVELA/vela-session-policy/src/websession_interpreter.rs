//! The four loops that connect the web-session handlers to their drivers.
//!
//! No web-session handler calls a driver transition by hand. Each expands one
//! macro from this module with `await`; this module expands the same macro text
//! into the synchronous `run_*` function hax extracts. F* proves, for every
//! executor implementation, that
//!
//! - an executor method is called only for the effect the driver has just
//!   emitted, in the order emitted, and each method returns the observation
//!   kind that effect expects (the types allow nothing else);
//! - the loop stops at the first terminal effect and performs nothing after it;
//! - the final driver is the driver's own `*_run` over the observations the
//!   executor actually returned, so every per-request theorem holds for the
//!   real handler.
//!
//! The server's expansions differ only by `.await` after each executor call.
//! What stays outside the proof is each executor method: that it runs the I/O
//! its name describes and reports the outcome honestly.

use crate::websession_driver::{
    DeleteDriver, DeleteEffect, DeleteTransition, GrantDriver, GrantEffect, GrantTransition,
    GrantUpdate, StartDriver, StartEffect, StartTransition, TokenDriver, TokenEffect,
    TokenTransition,
};
use crate::TokenPlan;

// The four transition records share the field names `driver` and `effect`.
// hax keeps the projections, and F* cannot infer a record type from a bare
// `transition.effect` when several records declare that field, so the extracted
// loops reach them through typed accessors. They are pure functions.

pub fn start_driver_of(transition: StartTransition) -> StartDriver {
    transition.driver
}
pub fn start_effect_of(transition: StartTransition) -> StartEffect {
    transition.effect
}
pub fn grant_driver_of(transition: GrantTransition) -> GrantDriver {
    transition.driver
}
pub fn grant_effect_of(transition: GrantTransition) -> GrantEffect {
    transition.effect
}
pub fn token_driver_of(transition: TokenTransition) -> TokenDriver {
    transition.driver
}
pub fn token_effect_of(transition: TokenTransition) -> TokenEffect {
    transition.effect
}
pub fn delete_driver_of(transition: DeleteTransition) -> DeleteDriver {
    transition.driver
}
pub fn delete_effect_of(transition: DeleteTransition) -> DeleteEffect {
    transition.effect
}

// ── POST /web-session/start ────────────────────────────────────────────────

/// The three effects a start can perform before its verdict.
pub const START_MAX_EFFECTS: usize = 3;

pub fn start_effect_is_terminal(effect: StartEffect) -> bool {
    matches!(
        effect,
        StartEffect::Complete | StartEffect::Fail(_) | StartEffect::Idle
    )
}

executor_trait! {
    /// The I/O behind each non-terminal start effect.
    pub trait StartIo {
        fn check_rate_limit(&mut self) -> crate::websession_driver::StartLimitObservation;
        fn validate_start(&mut self) -> crate::websession_driver::StartValidationObservation;
        fn insert_pending(&mut self) -> crate::websession_driver::StartInsertObservation;
    }
}

/// The start interpreter body, shared verbatim by [`run_start`] and
/// `post_start`. `$io` names a mutable executor; pass `await` as the last
/// argument to await each executor call.
#[macro_export]
macro_rules! websession_start_interpreter {
    ($io:ident $(, $aw:ident)?) => {{
        use $crate::websession_driver::{
            start_step as __step, StartEffect as __E, StartEvent as __V,
        };
        use $crate::websession_interpreter::{
            start_driver_of as __driver, start_effect_of as __effect,
        };
        let mut transition = $crate::websession_driver::begin_start();
        for _ in 0..$crate::websession_interpreter::START_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::websession_driver::start_state_is_sound(__driver(transition))
            });
            transition = match __effect(transition) {
                __E::CheckRateLimit => __step(
                    __driver(transition),
                    __V::LimitObserved($io.check_rate_limit()$(.$aw)?),
                ),
                __E::ValidateStart => __step(
                    __driver(transition),
                    __V::Validated($io.validate_start()$(.$aw)?),
                ),
                __E::InsertPending => __step(
                    __driver(transition),
                    __V::Inserted($io.insert_pending()$(.$aw)?),
                ),
                // The driver has decided: perform nothing, keep the verdict.
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`websession_start_interpreter!`].
pub fn run_start<Io: StartIo>(io: &mut Io) -> StartTransition {
    crate::websession_start_interpreter!(io)
}

// ── POST /web-session/:id/grant ────────────────────────────────────────────

/// The three effects a grant can perform before its verdict.
pub const GRANT_MAX_EFFECTS: usize = 3;

pub fn grant_effect_is_terminal(effect: GrantEffect) -> bool {
    matches!(
        effect,
        GrantEffect::Complete | GrantEffect::Fail(_) | GrantEffect::Idle
    )
}

executor_trait! {
    /// The I/O behind each non-terminal grant effect.
    pub trait GrantIo {
        fn validate_grant(&mut self) -> crate::websession_driver::GrantValidationObservation;
        fn grant_load_session(&mut self) -> crate::websession_driver::GrantLookupObservation;
        fn update_grant(&mut self, update: GrantUpdate)
            -> crate::websession_driver::GrantUpdateObservation;
    }
}

/// The grant interpreter body, shared verbatim by [`run_grant`] and
/// `post_grant`.
#[macro_export]
macro_rules! websession_grant_interpreter {
    ($io:ident, $actor:expr, $ttl:expr $(, $aw:ident)?) => {{
        use $crate::websession_driver::{
            grant_step as __step, GrantEffect as __E, GrantEvent as __V,
        };
        use $crate::websession_interpreter::{
            grant_driver_of as __driver, grant_effect_of as __effect,
        };
        let mut transition = $crate::websession_driver::begin_grant($actor, $ttl);
        for _ in 0..$crate::websession_interpreter::GRANT_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::websession_driver::grant_state_is_sound(__driver(transition))
            });
            transition = match __effect(transition) {
                __E::ValidateGrant => __step(
                    __driver(transition),
                    __V::Validated($io.validate_grant()$(.$aw)?),
                ),
                __E::LoadSession => __step(
                    __driver(transition),
                    __V::SessionObserved($io.grant_load_session()$(.$aw)?),
                ),
                __E::UpdateGrant(update) => __step(
                    __driver(transition),
                    __V::UpdateObserved($io.update_grant(update)$(.$aw)?),
                ),
                // The driver has decided: perform nothing, keep the verdict.
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`websession_grant_interpreter!`].
pub fn run_grant<Io: GrantIo>(
    io: &mut Io,
    actor: crate::websession_driver::GrantActorObservation,
    requested_ttl: Option<i64>,
) -> GrantTransition {
    crate::websession_grant_interpreter!(io, actor, requested_ttl)
}

// ── POST /web-session/:id/token ────────────────────────────────────────────

/// The eight effects an exchange can perform before its verdict.
pub const TOKEN_MAX_EFFECTS: usize = 7;

pub fn token_effect_is_terminal(effect: TokenEffect) -> bool {
    matches!(
        effect,
        TokenEffect::Complete | TokenEffect::Fail(_) | TokenEffect::Idle
    )
}

executor_trait! {
    /// The I/O behind each non-terminal token effect.
    pub trait TokenIo {
        fn check_token_limits(&mut self) -> crate::websession_driver::TokenLimitObservation;
        fn token_load_session(&mut self) -> crate::websession_driver::TokenLookupObservation;
        fn consume_web_token_challenge(&mut self)
            -> crate::websession_driver::TokenChallengeObservation;
        fn verify_web_signature(&mut self)
            -> crate::websession_driver::TokenSignatureObservation;
        fn record_token_failure(&mut self)
            -> crate::websession_driver::TokenFailureRecordObservation;
        fn reset_token_backoff(&mut self) -> crate::websession_driver::TokenResetObservation;
        fn claim_token(&mut self) -> crate::websession_driver::TokenClaimObservation;
        fn issue_token(&mut self, plan: TokenPlan)
            -> crate::websession_driver::TokenIssueObservation;
    }
}

/// The token interpreter body, shared verbatim by [`run_token`] and
/// `post_token`.
#[macro_export]
macro_rules! websession_token_interpreter {
    ($io:ident $(, $aw:ident)?) => {{
        use $crate::websession_driver::{
            token_step as __step, TokenEffect as __E, TokenEvent as __V,
        };
        use $crate::websession_interpreter::{
            token_driver_of as __driver, token_effect_of as __effect,
        };
        let mut transition = $crate::websession_driver::begin_token();
        for _ in 0..$crate::websession_interpreter::TOKEN_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::websession_driver::token_state_is_sound(__driver(transition))
            });
            transition = match __effect(transition) {
                __E::CheckTokenLimits => __step(
                    __driver(transition),
                    __V::LimitsObserved($io.check_token_limits()$(.$aw)?),
                ),
                __E::LoadSession => __step(
                    __driver(transition),
                    __V::SessionObserved($io.token_load_session()$(.$aw)?),
                ),
                __E::ConsumeWebTokenChallenge => __step(
                    __driver(transition),
                    __V::ChallengeObserved($io.consume_web_token_challenge()$(.$aw)?),
                ),
                __E::VerifyWebSignature => __step(
                    __driver(transition),
                    __V::SignatureObserved($io.verify_web_signature()$(.$aw)?),
                ),
                __E::RecordTokenFailure => __step(
                    __driver(transition),
                    __V::FailureRecorded($io.record_token_failure()$(.$aw)?),
                ),
                __E::ResetTokenBackoff => __step(
                    __driver(transition),
                    __V::ResetObserved($io.reset_token_backoff()$(.$aw)?),
                ),
                __E::ClaimToken => __step(
                    __driver(transition),
                    __V::ClaimObserved($io.claim_token()$(.$aw)?),
                ),
                __E::IssueToken(plan) => __step(
                    __driver(transition),
                    __V::Issued($io.issue_token(plan)$(.$aw)?),
                ),
                // The driver has decided: perform nothing, keep the verdict.
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`websession_token_interpreter!`].
pub fn run_token<Io: TokenIo>(io: &mut Io) -> TokenTransition {
    crate::websession_token_interpreter!(io)
}

// ── DELETE /web-session/:id ────────────────────────────────────────────────

/// The three effects a delete can perform before its verdict.
pub const DELETE_SESSION_MAX_EFFECTS: usize = 3;

pub fn delete_effect_is_terminal(effect: DeleteEffect) -> bool {
    matches!(
        effect,
        DeleteEffect::Complete | DeleteEffect::Fail(_) | DeleteEffect::Idle
    )
}

executor_trait! {
    /// The I/O behind each non-terminal delete effect.
    pub trait DeleteSessionIo {
        fn delete_load_session(&mut self) -> crate::websession_driver::DeleteLookupObservation;
        fn lockout_session(&mut self) -> crate::websession_driver::DeleteSentinelObservation;
        fn record_revocation(&mut self) -> crate::websession_driver::DeleteRecordObservation;
    }
}

/// The delete interpreter body, shared verbatim by [`run_delete`] and
/// `delete_session`.
#[macro_export]
macro_rules! websession_delete_interpreter {
    ($io:ident, $actor:expr $(, $aw:ident)?) => {{
        use $crate::websession_driver::{
            delete_step as __step, DeleteEffect as __E, DeleteEvent as __V,
        };
        use $crate::websession_interpreter::{
            delete_driver_of as __driver, delete_effect_of as __effect,
        };
        let mut transition = $crate::websession_driver::begin_delete($actor);
        for _ in 0..$crate::websession_interpreter::DELETE_SESSION_MAX_EFFECTS {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|_: usize| {
                $crate::websession_driver::delete_state_is_sound(__driver(transition))
            });
            transition = match __effect(transition) {
                __E::LoadSession => __step(
                    __driver(transition),
                    __V::SessionObserved($io.delete_load_session()$(.$aw)?),
                ),
                __E::LockoutSession => __step(
                    __driver(transition),
                    __V::SentinelWritten($io.lockout_session()$(.$aw)?),
                ),
                __E::RecordRevocation => __step(
                    __driver(transition),
                    __V::RecordObserved($io.record_revocation()$(.$aw)?),
                ),
                // The driver has decided: perform nothing, keep the verdict.
                __E::Complete | __E::Fail(_) | __E::Idle => transition,
            };
        }
        transition
    }};
}

/// The synchronous expansion of [`websession_delete_interpreter!`].
pub fn run_delete<Io: DeleteSessionIo>(
    io: &mut Io,
    actor: crate::websession_driver::DeleteActorObservation,
) -> DeleteTransition {
    crate::websession_delete_interpreter!(io, actor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::ChallengeConsumption;
    use crate::websession_driver::*;
    use crate::{GrantObservation, SessionMode, SessionPhase};

    struct StartScript {
        calls: Vec<StartEffect>,
    }
    impl StartIo for StartScript {
        fn check_rate_limit(&mut self) -> StartLimitObservation {
            self.calls.push(StartEffect::CheckRateLimit);
            StartLimitObservation::Allowed
        }
        fn validate_start(&mut self) -> StartValidationObservation {
            self.calls.push(StartEffect::ValidateStart);
            StartValidationObservation::Valid
        }
        fn insert_pending(&mut self) -> StartInsertObservation {
            self.calls.push(StartEffect::InsertPending);
            StartInsertObservation::Inserted
        }
    }

    #[test]
    fn start_interpreter_performs_only_the_emitted_effects() {
        let mut io = StartScript { calls: vec![] };
        let t = run_start(&mut io);
        assert_eq!(
            io.calls,
            vec![
                StartEffect::CheckRateLimit,
                StartEffect::ValidateStart,
                StartEffect::InsertPending
            ]
        );
        assert_eq!(t.effect, StartEffect::Complete);
    }

    struct GrantScript {
        calls: Vec<GrantEffect>,
    }
    impl GrantIo for GrantScript {
        fn validate_grant(&mut self) -> GrantValidationObservation {
            self.calls.push(GrantEffect::ValidateGrant);
            GrantValidationObservation::Valid
        }
        fn grant_load_session(&mut self) -> GrantLookupObservation {
            self.calls.push(GrantEffect::LoadSession);
            GrantLookupObservation::Present(GrantObservation {
                phase: SessionPhase::Pending,
                mode: SessionMode::ReadWrite,
                approver_user: Some(7),
                authenticated_user: 7,
                nonce_length: 32,
                nonce_equal: true,
                has_web_vk: true,
                declared_epoch: 2,
            })
        }
        fn update_grant(&mut self, update: GrantUpdate) -> GrantUpdateObservation {
            self.calls.push(GrantEffect::UpdateGrant(update));
            GrantUpdateObservation::Updated
        }
    }

    #[test]
    fn grant_interpreter_performs_only_the_emitted_effects() {
        let mut io = GrantScript { calls: vec![] };
        let t = run_grant(
            &mut io,
            GrantActorObservation { authenticated: true, device_active: true },
            Some(60),
        );
        assert_eq!(
            io.calls,
            vec![
                GrantEffect::ValidateGrant,
                GrantEffect::LoadSession,
                GrantEffect::UpdateGrant(GrantUpdate {
                    mode: SessionMode::ReadWrite,
                    epoch: 2,
                    ttl_secs: 60,
                })
            ]
        );
        assert_eq!(t.effect, GrantEffect::Complete);
    }

    struct TokenScript {
        calls: Vec<TokenEffect>,
    }
    impl TokenIo for TokenScript {
        fn check_token_limits(&mut self) -> TokenLimitObservation {
            self.calls.push(TokenEffect::CheckTokenLimits);
            TokenLimitObservation::Allowed
        }
        fn token_load_session(&mut self) -> TokenLookupObservation {
            self.calls.push(TokenEffect::LoadSession);
            TokenLookupObservation::Present(TokenSessionObservation {
                phase: SessionPhase::Granted,
                mode: SessionMode::ReadWrite,
                granted_user: Some(7),
                approver_user: Some(7),
                nonce_present: true,
                web_vk_present: true,
                key_epoch: 1,
                now: 100,
                expires_at: Some(1_000),
            })
        }
        fn consume_web_token_challenge(&mut self) -> TokenChallengeObservation {
            self.calls.push(TokenEffect::ConsumeWebTokenChallenge);
            TokenChallengeObservation::Observed(ChallengeConsumption::Accepted)
        }
        fn verify_web_signature(&mut self) -> TokenSignatureObservation {
            self.calls.push(TokenEffect::VerifyWebSignature);
            TokenSignatureObservation::Valid
        }
        fn record_token_failure(&mut self) -> TokenFailureRecordObservation {
            self.calls.push(TokenEffect::RecordTokenFailure);
            TokenFailureRecordObservation::Recorded
        }
        fn reset_token_backoff(&mut self) -> TokenResetObservation {
            self.calls.push(TokenEffect::ResetTokenBackoff);
            TokenResetObservation::Reset { now: 100 }
        }
        fn claim_token(&mut self) -> TokenClaimObservation {
            self.calls.push(TokenEffect::ClaimToken);
            TokenClaimObservation::Claimed
        }
        fn issue_token(&mut self, plan: TokenPlan) -> TokenIssueObservation {
            self.calls.push(TokenEffect::IssueToken(plan));
            TokenIssueObservation::Issued
        }
    }

    #[test]
    fn token_interpreter_performs_only_the_emitted_effects() {
        let mut io = TokenScript { calls: vec![] };
        let t = run_token(&mut io);
        assert_eq!(t.effect, TokenEffect::Complete);
        assert_eq!(io.calls.len(), 7);
        assert_eq!(io.calls[0], TokenEffect::CheckTokenLimits);
        assert!(matches!(io.calls[6], TokenEffect::IssueToken(_)));
    }

    struct DeleteScript {
        calls: Vec<DeleteEffect>,
    }
    impl DeleteSessionIo for DeleteScript {
        fn delete_load_session(&mut self) -> DeleteLookupObservation {
            self.calls.push(DeleteEffect::LoadSession);
            DeleteLookupObservation::Present(DeleteSessionFacts {
                session_user: Some(7),
                approver_user: None,
            })
        }
        fn lockout_session(&mut self) -> DeleteSentinelObservation {
            self.calls.push(DeleteEffect::LockoutSession);
            DeleteSentinelObservation::Applied
        }
        fn record_revocation(&mut self) -> DeleteRecordObservation {
            self.calls.push(DeleteEffect::RecordRevocation);
            DeleteRecordObservation::Updated
        }
    }

    #[test]
    fn delete_interpreter_performs_only_the_emitted_effects() {
        let mut io = DeleteScript { calls: vec![] };
        let t = run_delete(&mut io, DeleteActorObservation { authenticated: true, user: 7 });
        assert_eq!(
            io.calls,
            vec![
                DeleteEffect::LoadSession,
                DeleteEffect::LockoutSession,
                DeleteEffect::RecordRevocation
            ]
        );
        assert_eq!(t.effect, DeleteEffect::Complete);
    }
}
