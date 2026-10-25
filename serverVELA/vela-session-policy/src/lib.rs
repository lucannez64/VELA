//! Pure capability policy for temporary VELA web sessions.
//!
//! HTTP, PASETO, clocks, database queries, signature verification, and atomic
//! storage stay outside this crate. Production code converts those observations
//! into the facts below and may sign a token only from the private [`TokenPlan`]
//! returned here. hax extracts these exact decisions to F*.

pub mod challenge;
pub mod login_driver;
pub mod revocation_driver;

pub const TOKEN_LIFETIME_SECS: i64 = 15 * 60;
pub const DEVICE_HARD_CAP_SECS: i64 = 8 * 60 * 60;
pub const RENEWAL_WINDOW_SECS: i64 = 5 * 60;
pub const INITIAL_EPOCH: i64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityScope {
    Device,
    WebSession,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeClaim {
    MissingLegacy,
    Device,
    WebSession,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeDecision {
    Accept(CapabilityScope),
    Reject,
}

pub fn scope_decision_matches_spec(claim: ScopeClaim, decision: ScopeDecision) -> bool {
    matches!(
        (claim, decision),
        (
            ScopeClaim::MissingLegacy | ScopeClaim::Device,
            ScopeDecision::Accept(CapabilityScope::Device)
        ) | (
            ScopeClaim::WebSession,
            ScopeDecision::Accept(CapabilityScope::WebSession)
        ) | (ScopeClaim::Unknown, ScopeDecision::Reject)
    )
}

/// Parse the authenticated scope claim. Missing scope retains the bounded
/// legacy-device behavior; an explicit unknown value fails closed.
#[cfg_attr(hax, hax_lib::ensures(|decision| {
    scope_decision_matches_spec(claim, decision)
}))]
pub fn parse_scope_claim(claim: ScopeClaim) -> ScopeDecision {
    match claim {
        ScopeClaim::MissingLegacy | ScopeClaim::Device => {
            ScopeDecision::Accept(CapabilityScope::Device)
        }
        ScopeClaim::WebSession => ScopeDecision::Accept(CapabilityScope::WebSession),
        ScopeClaim::Unknown => ScopeDecision::Reject,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    Pending,
    Granted,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantFacts {
    pub phase: SessionPhase,
    pub mode: SessionMode,
    pub approver_matches: bool,
    pub nonce_matches: bool,
    pub has_web_vk: bool,
    pub declared_epoch: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantPermit {
    mode: SessionMode,
    epoch: i64,
}

impl GrantPermit {
    pub const fn mode(self) -> SessionMode {
        self.mode
    }

    pub const fn epoch(self) -> i64 {
        self.epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantDecision {
    Grant(GrantPermit),
    Reject,
}

pub fn grant_is_authorized(facts: GrantFacts) -> bool {
    matches!(facts.phase, SessionPhase::Pending)
        && facts.approver_matches
        && facts.nonce_matches
        && facts.declared_epoch >= INITIAL_EPOCH
        && (matches!(facts.mode, SessionMode::ReadOnly) || facts.has_web_vk)
}

pub fn grant_decision_matches_spec(facts: GrantFacts, decision: GrantDecision) -> bool {
    match decision {
        GrantDecision::Grant(permit) => {
            grant_is_authorized(facts)
                && same_session_mode(permit.mode, facts.mode)
                && permit.epoch == facts.declared_epoch
        }
        GrantDecision::Reject => !grant_is_authorized(facts),
    }
}

/// Produce the values consumed by the atomic pending/account-epoch grant CAS.
#[cfg_attr(hax, hax_lib::ensures(|decision| {
    grant_decision_matches_spec(facts, decision)
}))]
pub fn plan_grant(facts: GrantFacts) -> GrantDecision {
    if grant_is_authorized(facts) {
        GrantDecision::Grant(GrantPermit {
            mode: facts.mode,
            epoch: facts.declared_epoch,
        })
    } else {
        GrantDecision::Reject
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebTokenFacts {
    pub phase: SessionPhase,
    pub mode: SessionMode,
    pub approver_bound: bool,
    pub nonce_bound: bool,
    pub challenge_consumed: bool,
    pub signature_valid: bool,
}

/// Decoded observations from the session row and authenticated grant request.
/// UUID parsing, nonce comparison and row loading remain caller obligations;
/// account equality and nonce-length enforcement are computed here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantObservation {
    pub phase: SessionPhase,
    pub mode: SessionMode,
    pub approver_user: Option<u128>,
    pub authenticated_user: u128,
    pub nonce_length: usize,
    pub nonce_equal: bool,
    pub has_web_vk: bool,
    pub declared_epoch: i64,
}

fn observed_approver_matches(expected: Option<u128>, actual: u128) -> bool {
    match expected {
        Some(user) => user == actual,
        None => false,
    }
}

fn observed_users_match(user: Option<u128>, approver: Option<u128>) -> bool {
    match (user, approver) {
        (Some(user), Some(approver)) => user == approver,
        _ => false,
    }
}

pub fn grant_facts_match_observation(o: GrantObservation, f: GrantFacts) -> bool {
    same_session_phase(f.phase, o.phase)
        && same_session_mode(f.mode, o.mode)
        && f.approver_matches == observed_approver_matches(o.approver_user, o.authenticated_user)
        && f.nonce_matches == (o.nonce_length == 32 && o.nonce_equal)
        && f.has_web_vk == o.has_web_vk
        && f.declared_epoch == o.declared_epoch
}

#[cfg_attr(hax, hax_lib::ensures(|facts| grant_facts_match_observation(observation, facts)))]
pub fn grant_facts(observation: GrantObservation) -> GrantFacts {
    GrantFacts {
        phase: observation.phase,
        mode: observation.mode,
        approver_matches: observed_approver_matches(
            observation.approver_user,
            observation.authenticated_user,
        ),
        nonce_matches: observation.nonce_length == 32 && observation.nonce_equal,
        has_web_vk: observation.has_web_vk,
        declared_epoch: observation.declared_epoch,
    }
}

/// Observations after the actual challenge take and signature verification.
/// Absent accounts never establish a binding, including the (None, None) case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebTokenObservation {
    pub phase: SessionPhase,
    pub mode: SessionMode,
    pub granted_user: Option<u128>,
    pub approver_user: Option<u128>,
    pub nonce_present: bool,
    pub challenge_consumed: bool,
    pub signature_valid: bool,
}

pub fn web_facts_match_observation(o: WebTokenObservation, f: WebTokenFacts) -> bool {
    same_session_phase(f.phase, o.phase)
        && same_session_mode(f.mode, o.mode)
        && f.approver_bound == observed_users_match(o.granted_user, o.approver_user)
        && f.nonce_bound == o.nonce_present
        && f.challenge_consumed == o.challenge_consumed
        && f.signature_valid == o.signature_valid
}

#[cfg_attr(hax, hax_lib::ensures(|facts| web_facts_match_observation(observation, facts)))]
pub fn web_token_facts(observation: WebTokenObservation) -> WebTokenFacts {
    WebTokenFacts {
        phase: observation.phase,
        mode: observation.mode,
        approver_bound: observed_users_match(observation.granted_user, observation.approver_user),
        nonce_bound: observation.nonce_present,
        challenge_consumed: observation.challenge_consumed,
        signature_valid: observation.signature_valid,
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    grant_decision_matches_spec(grant_facts(observation), decision)
}))]
pub fn plan_observed_grant(observation: GrantObservation) -> GrantDecision {
    plan_grant(grant_facts(observation))
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    web_decision_matches_spec(web_token_facts(observation), now, hard_cap, epoch, decision)
}))]
pub fn plan_observed_web_token(
    observation: WebTokenObservation,
    now: i64,
    hard_cap: i64,
    epoch: i64,
) -> TokenDecision {
    plan_web_session_token(web_token_facts(observation), now, hard_cap, epoch)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_approver_observation_can_grant(mut observation: GrantObservation) -> bool {
    observation.approver_user = None;
    matches!(plan_observed_grant(observation), GrantDecision::Grant(_))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn wrong_nonce_length_observation_can_grant(mut observation: GrantObservation) -> bool {
    if observation.nonce_length == 32 {
        return false;
    }
    observation.nonce_equal = true;
    matches!(plan_observed_grant(observation), GrantDecision::Grant(_))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn cross_account_observation_can_issue(
    mut observation: WebTokenObservation,
    user: u128,
    approver: u128,
    now: i64,
    hard_cap: i64,
    epoch: i64,
) -> bool {
    if user == approver {
        return false;
    }
    observation.granted_user = Some(user);
    observation.approver_user = Some(approver);
    matches!(
        plan_observed_web_token(observation, now, hard_cap, epoch),
        TokenDecision::Issue(_)
    )
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_accounts_observation_can_issue(
    mut observation: WebTokenObservation,
    now: i64,
    hard_cap: i64,
    epoch: i64,
) -> bool {
    observation.granted_user = None;
    observation.approver_user = None;
    matches!(
        plan_observed_web_token(observation, now, hard_cap, epoch),
        TokenDecision::Issue(_)
    )
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unconsumed_challenge_observation_can_issue(
    mut observation: WebTokenObservation,
    now: i64,
    hard_cap: i64,
    epoch: i64,
) -> bool {
    observation.challenge_consumed = false;
    matches!(
        plan_observed_web_token(observation, now, hard_cap, epoch),
        TokenDecision::Issue(_)
    )
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn invalid_signature_observation_can_issue(
    mut observation: WebTokenObservation,
    now: i64,
    hard_cap: i64,
    epoch: i64,
) -> bool {
    observation.signature_valid = false;
    matches!(
        plan_observed_web_token(observation, now, hard_cap, epoch),
        TokenDecision::Issue(_)
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenClaims {
    pub scope: CapabilityScope,
    pub key_epoch: Option<i64>,
    pub expires_at: i64,
    pub hard_cap: i64,
}

/// The only value the production signer accepts. Its fields are private so
/// server code cannot bypass the verified constructors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenPlan {
    scope: CapabilityScope,
    key_epoch: Option<i64>,
    expires_at: i64,
    hard_cap: i64,
}

impl TokenPlan {
    pub const fn scope(self) -> CapabilityScope {
        self.scope
    }

    pub const fn key_epoch(self) -> Option<i64> {
        self.key_epoch
    }

    pub const fn expires_at(self) -> i64 {
        self.expires_at
    }

    pub const fn hard_cap(self) -> i64 {
        self.hard_cap
    }

    pub const fn claims(self) -> TokenClaims {
        TokenClaims {
            scope: self.scope,
            key_epoch: self.key_epoch,
            expires_at: self.expires_at,
            hard_cap: self.hard_cap,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenDecision {
    Issue(TokenPlan),
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenewalDecision {
    Renew(TokenPlan),
    Keep,
    Reject,
}

fn add_lifetime_without_overflow(now: i64) -> i64 {
    if now > i64::MAX - TOKEN_LIFETIME_SECS {
        i64::MAX
    } else {
        now + TOKEN_LIFETIME_SECS
    }
}

fn add_device_cap_without_overflow(now: i64) -> Option<i64> {
    if now > i64::MAX - DEVICE_HARD_CAP_SECS {
        None
    } else {
        Some(now + DEVICE_HARD_CAP_SECS)
    }
}

fn bounded_expiry(now: i64, hard_cap: i64) -> i64 {
    let normal_expiry = add_lifetime_without_overflow(now);
    if normal_expiry < hard_cap {
        normal_expiry
    } else {
        hard_cap
    }
}

fn claims_shape_is_valid(claims: TokenClaims) -> bool {
    match claims.scope {
        CapabilityScope::Device => claims.key_epoch.is_none(),
        CapabilityScope::WebSession => match claims.key_epoch {
            Some(epoch) => epoch >= INITIAL_EPOCH,
            // Legacy web-session tokens predate the epoch claim and represent
            // epoch one. New issuance always writes an explicit epoch.
            None => true,
        },
    }
}

pub fn token_plan_is_valid(plan: TokenPlan, now: i64) -> bool {
    let claims = plan.claims();
    now >= 0
        && claims_shape_is_valid(claims)
        && claims.hard_cap > now
        && claims.expires_at > now
        && claims.expires_at <= claims.hard_cap
}

pub fn device_decision_matches_spec(
    now: i64,
    requested_hard_cap: Option<i64>,
    decision: TokenDecision,
) -> bool {
    match decision {
        TokenDecision::Issue(plan) => {
            token_plan_is_valid(plan, now)
                && matches!(plan.scope, CapabilityScope::Device)
                && plan.key_epoch.is_none()
                && plan.expires_at == bounded_expiry(now, plan.hard_cap)
                && match requested_hard_cap {
                    Some(cap) => plan.hard_cap == cap,
                    None => add_device_cap_without_overflow(now) == Some(plan.hard_cap),
                }
        }
        TokenDecision::Reject => {
            now < 0
                || match requested_hard_cap {
                    Some(cap) => cap <= now,
                    None => add_device_cap_without_overflow(now).is_none(),
                }
        }
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    device_decision_matches_spec(now, requested_hard_cap, decision)
}))]
pub fn plan_device_token(now: i64, requested_hard_cap: Option<i64>) -> TokenDecision {
    if now < 0 {
        return TokenDecision::Reject;
    }
    let hard_cap = match requested_hard_cap {
        Some(cap) if cap > now => cap,
        Some(_) => return TokenDecision::Reject,
        None => match add_device_cap_without_overflow(now) {
            Some(cap) => cap,
            None => return TokenDecision::Reject,
        },
    };
    TokenDecision::Issue(TokenPlan {
        scope: CapabilityScope::Device,
        key_epoch: None,
        expires_at: bounded_expiry(now, hard_cap),
        hard_cap,
    })
}

pub fn web_exchange_is_authorized(
    facts: WebTokenFacts,
    now: i64,
    hard_cap: i64,
    epoch: i64,
) -> bool {
    now >= 0
        && hard_cap > now
        && epoch >= INITIAL_EPOCH
        && matches!(facts.phase, SessionPhase::Granted)
        && matches!(facts.mode, SessionMode::ReadWrite)
        && facts.approver_bound
        && facts.nonce_bound
        && facts.challenge_consumed
        && facts.signature_valid
}

pub fn web_decision_matches_spec(
    facts: WebTokenFacts,
    now: i64,
    hard_cap: i64,
    epoch: i64,
    decision: TokenDecision,
) -> bool {
    match decision {
        TokenDecision::Issue(plan) => {
            web_exchange_is_authorized(facts, now, hard_cap, epoch)
                && token_plan_is_valid(plan, now)
                && matches!(plan.scope, CapabilityScope::WebSession)
                && plan.key_epoch == Some(epoch)
                && plan.hard_cap == hard_cap
                && plan.expires_at == bounded_expiry(now, hard_cap)
        }
        TokenDecision::Reject => !web_exchange_is_authorized(facts, now, hard_cap, epoch),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    web_decision_matches_spec(facts, now, hard_cap, epoch, decision)
}))]
pub fn plan_web_session_token(
    facts: WebTokenFacts,
    now: i64,
    hard_cap: i64,
    epoch: i64,
) -> TokenDecision {
    if !web_exchange_is_authorized(facts, now, hard_cap, epoch) {
        return TokenDecision::Reject;
    }
    TokenDecision::Issue(TokenPlan {
        scope: CapabilityScope::WebSession,
        key_epoch: Some(epoch),
        expires_at: bounded_expiry(now, hard_cap),
        hard_cap,
    })
}

pub fn renewal_input_is_valid(claims: TokenClaims, now: i64) -> bool {
    now >= 0
        && claims_shape_is_valid(claims)
        && claims.hard_cap > now
        && claims.expires_at > now
        && claims.expires_at <= claims.hard_cap
}

pub fn renewal_decision_matches_spec(
    claims: TokenClaims,
    now: i64,
    decision: RenewalDecision,
) -> bool {
    if !renewal_input_is_valid(claims, now) {
        return matches!(decision, RenewalDecision::Reject);
    }
    let inside_window = now >= claims.expires_at - RENEWAL_WINDOW_SECS;
    if inside_window && claims.expires_at < claims.hard_cap {
        match decision {
            RenewalDecision::Renew(plan) => {
                token_plan_is_valid(plan, now)
                    && same_capability_scope(plan.scope, claims.scope)
                    && plan.key_epoch == claims.key_epoch
                    && plan.hard_cap == claims.hard_cap
                    && plan.expires_at == bounded_expiry(now, claims.hard_cap)
            }
            _ => false,
        }
    } else {
        matches!(decision, RenewalDecision::Keep)
    }
}

/// Renew only a live, structurally valid token, preserving its exact scope,
/// epoch binding, and hard cap.
#[cfg_attr(hax, hax_lib::ensures(|decision| {
    renewal_decision_matches_spec(claims, now, decision)
}))]
pub fn plan_renewal(claims: TokenClaims, now: i64) -> RenewalDecision {
    if !renewal_input_is_valid(claims, now) {
        return RenewalDecision::Reject;
    }
    if now < claims.expires_at - RENEWAL_WINDOW_SECS || claims.expires_at == claims.hard_cap {
        return RenewalDecision::Keep;
    }
    RenewalDecision::Renew(TokenPlan {
        scope: claims.scope,
        key_epoch: claims.key_epoch,
        expires_at: bounded_expiry(now, claims.hard_cap),
        hard_cap: claims.hard_cap,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteClass {
    Vault,
    PermanentAccount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutePermit {
    class: RouteClass,
}

impl RoutePermit {
    pub const fn class(self) -> RouteClass {
        self.class
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteDecision {
    Allow(RoutePermit),
    Reject,
}

// ── Web-session TTL and expiry (M25) ────────────────────────────────────────

pub const DEFAULT_WEB_TTL_SECS: i64 = 30 * 60; // 30 minutes
pub const MIN_WEB_TTL_SECS: i64 = 60;
pub const MAX_WEB_TTL_SECS: i64 = 24 * 60 * 60; // 24 hours

/// Clamp a browser-requested TTL to [60 s, 24 h], defaulting to 30 min.
/// Written with comparisons only (no min/max) so hax extracts a decision
/// that F* discharges without i64 op encoding.
pub fn clamp_web_ttl(requested: Option<i64>) -> i64 {
    let requested = match requested {
        None => return DEFAULT_WEB_TTL_SECS,
        Some(r) => r,
    };
    if requested < MIN_WEB_TTL_SECS {
        MIN_WEB_TTL_SECS
    } else if requested > MAX_WEB_TTL_SECS {
        MAX_WEB_TTL_SECS
    } else {
        requested
    }
}

/// A granted session past its expiry is terminal for admission purposes.
/// `now` and `expires_at` are unix seconds. A missing expiry never expires
/// here — pending-session reaping is a separate mechanism.
pub fn web_session_expired(now: i64, expires_at: Option<i64>) -> bool {
    match expires_at {
        Some(expires_at) => now >= expires_at,
        None => false,
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn ttl_clamp_can_be_violated(requested: Option<i64>) -> bool {
    let clamped = clamp_web_ttl(requested);
    clamped < MIN_WEB_TTL_SECS || clamped > MAX_WEB_TTL_SECS
}

pub fn route_is_authorized(scope: CapabilityScope, class: RouteClass) -> bool {
    matches!(scope, CapabilityScope::Device) || matches!(class, RouteClass::Vault)
}

pub fn route_decision_matches_spec(
    scope: CapabilityScope,
    class: RouteClass,
    decision: RouteDecision,
) -> bool {
    match decision {
        RouteDecision::Allow(permit) => {
            route_is_authorized(scope, class) && same_route_class(permit.class, class)
        }
        RouteDecision::Reject => !route_is_authorized(scope, class),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    route_decision_matches_spec(scope, class, decision)
}))]
pub fn authorize_route(scope: CapabilityScope, class: RouteClass) -> RouteDecision {
    if route_is_authorized(scope, class) {
        RouteDecision::Allow(RoutePermit { class })
    } else {
        RouteDecision::Reject
    }
}

/// Direct theorem used by the F* gate: renewal never changes the authority
/// class or epoch carried by an accepted input token.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn renewal_escalates_authority(claims: TokenClaims, now: i64) -> bool {
    match plan_renewal(claims, now) {
        RenewalDecision::Renew(plan) => {
            !same_capability_scope(plan.scope, claims.scope) || plan.key_epoch != claims.key_epoch
        }
        RenewalDecision::Keep | RenewalDecision::Reject => false,
    }
}

/// Direct theorem used by the F* gate: a terminal web session cannot issue a
/// token regardless of the other presented facts.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn terminal_session_issues_token(
    phase: SessionPhase,
    now: i64,
    hard_cap: i64,
    epoch: i64,
) -> bool {
    if !matches!(phase, SessionPhase::Revoked) && !matches!(phase, SessionPhase::Expired) {
        return false;
    }
    matches!(
        plan_web_session_token(
            WebTokenFacts {
                phase,
                mode: SessionMode::ReadWrite,
                approver_bound: true,
                nonce_bound: true,
                challenge_consumed: true,
                signature_valid: true,
            },
            now,
            hard_cap,
            epoch,
        ),
        TokenDecision::Issue(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_web_facts() -> WebTokenFacts {
        WebTokenFacts {
            phase: SessionPhase::Granted,
            mode: SessionMode::ReadWrite,
            approver_bound: true,
            nonce_bound: true,
            challenge_consumed: true,
            signature_valid: true,
        }
    }

    #[test]
    fn scope_parser_rejects_unknown_claims() {
        assert_eq!(
            parse_scope_claim(ScopeClaim::MissingLegacy),
            ScopeDecision::Accept(CapabilityScope::Device)
        );
        assert_eq!(
            parse_scope_claim(ScopeClaim::WebSession),
            ScopeDecision::Accept(CapabilityScope::WebSession)
        );
        assert_eq!(
            parse_scope_claim(ScopeClaim::Unknown),
            ScopeDecision::Reject
        );
    }

    #[test]
    fn web_issue_requires_every_lifecycle_fact() {
        let facts = valid_web_facts();
        let permit = match plan_web_session_token(facts, 100, 1_000, 7) {
            TokenDecision::Issue(plan) => plan,
            TokenDecision::Reject => panic!("valid exchange rejected"),
        };
        assert_eq!(permit.scope(), CapabilityScope::WebSession);
        assert_eq!(permit.key_epoch(), Some(7));
        assert_eq!(permit.expires_at(), 1_000);

        for rejected in [
            WebTokenFacts {
                phase: SessionPhase::Pending,
                ..facts
            },
            WebTokenFacts {
                phase: SessionPhase::Revoked,
                ..facts
            },
            WebTokenFacts {
                phase: SessionPhase::Expired,
                ..facts
            },
            WebTokenFacts {
                mode: SessionMode::ReadOnly,
                ..facts
            },
            WebTokenFacts {
                approver_bound: false,
                ..facts
            },
            WebTokenFacts {
                nonce_bound: false,
                ..facts
            },
            WebTokenFacts {
                challenge_consumed: false,
                ..facts
            },
            WebTokenFacts {
                signature_valid: false,
                ..facts
            },
        ] {
            assert_eq!(
                plan_web_session_token(rejected, 100, 1_000, 7),
                TokenDecision::Reject
            );
        }
    }

    #[test]
    fn grant_binds_pending_approver_nonce_mode_and_epoch() {
        let facts = GrantFacts {
            phase: SessionPhase::Pending,
            mode: SessionMode::ReadWrite,
            approver_matches: true,
            nonce_matches: true,
            has_web_vk: true,
            declared_epoch: 4,
        };
        let permit = match plan_grant(facts) {
            GrantDecision::Grant(permit) => permit,
            GrantDecision::Reject => panic!("valid grant rejected"),
        };
        assert_eq!(permit.mode(), SessionMode::ReadWrite);
        assert_eq!(permit.epoch(), 4);

        for rejected in [
            GrantFacts {
                phase: SessionPhase::Granted,
                ..facts
            },
            GrantFacts {
                approver_matches: false,
                ..facts
            },
            GrantFacts {
                nonce_matches: false,
                ..facts
            },
            GrantFacts {
                has_web_vk: false,
                ..facts
            },
            GrantFacts {
                declared_epoch: 0,
                ..facts
            },
        ] {
            assert_eq!(plan_grant(rejected), GrantDecision::Reject);
        }
        assert!(matches!(
            plan_grant(GrantFacts {
                mode: SessionMode::ReadOnly,
                has_web_vk: false,
                ..facts
            }),
            GrantDecision::Grant(_)
        ));
    }

    #[test]
    fn renewal_preserves_scope_epoch_and_cap() {
        let claims = TokenClaims {
            scope: CapabilityScope::WebSession,
            key_epoch: Some(7),
            expires_at: 1_000,
            hard_cap: 1_500,
        };
        let plan = match plan_renewal(claims, 800) {
            RenewalDecision::Renew(plan) => plan,
            other => panic!("expected renewal, got {other:?}"),
        };
        assert_eq!(plan.scope(), claims.scope);
        assert_eq!(plan.key_epoch(), claims.key_epoch);
        assert_eq!(plan.hard_cap(), claims.hard_cap);
        assert_eq!(plan.expires_at(), claims.hard_cap);
        assert!(!renewal_escalates_authority(claims, 800));
    }

    #[test]
    fn permanent_routes_are_device_only() {
        assert!(matches!(
            authorize_route(CapabilityScope::Device, RouteClass::PermanentAccount),
            RouteDecision::Allow(_)
        ));
        assert_eq!(
            authorize_route(CapabilityScope::WebSession, RouteClass::PermanentAccount),
            RouteDecision::Reject
        );
        assert!(matches!(
            authorize_route(CapabilityScope::WebSession, RouteClass::Vault),
            RouteDecision::Allow(_)
        ));
    }

    #[test]
    fn terminal_sessions_never_issue() {
        for phase in [SessionPhase::Revoked, SessionPhase::Expired] {
            assert!(!terminal_session_issues_token(phase, 100, 1_000, 1));
        }
    }

    #[test]
    fn invalid_and_overflowing_times_fail_closed() {
        assert_eq!(plan_device_token(-1, None), TokenDecision::Reject);
        assert_eq!(plan_device_token(i64::MAX, None), TokenDecision::Reject);
        assert_eq!(
            plan_web_session_token(valid_web_facts(), 100, 100, 1),
            TokenDecision::Reject
        );
        assert_eq!(
            plan_web_session_token(valid_web_facts(), 100, 1_000, 0),
            TokenDecision::Reject
        );
    }
}

// Structural comparisons keep the hax translation independent of opaque
// derived PartialEq implementations. Normal Rust retains its derived Eq API.
fn same_session_mode(a: SessionMode, b: SessionMode) -> bool {
    matches!(
        (a, b),
        (SessionMode::ReadOnly, SessionMode::ReadOnly)
            | (SessionMode::ReadWrite, SessionMode::ReadWrite)
    )
}
fn same_capability_scope(a: CapabilityScope, b: CapabilityScope) -> bool {
    matches!(
        (a, b),
        (CapabilityScope::Device, CapabilityScope::Device)
            | (CapabilityScope::WebSession, CapabilityScope::WebSession)
    )
}
fn same_route_class(a: RouteClass, b: RouteClass) -> bool {
    matches!(
        (a, b),
        (RouteClass::Vault, RouteClass::Vault)
            | (RouteClass::PermanentAccount, RouteClass::PermanentAccount)
    )
}
#[cfg(test)]
mod structural_equality_tests {
    use super::*;
    #[test]
    fn structural_comparisons_match_derived_equality_exhaustively() {
        for a in [SessionMode::ReadOnly, SessionMode::ReadWrite] {
            for b in [SessionMode::ReadOnly, SessionMode::ReadWrite] {
                assert_eq!(same_session_mode(a, b), a == b);
            }
        }
        for a in [CapabilityScope::Device, CapabilityScope::WebSession] {
            for b in [CapabilityScope::Device, CapabilityScope::WebSession] {
                assert_eq!(same_capability_scope(a, b), a == b);
            }
        }
        for a in [RouteClass::Vault, RouteClass::PermanentAccount] {
            for b in [RouteClass::Vault, RouteClass::PermanentAccount] {
                assert_eq!(same_route_class(a, b), a == b);
            }
        }
    }
}

fn same_session_phase(a: SessionPhase, b: SessionPhase) -> bool {
    matches!(
        (a, b),
        (SessionPhase::Pending, SessionPhase::Pending)
            | (SessionPhase::Granted, SessionPhase::Granted)
            | (SessionPhase::Revoked, SessionPhase::Revoked)
            | (SessionPhase::Expired, SessionPhase::Expired)
    )
}
