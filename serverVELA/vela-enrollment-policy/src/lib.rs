//! Pure policy for the permanent-device enrollment rendezvous.
//!
//! HTTP parsing, signatures, public-key decoding, clocks, SQL, and sled remain
//! outside this crate. Production converts those authenticated observations
//! into facts below. Private permits ensure a handler can reach a security-
//! sensitive transition only through a decision whose exact predicate hax
//! extracts and F* verifies.
//!
//! [`pairing_driver`] adds the per-request, total transition relation the
//! invitation and rendezvous handlers follow between their effects.

pub mod executor;
pub mod executor_model;
pub mod pairing_driver;
pub mod pairing_interpreter;
pub mod enroll_driver;
pub mod enroll_interpreter;

/// Decoded length of a hybrid encapsulation key (`X25519` + `ML-KEM`).
pub const HYBRID_EK_LEN: usize = 1568 + 32;

/// Decoded length of a hybrid verification key (`Ed25519` + `ML-DSA`).
pub const HYBRID_VK_LEN: usize = 2592 + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyPhase {
    Open,
    Claimed,
    Completed,
    Revoked,
    Expired,
}

/// Raw observations from the authenticated grant-opening request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenObservation {
    /// The authenticated session is a permanent device token, not a web session.
    pub scope_is_device: bool,
    /// The session names a user id.
    pub user_id_present: bool,
    /// The session names a device id.
    pub device_id_present: bool,
    /// Requested grant lifetime in seconds.
    pub ttl_secs: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenFacts {
    pub device_scope: bool,
    pub user_bound: bool,
    pub opener_bound: bool,
    pub ttl_positive: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenPermit {
    authorized: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenDecision {
    Open(OpenPermit),
    Reject,
}

pub fn open_is_authorized(facts: OpenFacts) -> bool {
    facts.device_scope && facts.user_bound && facts.opener_bound && facts.ttl_positive
}

/// Turn raw session observations into the grant-opening facts.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    facts.device_scope == obs.scope_is_device
        && facts.user_bound == obs.user_id_present
        && facts.opener_bound == obs.device_id_present
        && facts.ttl_positive == (obs.ttl_secs > 0)
}))]
pub fn open_facts(obs: OpenObservation) -> OpenFacts {
    OpenFacts {
        device_scope: obs.scope_is_device,
        user_bound: obs.user_id_present,
        opener_bound: obs.device_id_present,
        ttl_positive: obs.ttl_secs > 0,
    }
}

pub fn open_decision_matches_spec(facts: OpenFacts, decision: OpenDecision) -> bool {
    match decision {
        OpenDecision::Open(permit) => open_is_authorized(facts) && permit.authorized,
        OpenDecision::Reject => !open_is_authorized(facts),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    open_decision_matches_spec(facts, decision)
}))]
pub fn plan_open(facts: OpenFacts) -> OpenDecision {
    if open_is_authorized(facts) {
        OpenDecision::Open(OpenPermit { authorized: true })
    } else {
        OpenDecision::Reject
    }
}

/// Raw observations from the unauthenticated claim request and the store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimObservation {
    /// The grant key still exists (it is live and unconsumed).
    pub grant_live: bool,
    /// A claim record already exists for this grant.
    pub claim_exists: bool,
    /// Decoded byte length of the presented `hybrid_ek`.
    pub hybrid_ek_len: usize,
    /// Decoded byte length of the presented `hybrid_vk`.
    pub hybrid_vk_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimFacts {
    pub phase: CeremonyPhase,
    pub grant_live: bool,
    pub no_existing_claim: bool,
    pub public_keys_valid: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimPermit {
    authorized: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimDecision {
    Claim(ClaimPermit),
    Reject,
}

pub fn claim_is_authorized(facts: ClaimFacts) -> bool {
    matches!(facts.phase, CeremonyPhase::Open)
        && facts.grant_live
        && facts.no_existing_claim
        && facts.public_keys_valid
}

/// Turn raw grant/claim/store observations into the claim facts.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    (matches!(facts.phase, CeremonyPhase::Claimed) == obs.claim_exists)
        && (matches!(facts.phase, CeremonyPhase::Open) == !obs.claim_exists)
        && facts.grant_live == obs.grant_live
        && facts.no_existing_claim == !obs.claim_exists
        && facts.public_keys_valid
            == (obs.hybrid_ek_len == HYBRID_EK_LEN && obs.hybrid_vk_len == HYBRID_VK_LEN)
}))]
pub fn claim_facts(obs: ClaimObservation) -> ClaimFacts {
    ClaimFacts {
        phase: if obs.claim_exists {
            CeremonyPhase::Claimed
        } else {
            CeremonyPhase::Open
        },
        grant_live: obs.grant_live,
        no_existing_claim: !obs.claim_exists,
        public_keys_valid: obs.hybrid_ek_len == HYBRID_EK_LEN && obs.hybrid_vk_len == HYBRID_VK_LEN,
    }
}

pub fn claim_decision_matches_spec(facts: ClaimFacts, decision: ClaimDecision) -> bool {
    match decision {
        ClaimDecision::Claim(permit) => claim_is_authorized(facts) && permit.authorized,
        ClaimDecision::Reject => !claim_is_authorized(facts),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    claim_decision_matches_spec(facts, decision)
}))]
pub fn plan_claim(facts: ClaimFacts) -> ClaimDecision {
    if claim_is_authorized(facts) {
        ClaimDecision::Claim(ClaimPermit { authorized: true })
    } else {
        ClaimDecision::Reject
    }
}

/// Raw observations from the claim-inspection request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectObservation {
    /// A claim record exists for this grant.
    pub claim_present: bool,
    /// The session user id equals the grant's user id.
    pub user_matches: bool,
    /// The session device id equals the grant's opener device id.
    pub opener_matches: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectFacts {
    pub phase: CeremonyPhase,
    pub user_matches: bool,
    pub opener_matches: bool,
    pub claim_present: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectPermit {
    authorized: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectDecision {
    Inspect(InspectPermit),
    Reject,
}

pub fn inspection_is_authorized(facts: InspectFacts) -> bool {
    matches!(facts.phase, CeremonyPhase::Claimed)
        && facts.user_matches
        && facts.opener_matches
        && facts.claim_present
}

/// Turn raw claim/store/session observations into the inspection facts.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    (matches!(facts.phase, CeremonyPhase::Claimed) == obs.claim_present)
        && (matches!(facts.phase, CeremonyPhase::Open) == !obs.claim_present)
        && facts.user_matches == obs.user_matches
        && facts.opener_matches == obs.opener_matches
        && facts.claim_present == obs.claim_present
}))]
pub fn inspect_facts(obs: InspectObservation) -> InspectFacts {
    InspectFacts {
        phase: if obs.claim_present {
            CeremonyPhase::Claimed
        } else {
            CeremonyPhase::Open
        },
        user_matches: obs.user_matches,
        opener_matches: obs.opener_matches,
        claim_present: obs.claim_present,
    }
}

pub fn inspection_decision_matches_spec(facts: InspectFacts, decision: InspectDecision) -> bool {
    match decision {
        InspectDecision::Inspect(permit) => inspection_is_authorized(facts) && permit.authorized,
        InspectDecision::Reject => !inspection_is_authorized(facts),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    inspection_decision_matches_spec(facts, decision)
}))]
pub fn authorize_inspection(facts: InspectFacts) -> InspectDecision {
    if inspection_is_authorized(facts) {
        InspectDecision::Inspect(InspectPermit { authorized: true })
    } else {
        InspectDecision::Reject
    }
}

/// Where the completion path obtained the key material it verified and enrolled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimKeySource {
    /// The immutable claim record read from the store under the grant id.
    StoredClaim,
    /// Keys supplied by the completion request body.
    RequestSupplied,
}

/// Raw observations from the completion request, the store, SQL and the
/// primary's hybrid signature check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionObservation {
    /// A claim record exists for this grant.
    pub claim_present: bool,
    /// The session user id equals the grant's user id.
    pub user_matches: bool,
    /// The session device id equals the grant's opener device id.
    pub opener_matches: bool,
    /// The opener's `devices.revoked` column is clear.
    pub opener_active: bool,
    /// The primary's signature over the stored keys and capsule verified.
    pub signature_verified: bool,
    /// Provenance of the keys used for verification and enrollment.
    pub claim_key_source: ClaimKeySource,
    /// `users.key_epoch` observed for the grant's user (0 when no row).
    pub account_epoch: i64,
    /// Epoch named by the completion request.
    pub declared_epoch: i64,
    /// `users.rekey_state` is set.
    pub rotation_in_progress: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionFacts {
    pub phase: CeremonyPhase,
    pub user_matches: bool,
    pub opener_matches: bool,
    pub opener_active: bool,
    pub claim_present: bool,
    pub displayed_claim_is_stored_claim: bool,
    pub signature_covers_stored_claim: bool,
    pub account_epoch_active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionPermit {
    consume_grant_and_claim: bool,
}

impl CompletionPermit {
    pub const fn consumes_grant_and_claim(self) -> bool {
        self.consume_grant_and_claim
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionDecision {
    Complete(CompletionPermit),
    Reject,
}

pub fn completion_is_authorized(facts: CompletionFacts) -> bool {
    matches!(facts.phase, CeremonyPhase::Claimed)
        && facts.user_matches
        && facts.opener_matches
        && facts.opener_active
        && facts.claim_present
        && facts.displayed_claim_is_stored_claim
        && facts.signature_covers_stored_claim
        && facts.account_epoch_active
}

/// Turn raw completion observations into the completion facts.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    (matches!(facts.phase, CeremonyPhase::Claimed) == obs.claim_present)
        && (matches!(facts.phase, CeremonyPhase::Open) == !obs.claim_present)
        && facts.user_matches == obs.user_matches
        && facts.opener_matches == obs.opener_matches
        && facts.opener_active == obs.opener_active
        && facts.claim_present == obs.claim_present
        && facts.displayed_claim_is_stored_claim
            == (obs.claim_present
                && matches!(obs.claim_key_source, ClaimKeySource::StoredClaim))
        && facts.signature_covers_stored_claim
            == (obs.signature_verified
                && obs.claim_present
                && matches!(obs.claim_key_source, ClaimKeySource::StoredClaim))
        && facts.account_epoch_active
            == (obs.declared_epoch >= 1
                && obs.account_epoch == obs.declared_epoch
                && !obs.rotation_in_progress)
}))]
pub fn completion_facts(obs: CompletionObservation) -> CompletionFacts {
    CompletionFacts {
        phase: if obs.claim_present {
            CeremonyPhase::Claimed
        } else {
            CeremonyPhase::Open
        },
        user_matches: obs.user_matches,
        opener_matches: obs.opener_matches,
        opener_active: obs.opener_active,
        claim_present: obs.claim_present,
        displayed_claim_is_stored_claim: obs.claim_present
            && matches!(obs.claim_key_source, ClaimKeySource::StoredClaim),
        signature_covers_stored_claim: obs.signature_verified
            && obs.claim_present
            && matches!(obs.claim_key_source, ClaimKeySource::StoredClaim),
        account_epoch_active: obs.declared_epoch >= 1
            && obs.account_epoch == obs.declared_epoch
            && !obs.rotation_in_progress,
    }
}

pub fn completion_decision_matches_spec(
    facts: CompletionFacts,
    decision: CompletionDecision,
) -> bool {
    match decision {
        CompletionDecision::Complete(permit) => {
            completion_is_authorized(facts) && permit.consume_grant_and_claim
        }
        CompletionDecision::Reject => !completion_is_authorized(facts),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    completion_decision_matches_spec(facts, decision)
}))]
pub fn plan_completion(facts: CompletionFacts) -> CompletionDecision {
    if completion_is_authorized(facts) {
        CompletionDecision::Complete(CompletionPermit {
            consume_grant_and_claim: true,
        })
    } else {
        CompletionDecision::Reject
    }
}

/// Where the result request found the ceremony.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultSource {
    /// A completed result record carrying the joining device's public key.
    CompletedResult,
    /// A live claim awaiting completion.
    ClaimedClaim,
    /// Neither a result nor a claim exists (the grant is gone or expired).
    NoRecord,
}

/// Raw observations from the result request and the store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultObservation {
    pub source: ResultSource,
    /// Decoded byte length of the stored claimed verification key (0 if none).
    pub claimed_key_len: usize,
    /// The collector's signature verified under the claimed key.
    pub signature_verified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultFacts {
    pub phase: CeremonyPhase,
    pub claimed_key_present: bool,
    pub claimed_key_proof_valid: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultKind {
    Pending,
    Enrolled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultPermit {
    kind: ResultKind,
}

impl ResultPermit {
    pub const fn kind(self) -> ResultKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultDecision {
    Return(ResultPermit),
    Reject,
}

pub fn result_is_authorized(facts: ResultFacts) -> bool {
    (matches!(facts.phase, CeremonyPhase::Claimed)
        || matches!(facts.phase, CeremonyPhase::Completed))
        && facts.claimed_key_present
        && facts.claimed_key_proof_valid
}

/// Turn raw result/store/signature observations into the result facts.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    (matches!(facts.phase, CeremonyPhase::Completed)
        == matches!(obs.source, ResultSource::CompletedResult))
        && (matches!(facts.phase, CeremonyPhase::Claimed)
            == matches!(obs.source, ResultSource::ClaimedClaim))
        && (matches!(facts.phase, CeremonyPhase::Expired)
            == matches!(obs.source, ResultSource::NoRecord))
        && facts.claimed_key_present == (obs.claimed_key_len > 0)
        && facts.claimed_key_proof_valid
            == (obs.claimed_key_len > 0 && obs.signature_verified)
}))]
pub fn result_facts(obs: ResultObservation) -> ResultFacts {
    ResultFacts {
        phase: match obs.source {
            ResultSource::CompletedResult => CeremonyPhase::Completed,
            ResultSource::ClaimedClaim => CeremonyPhase::Claimed,
            ResultSource::NoRecord => CeremonyPhase::Expired,
        },
        claimed_key_present: obs.claimed_key_len > 0,
        claimed_key_proof_valid: obs.claimed_key_len > 0 && obs.signature_verified,
    }
}

pub fn result_decision_matches_spec(facts: ResultFacts, decision: ResultDecision) -> bool {
    match decision {
        ResultDecision::Return(permit) => {
            result_is_authorized(facts)
                && if matches!(facts.phase, CeremonyPhase::Claimed) {
                    matches!(permit.kind, ResultKind::Pending)
                } else {
                    matches!(permit.kind, ResultKind::Enrolled)
                }
        }
        ResultDecision::Reject => !result_is_authorized(facts),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    result_decision_matches_spec(facts, decision)
}))]
pub fn authorize_result(facts: ResultFacts) -> ResultDecision {
    if !result_is_authorized(facts) {
        return ResultDecision::Reject;
    }
    let kind = if matches!(facts.phase, CeremonyPhase::Claimed) {
        ResultKind::Pending
    } else {
        ResultKind::Enrolled
    };
    ResultDecision::Return(ResultPermit { kind })
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn completed_ceremony_can_complete_again(mut facts: CompletionFacts) -> bool {
    facts.phase = CeremonyPhase::Completed;
    completion_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn other_device_can_inspect(mut facts: InspectFacts) -> bool {
    facts.opener_matches = false;
    inspection_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn substituted_claim_can_complete(mut facts: CompletionFacts) -> bool {
    facts.displayed_claim_is_stored_claim = false;
    completion_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn result_without_claimed_key_proof(mut facts: ResultFacts) -> bool {
    facts.claimed_key_proof_valid = false;
    result_is_authorized(facts)
}

// ── Negative theorems over the real observation constructors ───────────────

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn web_session_can_open_enrollment_grant(mut obs: OpenObservation) -> bool {
    obs.scope_is_device = false;
    open_is_authorized(open_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn expired_grant_can_open(mut obs: OpenObservation) -> bool {
    obs.ttl_secs = 0;
    open_is_authorized(open_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_grant_can_be_claimed(mut obs: ClaimObservation) -> bool {
    obs.grant_live = false;
    claim_is_authorized(claim_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn invalid_public_key_length_can_be_claimed(mut obs: ClaimObservation) -> bool {
    obs.hybrid_ek_len = 0;
    claim_is_authorized(claim_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_claim_can_be_inspected(mut obs: InspectObservation) -> bool {
    obs.claim_present = false;
    inspection_is_authorized(inspect_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn other_device_can_inspect_observed_claim(mut obs: InspectObservation) -> bool {
    obs.opener_matches = false;
    inspection_is_authorized(inspect_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn revoked_opener_can_complete(mut obs: CompletionObservation) -> bool {
    obs.opener_active = false;
    completion_is_authorized(completion_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn foreign_device_can_complete_observed_ceremony(mut obs: CompletionObservation) -> bool {
    obs.opener_matches = false;
    completion_is_authorized(completion_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unverified_signature_can_complete(mut obs: CompletionObservation) -> bool {
    obs.signature_verified = false;
    completion_is_authorized(completion_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_claim_can_complete_observed_ceremony(mut obs: CompletionObservation) -> bool {
    obs.claim_present = false;
    completion_is_authorized(completion_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn request_supplied_claim_can_complete(mut obs: CompletionObservation) -> bool {
    obs.claim_key_source = ClaimKeySource::RequestSupplied;
    completion_is_authorized(completion_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn stale_epoch_can_complete(mut obs: CompletionObservation) -> bool {
    obs.declared_epoch = 1;
    obs.account_epoch = 0;
    completion_is_authorized(completion_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn invalid_result_signature_can_return_result(mut obs: ResultObservation) -> bool {
    obs.signature_verified = false;
    result_is_authorized(result_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_claimed_key_can_return_result(mut obs: ResultObservation) -> bool {
    obs.claimed_key_len = 0;
    result_is_authorized(result_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unclaimed_ceremony_can_return_result(mut obs: ResultObservation) -> bool {
    obs.source = ResultSource::NoRecord;
    result_is_authorized(result_facts(obs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_completion() -> CompletionFacts {
        CompletionFacts {
            phase: CeremonyPhase::Claimed,
            user_matches: true,
            opener_matches: true,
            opener_active: true,
            claim_present: true,
            displayed_claim_is_stored_claim: true,
            signature_covers_stored_claim: true,
            account_epoch_active: true,
        }
    }

    #[test]
    fn completion_requires_every_binding() {
        assert!(matches!(
            plan_completion(valid_completion()),
            CompletionDecision::Complete(_)
        ));
        assert!(!completed_ceremony_can_complete_again(valid_completion()));
        assert!(!substituted_claim_can_complete(valid_completion()));
    }

    #[test]
    fn result_requires_the_claimed_private_key() {
        let facts = ResultFacts {
            phase: CeremonyPhase::Completed,
            claimed_key_present: true,
            claimed_key_proof_valid: true,
        };
        assert!(matches!(
            authorize_result(facts),
            ResultDecision::Return(permit) if matches!(permit.kind(), ResultKind::Enrolled)
        ));
        assert!(!result_without_claimed_key_proof(facts));
    }
}
