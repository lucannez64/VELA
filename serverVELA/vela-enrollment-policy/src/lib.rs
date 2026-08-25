//! Pure policy for the permanent-device enrollment rendezvous.
//!
//! HTTP parsing, signatures, public-key decoding, clocks, SQL, and sled remain
//! outside this crate. Production converts those authenticated observations
//! into facts below. Private permits ensure a handler can reach a security-
//! sensitive transition only through a decision whose exact predicate hax
//! extracts and F* verifies.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyPhase {
    Open,
    Claimed,
    Completed,
    Revoked,
    Expired,
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
    facts.phase == CeremonyPhase::Open
        && facts.grant_live
        && facts.no_existing_claim
        && facts.public_keys_valid
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
    facts.phase == CeremonyPhase::Claimed
        && facts.user_matches
        && facts.opener_matches
        && facts.claim_present
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
    facts.phase == CeremonyPhase::Claimed
        && facts.user_matches
        && facts.opener_matches
        && facts.opener_active
        && facts.claim_present
        && facts.displayed_claim_is_stored_claim
        && facts.signature_covers_stored_claim
        && facts.account_epoch_active
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
    (facts.phase == CeremonyPhase::Claimed || facts.phase == CeremonyPhase::Completed)
        && facts.claimed_key_present
        && facts.claimed_key_proof_valid
}

pub fn result_decision_matches_spec(facts: ResultFacts, decision: ResultDecision) -> bool {
    match decision {
        ResultDecision::Return(permit) => {
            result_is_authorized(facts)
                && permit.kind
                    == if facts.phase == CeremonyPhase::Claimed {
                        ResultKind::Pending
                    } else {
                        ResultKind::Enrolled
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
    let kind = if facts.phase == CeremonyPhase::Claimed {
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
            ResultDecision::Return(permit) if permit.kind() == ResultKind::Enrolled
        ));
        assert!(!result_without_claimed_key_proof(facts));
    }
}
