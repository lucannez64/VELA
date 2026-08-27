//! Pure policy for WebAuthn-gated account recovery and recovered-device
//! enrollment.
//!
//! WebAuthn, clocks, SQL, sled, UUIDs, and HTTP stay outside this crate. The
//! server converts their authenticated observations into facts and can release
//! a share, rotate a stored credential, or enroll a device only from the
//! private permits constructed here. hax extracts these exact decisions to F*.

pub const INITIAL_EPOCH: i64 = 1;

// ── Recovery-share publication (M16) ───────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationStageRequest {
    pub declared_epoch: i64,
    pub split_id_present: bool,
    pub server_share_present: bool,
    pub device_authority: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationStagePermit {
    epoch: i64,
    binds_split_and_share: bool,
}

impl PublicationStagePermit {
    pub const fn epoch(self) -> i64 {
        self.epoch
    }

    pub const fn binds_split_and_share(self) -> bool {
        self.binds_split_and_share
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationStageDecision {
    Stage(PublicationStagePermit),
    Reject,
}

pub fn publication_stage_is_authorized(request: PublicationStageRequest) -> bool {
    request.declared_epoch >= INITIAL_EPOCH
        && request.split_id_present
        && request.server_share_present
        && request.device_authority
}

pub fn publication_stage_decision_matches_spec(
    request: PublicationStageRequest,
    decision: PublicationStageDecision,
) -> bool {
    match decision {
        PublicationStageDecision::Stage(permit) => {
            publication_stage_is_authorized(request)
                && permit.epoch == request.declared_epoch
                && permit.binds_split_and_share
        }
        PublicationStageDecision::Reject => !publication_stage_is_authorized(request),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    publication_stage_decision_matches_spec(request, decision)
}))]
pub fn plan_publication_stage(request: PublicationStageRequest) -> PublicationStageDecision {
    if publication_stage_is_authorized(request) {
        PublicationStageDecision::Stage(PublicationStagePermit {
            epoch: request.declared_epoch,
            binds_split_and_share: true,
        })
    } else {
        PublicationStageDecision::Reject
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationFinalizeRequest {
    pub declared_epoch: i64,
    pub split_id_present: bool,
    pub device_authority: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationFinalizePermit {
    epoch: i64,
    exact_pending_required: bool,
    empty_active_required: bool,
}

impl PublicationFinalizePermit {
    pub const fn epoch(self) -> i64 {
        self.epoch
    }

    pub const fn requires_exact_pending(self) -> bool {
        self.exact_pending_required
    }

    pub const fn requires_empty_active(self) -> bool {
        self.empty_active_required
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationFinalizeDecision {
    Finalize(PublicationFinalizePermit),
    Reject,
}

pub fn publication_finalize_is_authorized(request: PublicationFinalizeRequest) -> bool {
    request.declared_epoch >= INITIAL_EPOCH && request.split_id_present && request.device_authority
}

pub fn publication_finalize_decision_matches_spec(
    request: PublicationFinalizeRequest,
    decision: PublicationFinalizeDecision,
) -> bool {
    match decision {
        PublicationFinalizeDecision::Finalize(permit) => {
            publication_finalize_is_authorized(request)
                && permit.epoch == request.declared_epoch
                && permit.exact_pending_required
                && permit.empty_active_required
        }
        PublicationFinalizeDecision::Reject => !publication_finalize_is_authorized(request),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    publication_finalize_decision_matches_spec(request, decision)
}))]
pub fn plan_publication_finalize(
    request: PublicationFinalizeRequest,
) -> PublicationFinalizeDecision {
    if publication_finalize_is_authorized(request) {
        PublicationFinalizeDecision::Finalize(PublicationFinalizePermit {
            epoch: request.declared_epoch,
            exact_pending_required: true,
            empty_active_required: true,
        })
    } else {
        PublicationFinalizeDecision::Reject
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationStateFacts {
    pub account_epoch_active: bool,
    pub active_share_absent: bool,
    pub account_epoch: i64,
    pub pending_epoch: i64,
    pub pending_split_matches: bool,
    pub pending_share_present: bool,
}

pub fn pending_publication_can_commit(
    permit: PublicationFinalizePermit,
    state: PublicationStateFacts,
) -> bool {
    permit.exact_pending_required
        && permit.empty_active_required
        && state.account_epoch_active
        && state.active_share_absent
        && permit.epoch >= INITIAL_EPOCH
        && state.account_epoch == permit.epoch
        && state.pending_epoch == permit.epoch
        && state.pending_split_matches
        && state.pending_share_present
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn competing_split_can_finalize(
    permit: PublicationFinalizePermit,
    mut state: PublicationStateFacts,
) -> bool {
    state.pending_split_matches = false;
    pending_publication_can_commit(permit, state)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn retired_epoch_publication_can_finalize(
    permit: PublicationFinalizePermit,
    mut state: PublicationStateFacts,
) -> bool {
    state.account_epoch = if permit.epoch == i64::MAX {
        permit.epoch - 1
    } else {
        permit.epoch + 1
    };
    pending_publication_can_commit(permit, state)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn already_finalized_epoch_can_finalize(
    permit: PublicationFinalizePermit,
    mut state: PublicationStateFacts,
) -> bool {
    state.active_share_absent = false;
    pending_publication_can_commit(permit, state)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryPhase {
    Unavailable,
    Ready,
    ChallengePending,
    GrantIssued,
    Completed,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitiateFacts {
    pub phase: RecoveryPhase,
    pub account_exists: bool,
    pub share_present: bool,
    pub credential_present: bool,
    pub attempt_id_fresh: bool,
    pub ttl_positive: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengePermit {
    bind_user_attempt_and_credential: bool,
}

impl ChallengePermit {
    pub const fn binds_user_attempt_and_credential(self) -> bool {
        self.bind_user_attempt_and_credential
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitiateDecision {
    Start(ChallengePermit),
    Reject,
}

pub fn initiation_is_authorized(facts: InitiateFacts) -> bool {
    facts.phase == RecoveryPhase::Ready
        && facts.account_exists
        && facts.share_present
        && facts.credential_present
        && facts.attempt_id_fresh
        && facts.ttl_positive
}

pub fn initiation_decision_matches_spec(facts: InitiateFacts, decision: InitiateDecision) -> bool {
    match decision {
        InitiateDecision::Start(permit) => {
            initiation_is_authorized(facts) && permit.bind_user_attempt_and_credential
        }
        InitiateDecision::Reject => !initiation_is_authorized(facts),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    initiation_decision_matches_spec(facts, decision)
}))]
pub fn plan_initiation(facts: InitiateFacts) -> InitiateDecision {
    if initiation_is_authorized(facts) {
        InitiateDecision::Start(ChallengePermit {
            bind_user_attempt_and_credential: true,
        })
    } else {
        InitiateDecision::Reject
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationFacts {
    pub device_scope: bool,
    pub account_matches: bool,
    pub challenge_pending: bool,
    pub challenge_consumed: bool,
    pub credential_valid: bool,
    pub credential_unique: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationPermit {
    authorized: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationDecision {
    Register(RegistrationPermit),
    Reject,
}

pub fn registration_is_authorized(facts: RegistrationFacts) -> bool {
    facts.device_scope
        && facts.account_matches
        && facts.challenge_pending
        && facts.challenge_consumed
        && facts.credential_valid
        && facts.credential_unique
}

pub fn registration_decision_matches_spec(
    facts: RegistrationFacts,
    decision: RegistrationDecision,
) -> bool {
    match decision {
        RegistrationDecision::Register(permit) => {
            registration_is_authorized(facts) && permit.authorized
        }
        RegistrationDecision::Reject => !registration_is_authorized(facts),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    registration_decision_matches_spec(facts, decision)
}))]
pub fn plan_registration(facts: RegistrationFacts) -> RegistrationDecision {
    if registration_is_authorized(facts) {
        RegistrationDecision::Register(RegistrationPermit { authorized: true })
    } else {
        RegistrationDecision::Reject
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoverFacts {
    pub phase: RecoveryPhase,
    pub user_matches: bool,
    pub attempt_matches: bool,
    pub challenge_consumed: bool,
    pub credential_matches_current: bool,
    pub assertion_valid: bool,
    pub user_verified: bool,
    pub share_present: bool,
    pub account_epoch_active: bool,
    pub epoch: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleasePermit {
    epoch: i64,
    issue_single_use_grant: bool,
}

impl ReleasePermit {
    pub const fn epoch(self) -> i64 {
        self.epoch
    }

    pub const fn issues_single_use_grant(self) -> bool {
        self.issue_single_use_grant
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoverDecision {
    Release(ReleasePermit),
    Reject,
}

pub fn recovery_is_authorized(facts: RecoverFacts) -> bool {
    facts.phase == RecoveryPhase::ChallengePending
        && facts.user_matches
        && facts.attempt_matches
        && facts.challenge_consumed
        && facts.credential_matches_current
        && facts.assertion_valid
        && facts.user_verified
        && facts.share_present
        && facts.account_epoch_active
        && facts.epoch >= INITIAL_EPOCH
}

pub fn recovery_decision_matches_spec(facts: RecoverFacts, decision: RecoverDecision) -> bool {
    match decision {
        RecoverDecision::Release(permit) => {
            recovery_is_authorized(facts)
                && permit.epoch == facts.epoch
                && permit.issue_single_use_grant
        }
        RecoverDecision::Reject => !recovery_is_authorized(facts),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    recovery_decision_matches_spec(facts, decision)
}))]
pub fn plan_recovery(facts: RecoverFacts) -> RecoverDecision {
    if recovery_is_authorized(facts) {
        RecoverDecision::Release(ReleasePermit {
            epoch: facts.epoch,
            issue_single_use_grant: true,
        })
    } else {
        RecoverDecision::Reject
    }
}

// ── RMS-possession recovery without WebAuthn (M18) ─────────────────────────
//
// A caller holding any two shares of the current split can reconstruct the
// RMS locally; the possession proof (challenge-bound keyed hash) then proves
// exactly that, so the server may issue an enrollment grant *without*
// releasing its own share or demanding a WebAuthn assertion.

/// Facts for starting a possession-proof recovery attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofInitiateFacts {
    pub phase: RecoveryPhase,
    pub account_exists: bool,
    pub share_present: bool,
    /// The staged RMS-possession commitment exists. Without it there is
    /// nothing to check proofs against.
    pub possession_hash_present: bool,
    pub attempt_id_fresh: bool,
    pub ttl_positive: bool,
}

pub fn proof_initiation_is_authorized(facts: ProofInitiateFacts) -> bool {
    facts.phase == RecoveryPhase::Ready
        && facts.account_exists
        && facts.share_present
        && facts.possession_hash_present
        && facts.attempt_id_fresh
        && facts.ttl_positive
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofInitiateDecision {
    Start,
    Reject,
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    matches!(decision, ProofInitiateDecision::Start) == proof_initiation_is_authorized(facts)
}))]
pub fn plan_proof_initiation(facts: ProofInitiateFacts) -> ProofInitiateDecision {
    if proof_initiation_is_authorized(facts) {
        ProofInitiateDecision::Start
    } else {
        ProofInitiateDecision::Reject
    }
}

/// Facts for redeeming one possession-proof attempt. The cryptographic
/// comparison itself stays outside this crate; `proof_verified` carries only
/// its authenticated outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PossessionRecoverFacts {
    pub phase: RecoveryPhase,
    pub user_matches: bool,
    pub attempt_matches: bool,
    pub challenge_consumed: bool,
    pub proof_verified: bool,
    pub account_epoch_active: bool,
    /// Epoch recorded with the staged commitment must equal the live epoch.
    pub commitment_epoch_matches: bool,
    pub epoch: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PossessionRecoverDecision {
    Grant(PossessionGrantPermit),
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PossessionGrantPermit {
    epoch: i64,
    issues_single_use_grant: bool,
}

impl PossessionGrantPermit {
    pub const fn epoch(self) -> i64 {
        self.epoch
    }

    /// A possession grant never releases Share 2 — the caller already proved
    /// they can reconstruct without it.
    pub const fn releases_server_share(self) -> bool {
        false
    }

    pub const fn issues_single_use_grant(self) -> bool {
        self.issues_single_use_grant
    }
}

pub fn possession_recovery_is_authorized(facts: PossessionRecoverFacts) -> bool {
    facts.phase == RecoveryPhase::ChallengePending
        && facts.user_matches
        && facts.attempt_matches
        && facts.challenge_consumed
        && facts.proof_verified
        && facts.account_epoch_active
        && facts.commitment_epoch_matches
        && facts.epoch >= INITIAL_EPOCH
}

pub fn possession_recovery_decision_matches_spec(
    facts: PossessionRecoverFacts,
    decision: PossessionRecoverDecision,
) -> bool {
    match decision {
        PossessionRecoverDecision::Grant(permit) => {
            possession_recovery_is_authorized(facts)
                && permit.epoch == facts.epoch
                && permit.issues_single_use_grant
                && !permit.releases_server_share()
        }
        PossessionRecoverDecision::Reject => !possession_recovery_is_authorized(facts),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    possession_recovery_decision_matches_spec(facts, decision)
}))]
pub fn plan_possession_recovery(
    facts: PossessionRecoverFacts,
) -> PossessionRecoverDecision {
    if possession_recovery_is_authorized(facts) {
        PossessionRecoverDecision::Grant(PossessionGrantPermit {
            epoch: facts.epoch,
            issues_single_use_grant: true,
        })
    } else {
        PossessionRecoverDecision::Reject
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unproven_possession_claim_can_recover(mut facts: PossessionRecoverFacts) -> bool {
    facts.proof_verified = false;
    possession_recovery_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn stale_commitment_can_recover(mut facts: PossessionRecoverFacts) -> bool {
    facts.commitment_epoch_matches = false;
    possession_recovery_is_authorized(facts)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialUpdateFacts {
    pub assertion_valid: bool,
    pub credential_matches_current: bool,
    pub needs_update: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialUpdateDecision {
    Update,
    Keep,
    Reject,
}

pub fn credential_update_decision_matches_spec(
    facts: CredentialUpdateFacts,
    decision: CredentialUpdateDecision,
) -> bool {
    decision
        == if !facts.assertion_valid || !facts.credential_matches_current {
            CredentialUpdateDecision::Reject
        } else if facts.needs_update {
            CredentialUpdateDecision::Update
        } else {
            CredentialUpdateDecision::Keep
        }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    credential_update_decision_matches_spec(facts, decision)
}))]
pub fn plan_credential_update(facts: CredentialUpdateFacts) -> CredentialUpdateDecision {
    if !facts.assertion_valid || !facts.credential_matches_current {
        CredentialUpdateDecision::Reject
    } else if facts.needs_update {
        CredentialUpdateDecision::Update
    } else {
        CredentialUpdateDecision::Keep
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollmentFacts {
    pub phase: RecoveryPhase,
    pub user_matches: bool,
    pub grant_live: bool,
    pub grant_consumed: bool,
    pub credential_matches_current: bool,
    /// True when the grant was issued from an RMS-possession proof (M18)
    /// rather than a WebAuthn assertion. Such grants are bound to no
    /// credential, so the credential-match requirement is waived — but the
    /// commitment that verified the proof must still be present.
    pub possession_grant: bool,
    /// The RMS-possession commitment staged at setup is still present.
    pub possession_hash_present: bool,
    pub public_keys_valid: bool,
    pub account_epoch_active: bool,
    pub grant_epoch: i64,
    pub account_epoch: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollmentPermit {
    epoch: i64,
}

impl EnrollmentPermit {
    pub const fn epoch(self) -> i64 {
        self.epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentDecision {
    Enroll(EnrollmentPermit),
    Reject,
}

pub fn enrollment_is_authorized(facts: EnrollmentFacts) -> bool {
    // WebAuthn grants are revoked when the credential is replaced; possession
    // grants are bound to no credential but die with their staged commitment.
    let grant_authority_ok = if facts.possession_grant {
        facts.possession_hash_present
    } else {
        facts.credential_matches_current
    };
    grant_authority_ok
        && facts.phase == RecoveryPhase::GrantIssued
        && facts.user_matches
        && facts.grant_live
        && facts.grant_consumed
        && facts.public_keys_valid
        && facts.account_epoch_active
        && facts.grant_epoch >= INITIAL_EPOCH
        && facts.grant_epoch == facts.account_epoch
}

pub fn enrollment_decision_matches_spec(
    facts: EnrollmentFacts,
    decision: EnrollmentDecision,
) -> bool {
    match decision {
        EnrollmentDecision::Enroll(permit) => {
            enrollment_is_authorized(facts) && permit.epoch == facts.grant_epoch
        }
        EnrollmentDecision::Reject => !enrollment_is_authorized(facts),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    enrollment_decision_matches_spec(facts, decision)
}))]
pub fn plan_enrollment(facts: EnrollmentFacts) -> EnrollmentDecision {
    if enrollment_is_authorized(facts) {
        EnrollmentDecision::Enroll(EnrollmentPermit {
            epoch: facts.grant_epoch,
        })
    } else {
        EnrollmentDecision::Reject
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn replaced_credential_can_recover(mut facts: RecoverFacts) -> bool {
    facts.credential_matches_current = false;
    recovery_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn consumed_challenge_can_recover_again(mut facts: RecoverFacts) -> bool {
    facts.phase = RecoveryPhase::Completed;
    recovery_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn cross_user_grant_can_enroll(mut facts: EnrollmentFacts) -> bool {
    facts.user_matches = false;
    enrollment_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn revoked_credential_grant_can_enroll(mut facts: EnrollmentFacts) -> bool {
    facts.credential_matches_current = false;
    facts.possession_grant = false;
    enrollment_is_authorized(facts)
}

/// A possession grant whose verifying commitment was deleted (setup removal,
/// RMS rotation) can no longer enroll.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn commitmentless_possession_grant_can_enroll(mut facts: EnrollmentFacts) -> bool {
    facts.possession_grant = true;
    facts.credential_matches_current = false;
    facts.possession_hash_present = false;
    enrollment_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn rotated_grant_can_enroll(mut facts: EnrollmentFacts) -> bool {
    facts.account_epoch = if facts.grant_epoch == i64::MAX {
        facts.grant_epoch - 1
    } else {
        facts.grant_epoch + 1
    };
    enrollment_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn consumed_grant_can_enroll_again(mut facts: EnrollmentFacts) -> bool {
    facts.phase = RecoveryPhase::Completed;
    enrollment_is_authorized(facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_recovery() -> RecoverFacts {
        RecoverFacts {
            phase: RecoveryPhase::ChallengePending,
            user_matches: true,
            attempt_matches: true,
            challenge_consumed: true,
            credential_matches_current: true,
            assertion_valid: true,
            user_verified: true,
            share_present: true,
            account_epoch_active: true,
            epoch: 1,
        }
    }

    #[test]
    fn publication_requires_exact_epoch_split_and_staged_share() {
        let PublicationStageDecision::Stage(_) = plan_publication_stage(PublicationStageRequest {
            declared_epoch: 7,
            split_id_present: true,
            server_share_present: true,
            device_authority: true,
        }) else {
            panic!("valid publication stage rejected");
        };
        let PublicationFinalizeDecision::Finalize(permit) =
            plan_publication_finalize(PublicationFinalizeRequest {
                declared_epoch: 7,
                split_id_present: true,
                device_authority: true,
            })
        else {
            panic!("valid publication finalization rejected");
        };
        let state = PublicationStateFacts {
            account_epoch_active: true,
            active_share_absent: true,
            account_epoch: 7,
            pending_epoch: 7,
            pending_split_matches: true,
            pending_share_present: true,
        };
        assert!(pending_publication_can_commit(permit, state));
        assert!(!competing_split_can_finalize(permit, state));
        assert!(!retired_epoch_publication_can_finalize(permit, state));
        assert!(!already_finalized_epoch_can_finalize(permit, state));
    }

    #[test]
    fn recovery_requires_the_current_credential_and_one_shot_challenge() {
        assert!(matches!(
            plan_recovery(valid_recovery()),
            RecoverDecision::Release(_)
        ));
        assert!(!replaced_credential_can_recover(valid_recovery()));
        assert!(!consumed_challenge_can_recover_again(valid_recovery()));
    }

    #[test]
    fn enrollment_requires_an_exact_live_epoch_grant() {
        let facts = EnrollmentFacts {
            phase: RecoveryPhase::GrantIssued,
            user_matches: true,
            grant_live: true,
            grant_consumed: true,
            credential_matches_current: true,
            possession_grant: false,
            possession_hash_present: false,
            public_keys_valid: true,
            account_epoch_active: true,
            grant_epoch: 4,
            account_epoch: 4,
        };
        assert!(matches!(
            plan_enrollment(facts),
            EnrollmentDecision::Enroll(permit) if permit.epoch() == 4
        ));
        assert!(!cross_user_grant_can_enroll(facts));
        assert!(!revoked_credential_grant_can_enroll(facts));
        assert!(!rotated_grant_can_enroll(facts));
        assert!(!consumed_grant_can_enroll_again(facts));

        // M18: a possession grant enrolls without any credential, but only
        // while its staged commitment is still present.
        let mut possession = facts;
        possession.credential_matches_current = false;
        assert!(!enrollment_is_authorized(possession));
        possession.possession_grant = true;
        assert!(!enrollment_is_authorized(possession));
        possession.possession_hash_present = true;
        assert!(matches!(
            plan_enrollment(possession),
            EnrollmentDecision::Enroll(_)
        ));
        assert!(!commitmentless_possession_grant_can_enroll(possession));
    }

    #[test]
    fn possession_recovery_requires_a_verified_bound_proof() {
        let facts = PossessionRecoverFacts {
            phase: RecoveryPhase::ChallengePending,
            user_matches: true,
            attempt_matches: true,
            challenge_consumed: true,
            proof_verified: true,
            account_epoch_active: true,
            commitment_epoch_matches: true,
            epoch: 4,
        };
        let PossessionRecoverDecision::Grant(permit) = plan_possession_recovery(facts) else {
            panic!("valid possession recovery rejected");
        };
        assert_eq!(permit.epoch(), 4);
        assert!(permit.issues_single_use_grant());
        assert!(!permit.releases_server_share());
        assert!(!unproven_possession_claim_can_recover(facts));
        assert!(!stale_commitment_can_recover(facts));
    }

    #[test]
    fn possession_initiation_requires_share_and_commitment() {
        let valid = ProofInitiateFacts {
            phase: RecoveryPhase::Ready,
            account_exists: true,
            share_present: true,
            possession_hash_present: true,
            attempt_id_fresh: true,
            ttl_positive: true,
        };
        assert_eq!(
            plan_proof_initiation(valid),
            ProofInitiateDecision::Start
        );
        for missing in [
            ProofInitiateFacts {
                share_present: false,
                ..valid
            },
            ProofInitiateFacts {
                possession_hash_present: false,
                ..valid
            },
        ] {
            assert_eq!(plan_proof_initiation(missing), ProofInitiateDecision::Reject);
        }
    }
}
