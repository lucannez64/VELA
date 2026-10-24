//! Pure policy for WebAuthn-gated account recovery and recovered-device
//! enrollment.
//!
//! WebAuthn, clocks, SQL, sled, UUIDs, and HTTP stay outside this crate. The
//! server converts their authenticated observations into facts and can release
//! a share, rotate a stored credential, or enroll a device only from the
//! private permits constructed here. hax extracts these exact decisions to F*.

pub const INITIAL_EPOCH: i64 = 1;
pub const HYBRID_EK_LEN: usize = 1568 + 32;
pub const HYBRID_VK_LEN: usize = 2592 + 32;

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

/// Raw observations from the recovery-initiation request, the `users` row and
/// the store slot that will hold the new attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitiateObservation {
    /// The `users` row exists for the requested user id.
    pub account_present: bool,
    /// The row's `recovery_share` column is non-null.
    pub share_present: bool,
    /// A recovery WebAuthn credential was decoded for the user.
    pub credential_present: bool,
    /// No stored attempt state already occupies the generated attempt id.
    pub attempt_id_fresh: bool,
    /// Lifetime requested for the stored challenge state.
    pub ttl_secs: u64,
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
    matches!(facts.phase, RecoveryPhase::Ready)
        && facts.account_exists
        && facts.share_present
        && facts.credential_present
        && facts.attempt_id_fresh
        && facts.ttl_positive
}

/// Turn raw account/share/credential/store observations into the initiation
/// facts. The phase names exactly the observed availability of an account,
/// its recovery share and its recovery credential; it is not supplied by the
/// caller.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    (matches!(facts.phase, RecoveryPhase::Ready)
        == (obs.account_present && obs.share_present && obs.credential_present))
        && (matches!(facts.phase, RecoveryPhase::Unavailable)
            == !(obs.account_present && obs.share_present && obs.credential_present))
        && facts.account_exists == obs.account_present
        && facts.share_present == obs.share_present
        && facts.credential_present == obs.credential_present
        && facts.attempt_id_fresh == obs.attempt_id_fresh
        && facts.ttl_positive == (obs.ttl_secs > 0)
}))]
pub fn initiate_facts(obs: InitiateObservation) -> InitiateFacts {
    let available = obs.account_present && obs.share_present && obs.credential_present;
    InitiateFacts {
        phase: if available {
            RecoveryPhase::Ready
        } else {
            RecoveryPhase::Unavailable
        },
        account_exists: obs.account_present,
        share_present: obs.share_present,
        credential_present: obs.credential_present,
        attempt_id_fresh: obs.attempt_id_fresh,
        ttl_positive: obs.ttl_secs > 0,
    }
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

/// Where a `/recovery/recover` request found the stored challenge state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAttemptSource {
    /// No stored challenge state matched this user/attempt id.
    Missing,
    /// The exact stored challenge was present and consumed by this request.
    Consumed,
}

/// Raw observations from `/recovery/recover`, the consumed challenge state,
/// the WebAuthn assertion and the `users` row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoverObservation {
    pub attempt_source: RecoveryAttemptSource,
    /// The stored challenge's user id equals the request user id.
    pub user_matches: bool,
    /// The stored challenge's attempt id equals the request attempt id.
    pub attempt_matches: bool,
    /// The assertion, the challenge state and the live row all name the same
    /// recovery credential.
    pub credential_matches_current: bool,
    /// WebAuthn verification returned an authentication result.
    pub assertion_valid: bool,
    /// The authenticator reported user verification.
    pub user_verified: bool,
    /// The row's `recovery_share` column is non-null.
    pub share_present: bool,
    /// The row's `rekey_state` column is clear.
    pub account_epoch_active: bool,
    /// `users.key_epoch` as stored; `None` means the column is absent.
    pub stored_epoch: Option<i64>,
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
    matches!(facts.phase, RecoveryPhase::ChallengePending)
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

/// Normalize a stored recovery epoch the same way the handler does: a missing
/// or non-positive column falls back to the initial epoch.
#[cfg_attr(hax, hax_lib::ensures(|epoch| {
    epoch == match stored_epoch {
        None => INITIAL_EPOCH,
        Some(value) => {
            if value < INITIAL_EPOCH {
                INITIAL_EPOCH
            } else {
                value
            }
        }
    }
}))]
pub fn observed_recovery_epoch(stored_epoch: Option<i64>) -> i64 {
    match stored_epoch {
        None => INITIAL_EPOCH,
        Some(value) => {
            if value < INITIAL_EPOCH {
                INITIAL_EPOCH
            } else {
                value
            }
        }
    }
}

/// Turn the consumed-attempt, assertion, credential and row observations into
/// the share-release facts. The phase and one-shot flag come from whether the
/// store actually returned (and removed) the exact challenge.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    (matches!(facts.phase, RecoveryPhase::ChallengePending)
        == matches!(obs.attempt_source, RecoveryAttemptSource::Consumed))
        && (matches!(facts.phase, RecoveryPhase::Expired)
            == matches!(obs.attempt_source, RecoveryAttemptSource::Missing))
        && facts.user_matches == obs.user_matches
        && facts.attempt_matches == obs.attempt_matches
        && facts.challenge_consumed
            == matches!(obs.attempt_source, RecoveryAttemptSource::Consumed)
        && facts.credential_matches_current == obs.credential_matches_current
        && facts.assertion_valid == obs.assertion_valid
        && facts.user_verified == obs.user_verified
        && facts.share_present == obs.share_present
        && facts.account_epoch_active == obs.account_epoch_active
        && facts.epoch == observed_recovery_epoch(obs.stored_epoch)
}))]
pub fn recover_facts(obs: RecoverObservation) -> RecoverFacts {
    let challenge_consumed = matches!(obs.attempt_source, RecoveryAttemptSource::Consumed);
    RecoverFacts {
        phase: if challenge_consumed {
            RecoveryPhase::ChallengePending
        } else {
            RecoveryPhase::Expired
        },
        user_matches: obs.user_matches,
        attempt_matches: obs.attempt_matches,
        challenge_consumed,
        credential_matches_current: obs.credential_matches_current,
        assertion_valid: obs.assertion_valid,
        user_verified: obs.user_verified,
        share_present: obs.share_present,
        account_epoch_active: obs.account_epoch_active,
        epoch: observed_recovery_epoch(obs.stored_epoch),
    }
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

/// Raw observations from the possession-proof initiation request, the `users`
/// row and the store slot for the new attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofInitiateObservation {
    /// The `users` row exists for the requested user id.
    pub account_present: bool,
    /// The row's `recovery_share` column is non-null.
    pub share_present: bool,
    /// Decoded byte length of `users.recovery_auth_hash`; zero means the
    /// commitment is missing or empty, so no proof can ever verify.
    pub commitment_len: usize,
    /// The row's `rekey_state` column is set.
    pub rotation_active: bool,
    /// No stored attempt state already occupies the generated attempt id.
    pub attempt_id_fresh: bool,
    /// Lifetime requested for the stored challenge state.
    pub ttl_secs: u64,
}

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
    matches!(facts.phase, RecoveryPhase::Ready)
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

/// Turn the account, share, decoded-commitment, rotation, store-slot and TTL
/// observations into the possession-initiation facts. `Ready` names exactly
/// the observed availability of an account, its recovery share and a non-empty
/// staged commitment on an account that is not rotating.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    (matches!(facts.phase, RecoveryPhase::Ready)
        == (obs.account_present
            && obs.share_present
            && obs.commitment_len > 0
            && !obs.rotation_active))
        && (matches!(facts.phase, RecoveryPhase::Unavailable)
            == !(obs.account_present
                && obs.share_present
                && obs.commitment_len > 0
                && !obs.rotation_active))
        && facts.account_exists == obs.account_present
        && facts.share_present == obs.share_present
        && facts.possession_hash_present == (obs.commitment_len > 0)
        && facts.attempt_id_fresh == obs.attempt_id_fresh
        && facts.ttl_positive == (obs.ttl_secs > 0)
}))]
pub fn proof_initiate_facts(obs: ProofInitiateObservation) -> ProofInitiateFacts {
    let available =
        obs.account_present && obs.share_present && obs.commitment_len > 0 && !obs.rotation_active;
    ProofInitiateFacts {
        phase: if available {
            RecoveryPhase::Ready
        } else {
            RecoveryPhase::Unavailable
        },
        account_exists: obs.account_present,
        share_present: obs.share_present,
        possession_hash_present: obs.commitment_len > 0,
        attempt_id_fresh: obs.attempt_id_fresh,
        ttl_positive: obs.ttl_secs > 0,
    }
}

/// Facts for redeeming one possession-proof attempt. The cryptographic
/// comparison itself stays outside this crate; `proof_verified` carries only
/// its authenticated outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PossessionRecoverFacts {
    pub phase: RecoveryPhase,
    /// The `users` row named by the attempt still exists.
    pub account_present: bool,
    pub user_matches: bool,
    pub attempt_matches: bool,
    pub challenge_consumed: bool,
    pub proof_verified: bool,
    pub account_epoch_active: bool,
    /// A non-empty staged commitment exists to verify proofs against.
    pub commitment_present: bool,
    /// Epoch recorded with the staged commitment must equal the live epoch.
    pub commitment_epoch_matches: bool,
    pub epoch: i64,
}

/// Raw observations from the consumed possession attempt, the decoded proof
/// state, the verification result and the live `users` row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PossessionRecoverObservation {
    /// Whether the exact user/attempt key was consumed by this request.
    pub attempt_source: RecoveryAttemptSource,
    /// The `users` row exists for the attempt's user id.
    pub account_present: bool,
    /// The decoded attempt envelope's user id equals the request user id.
    pub user_matches: bool,
    /// The decoded attempt envelope's id equals the request attempt id.
    pub attempt_matches: bool,
    /// The hybrid possession proof verified against the staged commitment.
    pub proof_verified: bool,
    /// The row's `rekey_state` column is clear.
    pub account_epoch_active: bool,
    /// Decoded byte length of `users.recovery_auth_hash`; zero means no
    /// commitment is staged.
    pub commitment_len: usize,
    /// Epoch decoded from the consumed attempt envelope (`PossessionProofState`).
    pub commitment_epoch: i64,
    /// `users.key_epoch` as stored; `None` means the column is absent.
    pub stored_epoch: Option<i64>,
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
    matches!(facts.phase, RecoveryPhase::ChallengePending)
        && facts.account_present
        && facts.user_matches
        && facts.attempt_matches
        && facts.challenge_consumed
        && facts.proof_verified
        && facts.account_epoch_active
        && facts.commitment_present
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
pub fn plan_possession_recovery(facts: PossessionRecoverFacts) -> PossessionRecoverDecision {
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

/// Turn the consumed-attempt, decoded-envelope, verification and row
/// observations into the possession-recovery facts. The phase and one-shot
/// flag come from whether the store actually returned (and removed) the exact
/// attempt; commitment presence and epoch equality come from the decoded
/// commitment length and the decoded envelope epoch.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    (matches!(facts.phase, RecoveryPhase::ChallengePending)
        == matches!(obs.attempt_source, RecoveryAttemptSource::Consumed))
        && (matches!(facts.phase, RecoveryPhase::Expired)
            == matches!(obs.attempt_source, RecoveryAttemptSource::Missing))
        && facts.account_present == obs.account_present
        && facts.user_matches == obs.user_matches
        && facts.attempt_matches == obs.attempt_matches
        && facts.challenge_consumed
            == matches!(obs.attempt_source, RecoveryAttemptSource::Consumed)
        && facts.proof_verified == obs.proof_verified
        && facts.account_epoch_active == obs.account_epoch_active
        && facts.commitment_present == (obs.commitment_len > 0)
        && facts.commitment_epoch_matches
            == (obs.commitment_epoch == observed_recovery_epoch(obs.stored_epoch))
        && facts.epoch == observed_recovery_epoch(obs.stored_epoch)
}))]
pub fn possession_recover_facts(obs: PossessionRecoverObservation) -> PossessionRecoverFacts {
    let challenge_consumed = matches!(obs.attempt_source, RecoveryAttemptSource::Consumed);
    let epoch = observed_recovery_epoch(obs.stored_epoch);
    PossessionRecoverFacts {
        phase: if challenge_consumed {
            RecoveryPhase::ChallengePending
        } else {
            RecoveryPhase::Expired
        },
        account_present: obs.account_present,
        user_matches: obs.user_matches,
        attempt_matches: obs.attempt_matches,
        challenge_consumed,
        proof_verified: obs.proof_verified,
        account_epoch_active: obs.account_epoch_active,
        commitment_present: obs.commitment_len > 0,
        commitment_epoch_matches: obs.commitment_epoch == epoch,
        epoch,
    }
}

/// Raw observations from the WebAuthn assertion and the live credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialUpdateObservation {
    /// WebAuthn verification returned an authentication result.
    pub assertion_valid: bool,
    /// The assertion's credential id equals the challenge-bound credential id.
    pub credential_matches_current: bool,
    /// The authenticator signalled updated credential metadata.
    pub needs_update: bool,
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

/// Turn the assertion result and stored-credential comparison into the
/// metadata-update facts.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    facts.assertion_valid == obs.assertion_valid
        && facts.credential_matches_current == obs.credential_matches_current
        && facts.needs_update == obs.needs_update
}))]
pub fn credential_update_facts(obs: CredentialUpdateObservation) -> CredentialUpdateFacts {
    CredentialUpdateFacts {
        assertion_valid: obs.assertion_valid,
        credential_matches_current: obs.credential_matches_current,
        needs_update: obs.needs_update,
    }
}

pub fn credential_update_decision_matches_spec(
    facts: CredentialUpdateFacts,
    decision: CredentialUpdateDecision,
) -> bool {
    if !facts.assertion_valid || !facts.credential_matches_current {
        matches!(decision, CredentialUpdateDecision::Reject)
    } else if facts.needs_update {
        matches!(decision, CredentialUpdateDecision::Update)
    } else {
        matches!(decision, CredentialUpdateDecision::Keep)
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

// ── Pre-redemption sequencing gate ─────────────────────────────────────────
//
// The handler must reject account/epoch/rotation/credential/commitment
// problems *before* it spends the single-use grant, and it must not query the
// account at all when the unguessable grant is missing. This kernel is that
// ordering decision. Its permit is only permission to attempt the atomic
// `get_del`; it is not an enrollment permit and it carries no claim that
// consumption happened.

/// Decoded grant facts observed by the non-consuming lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollmentGrantFacts {
    /// `key_epoch` decoded from the stored grant.
    pub epoch: i64,
    /// The grant was minted from an RMS-possession proof (M18).
    pub possession: bool,
}

/// Live `users`-row facts. Constructed only after the grant lookup succeeded,
/// so a failed grant lookup cannot disclose account state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollmentAccountFacts {
    /// `users.key_epoch` as stored; `None` means the column is absent.
    pub stored_epoch: Option<i64>,
    /// The row's `rekey_state` column is clear.
    pub epoch_active: bool,
    /// The decoded grant credential id equals the row's current recovery
    /// credential id. Ignored for possession grants.
    pub credential_id_matches: bool,
    /// Decoded byte length of `users.recovery_auth_hash`; zero means the
    /// possession commitment is absent or empty.
    pub commitment_len: usize,
}

/// Whether the account query ran. `NotQueried` is the deliberate privacy state
/// for a missing grant and is never treated as an observed absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentAccountObservation {
    NotQueried,
    Absent,
    Present(EnrollmentAccountFacts),
}

/// Raw observations available before the single-use grant is redeemed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollmentPreflightObservation {
    /// The non-consuming lookup under `(user_id, grant)` returned a decoded
    /// grant. This is a store-key binding, not an embedded user id.
    pub grant: Option<EnrollmentGrantFacts>,
    pub account: EnrollmentAccountObservation,
}

/// The first failed precondition, in the handler's historical status/message
/// precedence order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentPreflightRejection {
    /// No grant was stored under the request's user/grant key.
    GrantUnavailable,
    /// A grant was observed but the account observation was not supplied.
    /// This is a fail-closed internal state, not an observed account absence.
    AccountUnavailable,
    /// The account query ran and found no row.
    AccountAbsent,
    /// The decoded grant epoch differs from the normalized live epoch.
    EpochMismatch,
    /// `users.rekey_state` is set; enrollment must wait for rotation.
    RotationPaused,
    /// A WebAuthn-bound grant's credential is no longer current.
    CredentialReplaced,
    /// A possession grant's staged commitment is absent or empty.
    CommitmentMissing,
}

/// Permission to attempt the atomic single-use redemption. It says nothing
/// about whether the grant was actually consumed or whether a device may be
/// inserted; `plan_enrollment` decides the latter from the actual consumed
/// grant and the final observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadyToConsume {
    epoch: i64,
    possession: bool,
}

impl ReadyToConsume {
    pub const fn epoch(self) -> i64 {
        self.epoch
    }

    pub const fn possession(self) -> bool {
        self.possession
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentPreflightDecision {
    Ready(ReadyToConsume),
    Reject(EnrollmentPreflightRejection),
}

/// WebAuthn grants need their exact credential; possession grants need their
/// staged commitment. The grant value carries no commitment id or generation,
/// so this is presence, not an exact binding.
pub fn enrollment_preflight_authority(account: EnrollmentAccountFacts, possession: bool) -> bool {
    if possession {
        account.commitment_len > 0
    } else {
        account.credential_id_matches
    }
}

/// The first rejection reason in status/message precedence order, or `None`
/// when the redemption may be attempted.
pub fn enrollment_preflight_rejection(
    obs: EnrollmentPreflightObservation,
) -> Option<EnrollmentPreflightRejection> {
    match obs.grant {
        None => Some(EnrollmentPreflightRejection::GrantUnavailable),
        Some(grant) => match obs.account {
            EnrollmentAccountObservation::NotQueried => {
                Some(EnrollmentPreflightRejection::AccountUnavailable)
            }
            EnrollmentAccountObservation::Absent => {
                Some(EnrollmentPreflightRejection::AccountAbsent)
            }
            EnrollmentAccountObservation::Present(account) => {
                if observed_recovery_epoch(account.stored_epoch) != grant.epoch {
                    Some(EnrollmentPreflightRejection::EpochMismatch)
                } else if !account.epoch_active {
                    Some(EnrollmentPreflightRejection::RotationPaused)
                } else if grant.possession && account.commitment_len == 0 {
                    Some(EnrollmentPreflightRejection::CommitmentMissing)
                } else if !grant.possession && !account.credential_id_matches {
                    Some(EnrollmentPreflightRejection::CredentialReplaced)
                } else {
                    None
                }
            }
        },
    }
}

/// Structural reason equality, kept explicit so the extracted kernel does not
/// depend on a derived `PartialEq` instance (hax would emit a trusted
/// declaration for that instance).
pub fn enrollment_preflight_rejection_matches(
    actual: EnrollmentPreflightRejection,
    expected: EnrollmentPreflightRejection,
) -> bool {
    match (actual, expected) {
        (
            EnrollmentPreflightRejection::GrantUnavailable,
            EnrollmentPreflightRejection::GrantUnavailable,
        )
        | (
            EnrollmentPreflightRejection::AccountUnavailable,
            EnrollmentPreflightRejection::AccountUnavailable,
        )
        | (
            EnrollmentPreflightRejection::AccountAbsent,
            EnrollmentPreflightRejection::AccountAbsent,
        )
        | (
            EnrollmentPreflightRejection::EpochMismatch,
            EnrollmentPreflightRejection::EpochMismatch,
        )
        | (
            EnrollmentPreflightRejection::RotationPaused,
            EnrollmentPreflightRejection::RotationPaused,
        )
        | (
            EnrollmentPreflightRejection::CredentialReplaced,
            EnrollmentPreflightRejection::CredentialReplaced,
        )
        | (
            EnrollmentPreflightRejection::CommitmentMissing,
            EnrollmentPreflightRejection::CommitmentMissing,
        ) => true,
        _ => false,
    }
}

/// A preflight observation is ready exactly when no rejection reason applies.
pub fn enrollment_preflight_is_ready(obs: EnrollmentPreflightObservation) -> bool {
    match enrollment_preflight_rejection(obs) {
        None => true,
        Some(_) => false,
    }
}

pub fn enrollment_preflight_decision_matches_spec(
    obs: EnrollmentPreflightObservation,
    decision: EnrollmentPreflightDecision,
) -> bool {
    match decision {
        EnrollmentPreflightDecision::Ready(permit) => {
            enrollment_preflight_is_ready(obs)
                && match obs.grant {
                    Some(grant) => {
                        permit.epoch == grant.epoch && permit.possession == grant.possession
                    }
                    None => false,
                }
        }
        EnrollmentPreflightDecision::Reject(reason) => match enrollment_preflight_rejection(obs) {
            Some(actual) => enrollment_preflight_rejection_matches(actual, reason),
            None => false,
        },
    }
}

/// Decide whether the handler may attempt to consume the grant, and why not
/// otherwise. This function has no effect and cannot observe consumption.
#[cfg_attr(hax, hax_lib::ensures(|decision| {
    enrollment_preflight_decision_matches_spec(obs, decision)
}))]
pub fn plan_enrollment_preflight(
    obs: EnrollmentPreflightObservation,
) -> EnrollmentPreflightDecision {
    match enrollment_preflight_rejection(obs) {
        Some(reason) => EnrollmentPreflightDecision::Reject(reason),
        None => match obs.grant {
            Some(grant) => EnrollmentPreflightDecision::Ready(ReadyToConsume {
                epoch: grant.epoch,
                possession: grant.possession,
            }),
            // Unreachable: a missing grant always yields `GrantUnavailable`.
            None => {
                EnrollmentPreflightDecision::Reject(EnrollmentPreflightRejection::GrantUnavailable)
            }
        },
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_preflight_grant_can_be_ready(mut obs: EnrollmentPreflightObservation) -> bool {
    obs.grant = None;
    enrollment_preflight_is_ready(obs)
}

/// A grant lookup that did not run the account query must never be treated as
/// an observed absence, let alone as ready.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unqueried_preflight_account_can_be_ready(mut obs: EnrollmentPreflightObservation) -> bool {
    obs.account = EnrollmentAccountObservation::NotQueried;
    enrollment_preflight_is_ready(obs)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn absent_preflight_account_can_be_ready(mut obs: EnrollmentPreflightObservation) -> bool {
    obs.account = EnrollmentAccountObservation::Absent;
    enrollment_preflight_is_ready(obs)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn epoch_mismatched_preflight_account_can_be_ready(
    mut obs: EnrollmentPreflightObservation,
) -> bool {
    obs.grant = Some(EnrollmentGrantFacts {
        epoch: INITIAL_EPOCH,
        possession: false,
    });
    obs.account = EnrollmentAccountObservation::Present(EnrollmentAccountFacts {
        stored_epoch: Some(INITIAL_EPOCH + 1),
        epoch_active: true,
        credential_id_matches: true,
        commitment_len: 0,
    });
    enrollment_preflight_is_ready(obs)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn rekeying_preflight_account_can_be_ready(mut obs: EnrollmentPreflightObservation) -> bool {
    obs.grant = Some(EnrollmentGrantFacts {
        epoch: INITIAL_EPOCH,
        possession: false,
    });
    obs.account = EnrollmentAccountObservation::Present(EnrollmentAccountFacts {
        stored_epoch: Some(INITIAL_EPOCH),
        epoch_active: false,
        credential_id_matches: true,
        commitment_len: 0,
    });
    enrollment_preflight_is_ready(obs)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn replaced_preflight_credential_can_be_ready(mut obs: EnrollmentPreflightObservation) -> bool {
    obs.grant = Some(EnrollmentGrantFacts {
        epoch: INITIAL_EPOCH,
        possession: false,
    });
    obs.account = EnrollmentAccountObservation::Present(EnrollmentAccountFacts {
        stored_epoch: Some(INITIAL_EPOCH),
        epoch_active: true,
        credential_id_matches: false,
        commitment_len: 0,
    });
    enrollment_preflight_is_ready(obs)
}

/// A possession grant whose staged commitment is absent or empty must not be
/// consumed. The check is presence-only; it does not bind an exact commitment.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn commitmentless_preflight_possession_can_be_ready(
    mut obs: EnrollmentPreflightObservation,
) -> bool {
    obs.grant = Some(EnrollmentGrantFacts {
        epoch: INITIAL_EPOCH,
        possession: true,
    });
    obs.account = EnrollmentAccountObservation::Present(EnrollmentAccountFacts {
        stored_epoch: Some(INITIAL_EPOCH),
        epoch_active: true,
        credential_id_matches: false,
        commitment_len: 0,
    });
    enrollment_preflight_is_ready(obs)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollmentFacts {
    pub phase: RecoveryPhase,
    /// The `users` row named by the grant still exists.
    pub account_present: bool,
    /// The observed grant was loaded under the request's `(user_id, grant)`
    /// store key. This is a caller-supplied store-key binding, not an independent
    /// identity comparison: the grant value has no embedded user id.
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

/// Raw observations from the enrollment grant store, the decoded grant and
/// the live `users` row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollmentObservation {
    /// A non-consuming lookup under `(user_id, grant)` returned a decoded
    /// grant. A grant stored for any other user or id cannot produce this.
    pub grant_present: bool,
    /// The consuming lookup returned a grant (the single-use artifact was
    /// actually removed by this request).
    pub grant_consumed: bool,
    /// The consumed grant equals the grant observed before validation; false
    /// means a concurrent request replaced it.
    pub consumed_matches_observed: bool,
    /// The `users` row exists for the grant's user.
    pub account_present: bool,
    /// The decoded grant marks an RMS-possession grant.
    pub grant_possession: bool,
    /// `key_epoch` decoded from the observed grant (the initial epoch when
    /// no grant was observed).
    pub grant_epoch: i64,
    /// `users.key_epoch` as stored; `None` means the column is absent.
    pub stored_epoch: Option<i64>,
    /// The row's `rekey_state` column is clear.
    pub account_epoch_active: bool,
    /// The decoded grant credential id equals the row's current recovery
    /// credential id.
    pub credential_id_matches: bool,
    /// Decoded byte length of `users.recovery_auth_hash`; zero means the
    /// possession commitment is absent or empty.
    pub commitment_len: usize,
    /// Lengths of the actual base64-decoded hybrid public keys.
    pub hybrid_ek_len: usize,
    pub hybrid_vk_len: usize,
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
        && matches!(facts.phase, RecoveryPhase::GrantIssued)
        && facts.account_present
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

/// Turn the grant-store, decoded-grant and `users`-row observations into the
/// enrollment facts. The phase distinguishes a consumed grant from a missing
/// or race-replaced one; user binding, consumption, credential/commitment
/// authority and the normalized grant/account epoch equality are exactly the
/// observed values.
#[cfg_attr(hax, hax_lib::ensures(|facts| {
    (matches!(facts.phase, RecoveryPhase::GrantIssued)
        == (obs.grant_present
            && obs.grant_consumed
            && obs.consumed_matches_observed))
        && (matches!(facts.phase, RecoveryPhase::Expired) == !obs.grant_present)
        && (matches!(facts.phase, RecoveryPhase::Revoked)
            == (obs.grant_present
                && !(obs.grant_consumed && obs.consumed_matches_observed)))
        && facts.account_present == obs.account_present
        && facts.user_matches == obs.grant_present
        && facts.grant_live == obs.grant_present
        && facts.grant_consumed
            == (obs.grant_consumed && obs.consumed_matches_observed)
        && facts.credential_matches_current == obs.credential_id_matches
        && facts.possession_grant == obs.grant_possession
        && facts.possession_hash_present == (obs.commitment_len > 0)
        && facts.public_keys_valid
            == (obs.hybrid_ek_len == HYBRID_EK_LEN && obs.hybrid_vk_len == HYBRID_VK_LEN)
        && facts.account_epoch_active == obs.account_epoch_active
        && facts.grant_epoch == obs.grant_epoch
        && facts.account_epoch == observed_recovery_epoch(obs.stored_epoch)
}))]
pub fn enrollment_facts(obs: EnrollmentObservation) -> EnrollmentFacts {
    let consumed = obs.grant_consumed && obs.consumed_matches_observed;
    EnrollmentFacts {
        phase: if obs.grant_present && consumed {
            RecoveryPhase::GrantIssued
        } else if !obs.grant_present {
            RecoveryPhase::Expired
        } else {
            RecoveryPhase::Revoked
        },
        account_present: obs.account_present,
        user_matches: obs.grant_present,
        grant_live: obs.grant_present,
        grant_consumed: consumed,
        credential_matches_current: obs.credential_id_matches,
        possession_grant: obs.grant_possession,
        possession_hash_present: obs.commitment_len > 0,
        public_keys_valid: obs.hybrid_ek_len == HYBRID_EK_LEN && obs.hybrid_vk_len == HYBRID_VK_LEN,
        account_epoch_active: obs.account_epoch_active,
        grant_epoch: obs.grant_epoch,
        account_epoch: observed_recovery_epoch(obs.stored_epoch),
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

// ── Composition and rejection theorems over the observation constructors ───

/// The initiation policy over the real observation is exactly the conjunction
/// of the observed availability and freshness values.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    result == (obs.account_present
        && obs.share_present
        && obs.credential_present
        && obs.attempt_id_fresh
        && obs.ttl_secs > 0)
}))]
pub fn initiate_facts_authorize(obs: InitiateObservation) -> bool {
    initiation_is_authorized(initiate_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_recovery_share_can_initiate(mut obs: InitiateObservation) -> bool {
    obs.share_present = false;
    initiation_is_authorized(initiate_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn credentialless_account_can_initiate(mut obs: InitiateObservation) -> bool {
    obs.credential_present = false;
    initiation_is_authorized(initiate_facts(obs))
}

/// A generated attempt id that already occupies stored state is not fresh.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn colliding_attempt_id_can_initiate(mut obs: InitiateObservation) -> bool {
    obs.attempt_id_fresh = false;
    initiation_is_authorized(initiate_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn expired_initiate_ttl_can_start(mut obs: InitiateObservation) -> bool {
    obs.ttl_secs = 0;
    initiation_is_authorized(initiate_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unverified_assertion_can_update_credential(mut obs: CredentialUpdateObservation) -> bool {
    obs.assertion_valid = false;
    matches!(
        plan_credential_update(credential_update_facts(obs)),
        CredentialUpdateDecision::Update
    )
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn stale_assertion_credential_can_update(mut obs: CredentialUpdateObservation) -> bool {
    obs.credential_matches_current = false;
    matches!(
        plan_credential_update(credential_update_facts(obs)),
        CredentialUpdateDecision::Update
    )
}

/// Normalization can never produce an epoch below the initial epoch, so the
/// epoch guard in `recovery_is_authorized` is implied for every observation.
#[cfg_attr(hax, hax_lib::ensures(|result| result == true))]
pub fn observed_recovery_epoch_is_active(stored_epoch: Option<i64>) -> bool {
    observed_recovery_epoch(stored_epoch) >= INITIAL_EPOCH
}

/// Share release over the real observation is exactly the conjunction of the
/// consumed exact attempt, the assertion and credential bindings, the row
/// observations and an active normalized epoch.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    result == (matches!(obs.attempt_source, RecoveryAttemptSource::Consumed)
        && obs.user_matches
        && obs.attempt_matches
        && obs.credential_matches_current
        && obs.assertion_valid
        && obs.user_verified
        && obs.share_present
        && obs.account_epoch_active
        && observed_recovery_epoch(obs.stored_epoch) >= INITIAL_EPOCH)
}))]
pub fn recover_facts_authorize(obs: RecoverObservation) -> bool {
    recovery_is_authorized(recover_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_attempt_can_release(mut obs: RecoverObservation) -> bool {
    obs.attempt_source = RecoveryAttemptSource::Missing;
    recovery_is_authorized(recover_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn cross_user_recover_observation_can_release(mut obs: RecoverObservation) -> bool {
    obs.user_matches = false;
    recovery_is_authorized(recover_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn mismatched_attempt_observation_can_release(mut obs: RecoverObservation) -> bool {
    obs.attempt_matches = false;
    recovery_is_authorized(recover_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn replaced_observed_credential_can_release(mut obs: RecoverObservation) -> bool {
    obs.credential_matches_current = false;
    recovery_is_authorized(recover_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unverified_observed_assertion_can_release(mut obs: RecoverObservation) -> bool {
    obs.assertion_valid = false;
    recovery_is_authorized(recover_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unverified_observation_user_can_release(mut obs: RecoverObservation) -> bool {
    obs.user_verified = false;
    recovery_is_authorized(recover_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_observed_share_can_release(mut obs: RecoverObservation) -> bool {
    obs.share_present = false;
    recovery_is_authorized(recover_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn rekeying_observed_account_can_release(mut obs: RecoverObservation) -> bool {
    obs.account_epoch_active = false;
    recovery_is_authorized(recover_facts(obs))
}

/// Possession initiation is authorized exactly when the account, share and a
/// non-empty decoded commitment are observed on a non-rotating account, the
/// generated attempt slot is free and the requested TTL is positive.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    result == (obs.account_present
        && obs.share_present
        && obs.commitment_len > 0
        && !obs.rotation_active
        && obs.attempt_id_fresh
        && obs.ttl_secs > 0)
}))]
pub fn proof_initiate_facts_authorize(obs: ProofInitiateObservation) -> bool {
    proof_initiation_is_authorized(proof_initiate_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn absent_account_can_start_possession_proof(mut obs: ProofInitiateObservation) -> bool {
    obs.account_present = false;
    proof_initiation_is_authorized(proof_initiate_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_share_can_start_possession_proof(mut obs: ProofInitiateObservation) -> bool {
    obs.share_present = false;
    proof_initiation_is_authorized(proof_initiate_facts(obs))
}

/// A row whose commitment is absent or empty can never verify a proof, so it
/// must not yield a challenge.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn commitmentless_account_can_start_possession_proof(
    mut obs: ProofInitiateObservation,
) -> bool {
    obs.commitment_len = 0;
    proof_initiation_is_authorized(proof_initiate_facts(obs))
}

/// Rotation retires the share and the commitment together, so no new
/// possession challenge may start while `rekey_state` is set.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn rotating_account_can_start_possession_proof(mut obs: ProofInitiateObservation) -> bool {
    obs.rotation_active = true;
    proof_initiation_is_authorized(proof_initiate_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn colliding_possession_attempt_id_can_start(mut obs: ProofInitiateObservation) -> bool {
    obs.attempt_id_fresh = false;
    proof_initiation_is_authorized(proof_initiate_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn expired_possession_initiate_ttl_can_start(mut obs: ProofInitiateObservation) -> bool {
    obs.ttl_secs = 0;
    proof_initiation_is_authorized(proof_initiate_facts(obs))
}

/// Possession grant issuance is authorized exactly when the exact attempt was
/// consumed, the decoded identity bindings match, the proof verified, the
/// account row is present and not rotating, a non-empty commitment is staged
/// at the current normalized epoch.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    result == (matches!(obs.attempt_source, RecoveryAttemptSource::Consumed)
        && obs.account_present
        && obs.user_matches
        && obs.attempt_matches
        && obs.proof_verified
        && obs.account_epoch_active
        && obs.commitment_len > 0
        && obs.commitment_epoch == observed_recovery_epoch(obs.stored_epoch)
        && observed_recovery_epoch(obs.stored_epoch) >= INITIAL_EPOCH)
}))]
pub fn possession_recover_facts_authorize(obs: PossessionRecoverObservation) -> bool {
    possession_recovery_is_authorized(possession_recover_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_possession_attempt_can_recover(mut obs: PossessionRecoverObservation) -> bool {
    obs.attempt_source = RecoveryAttemptSource::Missing;
    possession_recovery_is_authorized(possession_recover_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn absent_possession_account_can_recover(mut obs: PossessionRecoverObservation) -> bool {
    obs.account_present = false;
    possession_recovery_is_authorized(possession_recover_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn cross_user_possession_observation_can_recover(
    mut obs: PossessionRecoverObservation,
) -> bool {
    obs.user_matches = false;
    possession_recovery_is_authorized(possession_recover_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn mismatched_possession_attempt_observation_can_recover(
    mut obs: PossessionRecoverObservation,
) -> bool {
    obs.attempt_matches = false;
    possession_recovery_is_authorized(possession_recover_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unverified_possession_observation_can_recover(
    mut obs: PossessionRecoverObservation,
) -> bool {
    obs.proof_verified = false;
    possession_recovery_is_authorized(possession_recover_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn rekeying_possession_observation_can_recover(mut obs: PossessionRecoverObservation) -> bool {
    obs.account_epoch_active = false;
    possession_recovery_is_authorized(possession_recover_facts(obs))
}

/// Without a non-empty staged commitment there is nothing to verify a proof
/// against, so a possession grant must not issue.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_possession_commitment_can_recover(mut obs: PossessionRecoverObservation) -> bool {
    obs.commitment_len = 0;
    possession_recovery_is_authorized(possession_recover_facts(obs))
}

/// A commitment decoded at a different epoch than the live normalized one is
/// stale, so its proof must not issue a grant.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn rotated_commitment_observation_can_recover(mut obs: PossessionRecoverObservation) -> bool {
    let epoch = observed_recovery_epoch(obs.stored_epoch);
    obs.commitment_epoch = if epoch == i64::MAX {
        INITIAL_EPOCH
    } else {
        epoch + 1
    };
    possession_recovery_is_authorized(possession_recover_facts(obs))
}

/// Enrollment is authorized exactly when a live grant was consumed without a
/// concurrent replacement, the user row is present, the credential (or the
/// staged possession commitment for M18 grants) still authorizes, the decoded
/// keys are valid, the account is not rotating, and the decoded grant epoch
/// equals the normalized live account epoch.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    result == (obs.grant_present
        && obs.grant_consumed
        && obs.consumed_matches_observed
        && obs.account_present
        && (if obs.grant_possession {
            obs.commitment_len > 0
        } else {
            obs.credential_id_matches
        })
        && obs.hybrid_ek_len == HYBRID_EK_LEN
        && obs.hybrid_vk_len == HYBRID_VK_LEN
        && obs.account_epoch_active
        && obs.grant_epoch >= INITIAL_EPOCH
        && obs.grant_epoch == observed_recovery_epoch(obs.stored_epoch))
}))]
pub fn enrollment_facts_authorize(obs: EnrollmentObservation) -> bool {
    enrollment_is_authorized(enrollment_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn missing_enrollment_grant_observation_can_enroll(mut obs: EnrollmentObservation) -> bool {
    obs.grant_present = false;
    enrollment_is_authorized(enrollment_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unconsumed_enrollment_grant_observation_can_enroll(mut obs: EnrollmentObservation) -> bool {
    obs.grant_consumed = false;
    enrollment_is_authorized(enrollment_facts(obs))
}

/// A concurrent request that replaced the grant between the non-consuming
/// read and the single-use redemption must not enroll.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn replaced_enrollment_grant_observation_can_enroll(mut obs: EnrollmentObservation) -> bool {
    obs.consumed_matches_observed = false;
    enrollment_is_authorized(enrollment_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn absent_enrollment_account_can_enroll(mut obs: EnrollmentObservation) -> bool {
    obs.account_present = false;
    enrollment_is_authorized(enrollment_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn rekeying_enrollment_observation_can_enroll(mut obs: EnrollmentObservation) -> bool {
    obs.account_epoch_active = false;
    enrollment_is_authorized(enrollment_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn replaced_credential_observation_can_enroll(mut obs: EnrollmentObservation) -> bool {
    obs.credential_id_matches = false;
    obs.grant_possession = false;
    enrollment_is_authorized(enrollment_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn commitmentless_possession_observation_can_enroll(mut obs: EnrollmentObservation) -> bool {
    obs.grant_possession = true;
    obs.credential_id_matches = false;
    obs.commitment_len = 0;
    enrollment_is_authorized(enrollment_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn rotated_enrollment_observation_can_enroll(mut obs: EnrollmentObservation) -> bool {
    let epoch = observed_recovery_epoch(obs.stored_epoch);
    obs.grant_epoch = if epoch == i64::MAX {
        INITIAL_EPOCH
    } else {
        epoch + 1
    };
    enrollment_is_authorized(enrollment_facts(obs))
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn invalid_public_keys_observation_can_enroll(obs: EnrollmentObservation) -> bool {
    if obs.hybrid_ek_len == HYBRID_EK_LEN && obs.hybrid_vk_len == HYBRID_VK_LEN {
        return false;
    }
    enrollment_is_authorized(enrollment_facts(obs))
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
    fn preflight_decides_redemption_without_claiming_consumption() {
        let live = EnrollmentAccountFacts {
            stored_epoch: Some(4),
            epoch_active: true,
            credential_id_matches: true,
            commitment_len: 0,
        };
        let ready = EnrollmentPreflightObservation {
            grant: Some(EnrollmentGrantFacts {
                epoch: 4,
                possession: false,
            }),
            account: EnrollmentAccountObservation::Present(live),
        };
        let EnrollmentPreflightDecision::Ready(permit) = plan_enrollment_preflight(ready) else {
            panic!("valid preflight rejected");
        };
        assert_eq!(permit.epoch(), 4);
        assert!(!permit.possession());
        assert!(enrollment_preflight_is_ready(ready));
        assert_eq!(enrollment_preflight_rejection(ready), None);

        let missing = EnrollmentPreflightObservation {
            grant: None,
            account: EnrollmentAccountObservation::NotQueried,
        };
        assert_eq!(
            plan_enrollment_preflight(missing),
            EnrollmentPreflightDecision::Reject(EnrollmentPreflightRejection::GrantUnavailable)
        );

        let unqueried = EnrollmentPreflightObservation {
            grant: ready.grant,
            account: EnrollmentAccountObservation::NotQueried,
        };
        assert_eq!(
            plan_enrollment_preflight(unqueried),
            EnrollmentPreflightDecision::Reject(EnrollmentPreflightRejection::AccountUnavailable)
        );

        let absent = EnrollmentPreflightObservation {
            grant: ready.grant,
            account: EnrollmentAccountObservation::Absent,
        };
        assert_eq!(
            plan_enrollment_preflight(absent),
            EnrollmentPreflightDecision::Reject(EnrollmentPreflightRejection::AccountAbsent)
        );

        let mismatched = EnrollmentPreflightObservation {
            grant: ready.grant,
            account: EnrollmentAccountObservation::Present(EnrollmentAccountFacts {
                stored_epoch: Some(5),
                ..live
            }),
        };
        assert_eq!(
            plan_enrollment_preflight(mismatched),
            EnrollmentPreflightDecision::Reject(EnrollmentPreflightRejection::EpochMismatch)
        );

        // Precedence: rotation outranks a stale credential.
        let rotating = EnrollmentPreflightObservation {
            grant: ready.grant,
            account: EnrollmentAccountObservation::Present(EnrollmentAccountFacts {
                epoch_active: false,
                credential_id_matches: false,
                ..live
            }),
        };
        assert_eq!(
            plan_enrollment_preflight(rotating),
            EnrollmentPreflightDecision::Reject(EnrollmentPreflightRejection::RotationPaused)
        );

        let replaced = EnrollmentPreflightObservation {
            grant: ready.grant,
            account: EnrollmentAccountObservation::Present(EnrollmentAccountFacts {
                credential_id_matches: false,
                ..live
            }),
        };
        assert_eq!(
            plan_enrollment_preflight(replaced),
            EnrollmentPreflightDecision::Reject(EnrollmentPreflightRejection::CredentialReplaced)
        );

        let commitmentless = EnrollmentPreflightObservation {
            grant: Some(EnrollmentGrantFacts {
                epoch: 4,
                possession: true,
            }),
            account: EnrollmentAccountObservation::Present(EnrollmentAccountFacts {
                credential_id_matches: false,
                commitment_len: 0,
                ..live
            }),
        };
        assert_eq!(
            plan_enrollment_preflight(commitmentless),
            EnrollmentPreflightDecision::Reject(EnrollmentPreflightRejection::CommitmentMissing)
        );

        let possession = EnrollmentPreflightObservation {
            grant: Some(EnrollmentGrantFacts {
                epoch: 4,
                possession: true,
            }),
            account: EnrollmentAccountObservation::Present(EnrollmentAccountFacts {
                credential_id_matches: false,
                commitment_len: 1,
                ..live
            }),
        };
        assert!(matches!(
            plan_enrollment_preflight(possession),
            EnrollmentPreflightDecision::Ready(permit) if permit.possession()
        ));
    }

    #[test]
    fn enrollment_requires_an_exact_live_epoch_grant() {
        let facts = EnrollmentFacts {
            phase: RecoveryPhase::GrantIssued,
            account_present: true,
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
            account_present: true,
            user_matches: true,
            attempt_matches: true,
            challenge_consumed: true,
            proof_verified: true,
            account_epoch_active: true,
            commitment_present: true,
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
        assert_eq!(plan_proof_initiation(valid), ProofInitiateDecision::Start);
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
            assert_eq!(
                plan_proof_initiation(missing),
                ProofInitiateDecision::Reject
            );
        }
    }

    #[test]
    fn observation_constructors_cover_decoded_possession_and_enrollment_state() {
        let proof_obs = ProofInitiateObservation {
            account_present: true,
            share_present: true,
            commitment_len: 2624,
            rotation_active: false,
            attempt_id_fresh: true,
            ttl_secs: 300,
        };
        assert_eq!(
            plan_proof_initiation(proof_initiate_facts(proof_obs)),
            ProofInitiateDecision::Start
        );
        assert!(proof_initiate_facts_authorize(proof_obs));
        assert!(!rotating_account_can_start_possession_proof(proof_obs));
        assert!(!commitmentless_account_can_start_possession_proof(
            proof_obs
        ));

        let possession_obs = PossessionRecoverObservation {
            attempt_source: RecoveryAttemptSource::Consumed,
            account_present: true,
            user_matches: true,
            attempt_matches: true,
            proof_verified: true,
            account_epoch_active: true,
            commitment_len: 2624,
            commitment_epoch: 4,
            stored_epoch: Some(4),
        };
        let PossessionRecoverDecision::Grant(permit) =
            plan_possession_recovery(possession_recover_facts(possession_obs))
        else {
            panic!("valid decoded possession observation rejected");
        };
        assert_eq!(permit.epoch(), 4);
        assert!(!permit.releases_server_share());
        assert!(possession_recover_facts_authorize(possession_obs));
        assert!(!missing_possession_commitment_can_recover(possession_obs));
        assert!(!rotated_commitment_observation_can_recover(possession_obs));

        let enrollment_obs = EnrollmentObservation {
            grant_present: true,
            grant_consumed: true,
            consumed_matches_observed: true,
            account_present: true,
            grant_possession: true,
            grant_epoch: 4,
            stored_epoch: Some(4),
            account_epoch_active: true,
            credential_id_matches: false,
            commitment_len: 2624,
            hybrid_ek_len: 1600,
            hybrid_vk_len: 2624,
        };
        assert!(matches!(
            plan_enrollment(enrollment_facts(enrollment_obs)),
            EnrollmentDecision::Enroll(permit) if permit.epoch() == 4
        ));
        assert!(enrollment_facts_authorize(enrollment_obs));
        assert!(!commitmentless_possession_observation_can_enroll(
            enrollment_obs
        ));
        assert!(!unconsumed_enrollment_grant_observation_can_enroll(
            enrollment_obs
        ));
        assert!(!rotated_enrollment_observation_can_enroll(enrollment_obs));
    }
}
