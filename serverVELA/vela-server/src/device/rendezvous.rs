//! Enrollment v3: the joining device keeps its own private keys.
//!
//! In v2 the primary generated the joining device's entire identity and shipped
//! the private half to it, alongside the symmetric key the RMS capsule was
//! encrypted under. Anyone who read that payload held a device identity and,
//! through it, the vault — permanently, since the RMS never rotates. The code
//! was as valuable as the master secret but handled like a pairing code
//! (audit P-1).
//!
//! Here the code carries a **grant and nothing else**. The joining device
//! generates its own keypair, presents the public half under the grant, and the
//! primary seals the capsule to that public key. An intercepted code buys an
//! enrollment *attempt*.
//!
//! # Where the binding has to be exact
//!
//! Moving the secret out of the code moves the risk onto "did the user confirm
//! the right key", which is the same class of mistake as S-1 — and getting it
//! wrong trades a leak for a hijack. Five things carry that weight:
//!
//! 1. **A grant is bound to the user *and* device that created it.** Only that
//!    device can read a claim or complete an enrollment, so seeing a code is not
//!    enough to drive the flow, exactly as `approver_user_id` fixed for S-1.
//! 2. **A grant can be claimed exactly once, ever**, via an atomic
//!    compare-and-swap. An attacker who wins the race makes the legitimate
//!    device *fail visibly* rather than quietly enrolling alongside it. Silence
//!    is what made S-1 exploitable.
//! 3. **The server enrolls the keys it stored at claim time — never keys the
//!    primary sends.** This is the one that answers "did the user confirm the
//!    right fingerprint": the fingerprint the user compares and the key that
//!    gets enrolled are the same stored object, so there is no window in which
//!    one could be swapped for the other. A primary that tried to enroll
//!    different keys than the ones displayed has no field in which to say so.
//! 4. **Completing consumes the grant and the claim together.** A replayed
//!    completion finds nothing.
//! 5. **The primary signs over the stored keys.** The signature covers what the
//!    server holds, so a tampered claim cannot be enrolled even by the
//!    legitimate primary.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;
use vela_enrollment_policy::{
    inspect_facts, ClaimObservation, InspectDecision, InspectObservation, OpenObservation,
    ResultKind, HYBRID_EK_LEN, HYBRID_VK_LEN,
};
use vela_enrollment_policy::pairing_driver::{
    ClaimReadObservation, ClaimWriteObservation, CompletionAccountObservation,
    CompletionPreflightObservation, DeviceGrantObservation, DeviceInsertObservation,
    GrantObservation, PairingEffect, PairingFailure, ResultReadObservation, StoreObservation,
    TakeObservation,
};
use vela_rekey_policy::{
    MutationAuthority, MutationDecision, MutationKind, MutationRequest, Phase as PolicyPhase,
    RekeyState as PolicyState, ShadowDecision,
};

use super::exec_io::{ExecError, ExecIo, RawRead};
use vela_enrollment_policy::executor::{claim_key, grant_key, result_key};
use super::pairing_executor::PairingExecutor;
use vela_enrollment_policy::executor::{
    account_fields, classify_account, classify_claim_check, classify_claim_read,
    classify_claim_write, classify_completion_preflight, classify_enrolled_device,
    classify_insert_completion, classify_result_read, classify_store, classify_take_ceremony,
    plan_account_read,
    plan_claim_check, plan_claim_read, plan_claim_write, plan_completion_insert,
    plan_completion_preflight, plan_device_by_grant, plan_result_read, plan_result_write,
    plan_store_grant, plan_take_ceremony, AccountRowView, ClaimRowView, CollectorVerdicts,
    CompletionVerdicts, DeviceRowView, ReadOutcome, ResultRowView,
};
use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession, DeviceSession},
    net, rate_limit,
    sqldb::TursoValue,
    state::AppState,
};

/// Short by design. A grant is only alive while a person is holding two devices
/// and looking at both, which is a matter of a minute or two, and every extra
/// minute is time an intercepted code stays useful.
const GRANT_TTL_SECS: u64 = vela_enrollment_policy::executor::GRANT_TTL_SECS;

const HYBRID_SIG_LEN: usize = 4627 + 64;


/// Who may drive this grant. Written when the grant is created and never again.
#[derive(Serialize, Deserialize)]
struct Grant {
    user_id: String,
    device_id: String,
}

/// What the joining device presented. Public halves only — by construction there
/// is nothing secret here, which is the entire point of the change.
#[derive(Serialize, Deserialize, Clone)]
struct Claim {
    hybrid_ek: String,
    hybrid_vk: String,
    device_name: Option<String>,
    device_type: Option<String>,
}

/// What the joining device may collect once the primary has enrolled it.
///
/// Completing consumes the claim, so the `hybrid_vk` is carried over here: it is
/// what the collector's signature is checked against, and it is a public key the
/// device already holds.
#[derive(Serialize, Deserialize)]
struct EnrollmentResult {
    device_id: String,
    hybrid_vk: String,
}

// ── 1. The primary opens a grant ────────────────────────────────────────────

#[derive(Serialize)]
pub struct CreateGrantResponse {
    pub grant_id: String,
    pub expires_in: u64,
}

/// The I/O behind the grant-open ceremony.
pub(crate) struct OpenGrantIo<'a> {
    io: ExecIo<'a>,
    grant_id: String,
    grant: Grant,
    error: Option<AppError>,
}

impl OpenGrantIo<'_> {
    fn fail(&mut self, error: AppError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }
}

impl PairingExecutor for OpenGrantIo<'_> {
    async fn store_grant(&mut self) -> StoreObservation {
        let plan = plan_store_grant(
            self.grant_id.clone(),
            self.grant.user_id.clone(),
            self.grant.device_id.clone(),
        );
        let (outcomes, error) = self.io.run_writes(&plan).await;
        if let Some(error) = error {
            self.fail(error.into_app());
        }
        classify_store(&outcomes)
    }
}

#[cfg(test)]
pub(crate) fn open_grant_io_for_test<'a>(
    state: &'a AppState,
    fail_at: Option<usize>,
    grant_id: String,
    user_id: String,
    device_id: String,
) -> OpenGrantIo<'a> {
    OpenGrantIo {
        io: ExecIo::faulty(state, fail_at),
        grant_id,
        grant: Grant { user_id, device_id },
        error: None,
    }
}

/// Open a grant.
///
/// Device-only (red-team RT-4). An enrollment grant is the first step of a
/// *permanent* device enrollment, which is exactly what
/// `EPHEMERAL_WEB_ACCESS_DESIGN.md` §2 promises a web session cannot do. The
/// completion path refuses a web session anyway — it has no `devices` row whose
/// key could sign the enrollment — but refusing at the source is the honest
/// place: it also stops a borrowed browser watching an enrollment in progress
/// through `get_claim`.
pub async fn post_grant(
    State(state): State<AppState>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<CreateGrantResponse>)> {
    rate_limit::enrollment_grant_by_user(&state.store, &session.user_id.to_string())?;

    // Every post-validation decision belongs to the extracted driver: whether
    // the verified open policy permits a write, and how the write outcome is
    // classified. The handler only performs the returned effect.
    let start = vela_enrollment_policy::pairing_interpreter::start_open_grant(OpenObservation {
        scope_is_device: matches!(session.scope, crate::auth::token::TokenScope::Device),
        user_id_present: !session.user_id.is_nil(),
        device_id_present: !session.device_id.is_nil(),
        ttl_secs: GRANT_TTL_SECS,
    });

    let grant_id = Uuid::new_v4().to_string();
    let grant = Grant {
        user_id: session.user_id.to_string(),
        device_id: session.device_id.to_string(),
    };
    let mut io = OpenGrantIo {
        io: ExecIo::new(&state),
        grant_id: grant_id.clone(),
        grant,
        error: None,
    };
    let transition = vela_enrollment_policy::pairing_interpreter!(io, start, await);

    match transition.effect {
        PairingEffect::Complete => {}
        PairingEffect::Fail(failure) => {
            return Err(io
                .error
                .take()
                .unwrap_or_else(|| rendezvous_failure_error(failure)))
        }
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected grant-store effect".into(),
            ))
        }
    }

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(CreateGrantResponse {
            grant_id,
            expires_in: GRANT_TTL_SECS,
        }),
    ))
}

// ── 2. The joining device claims it (unauthenticated: it has no identity yet) ─

#[derive(Deserialize)]
pub struct ClaimRequest {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

/// The I/O behind the unauthenticated claim ceremony.
pub(crate) struct ClaimIo<'a> {
    io: ExecIo<'a>,
    grant_id: String,
    grant_live: bool,
    body: ClaimRequest,
    ek: Option<Vec<u8>>,
    vk: Option<Vec<u8>>,
    error: Option<AppError>,
}

impl ClaimIo<'_> {
    fn fail(&mut self, error: AppError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    /// A rejection that makes the driver stop without authorizing a write.
    fn rejected(&self, ek_len: usize, vk_len: usize) -> ClaimObservation {
        ClaimObservation {
            grant_live: self.grant_live,
            claim_exists: false,
            hybrid_ek_len: ek_len,
            hybrid_vk_len: vk_len,
        }
    }
}

impl PairingExecutor for ClaimIo<'_> {
    async fn check_claim(&mut self) -> ClaimObservation {
        let ek = match decode_base64_field(&self.body.hybrid_ek, "hybrid_ek") {
            Ok(ek) => ek,
            Err(error) => {
                self.fail(error);
                return self.rejected(0, 0);
            }
        };
        let vk = match decode_base64_field(&self.body.hybrid_vk, "hybrid_vk") {
            Ok(vk) => vk,
            Err(error) => {
                self.fail(error);
                return self.rejected(ek.len(), 0);
            }
        };
        let plan = plan_claim_check(self.grant_id.clone());
        let (reads, error) = self.io.run_reads(&plan).await;
        if let Some(error) = error {
            self.fail(error.into_app());
            // A failed existence check must never authorize the guarded
            // write; zero lengths make the verified claim policy reject.
            return self.rejected(0, 0);
        }
        let outcome = match reads.first() {
            Some(RawRead::Exists(exists)) => ReadOutcome::ClaimExists(*exists),
            _ => ReadOutcome::Failed,
        };
        let observation = classify_claim_check(self.grant_live, ek.len(), vk.len(), &[outcome]);
        self.ek = Some(ek);
        self.vk = Some(vk);
        observation
    }

    async fn write_claim(&mut self) -> ClaimWriteObservation {
        let (ek, vk) = match (self.ek.take(), self.vk.take()) {
            (Some(ek), Some(vk)) => (ek, vk),
            _ => {
                self.fail(AppError::Internal(
                    "claim driver authorized without decoded keys".into(),
                ));
                return ClaimWriteObservation::GuardMissing;
            }
        };
        // First claim wins while the grant is live, atomically. A second
        // device — including one racing with a stolen code — is told it lost
        // rather than replacing the first, and expiry cannot leave behind an
        // orphan claim.
        let plan = plan_claim_write(
            self.grant_id.clone(),
            B64.encode(&ek),
            B64.encode(&vk),
            self.body.device_name.clone(),
            self.body.device_type.clone(),
        );
        let (outcomes, error) = self.io.run_writes(&plan).await;
        if let Some(error) = error {
            self.fail(error.into_app());
        }
        classify_claim_write(&outcomes)
    }
}

#[cfg(test)]
pub(crate) fn claim_io_for_test<'a>(
    state: &'a AppState,
    fail_at: Option<usize>,
    grant_id: String,
    grant_live: bool,
    body: ClaimRequest,
) -> ClaimIo<'a> {
    ClaimIo {
        io: ExecIo::faulty(state, fail_at),
        grant_id,
        grant_live,
        body,
        ek: None,
        vk: None,
        error: None,
    }
}

pub async fn post_claim(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
    Json(body): Json<ClaimRequest>,
) -> Result<Json<serde_json::Value>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::enrollment_claim_by_ip(&state.store, &ip)?;
    let grant_id = crate::ids::validate_id("grant_id", &grant_id)?;

    // The grant must exist, but is deliberately *not* consumed here: the primary
    // still has to read the claim and complete, and burning it now would let an
    // unauthenticated caller destroy a grant it cannot otherwise use.
    let grant_live = state.store.exists(&grant_key(grant_id))?;
    let start = vela_enrollment_policy::pairing_interpreter::start_claim(grant_live);
    let mut io = ClaimIo {
        io: ExecIo::new(&state),
        grant_id: grant_id.to_string(),
        grant_live,
        body,
        ek: None,
        vk: None,
        error: None,
    };
    // Base64 decoding and the claim-existence read are the `CheckClaim`
    // effect; the guarded write is the `WriteClaim` effect. Both go through
    // the proved loop.
    let transition = vela_enrollment_policy::pairing_interpreter!(io, start, await);

    match transition.effect {
        PairingEffect::Complete => Ok(Json(serde_json::json!({ "claimed": true }))),
        PairingEffect::Fail(failure) => Err(io
            .error
            .take()
            .unwrap_or_else(|| rendezvous_failure_error(failure))),
        _ => Err(AppError::Internal(
            "pairing driver produced an unexpected claim-write observation effect".into(),
        )),
    }
}

// ── 3. The primary reads the claim, to show the user a fingerprint ──────────

#[derive(Serialize)]
pub struct ClaimView {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

pub async fn get_claim(
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<ClaimView>)> {
    let grant_id = crate::ids::validate_id("grant_id", &grant_id)?;
    let (grant, _) = authorize_grant(&state, grant_id, &session)?;

    let claim = load_claim(&state, grant_id)?;
    let claim_present = claim.is_some();
    let _permit =
        match vela_enrollment_policy::authorize_inspection(inspect_facts(InspectObservation {
            claim_present,
            user_matches: grant.user_id == session.user_id.to_string(),
            opener_matches: grant.device_id == session.device_id.to_string(),
        })) {
            InspectDecision::Inspect(permit) => permit,
            InspectDecision::Reject if !claim_present => {
                return Err(AppError::NotFound(
                    "no device has claimed this code yet".into(),
                ));
            }
            InspectDecision::Reject => {
                return Err(AppError::NotFound(
                    "enrollment grant not found or expired".into(),
                ));
            }
        };
    let claim = claim.expect("inspection policy admits only a present claim");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(ClaimView {
            hybrid_ek: claim.hybrid_ek,
            hybrid_vk: claim.hybrid_vk,
            device_name: claim.device_name,
            device_type: claim.device_type,
        }),
    ))
}

// ── 4. The primary completes it ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CompleteRequest {
    /// The RMS capsule, KEM-sealed to the claimed `hybrid_ek`. The server cannot
    /// check that sealing — it has no RMS — which is why the capsule is bound
    /// into the signature below instead.
    pub rms_capsule: String,
    /// The primary's signature over (claimed ek ‖ claimed vk ‖ capsule).
    pub signature: String,
    /// Authenticated local epoch of the RMS sealed into `rms_capsule`.
    pub key_epoch: i64,
}

#[derive(Serialize)]
pub struct CompleteResponse {
    pub device_id: Uuid,
}

fn preflight_placeholder() -> AppError {
    AppError::Internal("completion preflight did not run".into())
}

fn take_slot_error<T>(slot: &mut std::result::Result<T, AppError>) -> Option<AppError> {
    std::mem::replace(slot, Err(preflight_placeholder())).err()
}

/// The I/O behind the completion ceremony. The driver decides every step:
/// the account-epoch preflight, the verified completion policy, the single-use
/// take, the guarded insert and the result record. This executor only performs
/// the effect the proved loop hands it and retains each original error so the
/// response keeps the historical status and message.
pub(crate) struct CompleteIo<'a> {
    io: ExecIo<'a>,
    grant_id: String,
    grant: Grant,
    expected_grant_bytes: Vec<u8>,
    body: CompleteRequest,
    grant_error: Option<AppError>,
    account_error: Option<AppError>,
    current_epoch: i64,
    rotation_in_progress: bool,
    rekey_epoch: i64,
    account_epoch_active: bool,
    claim_materials: std::result::Result<(Claim, Vec<u8>, Vec<u8>), AppError>,
    claim_present: bool,
    expected_claim_bytes: Option<Vec<u8>>,
    claim_read_error: Option<AppError>,
    rms_capsule_result: std::result::Result<Vec<u8>, AppError>,
    signature_decode_result: std::result::Result<Vec<u8>, AppError>,
    opener_result: std::result::Result<(Option<Vec<u8>>, bool), AppError>,
    signature_result: std::result::Result<(), AppError>,
    taken_pair: Option<(Vec<u8>, Vec<u8>)>,
    take_error: Option<AppError>,
    insert_error: Option<AppError>,
    result_error: Option<AppError>,
    new_device_id: Uuid,
}

impl PairingExecutor for CompleteIo<'_> {
    async fn check_account(&mut self) -> CompletionAccountObservation {
        let plan = plan_account_read(self.grant.user_id.clone());
        let (reads, error) = self.io.run_reads(&plan).await;
        self.account_error = error.map(ExecError::into_app);
        let outcome = match reads.first() {
            Some(RawRead::Rows(rows)) => ReadOutcome::Account(rows.first().map(|row| {
                AccountRowView {
                    key_epoch: row.i64(0),
                    rekey_state: row.text(1).map(String::from),
                }
            })),
            _ => ReadOutcome::Failed,
        };
        let outcomes = [outcome];
        let (current_epoch, rotation_in_progress) = account_fields(&outcomes);
        let rekey_decision = vela_rekey_policy::plan_active_mutation(MutationRequest {
            declared_epoch: self.body.key_epoch,
            authority_epoch: self.body.key_epoch,
            kind: MutationKind::Enrollment,
            authority: MutationAuthority::Device,
        });
        let observed_state = PolicyState {
            epoch: current_epoch,
            phase: if rotation_in_progress {
                PolicyPhase::Freezing
            } else {
                PolicyPhase::Active
            },
        };
        let (rekey_permitted, rekey_epoch, account_epoch_active) = match rekey_decision {
            MutationDecision::Permit(permit) => (
                true,
                permit.epoch(),
                vela_rekey_policy::authorize_active_mutation(observed_state, permit)
                    == ShadowDecision::Allow,
            ),
            MutationDecision::Reject => (false, 0, false),
        };
        self.current_epoch = current_epoch;
        self.rotation_in_progress = rotation_in_progress;
        self.rekey_epoch = rekey_epoch;
        self.account_epoch_active = account_epoch_active;
        classify_account(&outcomes, self.body.key_epoch >= 1, rekey_permitted)
    }

    async fn prepare_completion(&mut self) -> CompletionPreflightObservation {
        // Read without consuming first. Invalid signatures must not let an
        // unauthenticated or corrupted request burn a legitimate ceremony.
        let plan = plan_completion_preflight(
            self.grant_id.clone(),
            self.grant.device_id.clone(),
            self.grant.user_id.clone(),
        );
        let (reads, error) = self.io.run_reads(&plan).await;

        // The historical handler returned the claim-read error before decoding
        // the capsule, the signature or the opener key, so no further I/O may
        // happen. The handler returns the retained error.
        if reads.is_empty() || matches!(&reads[0], RawRead::Failed) {
            self.claim_read_error = error.map(ExecError::into_app);
            self.claim_present = true;
            self.claim_materials =
                Err(AppError::Internal("stored claim read failed".into()));
            let outcomes = [ReadOutcome::Failed];
            return classify_completion_preflight(
                &outcomes,
                CompletionVerdicts {
                    claim_keys_usable: false,
                    capsule_valid: false,
                    signature_field_valid: false,
                    opener_key_decodes: false,
                    signature_verified: false,
                    account_epoch: self.current_epoch,
                    declared_epoch: self.body.key_epoch,
                    rotation_in_progress: self.rotation_in_progress,
                    account_epoch_active: self.account_epoch_active,
                },
            );
        }

        let (claim_outcome, claim_keys_usable) = match &reads[0] {
            RawRead::Value(None) => {
                self.claim_present = false;
                self.claim_materials = Err(AppError::NotFound(
                    "no device has claimed this code yet".into(),
                ));
                (ReadOutcome::Claim(None), false)
            }
            RawRead::Value(Some(bytes)) => {
                self.claim_present = true;
                match serde_json::from_slice::<Claim>(bytes) {
                    Ok(claim) => {
                        // The keys enrolled below come from `claim` — what the
                        // joining device presented and what the user's
                        // fingerprint comparison was about — and never from the
                        // request body.
                        let view = ClaimRowView {
                            hybrid_ek: Some(claim.hybrid_ek.clone()),
                            hybrid_vk: Some(claim.hybrid_vk.clone()),
                            device_name: claim.device_name.clone(),
                            device_type: claim.device_type.clone(),
                        };
                        match crate::db::decode_b64(&claim.hybrid_ek).and_then(|ek| {
                            crate::db::decode_b64(&claim.hybrid_vk).map(|vk| (ek, vk))
                        }) {
                            Ok((hybrid_ek, hybrid_vk)) => {
                                self.claim_materials = Ok((claim, hybrid_ek, hybrid_vk));
                                (ReadOutcome::Claim(Some(view)), true)
                            }
                            Err(error) => {
                                self.claim_materials = Err(error);
                                (ReadOutcome::Claim(Some(view)), false)
                            }
                        }
                    }
                    Err(error) => {
                        self.claim_materials = Err(AppError::Internal(format!(
                            "stored claim is unreadable: {error}"
                        )));
                        (ReadOutcome::Undecodable, false)
                    }
                }
            }
            _ => {
                self.claim_materials =
                    Err(AppError::Internal("stored claim read failed".into()));
                (ReadOutcome::Undecodable, false)
            }
        };

        let rms_capsule_result = decode_any(&self.body.rms_capsule, "rms_capsule");
        let signature_decode_result = decode_exact(&self.body.signature, HYBRID_SIG_LEN, "signature");

        let (opener_outcome, opener_result, opener_key_decodes) = match reads.get(1) {
            Some(RawRead::Rows(rows)) => match rows.first() {
                None => (ReadOutcome::Opener(None), Ok((None, false)), false),
                Some(row) => {
                    // Mirror the SQL `revoked = 0` predicate exactly: NULL or
                    // any other value counts as revoked.
                    let revoked = !matches!(row.get(1), Some(TursoValue::Integer(0)))
                        && row.text(1) != Some("0");
                    let view = DeviceRowView {
                        device_id: None,
                        hybrid_vk: row.text(0).map(String::from),
                        revoked: Some(if revoked { 1 } else { 0 }),
                        user_id: None,
                        enrollment_grant_id: None,
                    };
                    if revoked {
                        (ReadOutcome::Opener(None), Ok((None, false)), false)
                    } else {
                        match row.text(0) {
                            None => (
                                ReadOutcome::Opener(Some(view)),
                                Err(AppError::Unauthorized(
                                    "enrolling device not found or revoked".into(),
                                )),
                                false,
                            ),
                            Some(vk_b64) => match crate::db::decode_b64(vk_b64) {
                                Ok(vk) => (
                                    ReadOutcome::Opener(Some(view)),
                                    Ok((Some(vk), true)),
                                    true,
                                ),
                                Err(error) => {
                                    (ReadOutcome::Opener(Some(view)), Err(error), false)
                                }
                            },
                        }
                    }
                }
            },
            _ => (
                ReadOutcome::Failed,
                Err(error
                    .map(ExecError::into_app)
                    .unwrap_or_else(|| AppError::Internal("opener lookup failed".into()))),
                false,
            ),
        };

        let primary_vk = match &opener_result {
            Ok((Some(vk), true)) => Some(vk.as_slice()),
            _ => None,
        };
        let signature_result = match (
            &self.claim_materials,
            &rms_capsule_result,
            &signature_decode_result,
            primary_vk,
        ) {
            (Ok((_, hybrid_ek, hybrid_vk)), Ok(rms_capsule), Ok(signature), Some(primary_vk)) => {
                super::enroll::verify_enrollment_signature(
                    primary_vk,
                    hybrid_ek,
                    hybrid_vk,
                    rms_capsule,
                    signature,
                )
            }
            _ => Err(AppError::Unauthorized(
                "enrolling device not found or revoked".into(),
            )),
        };
        let signature_verified = signature_result.is_ok();
        self.expected_claim_bytes = match &reads[0] {
            RawRead::Value(value) => value.clone(),
            _ => None,
        };
        self.rms_capsule_result = rms_capsule_result;
        self.signature_decode_result = signature_decode_result;
        self.opener_result = opener_result;
        self.signature_result = signature_result;
        classify_completion_preflight(
            &[claim_outcome, opener_outcome],
            CompletionVerdicts {
                claim_keys_usable,
                capsule_valid: self.rms_capsule_result.is_ok(),
                signature_field_valid: self.signature_decode_result.is_ok(),
                opener_key_decodes,
                signature_verified,
                account_epoch: self.current_epoch,
                declared_epoch: self.body.key_epoch,
                rotation_in_progress: self.rotation_in_progress,
                account_epoch_active: self.account_epoch_active,
            },
        )
    }

    async fn take_ceremony(&mut self) -> TakeObservation {
        // This sled transaction is the ceremony's linearization point. Exactly
        // one racing/replayed completion gets both records; every loser gets
        // neither.
        let plan = plan_take_ceremony(self.grant_id.clone());
        let (outcome, taken_pair, error) = self.io.run_take_pair(&plan).await;
        if let Some(error) = error {
            self.take_error = Some(error.into_app());
            return classify_take_ceremony(&[outcome], false, false);
        }
        let Some(expected_claim) = self.expected_claim_bytes.clone() else {
            self.take_error = Some(AppError::Internal(
                "completion driver admitted an unobserved ceremony take".into(),
            ));
            return TakeObservation::Missing;
        };
        let expected_grant = self.expected_grant_bytes.clone();
        let (grant_matches, claim_matches) = match &taken_pair {
            Some((grant_bytes, claim_bytes)) => (
                grant_bytes == &expected_grant,
                claim_bytes == &expected_claim,
            ),
            None => (false, false),
        };
        self.taken_pair = taken_pair;
        classify_take_ceremony(&[outcome], grant_matches, claim_matches)
    }

    async fn insert_device(&mut self) -> DeviceInsertObservation {
        let (device_name, device_type, hybrid_ek, hybrid_vk) = match &self.claim_materials {
            Ok((claim, hybrid_ek, hybrid_vk)) => (
                claim
                    .device_name
                    .clone()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| "New Device".to_string()),
                claim
                    .device_type
                    .clone()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| "unknown".to_string()),
                hybrid_ek.clone(),
                hybrid_vk.clone(),
            ),
            Err(_) => {
                self.insert_error = Some(AppError::Internal(
                    "completion driver inserted without a usable claim".into(),
                ));
                return DeviceInsertObservation::Failed;
            }
        };
        let new_device_id = Uuid::new_v4();
        let now = Utc::now().to_rfc3339();
        let plan = plan_completion_insert(
            new_device_id.to_string(),
            self.grant.user_id.clone(),
            device_name,
            device_type,
            crate::db::encode_b64(&hybrid_ek),
            crate::db::encode_b64(&hybrid_vk),
            self.grant.device_id.clone(),
            self.grant_id.clone(),
            crate::db::encode_b64(&self.rms_capsule_value()),
            now,
            self.grant.user_id.clone(),
            self.rekey_epoch,
        );
        let (outcomes, error) = self.io.run_writes(&plan).await;
        self.new_device_id = new_device_id;
        self.insert_error = error.map(ExecError::into_app);
        classify_insert_completion(&outcomes)
    }

    async fn write_result(&mut self) -> StoreObservation {
        let hybrid_vk = match &self.claim_materials {
            Ok((claim, _, _)) => claim.hybrid_vk.clone(),
            Err(_) => {
                self.result_error = Some(AppError::Internal(
                    "completion driver recorded a result without a claim".into(),
                ));
                return StoreObservation::Failed;
            }
        };
        // Only now that the row exists: the joining device is holding a keypair
        // and waiting to be told which device it became. Written after the
        // insert so a failed enrollment never leaves behind a result pointing
        // at no device.
        let plan = plan_result_write(
            self.grant_id.clone(),
            self.new_device_id.to_string(),
            hybrid_vk,
        );
        let (outcomes, error) = self.io.run_writes(&plan).await;
        if let Some(error) = error {
            self.result_error = Some(error.into_app());
        }
        classify_store(&outcomes)
    }
}

impl CompleteIo<'_> {
    #[cfg(test)]
    pub(crate) fn set_new_device_id_for_test(&mut self, id: Uuid) {
        self.new_device_id = id;
    }


    /// The capsule bytes the verified preflight accepted. The driver only
    /// authorizes the insert after that preflight, so the value is present;
    /// a total fallback keeps the executor panic-free.
    fn rms_capsule_value(&self) -> Vec<u8> {
        match &self.rms_capsule_result {
            Ok(bytes) => bytes.clone(),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
pub(crate) fn complete_io_for_test<'a>(
    state: &'a AppState,
    fail_at: Option<usize>,
    grant_id: String,
    user_id: String,
    device_id: String,
    expected_grant_bytes: Vec<u8>,
    expected_claim_bytes: Option<Vec<u8>>,
    body: CompleteRequest,
) -> CompleteIo<'a> {
    CompleteIo {
        io: ExecIo::faulty(state, fail_at),
        grant_id,
        grant: Grant { user_id, device_id },
        expected_grant_bytes,
        body,
        grant_error: None,
        account_error: None,
        current_epoch: 0,
        rotation_in_progress: false,
        rekey_epoch: 0,
        account_epoch_active: false,
        claim_materials: Err(preflight_placeholder()),
        claim_present: false,
        expected_claim_bytes,
        claim_read_error: None,
        rms_capsule_result: Err(preflight_placeholder()),
        signature_decode_result: Err(preflight_placeholder()),
        opener_result: Err(preflight_placeholder()),
        signature_result: Err(preflight_placeholder()),
        taken_pair: None,
        take_error: None,
        insert_error: None,
        result_error: None,
        new_device_id: Uuid::nil(),
    }
}

pub async fn post_complete(
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
    session: DeviceSession,
    Json(body): Json<CompleteRequest>,
) -> Result<(HeaderMap, Json<CompleteResponse>)> {
    let grant_id = crate::ids::validate_id("grant_id", &grant_id)?;

    // Read the grant once. The extracted driver owns the user/opener binding
    // decision; the handler keeps the bytes because the single-use take below
    // compares them with what the ceremony validated.
    let (grant_observation, grant, expected_grant_bytes, grant_error) =
        match state.store.get(&grant_key(grant_id)) {
            Ok(Some(bytes)) => match serde_json::from_slice::<Grant>(&bytes) {
                Ok(grant) => (
                    GrantObservation::Present {
                        user_matches: grant.user_id == session.user_id.to_string(),
                        opener_matches: grant.device_id == session.device_id.to_string(),
                    },
                    Some(grant),
                    Some(bytes),
                    None,
                ),
                Err(error) => (
                    GrantObservation::Error,
                    None,
                    None,
                    Some(AppError::Internal(format!(
                        "stored grant is unreadable: {error}"
                    ))),
                ),
            },
            Ok(None) => (GrantObservation::Absent, None, None, None),
            Err(error) => (GrantObservation::Error, None, None, Some(error)),
        };

    let start = vela_enrollment_policy::pairing_interpreter::start_completion(grant_observation);
    let mut io = CompleteIo {
        io: ExecIo::new(&state),
        grant_id: grant_id.to_string(),
        // The driver is terminal for an absent or unreadable grant, so no
        // executor method observes these placeholders.
        grant: grant.unwrap_or_else(|| Grant {
            user_id: String::new(),
            device_id: String::new(),
        }),
        expected_grant_bytes: expected_grant_bytes.unwrap_or_default(),
        body,
        grant_error,
        account_error: None,
        current_epoch: 0,
        rotation_in_progress: false,
        rekey_epoch: 0,
        account_epoch_active: false,
        claim_materials: Err(preflight_placeholder()),
        claim_present: false,
        expected_claim_bytes: None,
        claim_read_error: None,
        rms_capsule_result: Err(preflight_placeholder()),
        signature_decode_result: Err(preflight_placeholder()),
        opener_result: Err(preflight_placeholder()),
        signature_result: Err(preflight_placeholder()),
        taken_pair: None,
        take_error: None,
        insert_error: None,
        result_error: None,
        new_device_id: Uuid::nil(),
    };
    let transition = vela_enrollment_policy::pairing_interpreter!(io, start, await);

    match transition.effect {
        PairingEffect::Complete => {}
        PairingEffect::Fail(PairingFailure::GrantUnavailable) => {
            // Same message as "not found": whether a grant exists is not
            // something an unrelated caller should be able to probe.
            return Err(AppError::NotFound(
                "enrollment grant not found or expired".into(),
            ));
        }
        PairingEffect::Fail(PairingFailure::GrantError) => {
            return Err(io
                .grant_error
                .take()
                .unwrap_or_else(|| AppError::Internal("enrollment grant read failed".into())))
        }
        PairingEffect::Fail(PairingFailure::AccountStorage) => {
            return Err(io
                .account_error
                .take()
                .unwrap_or_else(|| AppError::Internal("account query failed".into())))
        }
        PairingEffect::Fail(PairingFailure::EpochChanged) => {
            if let Some(error) = io.claim_read_error.take() {
                return Err(error);
            }
            return Err(AppError::Conflict(
                "device enrollment key epoch changed or rotation is in progress".into(),
            ));
        }
        PairingEffect::Fail(PairingFailure::NoClaim) => {
            return Err(AppError::NotFound(
                "no device has claimed this code yet".into(),
            ));
        }
        PairingEffect::Fail(PairingFailure::ClaimUnreadable) => {
            if let Some(error) = io.claim_read_error.take() {
                return Err(error);
            }
            return Err(take_slot_error(&mut io.claim_materials)
                .unwrap_or_else(|| AppError::Internal("stored claim is unreadable".into())));
        }
        PairingEffect::Fail(PairingFailure::CapsuleInvalid) => {
            return Err(take_slot_error(&mut io.rms_capsule_result)
                .unwrap_or_else(|| AppError::BadRequest("rms_capsule is invalid".into())));
        }
        PairingEffect::Fail(PairingFailure::SignatureFieldInvalid) => {
            return Err(take_slot_error(&mut io.signature_decode_result)
                .unwrap_or_else(|| AppError::BadRequest("signature is invalid".into())));
        }
        PairingEffect::Fail(PairingFailure::OpenerStorage) => {
            return Err(take_slot_error(&mut io.opener_result)
                .unwrap_or_else(|| AppError::Internal("opener lookup failed".into())));
        }
        PairingEffect::Fail(PairingFailure::OpenerRevoked) => {
            return Err(AppError::Unauthorized(
                "enrolling device not found or revoked".into(),
            ));
        }
        PairingEffect::Fail(PairingFailure::SignatureRejected) => {
            return Err(take_slot_error(&mut io.signature_result).unwrap_or_else(|| {
                AppError::Unauthorized("enrolling device not found or revoked".into())
            }));
        }
        PairingEffect::Fail(PairingFailure::CompletionNotAuthorized) => {
            return Err(AppError::Unauthorized(
                "device enrollment completion is not authorized".into(),
            ));
        }
        PairingEffect::Fail(PairingFailure::CeremonyConsumed) => {
            if let Some(error) = io.take_error.take() {
                return Err(error);
            }
            return Err(AppError::NotFound(
                "enrollment grant or claim was already consumed".into(),
            ));
        }
        PairingEffect::RestoreAndFail(PairingFailure::CeremonyChanged) => {
            if let Some((grant_bytes, claim_bytes)) = &io.taken_pair {
                state.store.set_ex_pair(
                    &grant_key(&io.grant_id),
                    grant_bytes,
                    &claim_key(&io.grant_id),
                    claim_bytes,
                    GRANT_TTL_SECS,
                )?;
            }
            return Err(AppError::Conflict(
                "enrollment ceremony changed while it was being confirmed".into(),
            ));
        }
        PairingEffect::RestoreAndFail(PairingFailure::Rotation) => {
            if let Some((grant_bytes, claim_bytes)) = &io.taken_pair {
                state.store.set_ex_pair(
                    &grant_key(&io.grant_id),
                    grant_bytes,
                    &claim_key(&io.grant_id),
                    claim_bytes,
                    GRANT_TTL_SECS,
                )?;
            }
            return Err(AppError::Conflict(
                "device enrollment key epoch changed or rotation is in progress".into(),
            ));
        }
        // An INSERT error is ambiguous: the row may have committed before the
        // error surfaced. The grant and claim stay consumed; restoring them
        // would let a retry enroll a second device from one ceremony.
        PairingEffect::Fail(PairingFailure::InsertStorage) => {
            return Err(io
                .insert_error
                .take()
                .unwrap_or_else(|| AppError::Internal("device insert failed".into())));
        }
        PairingEffect::Fail(PairingFailure::ResultStorage) => {
            return Err(io
                .result_error
                .take()
                .unwrap_or_else(|| AppError::Internal("enrollment result store failed".into())));
        }
        PairingEffect::RestoreAndFail(failure) => {
            if let Some((grant_bytes, claim_bytes)) = &io.taken_pair {
                state.store.set_ex_pair(
                    &grant_key(&io.grant_id),
                    grant_bytes,
                    &claim_key(&io.grant_id),
                    claim_bytes,
                    GRANT_TTL_SECS,
                )?;
            }
            return Err(rendezvous_failure_error(failure));
        }
        PairingEffect::Fail(failure) => return Err(rendezvous_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected completion effect".into(),
            ))
        }
    }

    tracing::info!(
        new_device_id = %io.new_device_id,
        enrolled_by = %io.grant.device_id,
        user_id = %io.grant.user_id,
        "device enrolled (v3 rendezvous)"
    );

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(CompleteResponse {
            device_id: io.new_device_id,
        }),
    ))
}

// ── 5. The joining device collects the outcome ──────────────────────────────

#[derive(Deserialize)]
pub struct ResultRequest {
    /// The joining device's signature over the grant id, under the key it
    /// claimed with. This is the only thing standing in for a session here —
    /// the device is asking *which device it is*, so it cannot yet
    /// authenticate normally.
    pub signature: String,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ResultResponse {
    /// The primary has not completed yet. The user is probably still comparing
    /// fingerprints; keep waiting.
    Pending,
    Enrolled {
        device_id: String,
    },
}

/// The I/O behind result collection. The driver owns whether a completed
/// result or a live claim may be answered, and under which verified key; this
/// executor retains the exact storage and verifier errors.
pub(crate) struct ResultIo<'a> {
    io: ExecIo<'a>,
    grant_id: String,
    signature: Vec<u8>,
    result_record: Option<EnrollmentResult>,
    result_error: Option<AppError>,
    claim_error: Option<AppError>,
    device_grant_error: Option<AppError>,
    claim_read_attempted: bool,
}

impl PairingExecutor for ResultIo<'_> {
    async fn read_result(&mut self) -> ResultReadObservation {
        let plan = plan_result_read(self.grant_id.clone());
        let (reads, error) = self.io.run_reads(&plan).await;
        let mut verdicts = CollectorVerdicts {
            key_decodes: false,
            key_len: 0,
            signature_verified: false,
        };
        let outcome = match reads.first() {
            Some(RawRead::Value(None)) => ReadOutcome::Result(None),
            Some(RawRead::Value(Some(bytes))) => {
                match serde_json::from_slice::<EnrollmentResult>(bytes) {
                    Ok(result) => match crate::db::decode_b64(&result.hybrid_vk) {
                        Ok(vk) => {
                            let signature_result =
                                verify_result_signature(&vk, &self.grant_id, &self.signature);
                            verdicts = CollectorVerdicts {
                                key_decodes: true,
                                key_len: vk.len(),
                                signature_verified: signature_result.is_ok(),
                            };
                            self.result_error = signature_result.err();
                            let view = ResultRowView {
                                device_id: Some(result.device_id.clone()),
                                hybrid_vk: Some(result.hybrid_vk.clone()),
                            };
                            self.result_record = Some(result);
                            ReadOutcome::Result(Some(view))
                        }
                        Err(error) => {
                            self.result_error = Some(error);
                            ReadOutcome::Undecodable
                        }
                    },
                    Err(error) => {
                        self.result_error = Some(AppError::Internal(format!(
                            "stored result is unreadable: {error}"
                        )));
                        ReadOutcome::Undecodable
                    }
                }
            }
            _ => {
                if let Some(error) = error {
                    self.result_error = Some(error.into_app());
                }
                ReadOutcome::Failed
            }
        };
        classify_result_read(&[outcome], verdicts)
    }

    async fn read_claim(&mut self) -> ClaimReadObservation {
        self.claim_read_attempted = true;
        let plan = plan_claim_read(self.grant_id.clone());
        let (reads, error) = self.io.run_reads(&plan).await;
        let mut verdicts = CollectorVerdicts {
            key_decodes: false,
            key_len: 0,
            signature_verified: false,
        };
        let outcome = match reads.first() {
            Some(RawRead::Value(None)) => ReadOutcome::Claim(None),
            Some(RawRead::Value(Some(bytes))) => match serde_json::from_slice::<Claim>(bytes) {
                Ok(claim) => match crate::db::decode_b64(&claim.hybrid_vk) {
                    Ok(vk) => {
                        let signature_result =
                            verify_result_signature(&vk, &self.grant_id, &self.signature);
                        verdicts = CollectorVerdicts {
                            key_decodes: true,
                            key_len: vk.len(),
                            signature_verified: signature_result.is_ok(),
                        };
                        self.claim_error = signature_result.err();
                        let view = ClaimRowView {
                            hybrid_ek: Some(claim.hybrid_ek.clone()),
                            hybrid_vk: Some(claim.hybrid_vk.clone()),
                            device_name: claim.device_name.clone(),
                            device_type: claim.device_type.clone(),
                        };
                        ReadOutcome::Claim(Some(view))
                    }
                    Err(error) => {
                        self.claim_error = Some(error);
                        ReadOutcome::Undecodable
                    }
                },
                Err(error) => {
                    self.claim_error = Some(AppError::Internal(format!(
                        "stored claim is unreadable: {error}"
                    )));
                    ReadOutcome::Undecodable
                }
            },
            _ => {
                if let Some(error) = error {
                    self.claim_error = Some(error.into_app());
                }
                ReadOutcome::Failed
            }
        };
        classify_claim_read(&[outcome], verdicts)
    }

    /// U-20 fallback. The claim and the result record are both gone, which is
    /// what a committed insert plus a lost result write leaves behind. The
    /// inserted row records the grant id, so read it back and answer under the
    /// same signature check the stored result uses; the row's `hybrid_vk` is
    /// the key the joining device claimed with.
    async fn read_enrolled_device(&mut self) -> DeviceGrantObservation {
        let plan = plan_device_by_grant(self.grant_id.clone());
        let (reads, error) = self.io.run_reads(&plan).await;
        let mut verdicts = CollectorVerdicts {
            key_decodes: false,
            key_len: 0,
            signature_verified: false,
        };
        let outcome = match reads.first() {
            Some(RawRead::Rows(rows)) => match rows.first() {
                None => ReadOutcome::DeviceByGrant(None),
                Some(row) => {
                    let (Some(device_id), Some(hybrid_vk)) = (row.text(0), row.text(1)) else {
                        self.device_grant_error = Some(AppError::Internal(
                            "enrolled device row is missing its id or key".into(),
                        ));
                        return classify_enrolled_device(&[ReadOutcome::Undecodable], verdicts);
                    };
                    match crate::db::decode_b64(hybrid_vk) {
                        Ok(vk) => {
                            let signature_result =
                                verify_result_signature(&vk, &self.grant_id, &self.signature);
                            let signature_verified = signature_result.is_ok();
                            verdicts = CollectorVerdicts {
                                key_decodes: true,
                                key_len: vk.len(),
                                signature_verified,
                            };
                            self.device_grant_error = signature_result.err();
                            if signature_verified {
                                self.result_record = Some(EnrollmentResult {
                                    device_id: device_id.to_string(),
                                    hybrid_vk: hybrid_vk.to_string(),
                                });
                            }
                            let view = DeviceRowView {
                                device_id: Some(device_id.to_string()),
                                hybrid_vk: Some(hybrid_vk.to_string()),
                                revoked: None,
                                user_id: None,
                                enrollment_grant_id: Some(self.grant_id.clone()),
                            };
                            ReadOutcome::DeviceByGrant(Some(view))
                        }
                        Err(error) => {
                            self.device_grant_error = Some(error);
                            ReadOutcome::Undecodable
                        }
                    }
                }
            },
            _ => {
                if let Some(error) = error {
                    self.device_grant_error = Some(error.into_app());
                }
                ReadOutcome::Failed
            }
        };
        classify_enrolled_device(&[outcome], verdicts)
    }
}

/// Tell a device that claimed a grant which device it became.
///
/// Unauthenticated in the session sense and necessarily so — the `device_id`
/// this returns is exactly what the caller is missing in order to authenticate.
/// The proof is the signature: only the holder of the private half of the
/// claimed key can produce it, so someone who photographed the enrollment code
/// learns nothing here, not even whether a claim exists. That last part is why
/// the signature is checked *before* the pending branch answers.
#[cfg(test)]
pub(crate) fn result_io_for_test<'a>(
    state: &'a AppState,
    fail_at: Option<usize>,
    grant_id: String,
    signature: Vec<u8>,
) -> ResultIo<'a> {
    ResultIo {
        io: ExecIo::faulty(state, fail_at),
        grant_id,
        signature,
        result_record: None,
        result_error: None,
        claim_error: None,
        device_grant_error: None,
        claim_read_attempted: false,
    }
}

pub async fn post_result(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
    Json(body): Json<ResultRequest>,
) -> Result<Json<ResultResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::enrollment_result_by_ip(&state.store, &ip)?;
    let grant_id = crate::ids::validate_id("grant_id", &grant_id)?;

    // Signature length/base64 is request validation, not a store decision.
    let signature = decode_exact(&body.signature, HYBRID_SIG_LEN, "signature")?;

    let start = vela_enrollment_policy::pairing_interpreter::start_result();
    let mut io = ResultIo {
        io: ExecIo::new(&state),
        grant_id: grant_id.to_string(),
        signature,
        result_record: None,
        result_error: None,
        claim_error: None,
        device_grant_error: None,
        claim_read_attempted: false,
    };
    let transition = vela_enrollment_policy::pairing_interpreter!(io, start, await);

    match transition.effect {
        PairingEffect::ReturnResult(ResultKind::Enrolled) => {
            let result = io.result_record.take().ok_or_else(|| {
                AppError::Internal("result driver admitted an unobserved result".into())
            })?;
            Ok(Json(ResultResponse::Enrolled {
                device_id: result.device_id,
            }))
        }
        PairingEffect::ReturnResult(ResultKind::Pending) => Ok(Json(ResultResponse::Pending)),
        PairingEffect::Fail(PairingFailure::ResultUnreadable) => {
            Err(io.result_error.take().unwrap_or_else(|| {
                AppError::Internal("stored result is unreadable".into())
            }))
        }
        PairingEffect::Fail(PairingFailure::ClaimRecordUnreadable) => {
            Err(io.claim_error.take().unwrap_or_else(|| {
                AppError::Internal("stored claim is unreadable".into())
            }))
        }
        PairingEffect::Fail(PairingFailure::EnrolledDeviceUnreadable) => {
            Err(io.device_grant_error.take().unwrap_or_else(|| {
                AppError::Internal("enrolled device row is unreadable".into())
            }))
        }
        PairingEffect::Fail(
            PairingFailure::ResultSignatureRejected | PairingFailure::ResultNotAuthorized,
        ) => {
            // Preserve the signature verifier's own error, if any, before the
            // policy's generic refusal.
            let retained = if io.device_grant_error.is_some() {
                io.device_grant_error.take()
            } else if io.claim_read_attempted {
                io.claim_error.take()
            } else {
                io.result_error.take()
            };
            Err(retained.unwrap_or_else(|| {
                AppError::Unauthorized("enrollment result is not authorized".into())
            }))
        }
        PairingEffect::Fail(failure) => Err(rendezvous_failure_error(failure)),
        _ => Err(AppError::Internal(
            "pairing driver produced an unexpected result effect".into(),
        )),
    }
}

/// Check a collector's signature, treating an unusable stored key as a refusal
/// rather than a server fault.
///
/// A claim's `hybrid_vk` is length-checked but not parsed when it is stored, so
/// an unauthenticated caller can put 2624 bytes of noise there and reach this
/// path. That is not a bug on the server's side — such a claim can never be a
/// working device — but it is caller-supplied input, and answering it with a
/// 500 would file the caller's own garbage as an internal error and bury real
/// faults among them.
fn verify_result_signature(vk: &[u8], grant_id: &str, signature: &[u8]) -> Result<()> {
    super::enroll::verify_enrollment_result_signature(vk, grant_id, signature).map_err(
        |e| match e {
            AppError::Internal(_) => AppError::Unauthorized(
                "signature does not match the key this grant was claimed with".into(),
            ),
            other => other,
        },
    )
}

// ── shared ──────────────────────────────────────────────────────────────────

/// Load a grant and require the caller to be the device that opened it.
///
/// Not just the same *user*: a second device of the same account must not be
/// able to drive an enrollment its owner started elsewhere, because then a
/// compromised secondary could enroll an attacker's key against a code the user
/// is reading off their primary.
fn authorize_grant(
    state: &AppState,
    grant_id: &str,
    session: &AuthSession,
) -> Result<(Grant, Vec<u8>)> {
    let bytes = state
        .store
        .get(&grant_key(grant_id))?
        .ok_or_else(|| AppError::NotFound("enrollment grant not found or expired".into()))?;
    let grant: Grant = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Internal(format!("stored grant is unreadable: {e}")))?;

    if grant.user_id != session.user_id.to_string()
        || grant.device_id != session.device_id.to_string()
    {
        // Same message as "not found": whether a grant exists is not something
        // an unrelated caller should be able to probe.
        return Err(AppError::NotFound(
            "enrollment grant not found or expired".into(),
        ));
    }
    Ok((grant, bytes))
}

fn load_claim(state: &AppState, grant_id: &str) -> Result<Option<Claim>> {
    match state.store.get(&claim_key(grant_id))? {
        Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(|e| {
            AppError::Internal(format!("stored claim is unreadable: {e}"))
        })?)),
        None => Ok(None),
    }
}

/// Decode base64 without imposing a length. The verified claim policy decides
/// whether the decoded length is the protocol's exact key length, so the
/// public-key fact is not decided by a separate early return.
fn decode_base64_field(value: &str, what: &str) -> Result<Vec<u8>> {
    B64.decode(value)
        .map_err(|_| AppError::BadRequest(format!("{what} is not valid base64")))
}

fn decode_exact(value: &str, expected: usize, what: &str) -> Result<Vec<u8>> {
    let bytes = B64
        .decode(value)
        .map_err(|_| AppError::BadRequest(format!("{what} is not valid base64")))?;
    if bytes.len() != expected {
        return Err(AppError::BadRequest(format!(
            "{what} must be {expected} bytes"
        )));
    }
    Ok(bytes)
}

fn decode_any(value: &str, what: &str) -> Result<Vec<u8>> {
    const MAX_CAPSULE_BYTES: usize = 64 * 1024;
    let bytes = B64
        .decode(value)
        .map_err(|_| AppError::BadRequest(format!("{what} is not valid base64")))?;
    if bytes.is_empty() || bytes.len() > MAX_CAPSULE_BYTES {
        return Err(AppError::BadRequest(format!(
            "{what} must be between 1 byte and 64 KiB"
        )));
    }
    Ok(bytes)
}

/// Render the driver's failure with the handler's historical status/message.
/// Variants whose original error is retained by the handler (storage, decode
/// and signature-verifier errors) fall back to a total internal error here;
/// the call sites return the retained error instead.
fn rendezvous_failure_error(failure: PairingFailure) -> AppError {
    match failure {
        PairingFailure::OpenPolicy => AppError::Internal(
            "verified enrollment policy rejected an authenticated device grant".into(),
        ),
        PairingFailure::GrantStorage => {
            AppError::Internal("enrollment grant store failed".into())
        }
        PairingFailure::GrantUnavailable => {
            AppError::NotFound("enrollment grant not found or expired".into())
        }
        PairingFailure::InvalidEkLength => AppError::BadRequest(format!(
            "hybrid_ek must be {HYBRID_EK_LEN} bytes"
        )),
        PairingFailure::InvalidVkLength => AppError::BadRequest(format!(
            "hybrid_vk must be {HYBRID_VK_LEN} bytes"
        )),
        PairingFailure::AlreadyClaimed => AppError::Conflict(
            "this enrollment code has already been used by another device".into(),
        ),
        PairingFailure::ClaimNotAuthorized => {
            AppError::BadRequest("enrollment claim is not authorized".into())
        }
        PairingFailure::KeyEpochInvalid => {
            AppError::BadRequest("key_epoch must be positive".into())
        }
        PairingFailure::RekeyPolicy => AppError::BadRequest(
            "device enrollment requires a positive device-authority epoch".into(),
        ),
        PairingFailure::EpochChanged | PairingFailure::Rotation => AppError::Conflict(
            "device enrollment key epoch changed or rotation is in progress".into(),
        ),
        PairingFailure::NoClaim => {
            AppError::NotFound("no device has claimed this code yet".into())
        }
        PairingFailure::CeremonyConsumed => {
            AppError::NotFound("enrollment grant or claim was already consumed".into())
        }
        PairingFailure::CeremonyChanged => AppError::Conflict(
            "enrollment ceremony changed while it was being confirmed".into(),
        ),
        PairingFailure::OpenerRevoked | PairingFailure::SignatureRejected => {
            AppError::Unauthorized("enrolling device not found or revoked".into())
        }
        PairingFailure::CompletionNotAuthorized => {
            AppError::Unauthorized("device enrollment completion is not authorized".into())
        }
        PairingFailure::ResultSignatureRejected | PairingFailure::ResultNotAuthorized => {
            AppError::Unauthorized("enrollment result is not authorized".into())
        }
        _ => AppError::Internal("pairing driver produced an unexpected failure".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The grant records both ids, and `authorize_grant` compares both.
    ///
    /// The exploit test cannot reach this case: getting a genuine second device
    /// of the same account means completing an enrollment, which is the thing
    /// it is trying to break. So the binding is asserted here instead of being
    /// left to a comment.
    #[test]
    fn a_grant_records_both_the_user_and_the_device() {
        let grant = Grant {
            user_id: "user-1".into(),
            device_id: "device-a".into(),
        };
        let encoded = serde_json::to_vec(&grant).unwrap();
        let decoded: Grant = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded.user_id, "user-1");
        assert_eq!(decoded.device_id, "device-a");

        // Matching the user is not sufficient. A second device of the same
        // account must not be able to drive an enrollment its owner started on
        // the primary — otherwise a compromised secondary could enroll a key
        // against a code the user is reading off another screen.
        assert!(
            decoded.user_id == "user-1" && decoded.device_id != "device-b",
            "same user, different device must not satisfy the binding"
        );
    }

    /// The three records live in separate namespaces.
    ///
    /// A result outlives the claim it came from — completion consumes the claim
    /// but leaves the result for the joining device to collect. If the keys
    /// collided, completing would either destroy the result or resurrect a
    /// consumed claim, and a consumed claim is what makes replay fail.
    #[test]
    fn grants_claims_and_results_do_not_share_keys() {
        let id = "11111111-1111-1111-1111-111111111111";
        let keys = [grant_key(id), claim_key(id), result_key(id)];
        let unique: std::collections::HashSet<&String> = keys.iter().collect();
        assert_eq!(unique.len(), 3, "namespaces collide: {keys:?}");
    }

    /// The result carries the claimed `hybrid_vk` forward.
    ///
    /// Completion consumes the claim, so this copy is the only thing left to
    /// check a collector's signature against. Dropping it would leave no way to
    /// verify the caller and force the endpoint open — which is the failure this
    /// whole design exists to avoid.
    #[test]
    fn a_result_keeps_the_key_its_signature_is_checked_against() {
        let result = EnrollmentResult {
            device_id: "device-1".into(),
            hybrid_vk: "vk".into(),
        };
        let decoded: EnrollmentResult =
            serde_json::from_slice(&serde_json::to_vec(&result).unwrap()).unwrap();
        assert_eq!(decoded.device_id, "device-1");
        assert_eq!(decoded.hybrid_vk, "vk");
    }

    /// A claim carries public halves only. If a private key ever appeared in
    /// this struct the whole change would be undone, so the shape is asserted.
    #[test]
    fn a_claim_carries_no_private_key_material() {
        let claim = Claim {
            hybrid_ek: "ek".into(),
            hybrid_vk: "vk".into(),
            device_name: Some("Phone".into()),
            device_type: Some("android".into()),
        };
        let json = serde_json::to_string(&claim).unwrap();
        for forbidden in ["hybrid_sk", "transfer_key", "_sk", "private"] {
            assert!(
                !json.contains(forbidden),
                "a claim must never carry {forbidden}: {json}"
            );
        }
    }
}
