use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;
use vela_enrollment_policy::enroll_driver::EnrollFailure;
use vela_enrollment_policy::executor::{
    classify_challenge_take, classify_device_check, classify_insert_enroll,
    plan_active_device_read, plan_challenge_take, plan_enroll_insert, DeviceRowView,
    EnrollAuthVerdict, ReadOutcome,
};
use vela_rekey_policy::{MutationAuthority, MutationDecision, MutationKind, MutationRequest};

use super::exec_io::{ExecIo, RawRead};
use crate::{
    error::{AppError, Result},
    net, rate_limit,
    state::AppState,
};

/// One message for every "this device did not authenticate" case.
///
/// `/auth/verify` and `/device/enroll` both used to answer "no such device" and
/// "that signature is wrong" differently, which told an anonymous caller whether
/// a device id exists. `/auth/verify` had already collapsed its not-found arm to
/// this wording — the three possibilities are named deliberately — but the
/// signature arm returned the helper's own message and undid it, so the
/// hardening was half applied on one endpoint and absent on the other.
///
/// This does not close the timing side of the same question: a miss returns
/// after one lookup, a hit after an ML-DSA-87 verification. Equalising that
/// means verifying against a dummy key on the miss path, which buys an
/// unauthenticated caller a signature verification per request — a poor trade
/// against an oracle that only confirms a UUIDv4 the caller already holds.
pub(crate) const DEVICE_AUTH_FAILED: &str = "invalid device, challenge or signature";

/// Rewrite an auth-signature rejection to [`DEVICE_AUTH_FAILED`].
///
/// Only the `Unauthorized` arm: a `BadRequest` is about the shape of what the
/// caller sent and tells them nothing about the device, and an `Internal` is a
/// fault on our side that must not be disguised as an authentication failure.
pub(crate) fn unify_device_auth_error(error: AppError) -> AppError {
    match error {
        AppError::Unauthorized(_) => AppError::Unauthorized(DEVICE_AUTH_FAILED.into()),
        other => other,
    }
}

#[derive(Deserialize)]
pub struct NewDevicePayload {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub rms_capsule: String,
    /// Authenticated local epoch of the RMS sealed into `rms_capsule`.
    pub key_epoch: i64,
    pub signature: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

#[derive(Deserialize)]
pub struct EnrollRequest {
    pub enrolling_device_id: Uuid,
    pub challenge: String,
    pub auth_signature: String,
    pub new_device: NewDevicePayload,
}

#[derive(Serialize)]
pub struct EnrollResponse {
    pub device_id: Uuid,
}

/// The I/O behind one `POST /device/enroll`. The challenge consumption, the
/// device row read, both signature checks and the guarded insert happen here;
/// every decision between them is the policy driver's. The handler keeps the
/// original error in `error`, so each failure keeps its exact status and text.
pub(crate) struct EnrollIo<'a> {
    io: ExecIo<'a>,
    body: EnrollRequest,
    enrolling_device_id_str: String,
    new_device_id: Uuid,
    device_a_user_id: Option<Uuid>,
    permit_epoch: i64,
    device_a_vk: Vec<u8>,
    new_hybrid_ek: Vec<u8>,
    new_hybrid_vk: Vec<u8>,
    rms_capsule: Vec<u8>,
    error: Option<AppError>,
}

impl EnrollIo<'_> {
    pub(crate) async fn consume_challenge(
        &mut self,
    ) -> vela_enrollment_policy::enroll_driver::ChallengeObservation {
        use vela_enrollment_policy::enroll_driver::ChallengeObservation;
        let plan = plan_challenge_take(self.body.challenge.clone());
        let (outcome, value, error) = self.io.run_take(&plan).await;
        if let Some(error) = error {
            if self.error.is_none() {
                self.error = Some(error.into_app());
            }
        }
        // The take removes the value whatever its purpose; the session policy
        // classifies the stored tag against the enrollment purpose.
        let consumption = vela_session_policy::challenge::classify_taken_challenge(
            &value,
            vela_session_policy::challenge::ChallengePurpose::Enroll,
        );
        let purpose_matches = matches!(
            consumption,
            vela_session_policy::challenge::ChallengeConsumption::Accepted
        );
        if classify_challenge_take(&outcome, purpose_matches) {
            ChallengeObservation::Consumed
        } else {
            if self.error.is_none() {
                self.error = Some(match consumption {
                    vela_session_policy::challenge::ChallengeConsumption::Accepted => {
                        AppError::Internal("challenge take classification disagrees".into())
                    }
                    vela_session_policy::challenge::ChallengeConsumption::Missing => {
                        AppError::Unauthorized("challenge not found or already used".into())
                    }
                    vela_session_policy::challenge::ChallengeConsumption::WrongPurpose => {
                        AppError::Unauthorized(
                            "challenge was issued for a different purpose".into(),
                        )
                    }
                });
            }
            ChallengeObservation::Rejected
        }
    }

    pub(crate) async fn check_device(&mut self) -> vela_enrollment_policy::enroll_driver::DeviceObservation {
        let plan = plan_active_device_read(self.enrolling_device_id_str.clone());
        let (reads, error) = self.io.run_reads(&plan).await;
        let (outcome, device_a) = match reads.first() {
            Some(RawRead::Rows(rows)) => match rows.first() {
                None => (ReadOutcome::ActiveDevice(None), None),
                Some(row) => match crate::db::parse_device_row_turso(row) {
                    Ok(device_a) => (
                        ReadOutcome::ActiveDevice(Some(DeviceRowView {
                            device_id: Some(device_a.id.to_string()),
                            hybrid_vk: row.text(6).map(String::from),
                            revoked: Some(0),
                            user_id: Some(device_a.user_id.to_string()),
                            enrollment_grant_id: None,
                        })),
                        Some(device_a),
                    ),
                    Err(error) => {
                        self.error = Some(error);
                        (ReadOutcome::Undecodable, None)
                    }
                },
            },
            _ => {
                if let Some(error) = error {
                    self.error = Some(error.into_app());
                }
                (ReadOutcome::Failed, None)
            }
        };
        let Some(device_a) = device_a else {
            return classify_device_check(&[outcome], EnrollAuthVerdict::Rejected);
        };
        self.device_a_user_id = Some(device_a.user_id);
        self.device_a_vk = device_a.hybrid_vk.clone();

        let challenge_bytes = match B64.decode(&self.body.challenge) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.error = Some(AppError::BadRequest("invalid challenge encoding".into()));
                return classify_device_check(&[outcome], EnrollAuthVerdict::MalformedChallenge);
            }
        };

        // Same answer whether the device was missing or the signature was
        // wrong. Internal errors keep their own identity.
        match verify_auth_signature(
            &device_a.hybrid_vk,
            &challenge_bytes,
            &self.enrolling_device_id_str,
            &self.body.auth_signature,
        )
        .map_err(unify_device_auth_error)
        {
            Ok(()) => classify_device_check(&[outcome], EnrollAuthVerdict::Verified),
            Err(error) => {
                self.error = Some(error);
                classify_device_check(&[outcome], EnrollAuthVerdict::Rejected)
            }
        }
    }

    async fn prepare_enrollment(
        &mut self,
    ) -> vela_enrollment_policy::enroll_driver::EnrollmentObservation {
        use vela_enrollment_policy::enroll_driver::EnrollmentObservation;
        const HYBRID_EK_LEN: usize = 1568 + 32;
        const HYBRID_VK_LEN: usize = 2592 + 32;
        const HYBRID_SIG_LEN: usize = 4627 + 64;

        let new_hybrid_ek = match B64.decode(&self.body.new_device.hybrid_ek) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.error = Some(AppError::BadRequest("hybrid_ek is not valid base64".into()));
                return EnrollmentObservation::DecodeFailed;
            }
        };
        let new_hybrid_vk_bytes = match B64.decode(&self.body.new_device.hybrid_vk) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.error = Some(AppError::BadRequest("hybrid_vk is not valid base64".into()));
                return EnrollmentObservation::DecodeFailed;
            }
        };
        let rms_capsule = match B64.decode(&self.body.new_device.rms_capsule) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.error = Some(AppError::BadRequest("rms_capsule is not valid base64".into()));
                return EnrollmentObservation::DecodeFailed;
            }
        };
        let signature_bytes = match B64.decode(&self.body.new_device.signature) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.error = Some(AppError::BadRequest("signature is not valid base64".into()));
                return EnrollmentObservation::DecodeFailed;
            }
        };

        if new_hybrid_ek.len() != HYBRID_EK_LEN {
            return EnrollmentObservation::EkLengthInvalid;
        }
        if new_hybrid_vk_bytes.len() != HYBRID_VK_LEN {
            return EnrollmentObservation::VkLengthInvalid;
        }
        if signature_bytes.len() != HYBRID_SIG_LEN {
            return EnrollmentObservation::SignatureLengthInvalid;
        }

        let vk = self.device_a_vk.clone();
        if vk.is_empty() {
            self.error = Some(AppError::Internal(
                "enrolling device row disappeared before signature verification".into(),
            ));
            return EnrollmentObservation::Error;
        }
        if let Err(error) = verify_enrollment_signature(
            &vk,
            &new_hybrid_ek,
            &new_hybrid_vk_bytes,
            &rms_capsule,
            &signature_bytes,
        ) {
            self.error = Some(error);
            return EnrollmentObservation::SignatureRejected;
        }

        self.new_hybrid_ek = new_hybrid_ek;
        self.new_hybrid_vk = new_hybrid_vk_bytes;
        self.rms_capsule = rms_capsule;
        EnrollmentObservation::Verified
    }

    async fn check_account(&mut self) -> vela_enrollment_policy::enroll_driver::AccountObservation {
        use vela_enrollment_policy::enroll_driver::AccountObservation;
        if self.body.new_device.key_epoch < 1 {
            return AccountObservation::EpochInvalid;
        }
        match vela_rekey_policy::plan_active_mutation(MutationRequest {
            declared_epoch: self.body.new_device.key_epoch,
            authority_epoch: self.body.new_device.key_epoch,
            kind: MutationKind::Enrollment,
            authority: MutationAuthority::Device,
        }) {
            MutationDecision::Permit(permit) => {
                self.permit_epoch = permit.epoch();
                AccountObservation::Permitted
            }
            MutationDecision::Reject => AccountObservation::RekeyRejected,
        }
    }

    pub(crate) async fn insert_device(&mut self) -> vela_enrollment_policy::enroll_driver::InsertObservation {
        use vela_enrollment_policy::enroll_driver::InsertObservation;
        let Some(user_id) = self.device_a_user_id else {
            self.error = Some(AppError::Internal(
                "device enrollment driver reached the insert without a device".into(),
            ));
            return InsertObservation::Failed;
        };
        let device_name = self
            .body
            .new_device
            .device_name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "Desktop Device".to_string());
        let device_type = self
            .body
            .new_device
            .device_type
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "desktop".to_string());
        let now = Utc::now().to_rfc3339();
        let plan = plan_enroll_insert(
            self.new_device_id.to_string(),
            user_id.to_string(),
            device_name,
            device_type,
            crate::db::encode_b64(&self.new_hybrid_ek),
            crate::db::encode_b64(&self.new_hybrid_vk),
            self.enrolling_device_id_str.clone(),
            crate::db::encode_b64(&self.rms_capsule),
            now,
            user_id.to_string(),
            self.permit_epoch,
        );
        let (outcomes, error) = self.io.run_writes(&plan).await;
        if let Some(error) = error {
            self.error = Some(error.into_app());
        }
        classify_insert_enroll(&outcomes)
    }
}

#[cfg(test)]
pub(crate) fn enroll_io_for_test<'a>(
    state: &'a AppState,
    fail_at: Option<usize>,
    body: EnrollRequest,
    enrolling_device_id_str: String,
    new_device_id: Uuid,
    device_a_user_id: Option<Uuid>,
    permit_epoch: i64,
    new_hybrid_ek: Vec<u8>,
    new_hybrid_vk: Vec<u8>,
    rms_capsule: Vec<u8>,
) -> EnrollIo<'a> {
    EnrollIo {
        io: ExecIo::faulty(state, fail_at),
        body,
        enrolling_device_id_str,
        new_device_id,
        device_a_user_id,
        permit_epoch,
        device_a_vk: Vec::new(),
        new_hybrid_ek,
        new_hybrid_vk,
        rms_capsule,
        error: None,
    }
}

/// Render a driver failure with the handler's historical status and message.
/// Branches whose original error text is request-dependent return the stored
/// `error` instead.
fn enroll_failure_error(failure: EnrollFailure, error: Option<AppError>) -> AppError {
    use vela_enrollment_policy::HYBRID_EK_LEN;
    const HYBRID_VK_LEN: usize = 2592 + 32;
    const HYBRID_SIG_LEN: usize = 4627 + 64;
    let stored = |fallback: AppError| error.unwrap_or(fallback);
    match failure {
        EnrollFailure::ChallengeRejected => stored(AppError::BadRequest(
            "challenge is missing, expired or already used".into(),
        )),
        EnrollFailure::DeviceUnavailable => AppError::Unauthorized(DEVICE_AUTH_FAILED.into()),
        EnrollFailure::MalformedChallenge => {
            stored(AppError::BadRequest("challenge must be 32 bytes".into()))
        }
        EnrollFailure::AuthSignatureRejected => {
            stored(AppError::Unauthorized(DEVICE_AUTH_FAILED.into()))
        }
        EnrollFailure::DeviceStorage => {
            stored(AppError::Internal("device enrollment storage failure".into()))
        }
        EnrollFailure::KeyDecode => stored(AppError::BadRequest(
            "enrollment key material is not valid base64".into(),
        )),
        EnrollFailure::EkLength => AppError::BadRequest(format!(
            "hybrid_ek must be {HYBRID_EK_LEN} bytes"
        )),
        EnrollFailure::VkLength => AppError::BadRequest(format!(
            "hybrid_vk must be {HYBRID_VK_LEN} bytes"
        )),
        EnrollFailure::SignatureLength => AppError::BadRequest(format!(
            "signature must be {HYBRID_SIG_LEN} bytes"
        )),
        EnrollFailure::EnrollmentSignatureRejected => stored(AppError::Unauthorized(
            "enrolling device signature over enrollment payload is invalid".into(),
        )),
        EnrollFailure::SignatureStorage => {
            stored(AppError::Internal("signature verification failed".into()))
        }
        EnrollFailure::KeyEpochInvalid => {
            AppError::BadRequest("key_epoch must be positive".into())
        }
        EnrollFailure::RekeyPolicy => AppError::BadRequest(
            "device enrollment requires a positive device-authority epoch".into(),
        ),
        EnrollFailure::EpochConflict => AppError::Conflict(
            "device enrollment key epoch changed or rotation is in progress".into(),
        ),
        EnrollFailure::InsertStorage => {
            stored(AppError::Internal("device enrollment insert failure".into()))
        }
    }
}

pub async fn post_enroll(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::enroll_by_ip(&state.store, &ip)?;

    let enrolling_device_id = body.enrolling_device_id;
    let enrolling_device_id_str = enrolling_device_id.to_string();
    let new_device_id = Uuid::new_v4();
    let mut io = EnrollIo {
        io: ExecIo::new(&state),
        body,
        enrolling_device_id_str,
        new_device_id,
        device_a_user_id: None,
        permit_epoch: 0,
        new_hybrid_ek: Vec::new(),
        new_hybrid_vk: Vec::new(),
        device_a_vk: Vec::new(),
        rms_capsule: Vec::new(),
        error: None,
    };

    // The driver owns every decision between the effects above; the loop is the
    // same text the policy crate extracts and F* checks.
    let start = vela_enrollment_policy::enroll_interpreter::start_enroll();
    let transition = vela_enrollment_policy::enroll_interpreter!(io, start, await);

    match transition.effect {
        vela_enrollment_policy::enroll_driver::EnrollEffect::Complete => {}
        vela_enrollment_policy::enroll_driver::EnrollEffect::Fail(failure) => {
            return Err(enroll_failure_error(failure, io.error.take()));
        }
        _ => {
            return Err(AppError::Internal(
                "device enrollment driver produced an unexpected completion effect".into(),
            ))
        }
    }

    tracing::info!(
        new_device_id = %new_device_id,
        enrolled_by   = %enrolling_device_id,
        user_id       = %io.device_a_user_id.unwrap_or_default(),
        "device enrolled"
    );

    Ok(Json(EnrollResponse {
        device_id: new_device_id,
    }))
}

pub fn verify_auth_signature(
    hybrid_vk_bytes: &[u8],
    challenge: &[u8],
    device_id: &str,
    signature_b64: &str,
) -> Result<()> {
    if challenge.len() != 32 {
        return Err(AppError::BadRequest("challenge must be 32 bytes".into()));
    }
    let signature_bytes = B64
        .decode(signature_b64)
        .map_err(|_| AppError::BadRequest("signature is not valid base64".into()))?;
    let message = vela_crypto::signing::auth_message(device_id, challenge);
    verify_hybrid_signature(
        hybrid_vk_bytes,
        &message,
        &signature_bytes,
        "authentication signature invalid",
    )
}

pub(crate) fn verify_enrollment_signature(
    device_a_vk_bytes: &[u8],
    hybrid_ek: &[u8],
    hybrid_vk: &[u8],
    rms_capsule: &[u8],
    signature_bytes: &[u8],
) -> Result<()> {
    let message = vela_crypto::signing::enrollment_message(hybrid_ek, hybrid_vk, rms_capsule);
    verify_hybrid_signature(
        device_a_vk_bytes,
        &message,
        signature_bytes,
        "enrolling device signature over enrollment payload is invalid",
    )
}

/// Prove the caller holds the private half of the key that claimed `grant_id`.
///
/// This is what stands in for a session on the joining device's side: it has no
/// identity yet, so it authenticates by signing under the very key it presented
/// at claim time. Someone who only saw the enrollment code cannot produce this.
pub(crate) fn verify_enrollment_result_signature(
    claimed_vk_bytes: &[u8],
    grant_id: &str,
    signature_bytes: &[u8],
) -> Result<()> {
    let message = vela_crypto::signing::enrollment_result_message(grant_id);
    verify_hybrid_signature(
        claimed_vk_bytes,
        &message,
        signature_bytes,
        "signature does not match the key this grant was claimed with",
    )
}

pub(crate) fn verify_hybrid_signature(
    verifying_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
    unauthorized_message: &str,
) -> Result<()> {
    use vela_crypto::signing::{
        HybridSignature, HybridVerifyingKey, HYBRID_SIG_LEN, HYBRID_VK_LEN,
    };

    let vk_arr: &[u8; HYBRID_VK_LEN] = verifying_key_bytes
        .try_into()
        .map_err(|_| AppError::Internal("stored hybrid_vk has wrong length".into()))?;
    let sig_arr: &[u8; HYBRID_SIG_LEN] = signature_bytes
        .try_into()
        .map_err(|_| AppError::BadRequest("signature has wrong length".into()))?;

    let vk = HybridVerifyingKey::from_bytes(vk_arr)
        .map_err(|e| AppError::Internal(format!("vk decode: {e}")))?;
    let sig = HybridSignature::from_bytes(sig_arr)
        .map_err(|e| AppError::BadRequest(format!("signature decode: {e}")))?;

    let ok = vela_crypto::signing::verify(&vk, message, &sig)
        .map_err(|e| AppError::Internal(format!("signature verify: {e}")))?;

    if !ok {
        return Err(AppError::Unauthorized(unauthorized_message.into()));
    }
    Ok(())
}
