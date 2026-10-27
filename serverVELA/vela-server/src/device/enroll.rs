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
use vela_rekey_policy::{MutationAuthority, MutationDecision, MutationKind, MutationRequest};

use crate::{
    error::{AppError, Result},
    net, rate_limit,
    sqldb::{Db as _, TursoValue},
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
struct EnrollIo<'a> {
    state: &'a AppState,
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
    async fn consume_challenge(
        &mut self,
    ) -> vela_enrollment_policy::enroll_driver::ChallengeObservation {
        use vela_enrollment_policy::enroll_driver::ChallengeObservation;
        match crate::auth::challenge::consume_challenge(
            self.state,
            &self.body.challenge,
            crate::auth::challenge::ChallengePurpose::Enroll,
        ) {
            Ok(()) => ChallengeObservation::Consumed,
            Err(error) => {
                self.error = Some(error);
                ChallengeObservation::Rejected
            }
        }
    }

    async fn check_device(&mut self) -> vela_enrollment_policy::enroll_driver::DeviceObservation {
        use vela_enrollment_policy::enroll_driver::DeviceObservation;
        let rows = match self
            .state
            .sqldb
            .query(
                "SELECT id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk,
                enrolled_by, rms_capsule, revoked,
                revoked_at, revoked_by, created_at
         FROM devices
         WHERE id = ? AND revoked = 0",
                vec![TursoValue::Text(self.enrolling_device_id_str.clone())],
            )
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                return DeviceObservation::Error;
            }
        };

        let Some(row) = rows.first() else {
            return DeviceObservation::Unavailable;
        };
        let device_a = match crate::db::parse_device_row_turso(row) {
            Ok(device_a) => device_a,
            Err(error) => {
                self.error = Some(error);
                return DeviceObservation::Error;
            }
        };
        self.device_a_user_id = Some(device_a.user_id);
        self.device_a_vk = device_a.hybrid_vk.clone();

        let challenge_bytes = match B64.decode(&self.body.challenge) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.error = Some(AppError::BadRequest("invalid challenge encoding".into()));
                return DeviceObservation::MalformedChallenge;
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
            Ok(()) => DeviceObservation::Verified,
            Err(error) => {
                self.error = Some(error);
                DeviceObservation::AuthSignatureRejected
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

    async fn insert_device(&mut self) -> vela_enrollment_policy::enroll_driver::InsertObservation {
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

        match self
            .state
            .sqldb
            .execute(
                "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, rms_capsule, created_at)
         SELECT ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?
         WHERE EXISTS (
             SELECT 1 FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
         )",
                vec![
                    TursoValue::Text(self.new_device_id.to_string()),
                    TursoValue::Text(user_id.to_string()),
                    TursoValue::Text(device_name),
                    TursoValue::Text(device_type),
                    TursoValue::Text(crate::db::encode_b64(&self.new_hybrid_ek)),
                    TursoValue::Text(crate::db::encode_b64(&self.new_hybrid_vk)),
                    TursoValue::Text(self.enrolling_device_id_str.clone()),
                    TursoValue::Text(crate::db::encode_b64(&self.rms_capsule)),
                    TursoValue::Text(now),
                    TursoValue::Text(user_id.to_string()),
                    TursoValue::Integer(self.permit_epoch),
                ],
            )
            .await
        {
            Ok(0) => InsertObservation::EpochMismatch,
            Ok(_) => InsertObservation::Inserted,
            Err(error) => {
                self.error = Some(AppError::Internal(error.to_string()));
                InsertObservation::Failed
            }
        }
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
        state: &state,
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
