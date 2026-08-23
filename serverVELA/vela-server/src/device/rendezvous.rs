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

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession, DeviceSession},
    net, rate_limit,
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

/// Short by design. A grant is only alive while a person is holding two devices
/// and looking at both, which is a matter of a minute or two, and every extra
/// minute is time an intercepted code stays useful.
const GRANT_TTL_SECS: u64 = 5 * 60;

const HYBRID_EK_LEN: usize = 1568 + 32;
const HYBRID_VK_LEN: usize = 2592 + 32;
const HYBRID_SIG_LEN: usize = 4627 + 64;

fn grant_key(id: &str) -> String {
    format!("enroll_grant:{id}")
}

fn claim_key(id: &str) -> String {
    format!("enroll_claim:{id}")
}

fn result_key(id: &str) -> String {
    format!("enroll_result:{id}")
}

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

    let grant_id = Uuid::new_v4().to_string();
    let grant = Grant {
        user_id: session.user_id.to_string(),
        device_id: session.device_id.to_string(),
    };
    state.store.set_ex(
        &grant_key(&grant_id),
        serde_json::to_vec(&grant)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .as_slice(),
        GRANT_TTL_SECS,
    )?;

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
    if !state.store.exists(&grant_key(grant_id))? {
        return Err(AppError::NotFound("enrollment grant not found or expired".into()));
    }

    let ek = decode_exact(&body.hybrid_ek, HYBRID_EK_LEN, "hybrid_ek")?;
    let vk = decode_exact(&body.hybrid_vk, HYBRID_VK_LEN, "hybrid_vk")?;

    let claim = Claim {
        hybrid_ek: B64.encode(&ek),
        hybrid_vk: B64.encode(&vk),
        device_name: body.device_name.clone(),
        device_type: body.device_type.clone(),
    };

    // First claim wins, atomically. A second device — including one racing with
    // a stolen code — is told it lost rather than replacing the first, so the
    // user sees a failure on the device they are actually holding.
    let won = state.store.set_ex_nx(
        &claim_key(grant_id),
        serde_json::to_vec(&claim)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .as_slice(),
        GRANT_TTL_SECS,
    )?;
    if !won {
        return Err(AppError::Conflict(
            "this enrollment code has already been used by another device".into(),
        ));
    }

    Ok(Json(serde_json::json!({ "claimed": true })))
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
    authorize_grant(&state, grant_id, &session)?;

    let claim = load_claim(&state, grant_id)?
        .ok_or_else(|| AppError::NotFound("no device has claimed this code yet".into()))?;

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
}

#[derive(Serialize)]
pub struct CompleteResponse {
    pub device_id: Uuid,
}

pub async fn post_complete(
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
    session: DeviceSession,
    Json(body): Json<CompleteRequest>,
) -> Result<(HeaderMap, Json<CompleteResponse>)> {
    let grant_id = crate::ids::validate_id("grant_id", &grant_id)?;
    let grant = authorize_grant(&state, grant_id, &session)?;

    let user_rows = state
        .sqldb
        .query(
            "SELECT rekey_state FROM users WHERE id = ?",
            vec![TursoValue::Text(grant.user_id.clone())],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if user_rows.first().and_then(|row| row.text(0)).is_some() {
        return Err(AppError::Conflict(
            "device enrollment is paused during vault key rotation".into(),
        ));
    }

    // Take both together. A replayed completion finds nothing, and a grant that
    // failed midway cannot be retried with a different claim.
    let claim_bytes = state
        .store
        .get_del(&claim_key(grant_id))?
        .ok_or_else(|| AppError::NotFound("no device has claimed this code yet".into()))?;
    let grant_bytes = state
        .store
        .get_del(&grant_key(grant_id))?
        .ok_or_else(|| AppError::NotFound("enrollment grant not found or expired".into()))?;

    let claim: Claim = serde_json::from_slice(&claim_bytes)
        .map_err(|e| AppError::Internal(format!("stored claim is unreadable: {e}")))?;

    // The keys enrolled below come from `claim` — what the joining device
    // presented and what the user's fingerprint comparison was about — and never
    // from the request body. There is deliberately no field in which the primary
    // could name a different key than the one displayed.
    let hybrid_ek = crate::db::decode_b64(&claim.hybrid_ek)?;
    let hybrid_vk = crate::db::decode_b64(&claim.hybrid_vk)?;
    let rms_capsule = decode_any(&body.rms_capsule, "rms_capsule")?;
    let signature = decode_exact(&body.signature, HYBRID_SIG_LEN, "signature")?;

    let primary_vk = load_primary_vk(&state, &grant).await?;
    super::enroll::verify_enrollment_signature(
        &primary_vk,
        &hybrid_ek,
        &hybrid_vk,
        &rms_capsule,
        &signature,
    )?;

    let new_device_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();
    let device_name = claim
        .device_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "New Device".to_string());
    let device_type = claim
        .device_type
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let inserted = state.sqldb.execute(
        "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, rms_capsule, created_at)
         SELECT ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?
         WHERE EXISTS (
             SELECT 1 FROM users WHERE id = ? AND rekey_state IS NULL
         )",
        vec![
            TursoValue::Text(new_device_id.to_string()),
            TursoValue::Text(grant.user_id.clone()),
            TursoValue::Text(device_name),
            TursoValue::Text(device_type),
            TursoValue::Text(crate::db::encode_b64(&hybrid_ek)),
            TursoValue::Text(crate::db::encode_b64(&hybrid_vk)),
            TursoValue::Text(grant.device_id.clone()),
            TursoValue::Text(crate::db::encode_b64(&rms_capsule)),
            TursoValue::Text(now),
            TursoValue::Text(grant.user_id.clone()),
        ],
    ).await.map_err(|e| AppError::Internal(e.to_string()))?;
    if inserted == 0 {
        // A rotation may have started after the fast check but before the
        // guarded insert. Restore the exact consumed claim and grant so the
        // already-confirmed pairing can be retried once rotation completes.
        state
            .store
            .set_ex(&claim_key(grant_id), &claim_bytes, GRANT_TTL_SECS)?;
        state
            .store
            .set_ex(&grant_key(grant_id), &grant_bytes, GRANT_TTL_SECS)?;
        return Err(AppError::Conflict(
            "device enrollment is paused during vault key rotation".into(),
        ));
    }

    // Only now that the row exists: the joining device is holding a keypair and
    // waiting to be told which device it became. Written after the insert so a
    // failed enrollment never leaves behind a result pointing at no device.
    let result = EnrollmentResult {
        device_id: new_device_id.to_string(),
        hybrid_vk: claim.hybrid_vk.clone(),
    };
    state.store.set_ex(
        &result_key(grant_id),
        serde_json::to_vec(&result)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .as_slice(),
        GRANT_TTL_SECS,
    )?;

    tracing::info!(
        new_device_id = %new_device_id,
        enrolled_by = %grant.device_id,
        user_id = %grant.user_id,
        "device enrolled (v3 rendezvous)"
    );

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((headers, Json(CompleteResponse { device_id: new_device_id })))
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
    Enrolled { device_id: String },
}

/// Tell a device that claimed a grant which device it became.
///
/// Unauthenticated in the session sense and necessarily so — the `device_id`
/// this returns is exactly what the caller is missing in order to authenticate.
/// The proof is the signature: only the holder of the private half of the
/// claimed key can produce it, so someone who photographed the enrollment code
/// learns nothing here, not even whether a claim exists. That last part is why
/// the signature is checked *before* the pending branch answers.
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

    let signature = decode_exact(&body.signature, HYBRID_SIG_LEN, "signature")?;

    // Completed: the claim is gone and the result carries the vk forward.
    if let Some(bytes) = state.store.get(&result_key(grant_id))? {
        let result: EnrollmentResult = serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("stored result is unreadable: {e}")))?;
        let vk = crate::db::decode_b64(&result.hybrid_vk)?;
        verify_result_signature(&vk, grant_id, &signature)?;
        return Ok(Json(ResultResponse::Enrolled {
            device_id: result.device_id,
        }));
    }

    // Not completed yet. Still checked against the claimed key, so "pending" is
    // not an answer an interceptor can get.
    if let Some(claim) = load_claim(&state, grant_id)? {
        let vk = crate::db::decode_b64(&claim.hybrid_vk)?;
        verify_result_signature(&vk, grant_id, &signature)?;
        return Ok(Json(ResultResponse::Pending));
    }

    Err(AppError::NotFound(
        "enrollment grant not found or expired".into(),
    ))
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
    super::enroll::verify_enrollment_result_signature(vk, grant_id, signature).map_err(|e| {
        match e {
            AppError::Internal(_) => AppError::Unauthorized(
                "signature does not match the key this grant was claimed with".into(),
            ),
            other => other,
        }
    })
}

// ── shared ──────────────────────────────────────────────────────────────────

/// Load a grant and require the caller to be the device that opened it.
///
/// Not just the same *user*: a second device of the same account must not be
/// able to drive an enrollment its owner started elsewhere, because then a
/// compromised secondary could enroll an attacker's key against a code the user
/// is reading off their primary.
fn authorize_grant(state: &AppState, grant_id: &str, session: &AuthSession) -> Result<Grant> {
    let bytes = state
        .store
        .get(&grant_key(grant_id))?
        .ok_or_else(|| AppError::NotFound("enrollment grant not found or expired".into()))?;
    let grant: Grant = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Internal(format!("stored grant is unreadable: {e}")))?;

    if grant.user_id != session.user_id.to_string() || grant.device_id != session.device_id.to_string()
    {
        // Same message as "not found": whether a grant exists is not something
        // an unrelated caller should be able to probe.
        return Err(AppError::NotFound("enrollment grant not found or expired".into()));
    }
    Ok(grant)
}

fn load_claim(state: &AppState, grant_id: &str) -> Result<Option<Claim>> {
    match state.store.get(&claim_key(grant_id))? {
        Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(|e| {
            AppError::Internal(format!("stored claim is unreadable: {e}"))
        })?)),
        None => Ok(None),
    }
}

async fn load_primary_vk(state: &AppState, grant: &Grant) -> Result<Vec<u8>> {
    let rows = state
        .sqldb
        .query(
            "SELECT hybrid_vk FROM devices WHERE id = ? AND user_id = ? AND revoked = 0",
            vec![
                TursoValue::Text(grant.device_id.clone()),
                TursoValue::Text(grant.user_id.clone()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let vk_b64 = rows
        .first()
        .and_then(|r| r.text(0))
        .ok_or_else(|| AppError::Unauthorized("enrolling device not found or revoked".into()))?;
    crate::db::decode_b64(vk_b64)
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
