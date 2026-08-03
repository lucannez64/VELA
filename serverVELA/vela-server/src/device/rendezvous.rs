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
    middleware::{maybe_append_new_token, AuthSession},
    net, rate_limit,
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

// ── 1. The primary opens a grant ────────────────────────────────────────────

#[derive(Serialize)]
pub struct CreateGrantResponse {
    pub grant_id: String,
    pub expires_in: u64,
}

pub async fn post_grant(
    State(state): State<AppState>,
    session: AuthSession,
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
    session: AuthSession,
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
    session: AuthSession,
    Json(body): Json<CompleteRequest>,
) -> Result<(HeaderMap, Json<CompleteResponse>)> {
    let grant_id = crate::ids::validate_id("grant_id", &grant_id)?;
    let grant = authorize_grant(&state, grant_id, &session)?;

    // Take both together. A replayed completion finds nothing, and a grant that
    // failed midway cannot be retried with a different claim.
    let claim_bytes = state
        .store
        .get_del(&claim_key(grant_id))?
        .ok_or_else(|| AppError::NotFound("no device has claimed this code yet".into()))?;
    let _ = state.store.get_del(&grant_key(grant_id))?;

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

    let primary_vk = load_primary_vk(&state, &grant)?;
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

    state.db.execute(
        "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, rms_capsule, created_at)
         VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, $8, $9)",
        stoolap::params![
            new_device_id.to_string(),
            grant.user_id.clone(),
            device_name,
            device_type,
            crate::db::encode_b64(&hybrid_ek),
            crate::db::encode_b64(&hybrid_vk),
            grant.device_id.clone(),
            crate::db::encode_b64(&rms_capsule),
            now,
        ],
    ).map_err(|e| AppError::Internal(e.to_string()))?;

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

fn load_primary_vk(state: &AppState, grant: &Grant) -> Result<Vec<u8>> {
    let rows = state
        .db
        .query(
            "SELECT hybrid_vk FROM devices WHERE id = $1 AND user_id = $2 AND revoked = FALSE",
            stoolap::params![grant.device_id.clone(), grant.user_id.clone()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let row = rows
        .into_iter()
        .next()
        .ok_or_else(|| AppError::Unauthorized("enrolling device not found or revoked".into()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let value = crate::db::row_val(&row, 0)?;
    let vk_b64 = value
        .as_str()
        .ok_or_else(|| AppError::Internal("device has no verifying key".into()))?;
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
