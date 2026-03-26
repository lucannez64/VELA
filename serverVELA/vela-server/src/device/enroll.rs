//! POST /device/enroll
//!
//! Registers a new device (Device B) on behalf of an already-enrolled
//! device (Device A).  Auth is provided by a fresh Cyclo ZKP from Device A —
//! this is an escalated-auth endpoint: even a valid session token is not
//! sufficient because enrollment is a high-value operation.
//!
//! ## Request body
//!
//! ```json
//! {
//!   "enrolling_device_id": "<uuid>",          // Device A
//!   "challenge":           "<base64 32-byte>", // from GET /auth/challenge
//!   "committed_hash":      "<hex 32-byte>",    // BLAKE3(sk_A ‖ challenge)
//!   "proof":               "<base64>",         // Cyclo proof for Device A
//!
//!   "new_device": {
//!     "hybrid_ek":   "<base64 1600-byte>",   // ML-KEM-1024 EK ‖ X25519 PK
//!     "hybrid_vk":   "<base64 2624-byte>",   // ML-DSA-87 VK ‖ Ed25519 VK
//!     "cyclo_pk":    "<base64 1024-byte>",   // Cyclo public key (128 × u64 LE)
//!     "rms_capsule": "<base64>",             // RMS encapsulated for Device B
//!     "signature":   "<base64 4691-byte>"    // Device A signs Device B's hybrid_vk
//!   }
//! }
//! ```
//!
//! ## Flow
//!
//! 1. Consume challenge nonce from Redis.
//! 2. Verify enrolling device's Cyclo proof (Device A must be active).
//! 3. Verify Device A's hybrid signature over Device B's `hybrid_vk`.
//! 4. Insert Device B into the `devices` table.
//!
//! The new device's ID is returned so Device B can authenticate via
//! `GET /auth/challenge` → `POST /auth/verify` to obtain its own session.

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    state::AppState,
};

// ─── Wire types ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct NewDevicePayload {
    /// ML-KEM-1024 encapsulation key (1568 B) ‖ X25519 public key (32 B) → 1600 B, base64.
    pub hybrid_ek: String,
    /// ML-DSA-87 verifying key (2592 B) ‖ Ed25519 verifying key (32 B) → 2624 B, base64.
    pub hybrid_vk: String,
    /// Cyclo ZKP public key: 128 u64 LE values → 1024 B, base64.
    pub cyclo_pk: String,
    /// Hybrid KEM capsule carrying the RMS for Device B, base64.
    pub rms_capsule: String,
    /// Device A's hybrid signature over Device B's raw `hybrid_vk` bytes, base64.
    pub signature: String,
}

#[derive(Deserialize)]
pub struct EnrollRequest {
    /// UUID of the device performing the enrollment (Device A).
    pub enrolling_device_id: Uuid,
    /// Base64-encoded 32-byte challenge nonce.
    pub challenge: String,
    /// Hex-encoded 32-byte BLAKE3(sk_A ‖ challenge).
    pub committed_hash: String,
    /// Base64-encoded Cyclo proof for Device A.
    pub proof: String,
    /// Public key material and capsule for Device B.
    pub new_device: NewDevicePayload,
}

#[derive(Serialize)]
pub struct EnrollResponse {
    /// UUID assigned to the newly enrolled device.
    pub device_id: Uuid,
}

// ─── Handler ──────────────────────────────────────────────────────────────────

pub async fn post_enroll(
    State(state): State<AppState>,
    Json(body): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>> {
    let mut redis = state.redis.clone();

    // ── 1. Consume challenge nonce ────────────────────────────────────────────
    let challenge_key = format!("challenge:{}", body.challenge);
    let consumed: i64 = redis
        .del(&challenge_key)
        .await
        .map_err(AppError::Redis)?;
    if consumed == 0 {
        return Err(AppError::Unauthorized(
            "challenge not found or already used".into(),
        ));
    }

    // ── 2. Fetch enrolling device (Device A) ──────────────────────────────────
    let device_a = sqlx::query_as::<_, crate::db::DeviceRow>(
        r#"SELECT id, user_id, hybrid_ek, hybrid_vk, cyclo_pk,
                  enrolled_by, rms_capsule, revoked,
                  revoked_at, revoked_by, created_at
           FROM devices
           WHERE id = $1 AND revoked = FALSE"#,
    )
    .bind(body.enrolling_device_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::Unauthorized("enrolling device not found or revoked".into()))?;

    // ── 3. Verify Device A's Cyclo proof ──────────────────────────────────────
    verify_cyclo_proof(
        &device_a.cyclo_pk,
        &body.committed_hash,
        &body.proof,
    )?;

    // ── 4. Decode new-device key material ─────────────────────────────────────
    let new_hybrid_ek = B64.decode(&body.new_device.hybrid_ek)
        .map_err(|_| AppError::BadRequest("hybrid_ek is not valid base64".into()))?;
    let new_hybrid_vk_bytes = B64.decode(&body.new_device.hybrid_vk)
        .map_err(|_| AppError::BadRequest("hybrid_vk is not valid base64".into()))?;
    let new_cyclo_pk = B64.decode(&body.new_device.cyclo_pk)
        .map_err(|_| AppError::BadRequest("cyclo_pk is not valid base64".into()))?;
    let rms_capsule = B64.decode(&body.new_device.rms_capsule)
        .map_err(|_| AppError::BadRequest("rms_capsule is not valid base64".into()))?;
    let signature_bytes = B64.decode(&body.new_device.signature)
        .map_err(|_| AppError::BadRequest("signature is not valid base64".into()))?;

    // Validate byte-length constants defined in vela-crypto::signing.
    const HYBRID_EK_LEN: usize = 1568 + 32;   // ML-KEM-1024 ct + X25519 pk
    const HYBRID_VK_LEN: usize = 2592 + 32;   // ML-DSA-87 vk + Ed25519 vk
    const CYCLO_PK_LEN:  usize = 128 * 8;     // 128 × u64
    const HYBRID_SIG_LEN: usize = 4627 + 64;  // ML-DSA-87 sig + Ed25519 sig

    if new_hybrid_ek.len() != HYBRID_EK_LEN {
        return Err(AppError::BadRequest(format!(
            "hybrid_ek must be {HYBRID_EK_LEN} bytes"
        )));
    }
    if new_hybrid_vk_bytes.len() != HYBRID_VK_LEN {
        return Err(AppError::BadRequest(format!(
            "hybrid_vk must be {HYBRID_VK_LEN} bytes"
        )));
    }
    if new_cyclo_pk.len() != CYCLO_PK_LEN {
        return Err(AppError::BadRequest(format!(
            "cyclo_pk must be {CYCLO_PK_LEN} bytes"
        )));
    }
    if signature_bytes.len() != HYBRID_SIG_LEN {
        return Err(AppError::BadRequest(format!(
            "signature must be {HYBRID_SIG_LEN} bytes"
        )));
    }

    // ── 5. Verify Device A's signature over Device B's hybrid_vk ──────────────
    verify_enrollment_signature(
        &device_a.hybrid_vk,
        &new_hybrid_vk_bytes,
        &signature_bytes,
    )?;

    // ── 6. Insert Device B ────────────────────────────────────────────────────
    let new_device_id = Uuid::new_v4();

    sqlx::query(
        r#"INSERT INTO devices
           (id, user_id, hybrid_ek, hybrid_vk, cyclo_pk, enrolled_by, rms_capsule)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(new_device_id)
    .bind(device_a.user_id)
    .bind(new_hybrid_ek)
    .bind(new_hybrid_vk_bytes)
    .bind(new_cyclo_pk)
    .bind(body.enrolling_device_id)
    .bind(rms_capsule)
    .execute(&state.db)
    .await?;

    tracing::info!(
        new_device_id = %new_device_id,
        enrolled_by   = %body.enrolling_device_id,
        user_id       = %device_a.user_id,
        "device enrolled"
    );

    Ok(Json(EnrollResponse { device_id: new_device_id }))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Verify a Cyclo ZKP for authentication (reused by both enroll and verify).
pub fn verify_cyclo_proof(
    cyclo_pk_bytes: &[u8],
    committed_hash_hex: &str,
    proof_b64: &str,
) -> Result<()> {
    let cyclo_pk_u64s = le_bytes_to_u64_slice(cyclo_pk_bytes)
        .ok_or_else(|| AppError::Internal("corrupt cyclo_pk".into()))?;

    let hash_bytes = hex::decode(committed_hash_hex)
        .map_err(|_| AppError::BadRequest("committed_hash is not valid hex".into()))?;
    if hash_bytes.len() != 32 {
        return Err(AppError::BadRequest("committed_hash must be 32 bytes".into()));
    }
    let hash_u64s = le_bytes_to_u64_slice(&hash_bytes).unwrap();

    let mut public_inputs: Vec<u64> =
        Vec::with_capacity(cyclo_pk_u64s.len() + hash_u64s.len());
    public_inputs.extend_from_slice(&cyclo_pk_u64s);
    public_inputs.extend_from_slice(&hash_u64s);

    let proof_bytes = B64
        .decode(proof_b64)
        .map_err(|_| AppError::BadRequest("proof is not valid base64".into()))?;
    let proof = vela_crypto::cyclo::CycloProof::from_bytes(proof_bytes);

    let ok = vela_crypto::cyclo::verify(&public_inputs, &proof)
        .map_err(|e| AppError::Internal(format!("ZKP verify error: {e}")))?;

    if !ok {
        return Err(AppError::Unauthorized("Cyclo proof invalid".into()));
    }
    Ok(())
}

/// Verify Device A's hybrid signature (ML-DSA-87 + Ed25519) over `message`.
fn verify_enrollment_signature(
    device_a_vk_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<()> {
    use vela_crypto::signing::{HybridSignature, HybridVerifyingKey, HYBRID_SIG_LEN, HYBRID_VK_LEN};

    let vk_arr: &[u8; HYBRID_VK_LEN] = device_a_vk_bytes
        .try_into()
        .map_err(|_| AppError::Internal("stored hybrid_vk has wrong length".into()))?;
    let sig_arr: &[u8; HYBRID_SIG_LEN] = signature_bytes
        .try_into()
        .map_err(|_| AppError::BadRequest("signature has wrong length".into()))?;

    let vk  = HybridVerifyingKey::from_bytes(vk_arr)
        .map_err(|e| AppError::Internal(format!("vk decode: {e}")))?;
    let sig = HybridSignature::from_bytes(sig_arr)
        .map_err(|e| AppError::BadRequest(format!("signature decode: {e}")))?;

    let ok = vela_crypto::signing::verify(&vk, message, &sig)
        .map_err(|e| AppError::Internal(format!("signature verify: {e}")))?;

    if !ok {
        return Err(AppError::Unauthorized(
            "enrolling device signature over new device's public key is invalid".into(),
        ));
    }
    Ok(())
}

fn le_bytes_to_u64_slice(bytes: &[u8]) -> Option<Vec<u64>> {
    if bytes.len() % 8 != 0 {
        return None;
    }
    Some(
        bytes
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect(),
    )
}
