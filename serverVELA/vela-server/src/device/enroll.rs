use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    state::AppState,
};

#[derive(Deserialize)]
pub struct NewDevicePayload {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub cyclo_pk: String,
    pub rms_capsule: String,
    pub signature: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

#[derive(Deserialize)]
pub struct EnrollRequest {
    pub enrolling_device_id: Uuid,
    pub challenge: String,
    pub committed_hash: String,
    pub proof: String,
    pub new_device: NewDevicePayload,
}

#[derive(Serialize)]
pub struct EnrollResponse {
    pub device_id: Uuid,
}

pub async fn post_enroll(
    State(state): State<AppState>,
    Json(body): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>> {
    let enrolling_device_id_str = body.enrolling_device_id.to_string();
    let challenge_key = format!("challenge:{}", body.challenge);
    let consumed = state.store.get_del(&challenge_key)?;
    if consumed.is_none() {
        return Err(AppError::Unauthorized(
            "challenge not found or already used".into(),
        ));
    }

    let rows = state
        .db
        .query(
            "SELECT id, user_id, device_name, device_type, last_active,
                hybrid_ek, hybrid_vk, cyclo_pk,
                enrolled_by, rms_capsule, revoked,
                revoked_at, revoked_by, created_at
         FROM devices
         WHERE id = $1 AND revoked = FALSE",
            stoolap::params![enrolling_device_id_str.clone()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let row = rows
        .into_iter()
        .next()
        .ok_or_else(|| AppError::Unauthorized("enrolling device not found or revoked".into()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let device_a = crate::db::parse_device_row(&row)?;

    let challenge_bytes = B64
        .decode(&body.challenge)
        .map_err(|_| AppError::BadRequest("invalid challenge encoding".into()))?;

    let mut hasher = Sha256::new();
    hasher.update(&challenge_bytes);
    hasher.update(enrolling_device_id_str.as_bytes());
    let expected_hash_hex = hex::encode(hasher.finalize());

    if body.committed_hash != expected_hash_hex {
        return Err(AppError::BadRequest(
            "committed_hash does not match challenge".into(),
        ));
    }

    verify_cyclo_proof(&device_a.cyclo_pk, &body.committed_hash, &body.proof)?;

    let new_hybrid_ek = B64
        .decode(&body.new_device.hybrid_ek)
        .map_err(|_| AppError::BadRequest("hybrid_ek is not valid base64".into()))?;
    let new_hybrid_vk_bytes = B64
        .decode(&body.new_device.hybrid_vk)
        .map_err(|_| AppError::BadRequest("hybrid_vk is not valid base64".into()))?;
    let new_cyclo_pk = B64
        .decode(&body.new_device.cyclo_pk)
        .map_err(|_| AppError::BadRequest("cyclo_pk is not valid base64".into()))?;
    let rms_capsule = B64
        .decode(&body.new_device.rms_capsule)
        .map_err(|_| AppError::BadRequest("rms_capsule is not valid base64".into()))?;
    let signature_bytes = B64
        .decode(&body.new_device.signature)
        .map_err(|_| AppError::BadRequest("signature is not valid base64".into()))?;

    const HYBRID_EK_LEN: usize = 1568 + 32;
    const HYBRID_VK_LEN: usize = 2592 + 32;
    const CYCLO_PK_LEN: usize = 128 * 8;
    const HYBRID_SIG_LEN: usize = 4627 + 64;

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

    verify_enrollment_signature(&device_a.hybrid_vk, &new_hybrid_vk_bytes, &signature_bytes)?;

    let new_device_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();
    let device_name = body
        .new_device
        .device_name
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Desktop Device".to_string());
    let device_type = body
        .new_device
        .device_type
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "desktop".to_string());

    state.db.execute(
        "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, cyclo_pk, enrolled_by, rms_capsule, created_at)
         VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, $8, $9, $10)",
        stoolap::params![
            new_device_id.to_string(),
            device_a.user_id.to_string(),
            device_name,
            device_type,
            crate::db::encode_b64(&new_hybrid_ek),
            crate::db::encode_b64(&new_hybrid_vk_bytes),
            crate::db::encode_b64(&new_cyclo_pk),
            enrolling_device_id_str,
            crate::db::encode_b64(&rms_capsule),
            now,
        ],
    ).map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::info!(
        new_device_id = %new_device_id,
        enrolled_by   = %body.enrolling_device_id,
        user_id       = %device_a.user_id,
        "device enrolled"
    );

    Ok(Json(EnrollResponse {
        device_id: new_device_id,
    }))
}

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
        return Err(AppError::BadRequest(
            "committed_hash must be 32 bytes".into(),
        ));
    }
    let hash_u64s = le_bytes_to_u64_slice(&hash_bytes).unwrap();

    let mut public_inputs: Vec<u64> = Vec::with_capacity(cyclo_pk_u64s.len() + hash_u64s.len());
    public_inputs.extend_from_slice(&cyclo_pk_u64s);
    public_inputs.extend_from_slice(&hash_u64s);

    let proof_bytes = B64
        .decode(proof_b64)
        .map_err(|_| AppError::BadRequest("proof is not valid base64".into()))?;
    let proof = vela_crypto::cyclo::CycloProof::from_bytes(proof_bytes);

    // VELA auth witness is always cyclo_sk: N=128 u64 ring-element coefficients.
    let ok = vela_crypto::cyclo::verify(&public_inputs, 128, &proof)
        .map_err(|e| AppError::Internal(format!("ZKP verify error: {e}")))?;

    if !ok {
        return Err(AppError::Unauthorized("Cyclo proof invalid".into()));
    }
    Ok(())
}

fn verify_enrollment_signature(
    device_a_vk_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<()> {
    use vela_crypto::signing::{
        HybridSignature, HybridVerifyingKey, HYBRID_SIG_LEN, HYBRID_VK_LEN,
    };

    let vk_arr: &[u8; HYBRID_VK_LEN] = device_a_vk_bytes
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
