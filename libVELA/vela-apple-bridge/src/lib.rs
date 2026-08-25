//! Apple (iOS/macOS) C-ABI bridge over the shared VELA Rust core.
//!
//! Mirrors the stable C ABI of the Android bridge but without JNI, so it links
//! into a Swift app as a static library / XCFramework. Most calls take and
//! return UTF-8 JSON via owned C strings; the caller must free every returned
//! pointer with `vela_ffi_free_string`.
//!
//! Secrets are the exception: like the Android bridge, every function that
//! consumes the RMS takes it as raw bytes beside the JSON envelope, never as
//! base64 inside it — Swift `String`s are immutable and un-wipeable, so an
//! encoded key stayed readable in memory for the life of the process (audit
//! I-2; same rationale as the identity seal key, audit C-1).

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::ffi::{c_char, c_uchar, CStr, CString};

use vela_core::{calculate_password_strength, PasswordStrength, VaultStore};
use vela_crypto::{aead, kdf, kem, shamir};

const VAULT_KEY_CONTEXT: &str = "vela vault encryption v1";

type FfiResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[derive(Serialize)]
struct BridgeError {
    error: String,
}

#[derive(Deserialize)]
struct PasswordStrengthRequest {
    password: String,
}
#[derive(Serialize)]
struct PasswordStrengthResponse {
    strength: PasswordStrength,
}

#[derive(Deserialize)]
struct EncryptVaultRequest {
    vault_json: String,
}
#[derive(Serialize, Deserialize)]
struct EncryptVaultResponse {
    ciphertext_b64: String,
}

#[derive(Deserialize)]
struct DecryptVaultRequest {
    ciphertext_b64: String,
}
#[derive(Serialize, Deserialize)]
struct DecryptVaultResponse {
    vault_json: String,
}

#[derive(Deserialize)]
struct SealShareRequest {
    recipient_share_ek_b64: String,
    item_json: String,
}

#[derive(Serialize)]
struct SealShareResponse {
    capsule_b64: String,
}

#[derive(Serialize)]
struct OpenShareResponse {
    item_json: String,
}

// Phase 4 ── sync / enrollment / recovery payloads ──────────────────────────────

/// Everything an identity handle exposes: public halves plus the sealed blob the
/// app persists. No private key appears here — that is the point (audit C-1).
#[derive(Serialize)]
struct IdentityHandleResponse {
    handle: u64,
    hybrid_ek_b64: String,
    hybrid_vk_b64: String,
    share_ek_b64: String,
    sealed_b64: String,
}

#[derive(Deserialize)]
struct IdentityImportRequest {
    hybrid_sk_b64: String,
    #[serde(default)]
    share_dk_b64: String,
    #[serde(default)]
    hybrid_ek_b64: String,
}

#[derive(Deserialize)]
struct IdentityOpenRequest {
    sealed_b64: String,
}

#[derive(Deserialize)]
struct IdentitySignRequest {
    handle: u64,
    device_id: String,
    challenge_b64: String,
}

#[derive(Serialize, Deserialize)]
struct AuthSignatureResponse {
    signature_b64: String,
}

#[derive(Deserialize)]
struct IdentityOpenShareRequest {
    handle: u64,
    capsule_b64: String,
}

#[derive(Deserialize)]
struct IdentityHandleRequest {
    handle: u64,
}

// Enrollment v3 (audit P-1). The fingerprint request carries only the handle:
// the value shown to the user has to come from the key this device holds, and
// an API that accepted key bytes would make "render what the server sent" a
// one-line mistake.

#[derive(Serialize, Deserialize)]
struct IdentityFingerprintResponse {
    fingerprint: String,
}

#[derive(Deserialize)]
struct IdentityEnrollmentResultRequest {
    handle: u64,
    grant_id: String,
}

#[derive(Deserialize)]
struct IdentityCapsuleRequest {
    handle: u64,
    capsule_b64: String,
}

#[derive(Serialize, Deserialize)]
struct IdentityCapsuleResponse {
    /// The 32-byte root master secret, base64. Sealed to this device's own
    /// `hybrid_ek`, so it opens here and nowhere else.
    rms_b64: String,
}

#[derive(Serialize)]
struct IdentityRotateShareKeyResponse {
    share_ek_b64: String,
    sealed_b64: String,
}

#[derive(Serialize)]
struct IdentityOkResponse {
    ok: bool,
}

/// No fields: the RMS arrives as raw bytes next to the request string, not in
/// it (audit I-2 — same treatment as the identity seal key, audit C-1).
#[derive(Deserialize)]
struct WebSessionChunkKeysRequest {}
#[derive(Serialize)]
struct WebSessionChunkKeysResponse {
    /// `chunk_id → base64(32-byte key)` for the chunks a read-write web session
    /// is granted. The RMS itself never leaves the approver (audit D-2).
    chunk_keys: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct EncryptChunkRequest {
    chunk_id: String,
    vault_json: String,
    /// Epoch 1 keeps the legacy AAD for Android/web compatibility. Rotated
    /// epochs are bound explicitly and reject legacy ciphertext.
    #[serde(default = "default_key_epoch")]
    key_epoch: i64,
    /// The clock this chunk will be stored under, bound into the ciphertext so
    /// the server cannot replay an older revision (audit C-2). Not defaulted:
    /// a caller that forgets it would seal against clock 0 and write something
    /// nothing can read.
    lamport_clock: i64,
}
#[derive(Deserialize)]
struct DecryptChunkRequest {
    chunk_id: String,
    #[serde(default = "default_key_epoch")]
    key_epoch: i64,
    /// Revision the server claimed for this chunk. Verified for sealed
    /// ciphertexts, ignored for legacy ones (audit C-2, rollout step 2).
    #[serde(default)]
    lamport_clock: i64,
    ciphertext_b64: String,
}

fn default_key_epoch() -> i64 {
    1
}

#[derive(Deserialize)]
struct DecryptRmsCapsuleRequest {
    transfer_key_b64: String,
    capsule_b64: String,
}
#[derive(Serialize, Deserialize)]
struct DecryptRmsCapsuleResponse {
    rms_b64: String,
}

#[derive(Deserialize)]
struct DecryptEnrollmentPackageRequest {
    key_b64: String,
    ciphertext_b64: String,
}
#[derive(Serialize, Deserialize)]
struct DecryptEnrollmentPackageResponse {
    plaintext: String,
}

#[derive(Deserialize)]
struct SplitRecoveryRequest {
    threshold: u8,
    n: u8,
}
#[derive(Serialize, Deserialize)]
struct SplitRecoveryResponse {
    /// One base64 Shamir share per `[x, y_0..y_31]` blob.
    shares_b64: Vec<String>,
}

#[derive(Deserialize)]
struct CombineShareInput {
    share_b64: String,
    /// One of "cloud", "server", "trusted_contact" (M18 pair selection).
    channel: String,
    account_id: String,
    key_epoch: i64,
    #[serde(default)]
    split_id: Option<String>,
    /// True only when this share was opened out of an authenticated,
    /// recipient-bound contact envelope.
    #[serde(default)]
    recipient_bound: bool,
}

#[derive(Deserialize)]
struct CombineRecoveryRequest {
    shares_b64: Vec<String>,
    #[serde(default)]
    requested_user_id: Option<String>,
    #[serde(default)]
    cloud_user_id: Option<String>,
    #[serde(default)]
    cloud_key_epoch: Option<i64>,
    #[serde(default)]
    cloud_split_id: Option<String>,
    #[serde(default)]
    server_user_id: Option<String>,
    #[serde(default)]
    server_key_epoch: Option<i64>,
    #[serde(default)]
    server_split_id: Option<String>,
    /// M18: channel-tagged bound shares. When present, exactly these two are
    /// reconstructed through the verified pair-selection policy; the legacy
    /// flat fields above remain for pre-M18 callers pinned to cloud+server.
    #[serde(default)]
    bound_shares: Vec<CombineShareInput>,
}
#[derive(Serialize, Deserialize)]
struct CombineRecoveryResponse {
    rms_b64: String,
}

#[derive(Deserialize)]
struct PublicationPlanRequest {
    journal_present: bool,
    account_matches: bool,
    split_id_present: bool,
    cloud_share_present: bool,
    server_share_present: bool,
    journal_epoch: i64,
    current_epoch: i64,
    account_epoch_active: bool,
    server_staged: bool,
    cloud_candidate_durable: bool,
    server_finalized: bool,
    cloud_active: bool,
}

#[derive(Serialize)]
struct PublicationPlanResponse {
    action: String,
}

// ── Exported C ABI ─────────────────────────────────────────────────────────────

/// Returns the bridge version string. Free with `vela_ffi_free_string`.
#[no_mangle]
pub extern "C" fn vela_ffi_version() -> *mut c_char {
    string_to_ptr(concat!("vela-apple-bridge/", env!("CARGO_PKG_VERSION")))
}

/// Free a string returned by any `vela_ffi_*` function.
///
/// # Safety
/// `ptr` must be a pointer previously returned by this library, or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

/// Compute the short out-of-band verification code for an enrollment code
/// string (see `vela_crypto::verification`). Call this right after
/// scanning/pasting an enrollment code, before importing it, so the user can
/// confirm it matches what the enrolling device shows. Free the result with
/// `vela_ffi_free_string`.
///
/// # Safety
/// `code` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_enrollment_verification_code(code: *const c_char) -> *mut c_char {
    let code_str = c_str(code).unwrap_or("");
    string_to_ptr(&vela_crypto::verification::enrollment_verification_code(
        code_str,
    ))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_password_strength_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| {
        let req: PasswordStrengthRequest = serde_json::from_str(c_str(request_json)?)?;
        Ok(PasswordStrengthResponse {
            strength: calculate_password_strength(&req.password),
        })
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
/// # Safety
/// `rms` must point to `rms_len` readable bytes; `request_json` must be a valid
/// NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_encrypt_vault_json(
    rms: *const c_uchar,
    rms_len: usize,
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| {
        let rms = rms_from(raw_slice(rms, rms_len)?)?;
        encrypt_vault_json(&rms, c_str(request_json)?)
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
/// # Safety
/// `rms` must point to `rms_len` readable bytes; `request_json` must be a valid
/// NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_decrypt_vault_json(
    rms: *const c_uchar,
    rms_len: usize,
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| {
        let rms = rms_from(raw_slice(rms, rms_len)?)?;
        decrypt_vault_json(&rms, c_str(request_json)?)
    })
}

// ── Identity handles (audit C-1) ─────────────────────────────────────────────
//
// The seal key arrives as raw bytes, never as a `String`: Swift strings are as
// immutable and un-wipeable as JVM ones. The signing key and share
// decapsulation key never cross this boundary in either direction.

/// # Safety
/// `seal_key` must point to `seal_key_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_identity_create(
    seal_key: *const c_uchar,
    seal_key_len: usize,
) -> *mut c_char {
    json_result(|| identity_create_impl(raw_slice(seal_key, seal_key_len)?))
}

/// # Safety
/// `seal_key` must point to `seal_key_len` readable bytes; `request_json` must
/// be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_identity_import(
    seal_key: *const c_uchar,
    seal_key_len: usize,
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| identity_import_impl(raw_slice(seal_key, seal_key_len)?, c_str(request_json)?))
}

/// # Safety
/// `seal_key` must point to `seal_key_len` readable bytes; `request_json` must
/// be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_identity_open(
    seal_key: *const c_uchar,
    seal_key_len: usize,
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| identity_open_impl(raw_slice(seal_key, seal_key_len)?, c_str(request_json)?))
}

/// # Safety
/// `seal_key` must point to `seal_key_len` readable bytes; `request_json` must
/// be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_identity_rotate_share_key(
    seal_key: *const c_uchar,
    seal_key_len: usize,
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| {
        identity_rotate_share_key_impl(raw_slice(seal_key, seal_key_len)?, c_str(request_json)?)
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_identity_sign_share_ek_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| identity_sign_share_ek_impl(c_str(request_json)?))
}

#[no_mangle]
pub unsafe extern "C" fn vela_ffi_identity_sign_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| identity_sign_impl(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_identity_open_share_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| identity_open_share_impl(c_str(request_json)?))
}

// ── Enrollment v3 (audit P-1) ───────────────────────────────────────────────

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_identity_enrollment_fingerprint_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| identity_enrollment_fingerprint_impl(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_identity_sign_enrollment_result_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| identity_sign_enrollment_result_impl(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_identity_open_enrollment_capsule_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| identity_open_enrollment_capsule_impl(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_identity_forget_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| identity_forget_impl(c_str(request_json)?))
}

#[no_mangle]
pub extern "C" fn vela_ffi_identity_forget_all() -> *mut c_char {
    vela_crypto::identity::forget_all();
    json_result(|| Ok(IdentityOkResponse { ok: true }))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
/// # Safety
/// `rms` must point to `rms_len` readable bytes; `request_json` must be a valid
/// NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_web_session_chunk_keys_json(
    rms: *const c_uchar,
    rms_len: usize,
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| {
        let rms = rms_from(raw_slice(rms, rms_len)?)?;
        web_session_chunk_keys_json(&rms, c_str(request_json)?)
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
/// # Safety
/// `rms` must point to `rms_len` readable bytes; `request_json` must be a valid
/// NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_encrypt_vault_chunk_json(
    rms: *const c_uchar,
    rms_len: usize,
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| {
        let rms = rms_from(raw_slice(rms, rms_len)?)?;
        encrypt_vault_chunk_json(&rms, c_str(request_json)?)
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
/// # Safety
/// `rms` must point to `rms_len` readable bytes; `request_json` must be a valid
/// NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_decrypt_vault_chunk_json(
    rms: *const c_uchar,
    rms_len: usize,
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| {
        let rms = rms_from(raw_slice(rms, rms_len)?)?;
        decrypt_vault_chunk_json(&rms, c_str(request_json)?)
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_decrypt_rms_capsule_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| decrypt_rms_capsule_json(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_decrypt_enrollment_package_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| decrypt_enrollment_package_json(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
/// # Safety
/// `rms` must point to `rms_len` readable bytes; `request_json` must be a valid
/// NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_split_recovery_json(
    rms: *const c_uchar,
    rms_len: usize,
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| {
        let rms = rms_from(raw_slice(rms, rms_len)?)?;
        split_recovery_json(&rms, c_str(request_json)?)
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_combine_recovery_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| combine_recovery_json(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_seal_contact_share_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| seal_contact_share_json(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_open_contact_share_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| open_contact_share_json(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_seal_contact_share_response_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| seal_contact_share_response_json(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_possession_proof_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| possession_proof_json(c_str(request_json)?))
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_generate_recovery_request_json() -> *mut c_char {
    json_result(generate_recovery_request_json)
}

/// # Safety
/// `rms` must point to `rms_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_rms_possession_hash_json(
    rms: *const c_uchar,
    rms_len: usize,
) -> *mut c_char {
    json_result(|| {
        let rms = rms_from(raw_slice(rms, rms_len)?)?;
        let hash_b64 = vela_crypto::recovery::rms_possession_hash(&rms);
        Ok(serde_json::json!({ "hash_b64": B64.encode(hash_b64) }))
    })
}

/// Plan the next crash-recovery action using the hax-verified shared reducer.
/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_plan_recovery_publication_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| plan_recovery_publication_json(c_str(request_json)?))
}

/// Encrypt a vault item for a recipient using their share public key.
/// Request: `{ recipient_share_ek_b64, item_json }` → `{ capsule_b64 }`.
/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_seal_share_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| seal_share_json(c_str(request_json)?))
}

// ── Core logic (also exercised by the unit tests) ──────────────────────────────

fn encrypt_vault_json(rms_bytes: &[u8], request_json: &str) -> FfiResult<EncryptVaultResponse> {
    let req: EncryptVaultRequest = serde_json::from_str(request_json)?;
    let rms = rms_from(rms_bytes)?;
    // Validate the payload really is a vault before sealing it.
    let _: VaultStore = serde_json::from_str(&req.vault_json)?;
    let key = kdf::derive(VAULT_KEY_CONTEXT, &rms);
    let ciphertext = aead::encrypt(key.as_bytes(), req.vault_json.as_bytes())?;
    Ok(EncryptVaultResponse {
        ciphertext_b64: B64.encode(ciphertext),
    })
}

fn decrypt_vault_json(rms_bytes: &[u8], request_json: &str) -> FfiResult<DecryptVaultResponse> {
    let req: DecryptVaultRequest = serde_json::from_str(request_json)?;
    let rms = rms_from(rms_bytes)?;
    let ciphertext = B64.decode(req.ciphertext_b64.as_bytes())?;
    let key = kdf::derive(VAULT_KEY_CONTEXT, &rms);
    let plaintext = aead::decrypt(key.as_bytes(), &ciphertext)?;
    Ok(DecryptVaultResponse {
        vault_json: String::from_utf8(plaintext.to_vec())?,
    })
}

fn seal_share_json(request_json: &str) -> FfiResult<SealShareResponse> {
    let req: SealShareRequest = serde_json::from_str(request_json)?;
    let ek_bytes = B64.decode(req.recipient_share_ek_b64.as_bytes())?;
    let pk = kem::HybridPublicKey::from_bytes(&ek_bytes)?;
    let capsule = kem::seal_share(&pk, req.item_json.as_bytes())?;
    Ok(SealShareResponse {
        capsule_b64: B64.encode(capsule),
    })
}

/// Per-chunk vault key, matching the Android bridge / desktop derivation so the
/// same encrypted chunk is interoperable across clients:
/// `derive("vela chunk key v1" || {:?}(chunk_id_bytes), rms)`.
/// Delegates to `vela_crypto`, which owns the derivation context.
///
/// This used to build the context here with `{:?}`, in a second copy that had to
/// stay byte-identical to the core's by hand — two places to get a key
/// derivation exactly right (audit crypto M4).
fn chunk_key(rms: &[u8; 32], chunk_id: &str) -> [u8; 32] {
    *kdf::chunk_key(rms, chunk_id.as_bytes()).as_bytes()
}

/// Derive the per-chunk vault keys handed to a read-write web session, so the
/// approver can seal those instead of the RMS (audit D-2).
fn web_session_chunk_keys_json(
    rms_bytes: &[u8],
    request_json: &str,
) -> FfiResult<WebSessionChunkKeysResponse> {
    let _req: WebSessionChunkKeysRequest = serde_json::from_str(request_json)?;
    let rms = rms_from(rms_bytes)?;
    let chunk_keys = kdf::web_session_chunk_keys(&rms)
        .into_iter()
        .map(|(id, key)| (id, B64.encode(key.as_bytes())))
        .collect();
    Ok(WebSessionChunkKeysResponse { chunk_keys })
}

// ── Identity handles (audit C-1) ─────────────────────────────────────────────

fn identity_response(
    identity: vela_crypto::identity::DeviceIdentity,
    seal_key: &[u8],
) -> FfiResult<IdentityHandleResponse> {
    let key = seal_key_from(seal_key)?;
    let sealed = identity.seal(&key)?;
    let publics = identity.publics().clone();
    let handle = vela_crypto::identity::register(identity);
    Ok(IdentityHandleResponse {
        handle,
        hybrid_ek_b64: B64.encode(publics.hybrid_ek),
        hybrid_vk_b64: B64.encode(publics.hybrid_vk),
        share_ek_b64: B64.encode(publics.share_ek),
        sealed_b64: B64.encode(sealed),
    })
}

fn seal_key_from(bytes: &[u8]) -> FfiResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
            "seal key must be 32 bytes".into()
        })
}

fn identity_create_impl(seal_key: &[u8]) -> FfiResult<IdentityHandleResponse> {
    identity_response(vela_crypto::identity::DeviceIdentity::generate()?, seal_key)
}

fn identity_import_impl(seal_key: &[u8], request_json: &str) -> FfiResult<IdentityHandleResponse> {
    let req: IdentityImportRequest = serde_json::from_str(request_json)?;
    let signing_sk = B64.decode(req.hybrid_sk_b64.as_bytes())?;
    let share_dk = if req.share_dk_b64.is_empty() {
        None
    } else {
        Some(B64.decode(req.share_dk_b64.as_bytes())?)
    };
    let hybrid_ek = if req.hybrid_ek_b64.is_empty() {
        None
    } else {
        Some(B64.decode(req.hybrid_ek_b64.as_bytes())?)
    };
    let identity = vela_crypto::identity::DeviceIdentity::import(
        &signing_sk,
        share_dk.as_deref(),
        hybrid_ek.as_deref(),
    )?;
    identity_response(identity, seal_key)
}

fn identity_open_impl(seal_key: &[u8], request_json: &str) -> FfiResult<IdentityHandleResponse> {
    let req: IdentityOpenRequest = serde_json::from_str(request_json)?;
    let sealed = B64.decode(req.sealed_b64.as_bytes())?;
    let key = seal_key_from(seal_key)?;
    let identity = vela_crypto::identity::DeviceIdentity::open(&sealed, &key)?;
    identity_response(identity, seal_key)
}

fn identity_sign_impl(request_json: &str) -> FfiResult<AuthSignatureResponse> {
    let req: IdentitySignRequest = serde_json::from_str(request_json)?;
    let challenge = B64.decode(req.challenge_b64.as_bytes())?;
    let signature = vela_crypto::identity::with_identity(req.handle, |identity| {
        identity.sign_auth(&req.device_id, &challenge)
    })?;
    Ok(AuthSignatureResponse {
        signature_b64: B64.encode(signature),
    })
}

/// Sign a share-key binding with the identity held under `handle` (M19).
fn identity_sign_share_ek_impl(request_json: &str) -> FfiResult<AuthSignatureResponse> {
    #[derive(Deserialize)]
    struct Request {
        handle: u64,
        share_ek_b64: String,
        signed_at: String,
    }
    let req: Request = serde_json::from_str(request_json)?;
    let ek = B64.decode(req.share_ek_b64.as_bytes())?;
    let signature = vela_crypto::identity::with_identity(req.handle, |identity| {
        identity.sign_share_ek_binding(&ek, &req.signed_at)
    })?;
    Ok(AuthSignatureResponse {
        signature_b64: B64.encode(signature),
    })
}

fn identity_open_share_impl(request_json: &str) -> FfiResult<OpenShareResponse> {
    let req: IdentityOpenShareRequest = serde_json::from_str(request_json)?;
    let capsule = B64.decode(req.capsule_b64.as_bytes())?;
    let plaintext =
        vela_crypto::identity::with_identity(req.handle, |identity| identity.open_share(&capsule))?;
    Ok(OpenShareResponse {
        item_json: String::from_utf8(plaintext)?,
    })
}

/// This device's own enrollment fingerprint (v3), from the key under `handle`.
fn identity_enrollment_fingerprint_impl(
    request_json: &str,
) -> FfiResult<IdentityFingerprintResponse> {
    let req: IdentityHandleRequest = serde_json::from_str(request_json)?;
    let fingerprint = vela_crypto::identity::with_identity(req.handle, |identity| {
        Ok(identity.enrollment_fingerprint())
    })?;
    Ok(IdentityFingerprintResponse { fingerprint })
}

/// Sign a grant id, to collect the outcome of this device's own enrollment.
fn identity_sign_enrollment_result_impl(request_json: &str) -> FfiResult<AuthSignatureResponse> {
    let req: IdentityEnrollmentResultRequest = serde_json::from_str(request_json)?;
    let signature = vela_crypto::identity::with_identity(req.handle, |identity| {
        identity.sign_enrollment_result(&req.grant_id)
    })?;
    Ok(AuthSignatureResponse {
        signature_b64: B64.encode(signature),
    })
}

/// Open the RMS capsule the enrolling device sealed to this device's key.
fn identity_open_enrollment_capsule_impl(request_json: &str) -> FfiResult<IdentityCapsuleResponse> {
    let req: IdentityCapsuleRequest = serde_json::from_str(request_json)?;
    let capsule = B64.decode(req.capsule_b64.as_bytes())?;
    let plaintext = vela_crypto::identity::with_identity(req.handle, |identity| {
        identity.open_identity_capsule(&capsule)
    })?;
    if plaintext.len() != 32 {
        return Err("capsule did not contain a 32-byte root seed".into());
    }
    Ok(IdentityCapsuleResponse {
        rms_b64: B64.encode(&plaintext),
    })
}

fn identity_rotate_share_key_impl(
    seal_key: &[u8],
    request_json: &str,
) -> FfiResult<IdentityRotateShareKeyResponse> {
    let req: IdentityHandleRequest = serde_json::from_str(request_json)?;
    let key = seal_key_from(seal_key)?;
    let (share_ek, sealed) = vela_crypto::identity::with_identity(req.handle, |identity| {
        let share_ek = identity.rotate_share_key();
        Ok((share_ek, identity.seal(&key)?))
    })?;
    Ok(IdentityRotateShareKeyResponse {
        share_ek_b64: B64.encode(share_ek),
        sealed_b64: B64.encode(sealed),
    })
}

fn identity_forget_impl(request_json: &str) -> FfiResult<IdentityOkResponse> {
    let req: IdentityHandleRequest = serde_json::from_str(request_json)?;
    Ok(IdentityOkResponse {
        ok: vela_crypto::identity::forget(req.handle),
    })
}

fn encrypt_vault_chunk_json(
    rms_bytes: &[u8],
    request_json: &str,
) -> FfiResult<EncryptVaultResponse> {
    let req: EncryptChunkRequest = serde_json::from_str(request_json)?;
    let rms = rms_from(rms_bytes)?;
    let _: VaultStore = serde_json::from_str(&req.vault_json)?;
    let key = chunk_key(&rms, &req.chunk_id);
    let epoch = u64::try_from(req.key_epoch).map_err(|_| "key_epoch must be positive")?;
    let ciphertext = vela_crypto::rekey::seal_fleet_chunk(
        &key,
        req.vault_json.as_bytes(),
        epoch,
        &req.chunk_id,
        req.lamport_clock,
    )?;
    Ok(EncryptVaultResponse {
        ciphertext_b64: B64.encode(ciphertext),
    })
}

fn decrypt_vault_chunk_json(
    rms_bytes: &[u8],
    request_json: &str,
) -> FfiResult<DecryptVaultResponse> {
    let req: DecryptChunkRequest = serde_json::from_str(request_json)?;
    let rms = rms_from(rms_bytes)?;
    let ciphertext = B64.decode(req.ciphertext_b64.as_bytes())?;
    let key = chunk_key(&rms, &req.chunk_id);
    let epoch = u64::try_from(req.key_epoch).map_err(|_| "key_epoch must be positive")?;
    let plaintext = vela_crypto::rekey::open_fleet_chunk(
        &key,
        &ciphertext,
        epoch,
        &req.chunk_id,
        req.lamport_clock,
    )?;
    Ok(DecryptVaultResponse {
        vault_json: String::from_utf8(plaintext.to_vec())?,
    })
}

fn decode_key32(b64: &str, what: &str) -> FfiResult<[u8; 32]> {
    let bytes = B64.decode(b64.as_bytes())?;
    if bytes.len() != 32 {
        return Err(format!("{what} must be 32 bytes").into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn decrypt_rms_capsule_json(request_json: &str) -> FfiResult<DecryptRmsCapsuleResponse> {
    let req: DecryptRmsCapsuleRequest = serde_json::from_str(request_json)?;
    let transfer_key = decode_key32(&req.transfer_key_b64, "transfer_key")?;
    let capsule = B64.decode(req.capsule_b64.as_bytes())?;
    let plaintext = aead::decrypt(&transfer_key, &capsule)?;
    if plaintext.len() < 32 {
        return Err("decrypted RMS capsule too short".into());
    }
    Ok(DecryptRmsCapsuleResponse {
        rms_b64: B64.encode(&plaintext[..32]),
    })
}

fn decrypt_enrollment_package_json(
    request_json: &str,
) -> FfiResult<DecryptEnrollmentPackageResponse> {
    let req: DecryptEnrollmentPackageRequest = serde_json::from_str(request_json)?;
    let key = decode_key32(&req.key_b64, "enrollment package key")?;
    let ciphertext = B64.decode(req.ciphertext_b64.as_bytes())?;
    let plaintext = aead::decrypt(&key, &ciphertext)?;
    Ok(DecryptEnrollmentPackageResponse {
        plaintext: String::from_utf8(plaintext.to_vec())?,
    })
}

fn split_recovery_json(rms_bytes: &[u8], request_json: &str) -> FfiResult<SplitRecoveryResponse> {
    let req: SplitRecoveryRequest = serde_json::from_str(request_json)?;
    let rms = rms_from(rms_bytes)?;
    let shares = shamir::split(&rms, req.threshold, req.n)?;
    Ok(SplitRecoveryResponse {
        shares_b64: shares.iter().map(|s| B64.encode(s.to_bytes())).collect(),
    })
}

fn combine_recovery_json(request_json: &str) -> FfiResult<CombineRecoveryResponse> {
    let req: CombineRecoveryRequest = serde_json::from_str(request_json)?;
    let shares: Vec<shamir::Share> = req
        .shares_b64
        .iter()
        .map(|s| -> FfiResult<shamir::Share> {
            let bytes = B64.decode(s.as_bytes())?;
            Ok(shamir::Share::from_bytes(&bytes)?)
        })
        .collect::<FfiResult<_>>()?;
    let binding = (
        req.requested_user_id.as_deref(),
        req.cloud_user_id.as_deref(),
        req.cloud_key_epoch,
        req.server_user_id.as_deref(),
        req.server_key_epoch,
    );
    // M18: channel-tagged bound shares go through the verified pair-selection
    // policy, which admits every distinct-channel pair (cloud + server,
    // cloud + trusted contact, server + trusted contact).
    if !req.bound_shares.is_empty() {
        let requested = req.requested_user_id.as_deref().ok_or(
            "requested_user_id is required for bound account recovery",
        )?;
        if req.bound_shares.len() != 2 || shares.len() != 2 {
            return Err("bound account recovery requires exactly two shares".into());
        }
        let channel = |name: &str| match name {
            "cloud" => Ok(vela_crypto::recovery::RecoveryShareChannel::Cloud),
            "server" => Ok(vela_crypto::recovery::RecoveryShareChannel::Server),
            "trusted_contact" => Ok(vela_crypto::recovery::RecoveryShareChannel::TrustedContact),
            other => Err(format!("unknown recovery share channel {other:?}")),
        };
        let first = &req.bound_shares[0];
        let second = &req.bound_shares[1];
        let recovered = vela_crypto::recovery::reconstruct_account_recovery(
            requested,
            vela_crypto::recovery::BoundRecoveryShare {
                account_id: first.account_id.as_str(),
                key_epoch: first.key_epoch,
                split_id: first.split_id.as_deref(),
                channel: channel(&first.channel)?,
                recipient_bound: first.recipient_bound,
                share: &shares[0],
            },
            vela_crypto::recovery::BoundRecoveryShare {
                account_id: second.account_id.as_str(),
                key_epoch: second.key_epoch,
                split_id: second.split_id.as_deref(),
                channel: channel(&second.channel)?,
                recipient_bound: second.recipient_bound,
                share: &shares[1],
            },
        )?;
        return Ok(CombineRecoveryResponse {
            rms_b64: B64.encode(recovered.rms),
        });
    }
    let secret = match binding {
        (
            Some(requested),
            Some(cloud_user),
            Some(cloud_epoch),
            Some(server_user),
            Some(server_epoch),
        ) => {
            if shares.len() != 2 {
                return Err("bound account recovery requires exactly two shares".into());
            }
            vela_crypto::recovery::reconstruct_account_recovery(
                requested,
                vela_crypto::recovery::BoundRecoveryShare {
                    account_id: cloud_user,
                    key_epoch: cloud_epoch,
                    split_id: req.cloud_split_id.as_deref(),
                    channel: vela_crypto::recovery::RecoveryShareChannel::Cloud,
                    recipient_bound: false,
                    share: &shares[0],
                },
                vela_crypto::recovery::BoundRecoveryShare {
                    account_id: server_user,
                    key_epoch: server_epoch,
                    split_id: req.server_split_id.as_deref(),
                    channel: vela_crypto::recovery::RecoveryShareChannel::Server,
                    recipient_bound: false,
                    share: &shares[1],
                },
            )?
            .rms
            .to_vec()
        }
        (None, None, None, None, None) => shamir::reconstruct(&shares, 32)?,
        _ => return Err("incomplete account/epoch recovery binding".into()),
    };
    Ok(CombineRecoveryResponse {
        rms_b64: B64.encode(secret),
    })
}

// ── M18: trusted-contact envelopes and RMS-possession proofs ────────────────

fn seal_contact_share_json(request_json: &str) -> FfiResult<serde_json::Value> {
    #[derive(Deserialize)]
    struct Request {
        recipient_public_key_b64: String,
        account_id: String,
        key_epoch: i64,
        split_id: Option<String>,
        share_b64: String,
    }
    let req: Request = serde_json::from_str(request_json)?;
    let pk = kem::HybridPublicKey::from_bytes(&B64.decode(req.recipient_public_key_b64.as_bytes())?)?;
    let share = shamir::Share::from_bytes(&B64.decode(req.share_b64.as_bytes())?)?;
    let context = vela_crypto::recovery::ContactShareContext {
        account_id: req.account_id.as_str(),
        key_epoch: req.key_epoch,
        split_id: req.split_id.as_deref(),
        coordinate: share.x,
    };
    let envelope = vela_crypto::recovery::seal_contact_share(&pk, &context, &share)?;
    Ok(serde_json::json!({
        "version": 1u32,
        "account_id": req.account_id,
        "key_epoch": req.key_epoch,
        "split_id": req.split_id,
        "coordinate": context.coordinate,
        "envelope_b64": B64.encode(&envelope),
    }))
}

fn open_contact_share_json(request_json: &str) -> FfiResult<serde_json::Value> {
    #[derive(Deserialize)]
    struct Request {
        recipient_secret_key_b64: String,
        account_id: String,
        key_epoch: i64,
        split_id: Option<String>,
        coordinate: u8,
        envelope_b64: String,
        response: bool,
    }
    let req: Request = serde_json::from_str(request_json)?;
    let sk = kem::HybridSecretKey::from_bytes(&B64.decode(req.recipient_secret_key_b64.as_bytes())?)?;
    let context = vela_crypto::recovery::ContactShareContext {
        account_id: req.account_id.as_str(),
        key_epoch: req.key_epoch,
        split_id: req.split_id.as_deref(),
        coordinate: req.coordinate,
    };
    let blob = B64.decode(req.envelope_b64.as_bytes())?;
    let share = if req.response {
        vela_crypto::recovery::open_contact_share_response(&sk, &context, &blob)?
    } else {
        vela_crypto::recovery::open_contact_share(&sk, &context, &blob)?
    };
    Ok(serde_json::json!({ "share_b64": B64.encode(share.to_bytes()), "x": share.x }))
}

/// Re-seal an opened contact share to a recovery requester's ephemeral key.
fn seal_contact_share_response_json(request_json: &str) -> FfiResult<serde_json::Value> {
    #[derive(Deserialize)]
    struct Request {
        requester_public_key_b64: String,
        account_id: String,
        key_epoch: i64,
        split_id: Option<String>,
        coordinate: u8,
        share_b64: String,
    }
    let req: Request = serde_json::from_str(request_json)?;
    let pk = kem::HybridPublicKey::from_bytes(&B64.decode(req.requester_public_key_b64.as_bytes())?)?;
    let share = shamir::Share::from_bytes(&B64.decode(req.share_b64.as_bytes())?)?;
    let context = vela_crypto::recovery::ContactShareContext {
        account_id: req.account_id.as_str(),
        key_epoch: req.key_epoch,
        split_id: req.split_id.as_deref(),
        coordinate: req.coordinate,
    };
    let envelope = vela_crypto::recovery::seal_contact_share_response(&pk, &context, &share)?;
    Ok(serde_json::json!({
        "account_id": req.account_id,
        "key_epoch": req.key_epoch,
        "split_id": req.split_id,
        "coordinate": context.coordinate,
        "envelope_b64": B64.encode(&envelope),
    }))
}

fn possession_proof_json(request_json: &str) -> FfiResult<serde_json::Value> {
    #[derive(Deserialize)]
    struct Request {
        rms_hex_or_b64: String,
        user_id: String,
        recovery_id: String,
        challenge_b64: String,
        key_epoch: i64,
    }
    let req: Request = serde_json::from_str(request_json)?;
    // The RMS crosses as base64 (the FFI never takes raw key material as
    // JSON); decode strictly.
    let rms_bytes = B64.decode(req.rms_hex_or_b64.as_bytes())?;
    let rms: [u8; 32] = rms_bytes
        .try_into()
        .map_err(|_| "rms must be exactly 32 bytes".to_string())?;
    let challenge = B64.decode(req.challenge_b64.as_bytes())?;
    let hash = vela_crypto::recovery::rms_possession_hash(&rms);
    let proof = vela_crypto::recovery::rms_possession_proof(
        &hash,
        &req.user_id,
        &req.recovery_id,
        &challenge,
        req.key_epoch,
    );
    Ok(serde_json::json!({
        "possession_hash_b64": B64.encode(hash),
        "proof_b64": B64.encode(proof),
    }))
}

fn generate_recovery_request_json() -> FfiResult<serde_json::Value> {
    let (pk, sk) = kem::generate_keypair();
    Ok(serde_json::json!({
        "public_key_b64": B64.encode(pk.to_bytes()),
        "secret_key_b64": B64.encode(sk.to_bytes()),
    }))
}

fn plan_recovery_publication_json(request_json: &str) -> FfiResult<PublicationPlanResponse> {
    let request: PublicationPlanRequest = serde_json::from_str(request_json)?;
    let action = vela_client_recovery_policy::plan_publication_resume(
        vela_client_recovery_policy::PublicationFacts {
            journal_present: request.journal_present,
            account_matches: request.account_matches,
            split_id_present: request.split_id_present,
            cloud_share_present: request.cloud_share_present,
            server_share_present: request.server_share_present,
            journal_epoch: request.journal_epoch,
            current_epoch: request.current_epoch,
            account_epoch_active: request.account_epoch_active,
            server_staged: request.server_staged,
            cloud_candidate_durable: request.cloud_candidate_durable,
            server_finalized: request.server_finalized,
            cloud_active: request.cloud_active,
        },
    );
    Ok(PublicationPlanResponse {
        action: match action {
            vela_client_recovery_policy::PublicationAction::StageServer => "stage_server",
            vela_client_recovery_policy::PublicationAction::UploadCloudCandidate => {
                "upload_cloud_candidate"
            }
            vela_client_recovery_policy::PublicationAction::FinalizeServer => "finalize_server",
            vela_client_recovery_policy::PublicationAction::PromoteCloudActive => {
                "promote_cloud_active"
            }
            vela_client_recovery_policy::PublicationAction::Complete => "complete",
            vela_client_recovery_policy::PublicationAction::Retire => "retire",
            vela_client_recovery_policy::PublicationAction::Reject => "reject",
        }
        .to_string(),
    })
}

/// Validate raw RMS bytes handed over the ABI (audit I-2: the RMS crosses as
/// wipeable bytes beside the JSON envelope, never as base64 inside it).
fn rms_from(bytes: &[u8]) -> FfiResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> { "RMS must be 32 bytes".into() })
}

// ── FFI plumbing ───────────────────────────────────────────────────────────────

/// Borrow raw bytes handed over from Swift (a seal key, never a string).
unsafe fn raw_slice<'a>(ptr: *const c_uchar, len: usize) -> FfiResult<&'a [u8]> {
    if ptr.is_null() {
        return Err("null byte pointer".into());
    }
    Ok(std::slice::from_raw_parts(ptr, len))
}

unsafe fn c_str<'a>(ptr: *const c_char) -> FfiResult<&'a str> {
    if ptr.is_null() {
        return Err("null string pointer".into());
    }
    Ok(CStr::from_ptr(ptr).to_str()?)
}

fn json_result<T, F>(f: F) -> *mut c_char
where
    T: Serialize,
    F: FnOnce() -> FfiResult<T>,
{
    match f().and_then(|value| Ok(serde_json::to_string(&value)?)) {
        Ok(json) => string_to_ptr(&json),
        Err(error) => string_to_ptr(&error_json(&error.to_string())),
    }
}

fn error_json(error: &str) -> String {
    serde_json::to_string(&BridgeError {
        error: error.to_string(),
    })
    .unwrap_or_else(|_| "{\"error\":\"bridge error\"}".to_string())
}

fn string_to_ptr(value: &str) -> *mut c_char {
    CString::new(value)
        .unwrap_or_else(|_| CString::new("").expect("empty CString"))
        .into_raw()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn call(f: unsafe extern "C" fn(*const c_char) -> *mut c_char, req: &str) -> String {
        let c = CString::new(req).unwrap();
        let ptr = unsafe { f(c.as_ptr()) };
        let s = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { vela_ffi_free_string(ptr) };
        s
    }

    /// For the RMS-consuming entry points: bytes beside the JSON envelope.
    fn call_rms(
        f: unsafe extern "C" fn(*const c_uchar, usize, *const c_char) -> *mut c_char,
        rms: &[u8],
        req: &str,
    ) -> String {
        let c = CString::new(req).unwrap();
        let ptr = unsafe { f(rms.as_ptr(), rms.len(), c.as_ptr()) };
        let s = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { vela_ffi_free_string(ptr) };
        s
    }

    #[test]
    fn verified_publication_planner_advances_and_retires_exact_journals() {
        let request = |current_epoch, server_staged| {
            serde_json::json!({
                "journal_present": true, "account_matches": true,
                "split_id_present": true, "cloud_share_present": true,
                "server_share_present": true, "journal_epoch": 7,
                "current_epoch": current_epoch, "account_epoch_active": true,
                "server_staged": server_staged, "cloud_candidate_durable": false,
                "server_finalized": false, "cloud_active": false
            })
            .to_string()
        };
        assert_eq!(
            plan_recovery_publication_json(&request(7, false))
                .unwrap()
                .action,
            "stage_server"
        );
        assert_eq!(
            plan_recovery_publication_json(&request(7, true))
                .unwrap()
                .action,
            "upload_cloud_candidate"
        );
        assert_eq!(
            plan_recovery_publication_json(&request(8, true))
                .unwrap()
                .action,
            "retire"
        );
    }

    #[test]
    fn version_is_reported() {
        let ptr = vela_ffi_version();
        let s = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { vela_ffi_free_string(ptr) };
        assert!(s.starts_with("vela-apple-bridge/"));
    }

    #[test]
    fn password_strength_returns_json() {
        let out = call(
            vela_ffi_password_strength_json,
            r#"{"password":"Abcdefgh123!"}"#,
        );
        assert!(out.contains("score"));
    }

    #[test]
    fn vault_encrypt_decrypt_round_trips() {
        let rms = [7u8; 32];
        let vault_json = r#"{"items":[],"tombstones":[]}"#;
        let enc = call_rms(
            vela_ffi_encrypt_vault_json,
            &rms,
            &serde_json::json!({"vault_json": vault_json}).to_string(),
        );
        let enc: EncryptVaultResponse = serde_json::from_str(&enc).unwrap();
        let dec = call_rms(
            vela_ffi_decrypt_vault_json,
            &rms,
            &serde_json::json!({"ciphertext_b64": enc.ciphertext_b64}).to_string(),
        );
        let dec: DecryptVaultResponse = serde_json::from_str(&dec).unwrap();
        assert_eq!(dec.vault_json, vault_json);
    }

    #[test]
    fn wrong_rms_does_not_decrypt() {
        let vault_json = r#"{"items":[],"tombstones":[]}"#;
        let enc = call_rms(
            vela_ffi_encrypt_vault_json,
            &[1u8; 32],
            &serde_json::json!({"vault_json": vault_json}).to_string(),
        );
        let enc: EncryptVaultResponse = serde_json::from_str(&enc).unwrap();
        let dec = call_rms(
            vela_ffi_decrypt_vault_json,
            &[2u8; 32],
            &serde_json::json!({"ciphertext_b64": enc.ciphertext_b64}).to_string(),
        );
        assert!(dec.contains("error"), "wrong RMS must fail: {dec}");

        // A short RMS is rejected outright, not silently misderived.
        let short = call_rms(
            vela_ffi_encrypt_vault_json,
            &[1u8; 16],
            &serde_json::json!({"vault_json": vault_json}).to_string(),
        );
        assert!(
            short.contains("error"),
            "non-32-byte RMS must fail: {short}"
        );
    }

    /// Enrollment v3 (audit P-1): the three calls the joining side runs.
    ///
    /// The important shape is that the fingerprint call takes only a handle. If
    /// it accepted key bytes, "render the value the server sent" would be a
    /// one-line mistake, and the user would end up comparing two devices'
    /// agreement about a number rather than about a key.
    #[test]
    fn enrollment_v3_fingerprint_is_over_the_devices_own_key_and_the_capsule_opens() {
        let seal_key = [11u8; 32];
        let created_ptr = unsafe { vela_ffi_identity_create(seal_key.as_ptr(), seal_key.len()) };
        let created = unsafe { CStr::from_ptr(created_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { vela_ffi_free_string(created_ptr) };
        let created: serde_json::Value = serde_json::from_str(&created).unwrap();
        let handle = created["handle"].as_u64().unwrap();
        let hybrid_ek = B64
            .decode(created["hybrid_ek_b64"].as_str().unwrap())
            .unwrap();
        let hybrid_vk = B64
            .decode(created["hybrid_vk_b64"].as_str().unwrap())
            .unwrap();

        // The fingerprint is over this device's own signing key, so a primary
        // reading its claim computes the same value from the public half.
        let fp = call(
            vela_ffi_identity_enrollment_fingerprint_json,
            &serde_json::json!({ "handle": handle }).to_string(),
        );
        let fp: IdentityFingerprintResponse = serde_json::from_str(&fp).unwrap();
        assert_eq!(
            fp.fingerprint,
            vela_crypto::verification::enrollment_fingerprint(&hybrid_vk),
            "the two sides must agree about the same key"
        );

        // The result signature proves possession of the claimed key.
        let sig = call(
            vela_ffi_identity_sign_enrollment_result_json,
            &serde_json::json!({ "handle": handle, "grant_id": "grant-1" }).to_string(),
        );
        let sig: AuthSignatureResponse = serde_json::from_str(&sig).unwrap();
        let vk = vela_crypto::signing::HybridVerifyingKey::from_bytes(
            hybrid_vk.as_slice().try_into().unwrap(),
        )
        .unwrap();
        let parsed = vela_crypto::signing::HybridSignature::from_bytes(
            B64.decode(&sig.signature_b64)
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        assert!(vela_crypto::signing::verify(
            &vk,
            &vela_crypto::signing::enrollment_result_message("grant-1"),
            &parsed
        )
        .unwrap());
        // And it is specific to the grant — a signature collected once must not
        // collect an unrelated enrollment's result.
        assert!(!vela_crypto::signing::verify(
            &vk,
            &vela_crypto::signing::enrollment_result_message("grant-2"),
            &parsed
        )
        .unwrap());

        // The capsule the primary seals to `hybrid_ek` opens here.
        let pk = vela_crypto::kem::HybridPublicKey::from_bytes(&hybrid_ek).unwrap();
        let capsule = vela_crypto::kem::seal_share(&pk, &[7u8; 32]).unwrap();
        let opened = call(
            vela_ffi_identity_open_enrollment_capsule_json,
            &serde_json::json!({
                "handle": handle,
                "capsule_b64": B64.encode(&capsule),
            })
            .to_string(),
        );
        let opened: IdentityCapsuleResponse = serde_json::from_str(&opened).unwrap();
        assert_eq!(B64.decode(&opened.rms_b64).unwrap(), vec![7u8; 32]);

        // And nowhere else: another device's handle must not open it.
        let other_ptr = unsafe { vela_ffi_identity_create(seal_key.as_ptr(), seal_key.len()) };
        let other = unsafe { CStr::from_ptr(other_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { vela_ffi_free_string(other_ptr) };
        let other: serde_json::Value = serde_json::from_str(&other).unwrap();
        let refused = call(
            vela_ffi_identity_open_enrollment_capsule_json,
            &serde_json::json!({
                "handle": other["handle"].as_u64().unwrap(),
                "capsule_b64": B64.encode(&capsule),
            })
            .to_string(),
        );
        assert!(
            refused.contains("error"),
            "another device opened it: {refused}"
        );
    }

    /// Audit C-1: the identity is created behind a handle. The response carries
    /// public halves and a sealed blob; nothing the app can read is a key.
    #[test]
    fn identity_handle_signs_and_reveals_no_private_key() {
        let seal_key = [4u8; 32];
        let created_ptr = unsafe { vela_ffi_identity_create(seal_key.as_ptr(), seal_key.len()) };
        let created = unsafe { CStr::from_ptr(created_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { vela_ffi_free_string(created_ptr) };

        for forbidden in ["hybrid_sk", "share_dk"] {
            assert!(
                !created.contains(forbidden),
                "response leaks {forbidden}: {created}"
            );
        }
        let created: serde_json::Value = serde_json::from_str(&created).unwrap();
        assert_eq!(
            B64.decode(created["hybrid_ek_b64"].as_str().unwrap())
                .unwrap()
                .len(),
            1600
        );

        let handle = created["handle"].as_u64().unwrap();
        let sig = call(
            vela_ffi_identity_sign_json,
            &serde_json::json!({
                "handle": handle,
                "device_id": "device-123",
                "challenge_b64": B64.encode([9u8; 32]),
            })
            .to_string(),
        );
        let sig: AuthSignatureResponse = serde_json::from_str(&sig).unwrap();
        assert!(!sig.signature_b64.is_empty());

        // Reopening the sealed blob is the same device; a wrong key is not.
        let open_request = serde_json::json!({ "sealed_b64": created["sealed_b64"] }).to_string();
        let request = CString::new(open_request.clone()).unwrap();
        let reopened_ptr =
            unsafe { vela_ffi_identity_open(seal_key.as_ptr(), seal_key.len(), request.as_ptr()) };
        let reopened = unsafe { CStr::from_ptr(reopened_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { vela_ffi_free_string(reopened_ptr) };
        let reopened: serde_json::Value = serde_json::from_str(&reopened).unwrap();
        assert_eq!(reopened["hybrid_vk_b64"], created["hybrid_vk_b64"]);

        let wrong = [7u8; 32];
        let wrong_ptr =
            unsafe { vela_ffi_identity_open(wrong.as_ptr(), wrong.len(), request.as_ptr()) };
        let wrong_out = unsafe { CStr::from_ptr(wrong_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { vela_ffi_free_string(wrong_ptr) };
        assert!(
            wrong_out.contains("error"),
            "wrong seal key must fail: {wrong_out}"
        );

        // Forgetting the handle ends the ability to sign with it.
        let forget = call(
            vela_ffi_identity_forget_json,
            &serde_json::json!({ "handle": handle }).to_string(),
        );
        assert!(forget.contains("true"), "{forget}");
        let after = call(
            vela_ffi_identity_sign_json,
            &serde_json::json!({
                "handle": handle,
                "device_id": "device-123",
                "challenge_b64": B64.encode([9u8; 32]),
            })
            .to_string(),
        );
        assert!(
            after.contains("error"),
            "a forgotten handle cannot sign: {after}"
        );
    }

    #[test]
    fn vault_chunk_round_trips_and_binds_chunk_id() {
        let rms = [5u8; 32];
        let vault_json = r#"{"items":[],"tombstones":[]}"#;
        let enc = call_rms(
            vela_ffi_encrypt_vault_chunk_json,
            &rms,
            &serde_json::json!({
                "chunk_id": "vault", "vault_json": vault_json, "lamport_clock": 7
            })
            .to_string(),
        );
        let enc: EncryptVaultResponse = serde_json::from_str(&enc).unwrap();

        let dec = call_rms(
            vela_ffi_decrypt_vault_chunk_json,
            &rms,
            &serde_json::json!({
                "chunk_id": "vault",
                "ciphertext_b64": enc.ciphertext_b64, "lamport_clock": 7
            })
            .to_string(),
        );
        let dec: DecryptVaultResponse = serde_json::from_str(&dec).unwrap();
        assert_eq!(dec.vault_json, vault_json);

        // A different chunk_id derives a different key → must not decrypt.
        let wrong = call_rms(
            vela_ffi_decrypt_vault_chunk_json,
            &rms,
            &serde_json::json!({
                "chunk_id": "other",
                "ciphertext_b64": enc.ciphertext_b64, "lamport_clock": 7
            })
            .to_string(),
        );
        assert!(
            wrong.contains("error"),
            "chunk_id must bind the key: {wrong}"
        );

        // An older revision replayed at the same id must not decrypt either —
        // that is the rollback this seal exists to stop (audit C-2).
        let replayed = call_rms(
            vela_ffi_decrypt_vault_chunk_json,
            &rms,
            &serde_json::json!({
                "chunk_id": "vault",
                "ciphertext_b64": enc.ciphertext_b64, "lamport_clock": 6
            })
            .to_string(),
        );
        assert!(
            replayed.contains("error"),
            "clock must bind the ciphertext: {replayed}"
        );

        let epoch_enc = call_rms(
            vela_ffi_encrypt_vault_chunk_json,
            &rms,
            &serde_json::json!({
                "chunk_id": "vault", "vault_json": vault_json,
                "lamport_clock": 7, "key_epoch": 2
            })
            .to_string(),
        );
        let epoch_enc: EncryptVaultResponse = serde_json::from_str(&epoch_enc).unwrap();
        let epoch_dec = |epoch| {
            call_rms(
                vela_ffi_decrypt_vault_chunk_json,
                &rms,
                &serde_json::json!({
                    "chunk_id": "vault", "ciphertext_b64": epoch_enc.ciphertext_b64,
                    "lamport_clock": 7, "key_epoch": epoch
                })
                .to_string(),
            )
        };
        let opened: DecryptVaultResponse = serde_json::from_str(&epoch_dec(2)).unwrap();
        assert_eq!(opened.vault_json, vault_json);
        assert!(epoch_dec(3).contains("error"), "wrong epoch must fail");

        let legacy_at_epoch_two = call_rms(
            vela_ffi_decrypt_vault_chunk_json,
            &rms,
            &serde_json::json!({
                "chunk_id": "vault", "ciphertext_b64": enc.ciphertext_b64,
                "lamport_clock": 7, "key_epoch": 2
            })
            .to_string(),
        );
        assert!(
            legacy_at_epoch_two.contains("legacy chunk ciphertext is forbidden"),
            "rotated epochs must not accept legacy AAD: {legacy_at_epoch_two}"
        );
    }

    #[test]
    fn rms_capsule_round_trips() {
        let transfer_key = [3u8; 32];
        let rms = [9u8; 32];
        let capsule = aead::encrypt(&transfer_key, &rms).unwrap();
        let out = call(
            vela_ffi_decrypt_rms_capsule_json,
            &serde_json::json!({
                "transfer_key_b64": B64.encode(transfer_key),
                "capsule_b64": B64.encode(&capsule),
            })
            .to_string(),
        );
        let out: DecryptRmsCapsuleResponse = serde_json::from_str(&out).unwrap();
        assert_eq!(B64.decode(out.rms_b64).unwrap(), rms);
    }

    #[test]
    fn enrollment_package_round_trips() {
        let key = [4u8; 32];
        let payload = r#"{"hello":"world"}"#;
        let ciphertext = aead::encrypt(&key, payload.as_bytes()).unwrap();
        let out = call(
            vela_ffi_decrypt_enrollment_package_json,
            &serde_json::json!({
                "key_b64": B64.encode(key),
                "ciphertext_b64": B64.encode(&ciphertext),
            })
            .to_string(),
        );
        let out: DecryptEnrollmentPackageResponse = serde_json::from_str(&out).unwrap();
        assert_eq!(out.plaintext, payload);
    }

    #[test]
    fn recovery_split_then_combine_recovers_rms() {
        let rms = [7u8; 32];
        let split = call_rms(
            vela_ffi_split_recovery_json,
            &rms,
            &serde_json::json!({"threshold": 2, "n": 3}).to_string(),
        );
        let split: SplitRecoveryResponse = serde_json::from_str(&split).unwrap();
        assert_eq!(split.shares_b64.len(), 3);

        // Any 2-of-3 shares reconstruct the RMS.
        let subset = vec![split.shares_b64[0].clone(), split.shares_b64[2].clone()];
        let combined = call(
            vela_ffi_combine_recovery_json,
            &serde_json::json!({"shares_b64": subset}).to_string(),
        );
        let combined: CombineRecoveryResponse = serde_json::from_str(&combined).unwrap();
        assert_eq!(combined.rms_b64, B64.encode(rms));
    }

    #[test]
    fn bound_recovery_rejects_cross_account_and_mixed_epoch_inputs() {
        let rms = [8u8; 32];
        let split = call_rms(
            vela_ffi_split_recovery_json,
            &rms,
            &serde_json::json!({"threshold": 2, "n": 3}).to_string(),
        );
        let split: SplitRecoveryResponse = serde_json::from_str(&split).unwrap();
        let request = |cloud_user: &str, cloud_epoch: i64| {
            serde_json::json!({
                "shares_b64": split.shares_b64[..2].to_vec(),
                "requested_user_id": "account-a",
                "cloud_user_id": cloud_user,
                "cloud_key_epoch": cloud_epoch,
                "cloud_split_id": "11111111-1111-1111-1111-111111111111",
                "server_user_id": "account-a",
                "server_key_epoch": 5,
                "server_split_id": "11111111-1111-1111-1111-111111111111"
            })
            .to_string()
        };

        let valid = combine_recovery_json(&request("account-a", 5)).unwrap();
        assert_eq!(valid.rms_b64, B64.encode(rms));
        assert!(combine_recovery_json(&request("account-b", 5)).is_err());
        assert!(combine_recovery_json(&request("account-a", 4)).is_err());
    }

    #[test]
    fn bound_shares_accept_every_channel_pair_and_reject_bad_ones() {
        let rms = [9u8; 32];
        let split = call_rms(
            vela_ffi_split_recovery_json,
            &rms,
            &serde_json::json!({"threshold": 2, "n": 3}).to_string(),
        );
        let split: SplitRecoveryResponse = serde_json::from_str(&split).unwrap();

        let bound_request =
            |first: &str, second: &str, second_bound: bool, second_epoch: i64| {
                serde_json::json!({
                    "shares_b64": [split.shares_b64[0], split.shares_b64[2]],
                    "requested_user_id": "account-a",
                    "bound_shares": [
                        {
                            "share_b64": split.shares_b64[0],
                            "channel": first,
                            "account_id": "account-a",
                            "key_epoch": 5,
                            "split_id": "11111111-1111-1111-1111-111111111111"
                        },
                        {
                            "share_b64": split.shares_b64[2],
                            "channel": second,
                            "account_id": "account-a",
                            "key_epoch": second_epoch,
                            "split_id": "11111111-1111-1111-1111-111111111111",
                            "recipient_bound": second_bound
                        }
                    ]
                })
                .to_string()
            };

        for pair in [("cloud", "server"), ("cloud", "trusted_contact"), ("server", "trusted_contact")] {
            let out = combine_recovery_json(
                &bound_request(pair.0, pair.1, pair.1 == "trusted_contact", 5),
            )
            .unwrap_or_else(|e| panic!("{pair:?} must reconstruct: {e}"));
            assert_eq!(out.rms_b64, B64.encode(rms));
        }

        // Duplicate channel, mixed epoch, and unbound contact share all fail.
        assert!(combine_recovery_json(&bound_request("cloud", "cloud", false, 5)).is_err());
        assert!(combine_recovery_json(&bound_request("cloud", "server", false, 4)).is_err());
        assert!(
            combine_recovery_json(&bound_request("cloud", "trusted_contact", false, 5)).is_err()
        );
    }

    #[test]
    fn possession_proof_matches_expected_construction() {
        let rms = [11u8; 32];
        let challenge = [12u8; 32];
        let out = call(
            vela_ffi_possession_proof_json,
            &serde_json::json!({
                "rms_hex_or_b64": B64.encode(rms),
                "user_id": "account-a",
                "recovery_id": "22222222-2222-2222-2222-222222222222",
                "challenge_b64": B64.encode(challenge),
                "key_epoch": 3,
            })
            .to_string(),
        );
        let response: serde_json::Value = serde_json::from_str(&out).unwrap();
        let proof_b64 = response["proof_b64"].as_str().unwrap();
        assert_eq!(B64.decode(proof_b64).unwrap().len(), 32);
        // Deterministic and attempt-bound.
        let again = call(
            vela_ffi_possession_proof_json,
            &serde_json::json!({
                "rms_hex_or_b64": B64.encode(rms),
                "user_id": "account-a",
                "recovery_id": "22222222-2222-2222-2222-222222222222",
                "challenge_b64": B64.encode(challenge),
                "key_epoch": 3,
            })
            .to_string(),
        );
        let again: serde_json::Value = serde_json::from_str(&again).unwrap();
        assert_eq!(proof_b64, again["proof_b64"]);
    }
}
