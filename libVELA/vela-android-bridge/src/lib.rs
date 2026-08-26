//! Android-facing FFI bridge for the shared VELA Rust core.
//!
//! The exported ABI deliberately uses UTF-8 JSON and owned byte buffers so the
//! Kotlin/JNI layer can remain thin and stable while the Rust internals evolve.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use jni::objects::{JByteArray, JObject, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use serde::{Deserialize, Serialize};
use std::ffi::{c_char, c_uchar, CStr, CString};
use std::ptr;
use std::slice;
use vela_core::{calculate_password_strength, PasswordStrength, VaultStore};
use vela_crypto::aead;
use vela_crypto::kdf;
use vela_crypto::kem;
use vela_crypto::rekey;
use vela_crypto::shamir;
use zeroize::Zeroize;

const VAULT_KEY_CONTEXT: &str = "vela vault encryption v1";

#[repr(C)]
pub struct VelaByteBuffer {
    ptr: *mut c_uchar,
    len: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct BridgeError {
    error: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PasswordStrengthRequest {
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PasswordStrengthResponse {
    strength: PasswordStrength,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptVaultRequest {
    /// Only the C ABI still carries the RMS here; the JNI entry points take it
    /// as a byte array instead (audit C-1).
    #[serde(default)]
    rms_b64: String,
    vault_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptVaultResponse {
    ciphertext_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecryptVaultRequest {
    /// C-ABI only; the JNI entry points pass the RMS as bytes (audit C-1).
    #[serde(default)]
    rms_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecryptVaultResponse {
    vault_json: String,
}

/// Everything an identity handle exposes: the public halves, plus the sealed
/// blob the app persists. No private key appears here — that is the point
/// (audit C-1).
#[derive(Debug, Serialize, Deserialize)]
struct IdentityHandleResponse {
    handle: u64,
    hybrid_ek_b64: String,
    hybrid_vk_b64: String,
    share_ek_b64: String,
    /// AEAD blob under the caller's seal key. Opaque to the app.
    sealed_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdentityImportRequest {
    hybrid_sk_b64: String,
    #[serde(default)]
    share_dk_b64: String,
    #[serde(default)]
    hybrid_ek_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdentityOpenRequest {
    sealed_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdentitySignRequest {
    handle: u64,
    device_id: String,
    challenge_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdentityOpenShareRequest {
    handle: u64,
    capsule_b64: String,
}

/// Enrollment v3 (audit P-1). Carries only the handle: the fingerprint must be
/// over the key this device holds, never one supplied by the caller.
#[derive(Debug, Serialize, Deserialize)]
struct IdentityFingerprintRequest {
    handle: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdentityFingerprintResponse {
    fingerprint: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdentityEnrollmentResultRequest {
    handle: u64,
    grant_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdentityCapsuleRequest {
    handle: u64,
    capsule_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdentityCapsuleResponse {
    /// The 32-byte root master secret, base64. Sealed to this device's own
    /// `hybrid_ek`, so it opens here and nowhere else.
    rms_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdentityRotateShareKeyRequest {
    handle: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdentityRotateShareKeyResponse {
    share_ek_b64: String,
    sealed_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdentityHandleRequest {
    handle: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct OkResponse2 {
    ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct WebSessionChunkKeysResponse {
    /// `chunk_id → base64(32-byte key)` for the chunks a read-write web session
    /// is granted. The RMS itself never leaves the approver (audit D-2).
    chunk_keys: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptChunkRequest {
    /// C-ABI only; the JNI entry points pass the RMS as bytes (audit C-1).
    #[serde(default)]
    rms_b64: String,
    chunk_id: String,
    vault_json: String,
    /// The clock this chunk will be stored under. Bound into the ciphertext so
    /// the server cannot serve an older revision back as if it were current
    /// (audit C-2). Deliberately *not* defaulted: a caller that forgets it would
    /// otherwise seal against clock 0 and write something nothing can read.
    lamport_clock: i64,
    /// Account epoch whose RMS derived this chunk key. Mandatory so an
    /// epoch-2 caller cannot accidentally emit legacy-AAD ciphertext.
    key_epoch: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecryptChunkRequest {
    /// C-ABI only; the JNI entry points pass the RMS as bytes (audit C-1).
    #[serde(default)]
    rms_b64: String,
    chunk_id: String,
    ciphertext_b64: String,
    /// Revision the server claimed for this chunk. Verified for sealed
    /// ciphertexts, ignored for legacy ones (audit C-2, rollout step 2).
    #[serde(default)]
    lamport_clock: i64,
    /// Authenticated manifest epoch. Mandatory and checked against the AEAD.
    key_epoch: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct SealShareRequest {
    recipient_share_ek_b64: String,
    item_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SealShareResponse {
    capsule_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenShareResponse {
    item_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenRekeyCapsuleResponse {
    rms_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthSignatureResponse {
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecryptRmsCapsuleRequest {
    transfer_key_b64: String,
    capsule_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecryptRmsCapsuleResponse {
    rms_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecryptEnrollmentPackageRequest {
    key_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecryptEnrollmentPackageResponse {
    plaintext: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SplitRecoveryRequest {
    /// C-ABI only; the JNI entry points pass the RMS as bytes (audit C-1).
    #[serde(default)]
    rms_b64: String,
    threshold: u8,
    n: u8,
}

#[derive(Debug, Serialize, Deserialize)]
struct SplitRecoveryResponse {
    /// One base64 Shamir share per `[x, y_0..y_31]` blob.
    shares_b64: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CombineShareInput {
    share_b64: String,
    /// One of "cloud", "server", "trusted_contact" (M18 pair selection).
    channel: String,
    account_id: String,
    key_epoch: i64,
    #[serde(default)]
    split_id: Option<String>,
    #[serde(default)]
    recipient_bound: bool,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
struct CombineRecoveryResponse {
    rms_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
struct PublicationPlanResponse {
    action: String,
}

#[no_mangle]
pub extern "C" fn vela_bridge_version() -> *mut c_char {
    string_to_ptr("vela-android-bridge/0.1.0")
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeVersion(
    mut env: JNIEnv,
    _object: JObject,
) -> jstring {
    jni_string(&mut env, "vela-android-bridge/0.1.0")
}

/// Compute the short out-of-band verification code for an enrollment code
/// string (see `vela_crypto::verification`). Called after scanning/pasting
/// an enrollment code, before importing it, so the user can confirm it
/// matches what the enrolling device shows.
#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeEnrollmentVerificationCode(
    mut env: JNIEnv,
    _object: JObject,
    code: JString,
) -> jstring {
    let code_str = match env.get_string(&code) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => String::new(),
    };
    let result = vela_crypto::verification::enrollment_verification_code(&code_str);
    jni_string(&mut env, &result)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeEncryptVaultJson(
    mut env: JNIEnv,
    _object: JObject,
    rms: JByteArray,
    request_json: JString,
) -> jstring {
    let response = jni_json_result_with_secret(&mut env, rms, request_json, |rms, request| {
        encrypt_vault_with_rms(rms, request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeDecryptVaultJson(
    mut env: JNIEnv,
    _object: JObject,
    rms: JByteArray,
    request_json: JString,
) -> jstring {
    let response = jni_json_result_with_secret(&mut env, rms, request_json, |rms, request| {
        decrypt_vault_with_rms(rms, request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeEncryptVaultChunkJson(
    mut env: JNIEnv,
    _object: JObject,
    rms: JByteArray,
    request_json: JString,
) -> jstring {
    let response = jni_json_result_with_secret(&mut env, rms, request_json, |rms, request| {
        encrypt_vault_chunk_with_rms(rms, request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeDecryptVaultChunkJson(
    mut env: JNIEnv,
    _object: JObject,
    rms: JByteArray,
    request_json: JString,
) -> jstring {
    let response = jni_json_result_with_secret(&mut env, rms, request_json, |rms, request| {
        decrypt_vault_chunk_with_rms(rms, request)
    });
    jni_string(&mut env, &response)
}

// The JNI entry points that returned `hybrid_sk_b64` / `share_dk_b64`, or took
// them as arguments, are gone: there is no longer a way for the app to obtain a
// private key from this bridge (audit C-1). The C-ABI equivalents remain for the
// desktop/test harness, which is Rust on both sides.

// ── Identity handle entry points ────────────────────────────────────────────
//
// `seal_key` is a JNI byte array, so both sides can wipe it; the private keys it
// protects never appear on the JVM heap at all (audit C-1).

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeIdentityCreateJson(
    mut env: JNIEnv,
    _object: JObject,
    seal_key: JByteArray,
    request_json: JString,
) -> jstring {
    let response = jni_json_result_with_secret(&mut env, seal_key, request_json, |key, request| {
        identity_create(key, request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeIdentityImportJson(
    mut env: JNIEnv,
    _object: JObject,
    seal_key: JByteArray,
    request_json: JString,
) -> jstring {
    let response = jni_json_result_with_secret(&mut env, seal_key, request_json, |key, request| {
        identity_import(key, request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeIdentityOpenJson(
    mut env: JNIEnv,
    _object: JObject,
    seal_key: JByteArray,
    request_json: JString,
) -> jstring {
    let response = jni_json_result_with_secret(&mut env, seal_key, request_json, |key, request| {
        identity_open(key, request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeIdentityRotateShareKeyJson(
    mut env: JNIEnv,
    _object: JObject,
    seal_key: JByteArray,
    request_json: JString,
) -> jstring {
    let response = jni_json_result_with_secret(&mut env, seal_key, request_json, |key, request| {
        identity_rotate_share_key(key, request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeIdentitySignJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| identity_sign(request));
    jni_string(&mut env, &response)
}

/// Open an RMS-rotation capsule with the device's hybrid DK (M24).
fn open_rekey_capsule_json(request_json: &str) -> anyhow_like::Result<OpenRekeyCapsuleResponse> {
    #[derive(Deserialize)]
    struct Request {
        hybrid_dk_b64: String,
        capsule_b64: String,
        previous_rms: Vec<u8>,
        expected_epoch: i64,
        expected_rotation_id: String,
    }
    #[derive(Serialize)]
    struct Response { rms_b64: String }
    let request: Request = serde_json::from_str(request_json)?;
    let dk = B64.decode(request.hybrid_dk_b64.as_bytes())?;
    let capsule = B64.decode(request.capsule_b64.as_bytes())?;
    let previous_rms: [u8; 32] = request.previous_rms.try_into()
        .map_err(|_| "previous_rms must be 32 bytes")?;
    let rms = vela_crypto::rekey::open_rekey_capsule(
        &dk, &capsule, &previous_rms,
        request.expected_epoch, &request.expected_rotation_id,
    )?;
    Ok(OpenRekeyCapsuleResponse { rms_b64: B64.encode(rms.as_slice()) })
}

/// Sign a share-key binding with the identity held under `handle` (M19).
#[no_mangle]
/// Open an RMS-rotation capsule for epoch adoption (M24).
#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeOpenRekeyCapsuleJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| {
        open_rekey_capsule_json(request)
    });
    jni_string(&mut env, &response)
}

pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeIdentitySignShareEkJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| {
        identity_sign_share_ek(request)
    });
    jni_string(&mut env, &response)
}

// ── Enrollment v3 (audit P-1) ───────────────────────────────────────────────

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeIdentityEnrollmentFingerprintJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| {
        identity_enrollment_fingerprint(request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeIdentitySignEnrollmentResultJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| {
        identity_sign_enrollment_result(request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeIdentityOpenEnrollmentCapsuleJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| {
        identity_open_enrollment_capsule(request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeIdentityOpenShareJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| {
        identity_open_share(request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeIdentityForgetJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| identity_forget(request));
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeIdentityForgetAllJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| {
        identity_forget_all(request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeWebSessionChunkKeysJson(
    mut env: JNIEnv,
    _object: JObject,
    rms: JByteArray,
    request_json: JString,
) -> jstring {
    let response = jni_json_result_with_secret(&mut env, rms, request_json, |rms, request| {
        web_session_chunk_keys_with_rms(rms, request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeDecryptRmsCapsuleJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
    rms_out: JByteArray,
) -> jstring {
    let response = jni_json_result_into_secret(&mut env, request_json, rms_out, |request| {
        decrypt_rms_capsule_bytes(request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeDecryptEnrollmentPackageJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| {
        decrypt_enrollment_package_json(request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeSealShareJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| seal_share_json(request));
    jni_string(&mut env, &response)
}

/// Split the RMS into an `n`-share, `threshold`-of-`n` Shamir scheme
/// (SPEC.md §4.3: recovery uses a 2-of-3 split). Called once during recovery
/// setup; the caller is responsible for delivering each share to its own
/// channel (cloud backup, server, trusted contact).
#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeSplitRecoveryJson(
    mut env: JNIEnv,
    _object: JObject,
    rms: JByteArray,
    request_json: JString,
) -> jstring {
    let response = jni_json_result_with_secret(&mut env, rms, request_json, |rms, request| {
        split_recovery_with_rms(rms, request)
    });
    jni_string(&mut env, &response)
}

/// Reconstruct the RMS from any `threshold` of the shares produced by
/// `nativeSplitRecoveryJson` (e.g. Share 1 from cloud backup + Share 2
/// released by the server after a WebAuthn-gated `/recovery/recover` call).
#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeCombineRecoveryJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
    rms_out: JByteArray,
) -> jstring {
    let response = jni_json_result_into_secret(&mut env, request_json, rms_out, |request| {
        combine_recovery_bytes(request)
    });
    jni_string(&mut env, &response)
}

/// Blind RMS-possession commitment for the reconstructed RMS (M18).
#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeRmsPossessionHashJson(
    mut env: JNIEnv,
    _object: JObject,
    rms: JByteArray,
) -> jstring {
    // No request JSON on this call; pass an empty JString via the shared
    // secret-carrying helper by reusing the raw-secret extraction directly.
    let response = match jni_secret_bytes(&mut env, &rms) {
        Ok(bytes) => match rms_possession_hash_bytes(&bytes) {
            Ok(hash_b64) => serde_json::json!({ "hash_b64": hash_b64 }).to_string(),
            Err(error) => error_json(&error.to_string()),
        },
        Err(error) => error_json(&error.to_string()),
    };
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativePlanRecoveryPublicationJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, plan_recovery_publication_json);
    jni_string(&mut env, &response)
}

#[no_mangle]
pub unsafe extern "C" fn vela_bridge_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

#[no_mangle]
/// # Safety
/// `buffer` must have come from this library and must not be freed twice.
/// Sound only because [`vec_to_buffer`] guarantees `capacity == len`.
pub unsafe extern "C" fn vela_bridge_free_bytes(buffer: VelaByteBuffer) {
    if !buffer.ptr.is_null() && buffer.len > 0 {
        drop(Box::from_raw(std::slice::from_raw_parts_mut(
            buffer.ptr, buffer.len,
        )));
    }
}

#[no_mangle]
pub unsafe extern "C" fn vela_password_strength_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| {
        let request: PasswordStrengthRequest = serde_json::from_str(c_str(request_json)?)?;
        Ok(PasswordStrengthResponse {
            strength: calculate_password_strength(&request.password),
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn vela_encrypt_vault_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| encrypt_vault_json(c_str(request_json)?))
}

#[no_mangle]
pub unsafe extern "C" fn vela_decrypt_vault_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| decrypt_vault_json(c_str(request_json)?))
}

#[no_mangle]
pub unsafe extern "C" fn vela_encrypt_bytes(
    plaintext_ptr: *const c_uchar,
    plaintext_len: usize,
    rms_ptr: *const c_uchar,
    rms_len: usize,
) -> VelaByteBuffer {
    let result = (|| -> anyhow_like::Result<Vec<u8>> {
        let plaintext = raw_slice(plaintext_ptr, plaintext_len)?;
        let rms = raw_rms(rms_ptr, rms_len)?;
        let key = kdf::derive(VAULT_KEY_CONTEXT, &rms);
        Ok(aead::encrypt(key.as_bytes(), plaintext)?)
    })();

    match result {
        Ok(bytes) => vec_to_buffer(bytes),
        Err(_) => VelaByteBuffer {
            ptr: ptr::null_mut(),
            len: 0,
        },
    }
}

fn decode_rms(input: &str) -> anyhow_like::Result<[u8; 32]> {
    let decoded = B64.decode(input.as_bytes())?;
    unsafe { raw_rms(decoded.as_ptr(), decoded.len()) }
}

/// RMS handed over as raw bytes (JNI path, audit C-1).
fn encrypt_vault_with_rms(
    rms: &[u8],
    request_json: &str,
) -> anyhow_like::Result<EncryptVaultResponse> {
    let request: EncryptVaultRequest = serde_json::from_str(request_json)?;
    let rms = unsafe { raw_rms(rms.as_ptr(), rms.len()) }?;
    let _: VaultStore = serde_json::from_str(&request.vault_json)?;
    let key = kdf::derive(VAULT_KEY_CONTEXT, &rms);
    let ciphertext = aead::encrypt(key.as_bytes(), request.vault_json.as_bytes())?;
    Ok(EncryptVaultResponse {
        ciphertext_b64: B64.encode(ciphertext),
    })
}

fn decrypt_vault_with_rms(
    rms: &[u8],
    request_json: &str,
) -> anyhow_like::Result<DecryptVaultResponse> {
    let request: DecryptVaultRequest = serde_json::from_str(request_json)?;
    let rms = unsafe { raw_rms(rms.as_ptr(), rms.len()) }?;
    let ciphertext = B64.decode(request.ciphertext_b64.as_bytes())?;
    let key = kdf::derive(VAULT_KEY_CONTEXT, &rms);
    let plaintext = aead::decrypt(key.as_bytes(), &ciphertext)?;
    Ok(DecryptVaultResponse {
        vault_json: String::from_utf8(plaintext.to_vec())?,
    })
}

fn encrypt_vault_chunk_with_rms(
    rms: &[u8],
    request_json: &str,
) -> anyhow_like::Result<EncryptVaultResponse> {
    let request: EncryptChunkRequest = serde_json::from_str(request_json)?;
    let rms = unsafe { raw_rms(rms.as_ptr(), rms.len()) }?;
    let _: VaultStore = serde_json::from_str(&request.vault_json)?;
    let key = chunk_key(&rms, &request.chunk_id);
    let epoch = u64::try_from(request.key_epoch).map_err(|_| "vault key epoch must be positive")?;
    let ciphertext = rekey::seal_fleet_chunk(
        &key,
        request.vault_json.as_bytes(),
        epoch,
        &request.chunk_id,
        request.lamport_clock,
    )?;
    Ok(EncryptVaultResponse {
        ciphertext_b64: B64.encode(ciphertext),
    })
}

fn decrypt_vault_chunk_with_rms(
    rms: &[u8],
    request_json: &str,
) -> anyhow_like::Result<DecryptVaultResponse> {
    let request: DecryptChunkRequest = serde_json::from_str(request_json)?;
    let rms = unsafe { raw_rms(rms.as_ptr(), rms.len()) }?;
    let ciphertext = B64.decode(request.ciphertext_b64.as_bytes())?;
    let key = chunk_key(&rms, &request.chunk_id);
    let epoch = u64::try_from(request.key_epoch).map_err(|_| "vault key epoch must be positive")?;
    let plaintext = rekey::open_fleet_chunk(
        &key,
        &ciphertext,
        epoch,
        &request.chunk_id,
        request.lamport_clock,
    )?;
    Ok(DecryptVaultResponse {
        vault_json: String::from_utf8(plaintext.to_vec())?,
    })
}

fn web_session_chunk_keys_with_rms(
    rms: &[u8],
    _request_json: &str,
) -> anyhow_like::Result<WebSessionChunkKeysResponse> {
    let rms = unsafe { raw_rms(rms.as_ptr(), rms.len()) }?;
    let chunk_keys = kdf::web_session_chunk_keys(&rms)
        .into_iter()
        .map(|(id, key)| (id, B64.encode(key.as_bytes())))
        .collect();
    Ok(WebSessionChunkKeysResponse { chunk_keys })
}

fn split_recovery_with_rms(
    rms: &[u8],
    request_json: &str,
) -> anyhow_like::Result<SplitRecoveryResponse> {
    let request: SplitRecoveryRequest = serde_json::from_str(request_json)?;
    let rms = unsafe { raw_rms(rms.as_ptr(), rms.len()) }?;
    let shares = shamir::split(&rms, request.threshold, request.n)?;
    Ok(SplitRecoveryResponse {
        shares_b64: shares.iter().map(|s| B64.encode(s.to_bytes())).collect(),
    })
}

/// Blind RMS-possession commitment (M18). Staged with the server share so
/// any two-share pair can prove RMS possession for enrollment without WebAuthn.
fn rms_possession_hash_bytes(rms: &[u8]) -> anyhow_like::Result<String> {
    if rms.len() != 32 {
        return Err("rms must be exactly 32 bytes".into());
    }
    let rms: [u8; 32] = rms.try_into().expect("length checked");
    Ok(B64.encode(vela_crypto::recovery::rms_possession_hash(&rms)))
}

fn encrypt_vault_json(request_json: &str) -> anyhow_like::Result<EncryptVaultResponse> {
    let request: EncryptVaultRequest = serde_json::from_str(request_json)?;
    let rms = decode_rms(&request.rms_b64)?;
    let _: VaultStore = serde_json::from_str(&request.vault_json)?;
    let key = kdf::derive(VAULT_KEY_CONTEXT, &rms);
    let ciphertext = aead::encrypt(key.as_bytes(), request.vault_json.as_bytes())?;
    Ok(EncryptVaultResponse {
        ciphertext_b64: B64.encode(ciphertext),
    })
}

fn decrypt_vault_json(request_json: &str) -> anyhow_like::Result<DecryptVaultResponse> {
    let request: DecryptVaultRequest = serde_json::from_str(request_json)?;
    let rms = decode_rms(&request.rms_b64)?;
    let ciphertext = B64.decode(request.ciphertext_b64.as_bytes())?;
    let key = kdf::derive(VAULT_KEY_CONTEXT, &rms);
    let plaintext = aead::decrypt(key.as_bytes(), &ciphertext)?;
    let vault_json = String::from_utf8(plaintext.to_vec())?;
    Ok(DecryptVaultResponse { vault_json })
}

/// Delegates to `vela_crypto`, which owns the derivation context.
///
/// This used to build the context here with `{:?}`, in a second copy that had to
/// stay byte-identical to the core's by hand — two places to get a key
/// derivation exactly right (audit crypto M4).
fn chunk_key(rms: &[u8; 32], chunk_id: &str) -> [u8; 32] {
    *kdf::chunk_key(rms, chunk_id.as_bytes()).as_bytes()
}

// ── Identity handles (audit C-1) ─────────────────────────────────────────────
//
// The app holds a `u64` and an opaque sealed blob; the signing key and the share
// decapsulation key never cross the JNI boundary in either direction. The seal
// key arrives as a byte array the caller can wipe, never as a `String`.

fn identity_response(
    identity: vela_crypto::identity::DeviceIdentity,
    seal_key: &[u8],
) -> anyhow_like::Result<IdentityHandleResponse> {
    let seal_key = raw_key32(seal_key)?;
    let sealed = identity.seal(&seal_key)?;
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

fn raw_key32(bytes: &[u8]) -> anyhow_like::Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow_like::Error::from("seal key must be 32 bytes".to_string()))
}

fn identity_create(seal_key: &[u8], _request: &str) -> anyhow_like::Result<IdentityHandleResponse> {
    identity_response(vela_crypto::identity::DeviceIdentity::generate()?, seal_key)
}

fn identity_import(
    seal_key: &[u8],
    request_json: &str,
) -> anyhow_like::Result<IdentityHandleResponse> {
    let request: IdentityImportRequest = serde_json::from_str(request_json)?;
    let signing_sk = B64.decode(request.hybrid_sk_b64.as_bytes())?;
    let share_dk = if request.share_dk_b64.is_empty() {
        None
    } else {
        Some(B64.decode(request.share_dk_b64.as_bytes())?)
    };
    let hybrid_ek = if request.hybrid_ek_b64.is_empty() {
        None
    } else {
        Some(B64.decode(request.hybrid_ek_b64.as_bytes())?)
    };
    let identity = vela_crypto::identity::DeviceIdentity::import(
        &signing_sk,
        share_dk.as_deref(),
        hybrid_ek.as_deref(),
    )?;
    identity_response(identity, seal_key)
}

fn identity_open(
    seal_key: &[u8],
    request_json: &str,
) -> anyhow_like::Result<IdentityHandleResponse> {
    let request: IdentityOpenRequest = serde_json::from_str(request_json)?;
    let sealed = B64.decode(request.sealed_b64.as_bytes())?;
    let key = raw_key32(seal_key)?;
    let identity = vela_crypto::identity::DeviceIdentity::open(&sealed, &key)?;
    identity_response(identity, seal_key)
}

fn identity_sign(request_json: &str) -> anyhow_like::Result<AuthSignatureResponse> {
    let request: IdentitySignRequest = serde_json::from_str(request_json)?;
    let challenge = B64.decode(request.challenge_b64.as_bytes())?;
    let signature = vela_crypto::identity::with_identity(request.handle, |identity| {
        identity.sign_auth(&request.device_id, &challenge)
    })?;
    Ok(AuthSignatureResponse {
        signature: B64.encode(signature),
    })
}

/// Sign a share-key binding with the identity held under `handle` (M19).
fn identity_sign_share_ek(request_json: &str) -> anyhow_like::Result<AuthSignatureResponse> {
    #[derive(Deserialize)]
    struct Request {
        handle: u64,
        share_ek_b64: String,
        signed_at: String,
    }
    let request: Request = serde_json::from_str(request_json)?;
    let ek = B64.decode(request.share_ek_b64.as_bytes())?;
    let signature = vela_crypto::identity::with_identity(request.handle, |identity| {
        identity.sign_share_ek_binding(&ek, &request.signed_at)
    })?;
    Ok(AuthSignatureResponse {
        signature: B64.encode(signature),
    })
}

fn identity_open_share(request_json: &str) -> anyhow_like::Result<OpenShareResponse> {
    let request: IdentityOpenShareRequest = serde_json::from_str(request_json)?;
    let capsule = B64.decode(request.capsule_b64.as_bytes())?;
    let plaintext = vela_crypto::identity::with_identity(request.handle, |identity| {
        identity.open_share(&capsule)
    })?;
    Ok(OpenShareResponse {
        item_json: String::from_utf8(plaintext)?,
    })
}

/// This device's own enrollment fingerprint (v3).
///
/// Computed from the key held under `handle`, so the app has no way to display
/// a fingerprint that arrived over the network — which is the property the
/// user's comparison depends on (audit P-1).
fn identity_enrollment_fingerprint(
    request_json: &str,
) -> anyhow_like::Result<IdentityFingerprintResponse> {
    let request: IdentityFingerprintRequest = serde_json::from_str(request_json)?;
    let fingerprint = vela_crypto::identity::with_identity(request.handle, |identity| {
        Ok(identity.enrollment_fingerprint())
    })?;
    Ok(IdentityFingerprintResponse { fingerprint })
}

/// Sign a grant id, to collect the outcome of this device's own enrollment.
fn identity_sign_enrollment_result(
    request_json: &str,
) -> anyhow_like::Result<AuthSignatureResponse> {
    let request: IdentityEnrollmentResultRequest = serde_json::from_str(request_json)?;
    let signature = vela_crypto::identity::with_identity(request.handle, |identity| {
        identity.sign_enrollment_result(&request.grant_id)
    })?;
    Ok(AuthSignatureResponse {
        signature: B64.encode(signature),
    })
}

/// Open the RMS capsule the enrolling device sealed to this device's key.
fn identity_open_enrollment_capsule(
    request_json: &str,
) -> anyhow_like::Result<IdentityCapsuleResponse> {
    let request: IdentityCapsuleRequest = serde_json::from_str(request_json)?;
    let capsule = B64.decode(request.capsule_b64.as_bytes())?;
    let plaintext = vela_crypto::identity::with_identity(request.handle, |identity| {
        identity.open_identity_capsule(&capsule)
    })?;
    if plaintext.len() != 32 {
        return Err(anyhow_like::Error::from(
            "capsule did not contain a 32-byte root seed".to_string(),
        ));
    }
    Ok(IdentityCapsuleResponse {
        rms_b64: B64.encode(&plaintext),
    })
}

fn identity_rotate_share_key(
    seal_key: &[u8],
    request_json: &str,
) -> anyhow_like::Result<IdentityRotateShareKeyResponse> {
    let request: IdentityRotateShareKeyRequest = serde_json::from_str(request_json)?;
    let key = raw_key32(seal_key)?;
    let (share_ek, sealed) = vela_crypto::identity::with_identity(request.handle, |identity| {
        let share_ek = identity.rotate_share_key();
        Ok((share_ek, identity.seal(&key)?))
    })?;
    Ok(IdentityRotateShareKeyResponse {
        share_ek_b64: B64.encode(share_ek),
        sealed_b64: B64.encode(sealed),
    })
}

fn identity_forget(request_json: &str) -> anyhow_like::Result<OkResponse2> {
    let request: IdentityHandleRequest = serde_json::from_str(request_json)?;
    Ok(OkResponse2 {
        ok: vela_crypto::identity::forget(request.handle),
    })
}

fn identity_forget_all(_request_json: &str) -> anyhow_like::Result<OkResponse2> {
    vela_crypto::identity::forget_all();
    Ok(OkResponse2 { ok: true })
}

fn seal_share_json(request_json: &str) -> anyhow_like::Result<SealShareResponse> {
    let req: SealShareRequest = serde_json::from_str(request_json)?;
    let ek_bytes = B64.decode(req.recipient_share_ek_b64.as_bytes())?;
    let pk = kem::HybridPublicKey::from_bytes(&ek_bytes)?;
    let capsule = kem::seal_share(&pk, req.item_json.as_bytes())?;
    Ok(SealShareResponse {
        capsule_b64: B64.encode(capsule),
    })
}

/// Same as [`decrypt_rms_capsule_json`] but yields the raw RMS for the
/// byte-array JNI path (audit C-1).
fn decrypt_rms_capsule_bytes(request_json: &str) -> anyhow_like::Result<[u8; 32]> {
    let response = decrypt_rms_capsule_json(request_json)?;
    decode_rms(&response.rms_b64)
}

fn combine_recovery_bytes(request_json: &str) -> anyhow_like::Result<[u8; 32]> {
    let response = combine_recovery_json(request_json)?;
    decode_rms(&response.rms_b64)
}

fn decrypt_rms_capsule_json(request_json: &str) -> anyhow_like::Result<DecryptRmsCapsuleResponse> {
    let request: DecryptRmsCapsuleRequest = serde_json::from_str(request_json)?;
    let transfer_key = B64.decode(request.transfer_key_b64.as_bytes())?;
    if transfer_key.len() != 32 {
        return Err("transfer_key must be 32 bytes".into());
    }
    let transfer_key: [u8; 32] = transfer_key
        .try_into()
        .map_err(|_| "transfer_key must be 32 bytes")?;
    let capsule = B64.decode(request.capsule_b64.as_bytes())?;
    let plaintext = aead::decrypt(&transfer_key, &capsule)?;
    if plaintext.len() != 32 {
        return Err("decrypted RMS must be 32 bytes".into());
    }
    Ok(DecryptRmsCapsuleResponse {
        rms_b64: B64.encode(plaintext),
    })
}

fn decrypt_enrollment_package_json(
    request_json: &str,
) -> anyhow_like::Result<DecryptEnrollmentPackageResponse> {
    let request: DecryptEnrollmentPackageRequest = serde_json::from_str(request_json)?;
    let key = B64.decode(request.key_b64.as_bytes())?;
    if key.len() != 32 {
        return Err("enrollment package key must be 32 bytes".into());
    }
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| "enrollment package key must be 32 bytes")?;
    let ciphertext = B64.decode(request.ciphertext_b64.as_bytes())?;
    let plaintext = aead::decrypt(&key, &ciphertext)?;
    Ok(DecryptEnrollmentPackageResponse {
        plaintext: String::from_utf8(plaintext.to_vec())?,
    })
}

fn combine_recovery_json(request_json: &str) -> anyhow_like::Result<CombineRecoveryResponse> {
    let request: CombineRecoveryRequest = serde_json::from_str(request_json)?;
    let shares: Vec<shamir::Share> = request
        .shares_b64
        .iter()
        .map(|s| -> anyhow_like::Result<shamir::Share> {
            let bytes = B64.decode(s.as_bytes())?;
            Ok(shamir::Share::from_bytes(&bytes)?)
        })
        .collect::<anyhow_like::Result<_>>()?;
    let binding = (
        request.requested_user_id.as_deref(),
        request.cloud_user_id.as_deref(),
        request.cloud_key_epoch,
        request.server_user_id.as_deref(),
        request.server_key_epoch,
    );
    // M18: channel-tagged bound shares go through the verified pair-selection
    // policy, which admits every distinct-channel pair (cloud + server,
    // cloud + trusted contact, server + trusted contact).
    if !request.bound_shares.is_empty() {
        let requested = request
            .requested_user_id
            .as_deref()
            .ok_or("requested_user_id is required for bound account recovery")?;
        if request.bound_shares.len() != 2 || shares.len() != 2 {
            return Err("bound account recovery requires exactly two shares".into());
        }
        let channel = |name: &str| match name {
            "cloud" => Ok(vela_crypto::recovery::RecoveryShareChannel::Cloud),
            "server" => Ok(vela_crypto::recovery::RecoveryShareChannel::Server),
            "trusted_contact" => Ok(vela_crypto::recovery::RecoveryShareChannel::TrustedContact),
            other => Err(format!("unknown recovery share channel {other:?}")),
        };
        let first = &request.bound_shares[0];
        let second = &request.bound_shares[1];
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
                    split_id: request.cloud_split_id.as_deref(),
                    channel: vela_crypto::recovery::RecoveryShareChannel::Cloud,
                    recipient_bound: false,
                    share: &shares[0],
                },
                vela_crypto::recovery::BoundRecoveryShare {
                    account_id: server_user,
                    key_epoch: server_epoch,
                    split_id: request.server_split_id.as_deref(),
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

fn plan_recovery_publication_json(
    request_json: &str,
) -> anyhow_like::Result<PublicationPlanResponse> {
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

/// Read a JNI byte array into a buffer that is wiped when it drops.
///
/// Key material used to reach Rust as base64 inside a JVM `String`: immutable,
/// possibly interned, never zeroized, and therefore still sitting in the heap
/// (and in any heap dump or crash report) long after use. A `ByteArray` is
/// something both sides can actually erase — Kotlin calls `fill(0)`, and the
/// copy below is zeroized on drop (audit C-1).
struct SecretBytes(Vec<u8>);

impl std::ops::Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn jni_secret_bytes(env: &mut JNIEnv, array: &JByteArray) -> anyhow_like::Result<SecretBytes> {
    let bytes = env
        .convert_byte_array(array)
        .map_err(|e| anyhow_like::Error::from(e.to_string()))?;
    Ok(SecretBytes(bytes))
}

/// Run `f` with the RMS taken from a JNI byte array rather than a `String`.
fn jni_json_result_with_secret<T, F>(
    env: &mut JNIEnv,
    secret: JByteArray,
    request_json: JString,
    f: F,
) -> String
where
    T: Serialize,
    F: FnOnce(&[u8], &str) -> anyhow_like::Result<T>,
{
    let secret = match jni_secret_bytes(env, &secret) {
        Ok(bytes) => bytes,
        Err(error) => return error_json(&error.to_string()),
    };
    let request = match env.get_string(&request_json) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(error) => return error_json(&error.to_string()),
    };
    match f(&secret, &request).and_then(|value| Ok(serde_json::to_string(&value)?)) {
        Ok(json) => json,
        Err(error) => error_json(&error.to_string()),
    }
}

#[derive(Serialize)]
struct OkResponse {
    ok: bool,
}

/// Run `f` and hand its 32-byte secret back through the caller's byte array
/// instead of a JSON string.
///
/// Returning the RMS as base64 in a JVM `String` (as the recovery and
/// enrollment paths used to) leaves it un-zeroizable on the JVM heap, which is
/// the same problem as passing it in (audit C-1). The JSON return value is kept
/// for the error message only.
fn jni_json_result_into_secret<F>(
    env: &mut JNIEnv,
    request_json: JString,
    out: JByteArray,
    f: F,
) -> String
where
    F: FnOnce(&str) -> anyhow_like::Result<[u8; 32]>,
{
    let request = match env.get_string(&request_json) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(error) => return error_json(&error.to_string()),
    };
    match f(&request) {
        Ok(secret) => {
            let signed: Vec<i8> = secret.iter().map(|b| *b as i8).collect();
            if let Err(error) = env.set_byte_array_region(&out, 0, &signed) {
                return error_json(&error.to_string());
            }
            match serde_json::to_string(&OkResponse { ok: true }) {
                Ok(json) => json,
                Err(error) => error_json(&error.to_string()),
            }
        }
        Err(error) => error_json(&error.to_string()),
    }
}

fn jni_json_result<T, F>(env: &mut JNIEnv, request_json: JString, f: F) -> String
where
    T: Serialize,
    F: FnOnce(&str) -> anyhow_like::Result<T>,
{
    let request = match env.get_string(&request_json) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(error) => return error_json(&error.to_string()),
    };
    match f(&request).and_then(|value| Ok(serde_json::to_string(&value)?)) {
        Ok(json) => json,
        Err(error) => error_json(&error.to_string()),
    }
}

fn jni_string(env: &mut JNIEnv, value: &str) -> jstring {
    env.new_string(value)
        .map(|string| string.into_raw())
        .unwrap_or(ptr::null_mut())
}

unsafe fn c_str<'a>(ptr: *const c_char) -> anyhow_like::Result<&'a str> {
    if ptr.is_null() {
        return Err("null string pointer".into());
    }
    Ok(CStr::from_ptr(ptr).to_str()?)
}

unsafe fn raw_slice<'a>(ptr: *const c_uchar, len: usize) -> anyhow_like::Result<&'a [u8]> {
    if ptr.is_null() && len != 0 {
        return Err("null byte pointer".into());
    }
    Ok(slice::from_raw_parts(ptr, len))
}

unsafe fn raw_rms(ptr: *const c_uchar, len: usize) -> anyhow_like::Result<[u8; 32]> {
    let bytes = raw_slice(ptr, len)?;
    if bytes.len() != 32 {
        return Err("RMS must be 32 bytes".into());
    }
    let mut rms = [0u8; 32];
    rms.copy_from_slice(bytes);
    Ok(rms)
}

fn json_result<T, F>(f: F) -> *mut c_char
where
    T: Serialize,
    F: FnOnce() -> anyhow_like::Result<T>,
{
    match f().and_then(|value| Ok(serde_json::to_string(&value)?)) {
        Ok(json) => string_to_ptr(&json),
        Err(error) => {
            let fallback = error_json(&error.to_string());
            string_to_ptr(&fallback)
        }
    }
}

fn error_json(error: &str) -> String {
    serde_json::to_string(&BridgeError {
        error: error.to_string(),
    })
    .unwrap_or_else(|_| "{\"error\":\"bridge error\"}".to_string())
}

/// Hand a string to C, never panicking.
///
/// Both fallbacks used to end in `.expect(...)`, and an unwind across
/// `extern "C"` is undefined behaviour — the fact that an empty `CString` cannot
/// realistically fail is not a guarantee the compiler or a future refactor
/// respects (audit L2). `CString::new` only fails on an interior NUL, so the
/// fallback strips them and the last resort is built without any fallible call.
fn string_to_ptr(value: &str) -> *mut c_char {
    if let Ok(c_string) = CString::new(value) {
        return c_string.into_raw();
    }
    let without_nul: Vec<u8> = value.bytes().filter(|byte| *byte != 0).collect();
    if let Ok(c_string) = CString::new(without_nul) {
        return c_string.into_raw();
    }
    // Unreachable — the bytes above contain no NUL — but expressed without a
    // panic so no path out of this function can unwind into C.
    let mut empty = Vec::with_capacity(1);
    empty.push(0u8);
    Box::into_raw(empty.into_boxed_slice()) as *mut c_char
}

/// Hand a `Vec` to C as a pointer + length.
///
/// The boxed slice is what makes this sound: a `Vec` can hold `capacity > len`,
/// and `vela_bridge_free_bytes` rebuilds it with `capacity = len`, so the
/// allocator would be told a different layout than it handed out — undefined
/// behaviour (audit C-4). `into_boxed_slice` shrinks the allocation so the two
/// are equal by construction, and the C ABI stays as it is.
fn vec_to_buffer(bytes: Vec<u8>) -> VelaByteBuffer {
    let mut boxed = bytes.into_boxed_slice();
    let buffer = VelaByteBuffer {
        ptr: boxed.as_mut_ptr(),
        len: boxed.len(),
    };
    std::mem::forget(boxed);
    buffer
}

mod anyhow_like {
    pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
    pub type Result<T> = std::result::Result<T, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

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

    /// Enrollment v3 (audit P-1): the three calls the joining side runs.
    ///
    /// These go through the plain impls rather than the JNI wrappers, which
    /// need a JVM. The shape being pinned is that the fingerprint request
    /// carries only a handle — an API taking key bytes would make "render the
    /// value the server sent" a one-line mistake, and that one line is what
    /// would turn the comparison from two devices agreeing about a key into two
    /// devices agreeing about a number.
    #[test]
    fn enrollment_v3_fingerprint_is_over_the_devices_own_key_and_the_capsule_opens() {
        let created = identity_create(&[13u8; 32], "{}").expect("create");
        let handle = created.handle;
        let hybrid_ek = B64.decode(&created.hybrid_ek_b64).unwrap();
        let hybrid_vk = B64.decode(&created.hybrid_vk_b64).unwrap();

        let fp =
            identity_enrollment_fingerprint(&serde_json::json!({ "handle": handle }).to_string())
                .expect("fingerprint");
        assert_eq!(
            fp.fingerprint,
            vela_crypto::verification::enrollment_fingerprint(&hybrid_vk),
            "both sides must be talking about the same key"
        );

        let sig = identity_sign_enrollment_result(
            &serde_json::json!({ "handle": handle, "grant_id": "grant-1" }).to_string(),
        )
        .expect("sign");
        let vk = vela_crypto::signing::HybridVerifyingKey::from_bytes(
            hybrid_vk.as_slice().try_into().unwrap(),
        )
        .unwrap();
        let parsed = vela_crypto::signing::HybridSignature::from_bytes(
            B64.decode(&sig.signature)
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
        // Bound to the grant: a signature collected once cannot collect another
        // enrollment's result.
        assert!(!vela_crypto::signing::verify(
            &vk,
            &vela_crypto::signing::enrollment_result_message("grant-2"),
            &parsed
        )
        .unwrap());

        // What the primary seals to `hybrid_ek` opens here, and nowhere else.
        let pk = vela_crypto::kem::HybridPublicKey::from_bytes(&hybrid_ek).unwrap();
        let capsule = vela_crypto::kem::seal_share(&pk, &[5u8; 32]).unwrap();
        let opened = identity_open_enrollment_capsule(
            &serde_json::json!({ "handle": handle, "capsule_b64": B64.encode(&capsule) })
                .to_string(),
        )
        .expect("open");
        assert_eq!(B64.decode(&opened.rms_b64).unwrap(), vec![5u8; 32]);

        let other = identity_create(&[13u8; 32], "{}").expect("create");
        assert!(
            identity_open_enrollment_capsule(
                &serde_json::json!({
                    "handle": other.handle,
                    "capsule_b64": B64.encode(&capsule),
                })
                .to_string(),
            )
            .is_err(),
            "another device's key must not open it"
        );
    }

    /// Audit C-4: a `Vec` with spare capacity must still round-trip through the
    /// C ABI without lying to the allocator about the layout.
    #[test]
    fn byte_buffers_survive_a_round_trip_with_spare_capacity() {
        let mut bytes = Vec::with_capacity(4096);
        bytes.extend_from_slice(b"ciphertext");
        assert!(
            bytes.capacity() > bytes.len(),
            "the case that used to be UB"
        );

        let buffer = vec_to_buffer(bytes);
        assert_eq!(buffer.len, b"ciphertext".len());
        let seen = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) };
        assert_eq!(seen, b"ciphertext");

        // Under Miri or a hardened allocator, a capacity mismatch aborts here.
        unsafe { vela_bridge_free_bytes(buffer) };
    }

    #[test]
    fn password_strength_bridge_returns_json() {
        let request = CString::new(r#"{"password":"Abcdefgh123!"}"#).unwrap();
        let ptr = unsafe { vela_password_strength_json(request.as_ptr()) };
        let json = unsafe { CString::from_raw(ptr) }.into_string().unwrap();
        assert!(json.contains("\"score\":\"strong\""));
    }

    /// Audit C-1: the JNI paths take the RMS as bytes, so the request JSON no
    /// longer carries any key material at all.
    #[test]
    fn byte_array_paths_round_trip_without_key_material_in_json() {
        let rms = [7u8; 32];
        let vault_json = r#"{"items":[],"tombstones":[]}"#;

        let encrypted = encrypt_vault_chunk_with_rms(
            &rms,
            &serde_json::json!({
                "chunk_id": "vault-data-000000",
                "vault_json": vault_json,
                "lamport_clock": 3,
                "key_epoch": 1,
            })
            .to_string(),
        )
        .expect("encrypt");
        let decrypted = decrypt_vault_chunk_with_rms(
            &rms,
            &serde_json::json!({
                "chunk_id": "vault-data-000000",
                "ciphertext_b64": encrypted.ciphertext_b64,
                "lamport_clock": 3,
                "key_epoch": 1,
            })
            .to_string(),
        )
        .expect("decrypt");
        assert_eq!(decrypted.vault_json, vault_json);

        // Whole-vault path too.
        let encrypted = encrypt_vault_with_rms(
            &rms,
            &serde_json::json!({ "vault_json": vault_json }).to_string(),
        )
        .expect("encrypt vault");
        let decrypted = decrypt_vault_with_rms(
            &rms,
            &serde_json::json!({ "ciphertext_b64": encrypted.ciphertext_b64 }).to_string(),
        )
        .expect("decrypt vault");
        assert_eq!(decrypted.vault_json, vault_json);

        // A wrong-length RMS is rejected rather than silently padded.
        assert!(encrypt_vault_with_rms(
            &[0u8; 16],
            &serde_json::json!({ "vault_json": vault_json }).to_string()
        )
        .is_err());
    }

    #[test]
    fn android_chunk_crypto_binds_and_enforces_rotated_epochs() {
        let rms = [8u8; 32];
        let vault_json = r#"{"items":[],"tombstones":[]}"#;
        let encrypted = encrypt_vault_chunk_with_rms(
            &rms,
            &serde_json::json!({
                "chunk_id": "vault-data-000000",
                "vault_json": vault_json,
                "lamport_clock": 9,
                "key_epoch": 2,
            })
            .to_string(),
        )
        .expect("seal epoch-2 chunk");

        let decrypt = |epoch| {
            decrypt_vault_chunk_with_rms(
                &rms,
                &serde_json::json!({
                    "chunk_id": "vault-data-000000",
                    "ciphertext_b64": encrypted.ciphertext_b64,
                    "lamport_clock": 9,
                    "key_epoch": epoch,
                })
                .to_string(),
            )
        };
        assert_eq!(decrypt(2).unwrap().vault_json, vault_json);
        assert!(
            decrypt(1).is_err(),
            "an epoch-2 chunk must not open as epoch 1"
        );
        assert!(
            decrypt(3).is_err(),
            "an epoch-2 chunk must not open as epoch 3"
        );
        for (candidate_rms, chunk_id, lamport) in [
            ([9u8; 32], "vault-data-000000", 9),
            (rms, "vault-data-000001", 9),
            (rms, "vault-data-000000", 10),
        ] {
            assert!(decrypt_vault_chunk_with_rms(
                &candidate_rms,
                &serde_json::json!({
                    "chunk_id": chunk_id,
                    "ciphertext_b64": encrypted.ciphertext_b64,
                    "lamport_clock": lamport,
                    "key_epoch": 2,
                })
                .to_string(),
            )
            .is_err());
        }

        for invalid in [
            serde_json::json!({
                "chunk_id": "vault-data-000000",
                "vault_json": vault_json,
                "lamport_clock": 9,
            }),
            serde_json::json!({
                "chunk_id": "vault-data-000000",
                "vault_json": vault_json,
                "lamport_clock": 9,
                "key_epoch": 0,
            }),
        ] {
            assert!(encrypt_vault_chunk_with_rms(&rms, &invalid.to_string()).is_err());
        }
        for invalid in [
            serde_json::json!({
                "chunk_id": "vault-data-000000",
                "ciphertext_b64": encrypted.ciphertext_b64,
                "lamport_clock": 9,
            }),
            serde_json::json!({
                "chunk_id": "vault-data-000000",
                "ciphertext_b64": encrypted.ciphertext_b64,
                "lamport_clock": 9,
                "key_epoch": 0,
            }),
        ] {
            assert!(decrypt_vault_chunk_with_rms(&rms, &invalid.to_string()).is_err());
        }
    }

    #[test]
    fn android_accepts_legacy_chunks_only_at_epoch_one() {
        let rms = [10u8; 32];
        let chunk_id = "vault-data-000000";
        let lamport = 4;
        let key = chunk_key(&rms, chunk_id);
        let legacy = aead::seal(
            &key,
            br#"{"items":[],"tombstones":[]}"#,
            &aead::vault_chunk_aad(chunk_id, lamport),
        )
        .unwrap();
        let request = |epoch| {
            serde_json::json!({
                "chunk_id": chunk_id,
                "ciphertext_b64": B64.encode(&legacy),
                "lamport_clock": lamport,
                "key_epoch": epoch,
            })
            .to_string()
        };

        assert!(decrypt_vault_chunk_with_rms(&rms, &request(1)).is_ok());
        assert!(decrypt_vault_chunk_with_rms(&rms, &request(2)).is_err());

        let encrypted_at_one = encrypt_vault_chunk_with_rms(
            &rms,
            &serde_json::json!({
                "chunk_id": chunk_id,
                "vault_json": r#"{"items":[],"tombstones":[]}"#,
                "lamport_clock": lamport,
                "key_epoch": 1,
            })
            .to_string(),
        )
        .unwrap();
        let emitted = B64.decode(encrypted_at_one.ciphertext_b64).unwrap();
        assert!(
            aead::open_vault_chunk(&key, &emitted, chunk_id, lamport).is_ok(),
            "epoch 1 must remain readable by legacy mobile clients"
        );
    }

    /// The recovery/enrollment paths hand the RMS back as raw bytes for the
    /// caller's `ByteArray`, never as base64 in a JVM string (audit C-1).
    #[test]
    fn recovered_rms_is_returned_as_raw_bytes() {
        let rms = [9u8; 32];
        let shares = split_recovery_with_rms(
            &rms,
            &serde_json::json!({ "threshold": 2, "n": 3 }).to_string(),
        )
        .expect("split");
        assert_eq!(shares.shares_b64.len(), 3);

        let combined = combine_recovery_bytes(
            &serde_json::json!({ "shares_b64": shares.shares_b64[..2].to_vec() }).to_string(),
        )
        .expect("combine");
        assert_eq!(combined, rms);
    }

    #[test]
    fn bound_recovery_rejects_cross_account_and_mixed_epoch_inputs() {
        let rms = [10u8; 32];
        let shares = split_recovery_with_rms(
            &rms,
            &serde_json::json!({ "threshold": 2, "n": 3 }).to_string(),
        )
        .unwrap();
        let request = |cloud_user: &str, cloud_epoch: i64, server_split: &str| {
            serde_json::json!({
                "shares_b64": shares.shares_b64[..2].to_vec(),
                "requested_user_id": "account-a",
                "cloud_user_id": cloud_user,
                "cloud_key_epoch": cloud_epoch,
                "cloud_split_id": "11111111-1111-1111-1111-111111111111",
                "server_user_id": "account-a",
                "server_key_epoch": 4,
                "server_split_id": server_split
            })
            .to_string()
        };

        assert_eq!(
            combine_recovery_bytes(&request(
                "account-a",
                4,
                "11111111-1111-1111-1111-111111111111",
            ))
            .unwrap(),
            rms
        );
        assert!(combine_recovery_bytes(&request(
            "account-b",
            4,
            "11111111-1111-1111-1111-111111111111",
        ))
        .is_err());
        assert!(combine_recovery_bytes(&request(
            "account-a",
            3,
            "11111111-1111-1111-1111-111111111111",
        ))
        .is_err());
        assert!(combine_recovery_bytes(&request(
            "account-a",
            4,
            "22222222-2222-2222-2222-222222222222",
        ))
        .is_err());
    }

    #[test]
    fn encrypt_decrypt_vault_json_round_trips_through_crypto() {
        let rms = [7u8; 32];
        let vault_json = r#"{"items":[],"tombstones":[]}"#;
        let encrypt_request = CString::new(
            serde_json::json!({
                "rms_b64": B64.encode(rms),
                "vault_json": vault_json
            })
            .to_string(),
        )
        .unwrap();

        let encrypted_ptr = unsafe { vela_encrypt_vault_json(encrypt_request.as_ptr()) };
        let encrypted_json = unsafe { CString::from_raw(encrypted_ptr) }
            .into_string()
            .unwrap();
        let encrypted: EncryptVaultResponse = serde_json::from_str(&encrypted_json).unwrap();

        let decrypt_request = CString::new(
            serde_json::json!({
                "rms_b64": B64.encode(rms),
                "ciphertext_b64": encrypted.ciphertext_b64
            })
            .to_string(),
        )
        .unwrap();
        let decrypted_ptr = unsafe { vela_decrypt_vault_json(decrypt_request.as_ptr()) };
        let decrypted_json = unsafe { CString::from_raw(decrypted_ptr) }
            .into_string()
            .unwrap();
        let decrypted: DecryptVaultResponse = serde_json::from_str(&decrypted_json).unwrap();
        assert_eq!(decrypted.vault_json, vault_json);
    }

    #[test]
    fn split_then_combine_recovery_reconstructs_rms() {
        let rms = [9u8; 32];
        let split_request = serde_json::json!({
            "rms_b64": B64.encode(rms),
            "threshold": 2,
            "n": 3,
        })
        .to_string();
        let split = split_recovery_with_rms(&rms, &split_request).unwrap();
        assert_eq!(split.shares_b64.len(), 3);

        // Any 2 of the 3 shares must reconstruct the original RMS.
        let combine_request = serde_json::json!({
            "shares_b64": [split.shares_b64[0].clone(), split.shares_b64[2].clone()],
        })
        .to_string();
        let combined = combine_recovery_json(&combine_request).unwrap();
        assert_eq!(B64.decode(combined.rms_b64).unwrap(), rms.to_vec());
    }

    #[test]
    fn combine_recovery_rejects_single_share() {
        let rms = [3u8; 32];
        let split_request = serde_json::json!({
            "rms_b64": B64.encode(rms),
            "threshold": 2,
            "n": 3,
        })
        .to_string();
        let split = split_recovery_with_rms(&rms, &split_request).unwrap();

        let combine_request = serde_json::json!({
            "shares_b64": [split.shares_b64[0].clone()],
        })
        .to_string();
        assert!(combine_recovery_json(&combine_request).is_err());
    }

    /// The identity the app registers with the server is still the right shape,
    /// now that it is created behind a handle and only its public halves are
    /// returned (audit C-1).
    #[test]
    fn identity_handle_returns_server_sized_public_keys_and_no_secrets() {
        let seal_key = [5u8; 32];
        let created = identity_create(&seal_key, "{}").unwrap();

        assert_eq!(B64.decode(&created.hybrid_ek_b64).unwrap().len(), 1600);
        assert_eq!(B64.decode(&created.hybrid_vk_b64).unwrap().len(), 2624);
        assert_eq!(B64.decode(&created.share_ek_b64).unwrap().len(), 1600);

        let serialized = serde_json::to_string(&created).unwrap();
        for forbidden in ["hybrid_sk", "share_dk", "private"] {
            assert!(
                !serialized.contains(forbidden),
                "the handle response must not carry {forbidden}"
            );
        }

        // The handle can sign and can be revoked; the app never sees the key.
        let sign_request = serde_json::json!({
            "handle": created.handle,
            "device_id": "device-1",
            "challenge_b64": B64.encode(b"challenge"),
        })
        .to_string();
        assert!(!identity_sign(&sign_request).unwrap().signature.is_empty());

        let forget_request = serde_json::json!({ "handle": created.handle }).to_string();
        assert!(identity_forget(&forget_request).unwrap().ok);
        assert!(
            identity_sign(&sign_request).is_err(),
            "a forgotten handle cannot sign"
        );
    }

    /// Reopening the sealed blob has to yield the same device, or an app restart
    /// would silently lose the identity.
    #[test]
    fn a_sealed_identity_reopens_as_the_same_device() {
        let seal_key = [6u8; 32];
        let created = identity_create(&seal_key, "{}").unwrap();

        let open_request = serde_json::json!({ "sealed_b64": created.sealed_b64 }).to_string();
        let reopened = identity_open(&seal_key, &open_request).unwrap();

        assert_eq!(reopened.hybrid_vk_b64, created.hybrid_vk_b64);
        assert_eq!(reopened.share_ek_b64, created.share_ek_b64);
        assert_ne!(reopened.handle, created.handle, "a new handle each time");

        // A different seal key must not open it.
        assert!(identity_open(&[9u8; 32], &open_request).is_err());
    }
}
