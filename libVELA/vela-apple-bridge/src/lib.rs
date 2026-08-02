//! Apple (iOS/macOS) C-ABI bridge over the shared VELA Rust core.
//!
//! Mirrors the stable C ABI of the Android bridge but without JNI, so it links
//! into a Swift app as a static library / XCFramework. All calls take and return
//! UTF-8 JSON via owned C strings; the caller must free every returned pointer
//! with `vela_ffi_free_string`.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::ffi::{c_char, c_uchar, CStr, CString};

use vela_core::{calculate_password_strength, PasswordStrength, VaultStore};
use vela_crypto::{aead, kdf, kem, shamir};

const VAULT_KEY_CONTEXT: &str = "vela vault encryption v1";
const CHUNK_KEY_CONTEXT: &str = "vela chunk key v1";

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
    rms_b64: String,
    vault_json: String,
}
#[derive(Serialize, Deserialize)]
struct EncryptVaultResponse {
    ciphertext_b64: String,
}

#[derive(Deserialize)]
struct DecryptVaultRequest {
    rms_b64: String,
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

#[derive(Serialize)]
struct IdentityRotateShareKeyResponse {
    share_ek_b64: String,
    sealed_b64: String,
}

#[derive(Serialize)]
struct IdentityOkResponse {
    ok: bool,
}

#[derive(Deserialize)]
struct WebSessionChunkKeysRequest {
    rms_b64: String,
}
#[derive(Serialize)]
struct WebSessionChunkKeysResponse {
    /// `chunk_id → base64(32-byte key)` for the chunks a read-write web session
    /// is granted. The RMS itself never leaves the approver (audit D-2).
    chunk_keys: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct EncryptChunkRequest {
    rms_b64: String,
    chunk_id: String,
    vault_json: String,
}
#[derive(Deserialize)]
struct DecryptChunkRequest {
    rms_b64: String,
    chunk_id: String,
    ciphertext_b64: String,
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
    rms_b64: String,
    threshold: u8,
    n: u8,
}
#[derive(Serialize, Deserialize)]
struct SplitRecoveryResponse {
    /// One base64 Shamir share per `[x, y_0..y_31]` blob.
    shares_b64: Vec<String>,
}

#[derive(Deserialize)]
struct CombineRecoveryRequest {
    shares_b64: Vec<String>,
}
#[derive(Serialize, Deserialize)]
struct CombineRecoveryResponse {
    rms_b64: String,
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
    string_to_ptr(&vela_crypto::verification::enrollment_verification_code(code_str))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_password_strength_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| {
        let req: PasswordStrengthRequest = serde_json::from_str(c_str(request_json)?)?;
        Ok(PasswordStrengthResponse {
            strength: calculate_password_strength(&req.password),
        })
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_encrypt_vault_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| encrypt_vault_json(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_decrypt_vault_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| decrypt_vault_json(c_str(request_json)?))
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
    json_result(|| {
        identity_import_impl(raw_slice(seal_key, seal_key_len)?, c_str(request_json)?)
    })
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

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_identity_forget_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| identity_forget_impl(c_str(request_json)?))
}

#[no_mangle]
pub extern "C" fn vela_ffi_identity_forget_all() -> *mut c_char {
    vela_crypto::identity::forget_all();
    json_result(|| Ok(IdentityOkResponse { ok: true }))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_web_session_chunk_keys_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| web_session_chunk_keys_json(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_encrypt_vault_chunk_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| encrypt_vault_chunk_json(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_decrypt_vault_chunk_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| decrypt_vault_chunk_json(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_decrypt_rms_capsule_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| decrypt_rms_capsule_json(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_decrypt_enrollment_package_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| decrypt_enrollment_package_json(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_split_recovery_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| split_recovery_json(c_str(request_json)?))
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_combine_recovery_json(request_json: *const c_char) -> *mut c_char {
    json_result(|| combine_recovery_json(c_str(request_json)?))
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

fn encrypt_vault_json(request_json: &str) -> FfiResult<EncryptVaultResponse> {
    let req: EncryptVaultRequest = serde_json::from_str(request_json)?;
    let rms = decode_rms(&req.rms_b64)?;
    // Validate the payload really is a vault before sealing it.
    let _: VaultStore = serde_json::from_str(&req.vault_json)?;
    let key = kdf::derive(VAULT_KEY_CONTEXT, &rms);
    let ciphertext = aead::encrypt(key.as_bytes(), req.vault_json.as_bytes())?;
    Ok(EncryptVaultResponse {
        ciphertext_b64: B64.encode(ciphertext),
    })
}

fn decrypt_vault_json(request_json: &str) -> FfiResult<DecryptVaultResponse> {
    let req: DecryptVaultRequest = serde_json::from_str(request_json)?;
    let rms = decode_rms(&req.rms_b64)?;
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
fn chunk_key(rms: &[u8; 32], chunk_id: &str) -> [u8; 32] {
    let context = format!("{} || {:?}", CHUNK_KEY_CONTEXT, chunk_id.as_bytes());
    *kdf::derive(&context, rms).as_bytes()
}

/// Derive the per-chunk vault keys handed to a read-write web session, so the
/// approver can seal those instead of the RMS (audit D-2).
fn web_session_chunk_keys_json(request_json: &str) -> FfiResult<WebSessionChunkKeysResponse> {
    let req: WebSessionChunkKeysRequest = serde_json::from_str(request_json)?;
    let rms = decode_rms(&req.rms_b64)?;
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

fn identity_open_share_impl(request_json: &str) -> FfiResult<OpenShareResponse> {
    let req: IdentityOpenShareRequest = serde_json::from_str(request_json)?;
    let capsule = B64.decode(req.capsule_b64.as_bytes())?;
    let plaintext = vela_crypto::identity::with_identity(req.handle, |identity| {
        identity.open_share(&capsule)
    })?;
    Ok(OpenShareResponse {
        item_json: String::from_utf8(plaintext)?,
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

fn encrypt_vault_chunk_json(request_json: &str) -> FfiResult<EncryptVaultResponse> {
    let req: EncryptChunkRequest = serde_json::from_str(request_json)?;
    let rms = decode_rms(&req.rms_b64)?;
    let _: VaultStore = serde_json::from_str(&req.vault_json)?;
    let key = chunk_key(&rms, &req.chunk_id);
    let ciphertext = aead::encrypt(&key, req.vault_json.as_bytes())?;
    Ok(EncryptVaultResponse {
        ciphertext_b64: B64.encode(ciphertext),
    })
}

fn decrypt_vault_chunk_json(request_json: &str) -> FfiResult<DecryptVaultResponse> {
    let req: DecryptChunkRequest = serde_json::from_str(request_json)?;
    let rms = decode_rms(&req.rms_b64)?;
    let ciphertext = B64.decode(req.ciphertext_b64.as_bytes())?;
    let key = chunk_key(&rms, &req.chunk_id);
    let plaintext = aead::decrypt(&key, &ciphertext)?;
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

fn decrypt_enrollment_package_json(request_json: &str) -> FfiResult<DecryptEnrollmentPackageResponse> {
    let req: DecryptEnrollmentPackageRequest = serde_json::from_str(request_json)?;
    let key = decode_key32(&req.key_b64, "enrollment package key")?;
    let ciphertext = B64.decode(req.ciphertext_b64.as_bytes())?;
    let plaintext = aead::decrypt(&key, &ciphertext)?;
    Ok(DecryptEnrollmentPackageResponse {
        plaintext: String::from_utf8(plaintext.to_vec())?,
    })
}

fn split_recovery_json(request_json: &str) -> FfiResult<SplitRecoveryResponse> {
    let req: SplitRecoveryRequest = serde_json::from_str(request_json)?;
    let rms = decode_rms(&req.rms_b64)?;
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
    let secret = shamir::reconstruct(&shares, 32)?;
    Ok(CombineRecoveryResponse {
        rms_b64: B64.encode(secret),
    })
}

fn decode_rms(b64: &str) -> FfiResult<[u8; 32]> {
    let bytes = B64.decode(b64.as_bytes())?;
    if bytes.len() != 32 {
        return Err("RMS must be 32 bytes".into());
    }
    let mut rms = [0u8; 32];
    rms.copy_from_slice(&bytes);
    Ok(rms)
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
        let s = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
        unsafe { vela_ffi_free_string(ptr) };
        s
    }

    #[test]
    fn version_is_reported() {
        let ptr = vela_ffi_version();
        let s = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
        unsafe { vela_ffi_free_string(ptr) };
        assert!(s.starts_with("vela-apple-bridge/"));
    }

    #[test]
    fn password_strength_returns_json() {
        let out = call(vela_ffi_password_strength_json, r#"{"password":"Abcdefgh123!"}"#);
        assert!(out.contains("score"));
    }

    #[test]
    fn vault_encrypt_decrypt_round_trips() {
        let rms = B64.encode([7u8; 32]);
        let vault_json = r#"{"items":[],"tombstones":[]}"#;
        let enc = call(
            vela_ffi_encrypt_vault_json,
            &serde_json::json!({"rms_b64": rms, "vault_json": vault_json}).to_string(),
        );
        let enc: EncryptVaultResponse = serde_json::from_str(&enc).unwrap();
        let dec = call(
            vela_ffi_decrypt_vault_json,
            &serde_json::json!({"rms_b64": rms, "ciphertext_b64": enc.ciphertext_b64}).to_string(),
        );
        let dec: DecryptVaultResponse = serde_json::from_str(&dec).unwrap();
        assert_eq!(dec.vault_json, vault_json);
    }

    #[test]
    fn wrong_rms_does_not_decrypt() {
        let vault_json = r#"{"items":[],"tombstones":[]}"#;
        let enc = call(
            vela_ffi_encrypt_vault_json,
            &serde_json::json!({"rms_b64": B64.encode([1u8;32]), "vault_json": vault_json}).to_string(),
        );
        let enc: EncryptVaultResponse = serde_json::from_str(&enc).unwrap();
        let dec = call(
            vela_ffi_decrypt_vault_json,
            &serde_json::json!({"rms_b64": B64.encode([2u8;32]), "ciphertext_b64": enc.ciphertext_b64}).to_string(),
        );
        assert!(dec.contains("error"), "wrong RMS must fail: {dec}");
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
            assert!(!created.contains(forbidden), "response leaks {forbidden}: {created}");
        }
        let created: serde_json::Value = serde_json::from_str(&created).unwrap();
        assert_eq!(
            B64.decode(created["hybrid_ek_b64"].as_str().unwrap()).unwrap().len(),
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
        let open_request =
            serde_json::json!({ "sealed_b64": created["sealed_b64"] }).to_string();
        let request = CString::new(open_request.clone()).unwrap();
        let reopened_ptr = unsafe {
            vela_ffi_identity_open(seal_key.as_ptr(), seal_key.len(), request.as_ptr())
        };
        let reopened = unsafe { CStr::from_ptr(reopened_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { vela_ffi_free_string(reopened_ptr) };
        let reopened: serde_json::Value = serde_json::from_str(&reopened).unwrap();
        assert_eq!(reopened["hybrid_vk_b64"], created["hybrid_vk_b64"]);

        let wrong = [7u8; 32];
        let wrong_ptr =
            unsafe { vela_ffi_identity_open(wrong.as_ptr(), wrong.len(), request.as_ptr()) };
        let wrong_out = unsafe { CStr::from_ptr(wrong_ptr) }.to_string_lossy().into_owned();
        unsafe { vela_ffi_free_string(wrong_ptr) };
        assert!(wrong_out.contains("error"), "wrong seal key must fail: {wrong_out}");

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
        assert!(after.contains("error"), "a forgotten handle cannot sign: {after}");
    }

    #[test]
    fn vault_chunk_round_trips_and_binds_chunk_id() {
        let rms = B64.encode([5u8; 32]);
        let vault_json = r#"{"items":[],"tombstones":[]}"#;
        let enc = call(
            vela_ffi_encrypt_vault_chunk_json,
            &serde_json::json!({"rms_b64": rms, "chunk_id": "vault", "vault_json": vault_json}).to_string(),
        );
        let enc: EncryptVaultResponse = serde_json::from_str(&enc).unwrap();

        let dec = call(
            vela_ffi_decrypt_vault_chunk_json,
            &serde_json::json!({"rms_b64": rms, "chunk_id": "vault", "ciphertext_b64": enc.ciphertext_b64}).to_string(),
        );
        let dec: DecryptVaultResponse = serde_json::from_str(&dec).unwrap();
        assert_eq!(dec.vault_json, vault_json);

        // A different chunk_id derives a different key → must not decrypt.
        let wrong = call(
            vela_ffi_decrypt_vault_chunk_json,
            &serde_json::json!({"rms_b64": rms, "chunk_id": "other", "ciphertext_b64": enc.ciphertext_b64}).to_string(),
        );
        assert!(wrong.contains("error"), "chunk_id must bind the key: {wrong}");
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
        let rms = B64.encode([7u8; 32]);
        let split = call(
            vela_ffi_split_recovery_json,
            &serde_json::json!({"rms_b64": rms, "threshold": 2, "n": 3}).to_string(),
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
        assert_eq!(combined.rms_b64, rms);
    }
}
