//! Android-facing FFI bridge for the shared VELA Rust core.
//!
//! The exported ABI deliberately uses UTF-8 JSON and owned byte buffers so the
//! Kotlin/JNI layer can remain thin and stable while the Rust internals evolve.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use jni::objects::{JObject, JString};
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
use vela_crypto::signing;

const VAULT_KEY_CONTEXT: &str = "vela vault encryption v1";
const CHUNK_KEY_CONTEXT: &str = "vela chunk key v1";

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
    rms_b64: String,
    vault_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptVaultResponse {
    ciphertext_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecryptVaultRequest {
    rms_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecryptVaultResponse {
    vault_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptChunkRequest {
    rms_b64: String,
    chunk_id: String,
    vault_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecryptChunkRequest {
    rms_b64: String,
    chunk_id: String,
    ciphertext_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GenerateIdentityResponse {
    hybrid_ek_b64: String,
    hybrid_vk_b64: String,
    hybrid_sk_b64: String,
    share_ek_b64: String,
    share_dk_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ShareKeypairResponse {
    share_ek_b64: String,
    share_dk_b64: String,
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
struct OpenShareRequest {
    share_dk_b64: String,
    capsule_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenShareResponse {
    item_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthSignatureRequest {
    hybrid_sk_b64: String,
    challenge_b64: String,
    device_id: String,
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
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| {
        encrypt_vault_json(request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeDecryptVaultJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| {
        decrypt_vault_json(request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeEncryptVaultChunkJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| {
        encrypt_vault_chunk_json(request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeDecryptVaultChunkJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| {
        decrypt_vault_chunk_json(request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeGenerateServerIdentityJson(
    mut env: JNIEnv,
    _object: JObject,
) -> jstring {
    let response = match generate_server_identity() {
        Ok(value) => {
            serde_json::to_string(&value).unwrap_or_else(|error| error_json(&error.to_string()))
        }
        Err(error) => error_json(&error.to_string()),
    };
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeGenerateShareKeypairJson(
    mut env: JNIEnv,
    _object: JObject,
) -> jstring {
    let response = match generate_share_keypair() {
        Ok(value) => {
            serde_json::to_string(&value).unwrap_or_else(|error| error_json(&error.to_string()))
        }
        Err(error) => error_json(&error.to_string()),
    };
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeCreateAuthSignatureJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| {
        create_auth_signature_json(request)
    });
    jni_string(&mut env, &response)
}

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeDecryptRmsCapsuleJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| {
        decrypt_rms_capsule_json(request)
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

#[no_mangle]
pub extern "system" fn Java_com_vela_android_core_NativeVelaCore_nativeOpenShareJson(
    mut env: JNIEnv,
    _object: JObject,
    request_json: JString,
) -> jstring {
    let response = jni_json_result(&mut env, request_json, |request| open_share_json(request));
    jni_string(&mut env, &response)
}

#[no_mangle]
pub unsafe extern "C" fn vela_bridge_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn vela_bridge_free_bytes(buffer: VelaByteBuffer) {
    if !buffer.ptr.is_null() && buffer.len > 0 {
        drop(Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.len));
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

fn chunk_key(rms: &[u8; 32], chunk_id: &str) -> [u8; 32] {
    let context = format!("{} || {:?}", CHUNK_KEY_CONTEXT, chunk_id.as_bytes());
    *kdf::derive(&context, rms).as_bytes()
}

fn encrypt_vault_chunk_json(request_json: &str) -> anyhow_like::Result<EncryptVaultResponse> {
    let request: EncryptChunkRequest = serde_json::from_str(request_json)?;
    let rms = decode_rms(&request.rms_b64)?;
    let _: VaultStore = serde_json::from_str(&request.vault_json)?;
    let key = chunk_key(&rms, &request.chunk_id);
    let ciphertext = aead::encrypt(&key, request.vault_json.as_bytes())?;
    Ok(EncryptVaultResponse {
        ciphertext_b64: B64.encode(ciphertext),
    })
}

fn decrypt_vault_chunk_json(request_json: &str) -> anyhow_like::Result<DecryptVaultResponse> {
    let request: DecryptChunkRequest = serde_json::from_str(request_json)?;
    let rms = decode_rms(&request.rms_b64)?;
    let ciphertext = B64.decode(request.ciphertext_b64.as_bytes())?;
    let key = chunk_key(&rms, &request.chunk_id);
    let plaintext = aead::decrypt(&key, &ciphertext)?;
    let vault_json = String::from_utf8(plaintext.to_vec())?;
    Ok(DecryptVaultResponse { vault_json })
}

fn generate_server_identity() -> anyhow_like::Result<GenerateIdentityResponse> {
    // `hybrid_ek` must be a real KEM public key, not filler bytes — it is
    // signed and transmitted to the server as this device's identity. The
    // matching secret key is intentionally not persisted: nothing in the
    // current protocol encapsulates under hybrid_ek (the RMS capsule uses a
    // symmetric transfer_key instead), so a public key with no stored
    // private counterpart is inert, not insecure.
    let (hybrid_ek_pk, _unused_hybrid_ek_sk) = kem::generate_keypair();
    let hybrid_ek = hybrid_ek_pk.to_bytes();

    let (signing_vk, signing_sk) = signing::generate_keypair()?;
    let hybrid_vk = signing_vk.to_bytes().to_vec();
    let hybrid_sk = signing_sk.into_bytes();

    let (share_pk, share_sk) = kem::generate_keypair();

    Ok(GenerateIdentityResponse {
        hybrid_ek_b64: B64.encode(hybrid_ek),
        hybrid_vk_b64: B64.encode(hybrid_vk),
        hybrid_sk_b64: B64.encode(hybrid_sk),
        share_ek_b64: B64.encode(share_pk.to_bytes()),
        share_dk_b64: B64.encode(share_sk.to_bytes()),
    })
}

fn generate_share_keypair() -> anyhow_like::Result<ShareKeypairResponse> {
    let (share_pk, share_sk) = kem::generate_keypair();
    Ok(ShareKeypairResponse {
        share_ek_b64: B64.encode(share_pk.to_bytes()),
        share_dk_b64: B64.encode(share_sk.to_bytes()),
    })
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

fn open_share_json(request_json: &str) -> anyhow_like::Result<OpenShareResponse> {
    let req: OpenShareRequest = serde_json::from_str(request_json)?;
    let dk_bytes = B64.decode(req.share_dk_b64.as_bytes())?;
    let sk = kem::HybridSecretKey::from_bytes(&dk_bytes)?;
    let capsule = B64.decode(req.capsule_b64.as_bytes())?;
    let plaintext = kem::open_share(&sk, &capsule)?;
    Ok(OpenShareResponse {
        item_json: String::from_utf8(plaintext)?,
    })
}

fn create_auth_signature_json(request_json: &str) -> anyhow_like::Result<AuthSignatureResponse> {
    let request: AuthSignatureRequest = serde_json::from_str(request_json)?;
    let hybrid_sk = B64.decode(request.hybrid_sk_b64.as_bytes())?;
    let challenge = B64.decode(request.challenge_b64.as_bytes())?;
    create_auth_signature(&hybrid_sk, &challenge, &request.device_id)
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

fn create_auth_signature(
    hybrid_sk: &[u8],
    challenge: &[u8],
    device_id: &str,
) -> anyhow_like::Result<AuthSignatureResponse> {
    let sk = signing::HybridSigningKey::from_bytes(hybrid_sk)?;
    let message = signing::auth_message(device_id, challenge);
    let signature = signing::sign(&sk, &message)?;
    Ok(AuthSignatureResponse {
        signature: B64.encode(signature.to_bytes()),
    })
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

fn string_to_ptr(value: &str) -> *mut c_char {
    CString::new(value)
        .unwrap_or_else(|_| CString::new("").expect("empty CString"))
        .into_raw()
}

fn vec_to_buffer(mut bytes: Vec<u8>) -> VelaByteBuffer {
    let buffer = VelaByteBuffer {
        ptr: bytes.as_mut_ptr(),
        len: bytes.len(),
    };
    std::mem::forget(bytes);
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
    fn password_strength_bridge_returns_json() {
        let request = CString::new(r#"{"password":"Abcdefgh123!"}"#).unwrap();
        let ptr = unsafe { vela_password_strength_json(request.as_ptr()) };
        let json = unsafe { CString::from_raw(ptr) }.into_string().unwrap();
        assert!(json.contains("\"score\":\"strong\""));
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
    fn generate_server_identity_returns_server_sized_keys() {
        let identity = generate_server_identity().unwrap();
        assert_eq!(B64.decode(identity.hybrid_ek_b64).unwrap().len(), 1600);
        assert_eq!(B64.decode(identity.hybrid_vk_b64).unwrap().len(), 2624);
    }
}
