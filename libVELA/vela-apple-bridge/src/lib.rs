//! Apple (iOS/macOS) C-ABI bridge over the shared VELA Rust core.
//!
//! Mirrors the stable C ABI of the Android bridge but without JNI, so it links
//! into a Swift app as a static library / XCFramework. All calls take and return
//! UTF-8 JSON via owned C strings; the caller must free every returned pointer
//! with `vela_ffi_free_string`.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::ffi::{c_char, CStr, CString};

use vela_core::{calculate_password_strength, PasswordStrength, VaultStore};
use vela_crypto::{aead, kdf, signing};

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

#[derive(Serialize, Deserialize)]
struct GenerateIdentityResponse {
    hybrid_ek_b64: String,
    hybrid_vk_b64: String,
    hybrid_sk_b64: String,
}

#[derive(Deserialize)]
struct AuthSignatureRequest {
    hybrid_sk_b64: String,
    challenge_b64: String,
    device_id: String,
}
#[derive(Serialize, Deserialize)]
struct AuthSignatureResponse {
    signature_b64: String,
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

/// Generate a fresh device identity (hybrid EK/VK/SK, base64). Free the result.
#[no_mangle]
pub extern "C" fn vela_ffi_generate_identity_json() -> *mut c_char {
    json_result(generate_identity)
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string or null.
#[no_mangle]
pub unsafe extern "C" fn vela_ffi_create_auth_signature_json(
    request_json: *const c_char,
) -> *mut c_char {
    json_result(|| create_auth_signature_json(c_str(request_json)?))
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

fn generate_identity() -> FfiResult<GenerateIdentityResponse> {
    let mut hybrid_ek = vec![0u8; 1600];
    getrandom::getrandom(&mut hybrid_ek)
        .map_err(|e| format!("OS random source unavailable: {e}"))?;
    let (vk, sk) = signing::generate_keypair()?;
    Ok(GenerateIdentityResponse {
        hybrid_ek_b64: B64.encode(hybrid_ek),
        hybrid_vk_b64: B64.encode(vk.to_bytes()),
        hybrid_sk_b64: B64.encode(sk.into_bytes()),
    })
}

fn create_auth_signature_json(request_json: &str) -> FfiResult<AuthSignatureResponse> {
    let req: AuthSignatureRequest = serde_json::from_str(request_json)?;
    let sk_bytes = B64.decode(req.hybrid_sk_b64.as_bytes())?;
    let challenge = B64.decode(req.challenge_b64.as_bytes())?;
    let sk = signing::HybridSigningKey::from_bytes(&sk_bytes)?;
    let message = signing::auth_message(&req.device_id, &challenge);
    let signature = signing::sign(&sk, &message)?;
    Ok(AuthSignatureResponse {
        signature_b64: B64.encode(signature.to_bytes()),
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

    #[test]
    fn generate_identity_and_sign_roundtrip() {
        let id_ptr = vela_ffi_generate_identity_json();
        let id = unsafe { CStr::from_ptr(id_ptr) }.to_string_lossy().into_owned();
        unsafe { vela_ffi_free_string(id_ptr) };
        let id: GenerateIdentityResponse = serde_json::from_str(&id).unwrap();
        assert_eq!(B64.decode(&id.hybrid_ek_b64).unwrap().len(), 1600);

        let sig = call(
            vela_ffi_create_auth_signature_json,
            &serde_json::json!({
                "hybrid_sk_b64": id.hybrid_sk_b64,
                "challenge_b64": B64.encode([9u8; 32]),
                "device_id": "device-123"
            })
            .to_string(),
        );
        let sig: AuthSignatureResponse = serde_json::from_str(&sig).unwrap();
        assert!(!sig.signature_b64.is_empty());
    }
}
