//! WebAssembly bridge for the VELA core, used by the ephemeral web vault client
//! (see `EPHEMERAL_WEB_ACCESS_DESIGN.md`).
//!
//! Every exported function takes a JSON request string and returns a JSON
//! response string. On error the response is `{"error": "..."}`. The core logic
//! lives in plain `*_impl` functions so it is exercised by native `cargo test`;
//! the `#[wasm_bindgen]` wrappers only adapt them to the browser ABI.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use vela_core::calculate_password_strength;
use vela_crypto::{aead, kdf, kem};

const CHUNK_KEY_CONTEXT: &str = "vela chunk key v1";

// Argon2id parameters, matching SPEC.md §7.4 (3 iterations, 64 MiB, 4 lanes).
const ARGON2_M_COST_KIB: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;
const ARGON2_SALT_LEN: usize = 16;

// ── Response plumbing ───────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn err_json(msg: &str) -> String {
    serde_json::to_string(&ErrorResponse {
        error: msg.to_string(),
    })
    .unwrap_or_else(|_| "{\"error\":\"serialization failed\"}".to_string())
}

fn respond<T: Serialize>(result: Result<T, String>) -> String {
    match result {
        Ok(value) => serde_json::to_string(&value).unwrap_or_else(|e| err_json(&e.to_string())),
        Err(e) => err_json(&e),
    }
}

// ── DTOs ────────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ShareKeypairResponse {
    share_ek_b64: String,
    share_dk_b64: String,
}

#[derive(Deserialize)]
struct OpenShareRequest {
    share_dk_b64: String,
    capsule_b64: String,
}

#[derive(Serialize)]
struct OpenShareResponse {
    item_json: String,
}

#[derive(Deserialize)]
struct EncryptChunkRequest {
    rms_b64: String,
    chunk_id: String,
    vault_json: String,
}

#[derive(Serialize)]
struct EncryptChunkResponse {
    ciphertext_b64: String,
}

#[derive(Deserialize)]
struct DecryptChunkRequest {
    rms_b64: String,
    chunk_id: String,
    ciphertext_b64: String,
}

#[derive(Serialize)]
struct DecryptChunkResponse {
    vault_json: String,
}

#[derive(Deserialize)]
struct PasswordStrengthRequest {
    password: String,
}

#[derive(Serialize)]
struct PasswordStrengthResponse {
    entropy: f64,
    score: String,
    crack_time: String,
}

#[derive(Deserialize)]
struct Argon2WrapRequest {
    pin: String,
    plaintext_b64: String,
}

#[derive(Serialize)]
struct Argon2WrapResponse {
    blob_b64: String,
}

#[derive(Deserialize)]
struct Argon2UnwrapRequest {
    pin: String,
    blob_b64: String,
}

#[derive(Serialize)]
struct Argon2UnwrapResponse {
    plaintext_b64: String,
}

// ── Helpers ─────────────────────────────────────────────────────────────────────

fn decode_rms(b64: &str) -> Result<[u8; 32], String> {
    let bytes = B64.decode(b64.as_bytes()).map_err(|e| e.to_string())?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "rms must be 32 bytes".to_string())?;
    Ok(arr)
}

/// Per-chunk vault key, byte-identical to the Apple/Android/desktop derivation so
/// chunks written by any client decrypt here: `derive("vela chunk key v1" ||
/// {:?}(chunk_id_bytes), rms)`.
fn chunk_key(rms: &[u8; 32], chunk_id: &str) -> [u8; 32] {
    let context = format!("{} || {:?}", CHUNK_KEY_CONTEXT, chunk_id.as_bytes());
    *kdf::derive(&context, rms).as_bytes()
}

fn argon2_key(pin: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = argon2::Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(32),
    )
    .map_err(|e| e.to_string())?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(pin.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

// ── Core logic (also exercised by native tests) ─────────────────────────────────

fn generate_ephemeral_keypair_impl() -> Result<ShareKeypairResponse, String> {
    let (pk, sk) = kem::generate_keypair();
    Ok(ShareKeypairResponse {
        share_ek_b64: B64.encode(pk.to_bytes()),
        share_dk_b64: B64.encode(sk.to_bytes()),
    })
}

fn open_share_impl(request_json: &str) -> Result<OpenShareResponse, String> {
    let req: OpenShareRequest = serde_json::from_str(request_json).map_err(|e| e.to_string())?;
    let dk_bytes = B64.decode(req.share_dk_b64.as_bytes()).map_err(|e| e.to_string())?;
    let sk = kem::HybridSecretKey::from_bytes(&dk_bytes).map_err(|e| e.to_string())?;
    let capsule = B64.decode(req.capsule_b64.as_bytes()).map_err(|e| e.to_string())?;
    let plaintext = kem::open_share(&sk, &capsule).map_err(|e| e.to_string())?;
    Ok(OpenShareResponse {
        item_json: String::from_utf8(plaintext).map_err(|e| e.to_string())?,
    })
}

fn encrypt_vault_chunk_impl(request_json: &str) -> Result<EncryptChunkResponse, String> {
    let req: EncryptChunkRequest = serde_json::from_str(request_json).map_err(|e| e.to_string())?;
    let rms = decode_rms(&req.rms_b64)?;
    let key = chunk_key(&rms, &req.chunk_id);
    let ciphertext = aead::encrypt(&key, req.vault_json.as_bytes()).map_err(|e| e.to_string())?;
    Ok(EncryptChunkResponse {
        ciphertext_b64: B64.encode(ciphertext),
    })
}

fn decrypt_vault_chunk_impl(request_json: &str) -> Result<DecryptChunkResponse, String> {
    let req: DecryptChunkRequest = serde_json::from_str(request_json).map_err(|e| e.to_string())?;
    let rms = decode_rms(&req.rms_b64)?;
    let ciphertext = B64.decode(req.ciphertext_b64.as_bytes()).map_err(|e| e.to_string())?;
    let key = chunk_key(&rms, &req.chunk_id);
    let plaintext = aead::decrypt(&key, &ciphertext).map_err(|e| e.to_string())?;
    Ok(DecryptChunkResponse {
        vault_json: String::from_utf8(plaintext.to_vec()).map_err(|e| e.to_string())?,
    })
}

fn password_strength_impl(request_json: &str) -> Result<PasswordStrengthResponse, String> {
    let req: PasswordStrengthRequest =
        serde_json::from_str(request_json).map_err(|e| e.to_string())?;
    let s = calculate_password_strength(&req.password);
    Ok(PasswordStrengthResponse {
        entropy: s.entropy,
        score: s.score,
        crack_time: s.crack_time,
    })
}

/// Wrap `plaintext` (e.g. the RMS + ephemeral signing key for RW reload survival,
/// §8.1) under an Argon2id(PIN) key. Output blob = `salt(16) ‖ XChaCha20-Poly1305`.
fn argon2_wrap_impl(request_json: &str) -> Result<Argon2WrapResponse, String> {
    let req: Argon2WrapRequest = serde_json::from_str(request_json).map_err(|e| e.to_string())?;
    let plaintext = B64.decode(req.plaintext_b64.as_bytes()).map_err(|e| e.to_string())?;
    let mut salt = [0u8; ARGON2_SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| e.to_string())?;
    let key = argon2_key(&req.pin, &salt)?;
    let ciphertext = aead::encrypt(&key, &plaintext).map_err(|e| e.to_string())?;
    let mut blob = Vec::with_capacity(ARGON2_SALT_LEN + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&ciphertext);
    Ok(Argon2WrapResponse {
        blob_b64: B64.encode(blob),
    })
}

fn argon2_unwrap_impl(request_json: &str) -> Result<Argon2UnwrapResponse, String> {
    let req: Argon2UnwrapRequest = serde_json::from_str(request_json).map_err(|e| e.to_string())?;
    let blob = B64.decode(req.blob_b64.as_bytes()).map_err(|e| e.to_string())?;
    if blob.len() <= ARGON2_SALT_LEN {
        return Err("argon2 blob too short".to_string());
    }
    let (salt, ciphertext) = blob.split_at(ARGON2_SALT_LEN);
    let key = argon2_key(&req.pin, salt)?;
    let plaintext = aead::decrypt(&key, ciphertext).map_err(|e| e.to_string())?;
    Ok(Argon2UnwrapResponse {
        plaintext_b64: B64.encode(plaintext.as_slice()),
    })
}

// ── wasm-bindgen exports ────────────────────────────────────────────────────────

/// Bridge version string.
#[wasm_bindgen]
pub fn vela_wasm_version() -> String {
    concat!("vela-wasm-bridge/", env!("CARGO_PKG_VERSION")).to_string()
}

/// Generate a fresh ephemeral hybrid keypair → `{ share_ek_b64, share_dk_b64 }`.
/// The public half goes in the linking QR; the secret half stays in WASM memory.
#[wasm_bindgen]
pub fn generate_ephemeral_keypair() -> String {
    respond(generate_ephemeral_keypair_impl())
}

/// Open a KEM-sealed capsule (RW RMS capsule or RO snapshot) with our ephemeral
/// secret key. Request `{ share_dk_b64, capsule_b64 }` → `{ item_json }`.
#[wasm_bindgen]
pub fn open_share_json(request_json: &str) -> String {
    respond(open_share_impl(request_json))
}

/// Encrypt a vault chunk. Request `{ rms_b64, chunk_id, vault_json }` → `{ ciphertext_b64 }`.
#[wasm_bindgen]
pub fn encrypt_vault_chunk_json(request_json: &str) -> String {
    respond(encrypt_vault_chunk_impl(request_json))
}

/// Decrypt a vault chunk. Request `{ rms_b64, chunk_id, ciphertext_b64 }` → `{ vault_json }`.
#[wasm_bindgen]
pub fn decrypt_vault_chunk_json(request_json: &str) -> String {
    respond(decrypt_vault_chunk_impl(request_json))
}

/// Password strength. Request `{ password }` → `{ entropy, score, crack_time }`.
#[wasm_bindgen]
pub fn password_strength_json(request_json: &str) -> String {
    respond(password_strength_impl(request_json))
}

/// Argon2id-wrap arbitrary bytes under a PIN (RW reload survival, §8.1).
/// Request `{ pin, plaintext_b64 }` → `{ blob_b64 }`.
#[wasm_bindgen]
pub fn argon2_wrap_json(request_json: &str) -> String {
    respond(argon2_wrap_impl(request_json))
}

/// Argon2id-unwrap a blob produced by [`argon2_wrap_json`].
/// Request `{ pin, blob_b64 }` → `{ plaintext_b64 }`.
#[wasm_bindgen]
pub fn argon2_unwrap_json(request_json: &str) -> String {
    respond(argon2_unwrap_impl(request_json))
}

// ── Tests (native) ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn field(json: &str, key: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        v.get(key)
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn keypair_and_open_share_roundtrip() {
        // Generate an ephemeral keypair in "web" form.
        let kp = generate_ephemeral_keypair();
        let share_ek_b64 = field(&kp, "share_ek_b64");
        let share_dk_b64 = field(&kp, "share_dk_b64");
        assert_eq!(B64.decode(&share_ek_b64).unwrap().len(), 1600);

        // Approver seals a payload to the ephemeral public key (core API).
        let ek = kem::HybridPublicKey::from_bytes(&B64.decode(&share_ek_b64).unwrap()).unwrap();
        let item = b"{\"name\":\"GitHub\",\"password\":\"hunter2\"}";
        let capsule = kem::seal_share(&ek, item).unwrap();

        // Web client opens it.
        let req = serde_json::json!({
            "share_dk_b64": share_dk_b64,
            "capsule_b64": B64.encode(&capsule),
        })
        .to_string();
        let out = open_share_json(&req);
        assert_eq!(field(&out, "item_json").as_bytes(), item);
    }

    #[test]
    fn chunk_encrypt_decrypt_roundtrip() {
        let rms_b64 = B64.encode([7u8; 32]);
        let vault_json = "{\"items\":[],\"tombstones\":[]}";
        let enc = encrypt_vault_chunk_json(
            &serde_json::json!({ "rms_b64": rms_b64, "chunk_id": "vault-data-0", "vault_json": vault_json }).to_string(),
        );
        let ct = field(&enc, "ciphertext_b64");
        assert!(!ct.is_empty());
        let dec = decrypt_vault_chunk_json(
            &serde_json::json!({ "rms_b64": rms_b64, "chunk_id": "vault-data-0", "ciphertext_b64": ct }).to_string(),
        );
        assert_eq!(field(&dec, "vault_json"), vault_json);
    }

    #[test]
    fn chunk_wrong_id_fails() {
        let rms_b64 = B64.encode([7u8; 32]);
        let enc = encrypt_vault_chunk_json(
            &serde_json::json!({ "rms_b64": rms_b64, "chunk_id": "vault-data-0", "vault_json": "{}" }).to_string(),
        );
        let ct = field(&enc, "ciphertext_b64");
        let dec = decrypt_vault_chunk_json(
            &serde_json::json!({ "rms_b64": rms_b64, "chunk_id": "vault-data-9", "ciphertext_b64": ct }).to_string(),
        );
        assert!(!field(&dec, "error").is_empty());
    }

    #[test]
    fn argon2_wrap_unwrap_roundtrip() {
        let secret = B64.encode([42u8; 96]); // e.g. RMS(32) + ephemeral sk material
        let wrapped = argon2_wrap_json(
            &serde_json::json!({ "pin": "correct horse", "plaintext_b64": secret }).to_string(),
        );
        let blob = field(&wrapped, "blob_b64");
        assert!(!blob.is_empty());

        let unwrapped = argon2_unwrap_json(
            &serde_json::json!({ "pin": "correct horse", "blob_b64": blob }).to_string(),
        );
        assert_eq!(field(&unwrapped, "plaintext_b64"), secret);
    }

    #[test]
    fn argon2_wrong_pin_fails() {
        let secret = B64.encode([1u8; 32]);
        let wrapped = argon2_wrap_json(
            &serde_json::json!({ "pin": "right-pin-123", "plaintext_b64": secret }).to_string(),
        );
        let blob = field(&wrapped, "blob_b64");
        let out = argon2_unwrap_json(
            &serde_json::json!({ "pin": "wrong-pin-123", "blob_b64": blob }).to_string(),
        );
        assert!(!field(&out, "error").is_empty());
    }

    #[test]
    fn password_strength_scores() {
        let out = password_strength_json(&serde_json::json!({ "password": "Tr0ub4dor&3xtra!" }).to_string());
        assert!(!field(&out, "score").is_empty());
    }
}
