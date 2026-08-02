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
use vela_crypto::{aead, kem, signing};


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

#[derive(Serialize)]
struct SigningKeypairResponse {
    vk_b64: String,
    sk_b64: String,
}

#[derive(Deserialize)]
struct AuthSignatureRequest {
    sk_b64: String,
    device_id: String,
    challenge_b64: String,
}

#[derive(Serialize)]
struct AuthSignatureResponse {
    signature_b64: String,
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
    /// The per-chunk key granted for this chunk id — **not** the RMS. A web
    /// session never receives the root seed (audit D-2).
    chunk_key_b64: String,
    vault_json: String,
}

#[derive(Serialize)]
struct EncryptChunkResponse {
    ciphertext_b64: String,
}

#[derive(Deserialize)]
struct DecryptChunkRequest {
    /// The per-chunk key granted for this chunk id — **not** the RMS.
    chunk_key_b64: String,
    ciphertext_b64: String,
    /// Chunk id and the revision the server claimed for it. Verified for sealed
    /// ciphertexts, ignored for legacy ones (audit C-2, rollout step 2).
    #[serde(default)]
    chunk_id: String,
    #[serde(default)]
    lamport_clock: i64,
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

// ── Helpers ─────────────────────────────────────────────────────────────────────

/// Decode a 32-byte key handed to the browser in the grant capsule.
///
/// There is deliberately no `decode_rms` here: the browser is given the
/// individual per-chunk vault keys the approver derived, never the RMS they come
/// from, so no other key in the hierarchy is reachable from what a leaked
/// capsule contains (audit D-2).
fn decode_key(b64: &str) -> Result<[u8; 32], String> {
    let bytes = B64.decode(b64.as_bytes()).map_err(|e| e.to_string())?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "chunk key must be 32 bytes".to_string())?;
    Ok(arr)
}

// ── Core logic (also exercised by native tests) ─────────────────────────────────

fn generate_ephemeral_keypair_impl() -> Result<ShareKeypairResponse, String> {
    let (pk, sk) = kem::generate_keypair();
    Ok(ShareKeypairResponse {
        share_ek_b64: B64.encode(pk.to_bytes()),
        share_dk_b64: B64.encode(sk.to_bytes()),
    })
}

/// Generate a fresh ephemeral hybrid signing keypair (ML-DSA-87 + Ed25519). Used
/// to authenticate an RW web session at `POST /web-session/:id/token`. The `vk`
/// goes in the link QR (`web_vk`); the `sk` stays in WASM memory.
fn generate_signing_keypair_impl() -> Result<SigningKeypairResponse, String> {
    let (vk, sk) = signing::generate_keypair().map_err(|e| e.to_string())?;
    Ok(SigningKeypairResponse {
        vk_b64: B64.encode(vk.to_bytes()),
        sk_b64: B64.encode(sk.into_bytes()),
    })
}

/// Sign a server auth challenge with our ephemeral signing key, binding it to the
/// session id (used as `device_id`). Request `{ sk_b64, device_id, challenge_b64 }`.
fn create_auth_signature_impl(request_json: &str) -> Result<AuthSignatureResponse, String> {
    let req: AuthSignatureRequest = serde_json::from_str(request_json).map_err(|e| e.to_string())?;
    let sk_bytes = B64.decode(req.sk_b64.as_bytes()).map_err(|e| e.to_string())?;
    let sk = signing::HybridSigningKey::from_bytes(&sk_bytes).map_err(|e| e.to_string())?;
    let challenge = B64.decode(req.challenge_b64.as_bytes()).map_err(|e| e.to_string())?;
    let message = signing::auth_message(&req.device_id, &challenge);
    let signature = signing::sign(&sk, &message).map_err(|e| e.to_string())?;
    Ok(AuthSignatureResponse {
        signature_b64: B64.encode(signature.to_bytes()),
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
    let key = decode_key(&req.chunk_key_b64)?;
    let ciphertext = aead::encrypt(&key, req.vault_json.as_bytes()).map_err(|e| e.to_string())?;
    Ok(EncryptChunkResponse {
        ciphertext_b64: B64.encode(ciphertext),
    })
}

fn decrypt_vault_chunk_impl(request_json: &str) -> Result<DecryptChunkResponse, String> {
    let req: DecryptChunkRequest = serde_json::from_str(request_json).map_err(|e| e.to_string())?;
    let ciphertext = B64.decode(req.ciphertext_b64.as_bytes()).map_err(|e| e.to_string())?;
    let key = decode_key(&req.chunk_key_b64)?;
    let plaintext =
        aead::open_vault_chunk(&key, &ciphertext, &req.chunk_id, req.lamport_clock)
            .map_err(|e| e.to_string())?;
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

/// Generate an ephemeral signing keypair → `{ vk_b64, sk_b64 }`. The `vk` is sent
/// as `web_vk` in the link; the `sk` authenticates the RW token request.
#[wasm_bindgen]
pub fn generate_signing_keypair() -> String {
    respond(generate_signing_keypair_impl())
}

/// Sign a server auth challenge for an RW web session.
/// Request `{ sk_b64, device_id, challenge_b64 }` → `{ signature_b64 }`.
#[wasm_bindgen]
pub fn create_auth_signature_json(request_json: &str) -> String {
    respond(create_auth_signature_impl(request_json))
}

/// Open a KEM-sealed capsule (RW chunk-key capsule or RO snapshot) with our ephemeral
/// secret key. Request `{ share_dk_b64, capsule_b64 }` → `{ item_json }`.
#[wasm_bindgen]
pub fn open_share_json(request_json: &str) -> String {
    respond(open_share_impl(request_json))
}

/// Encrypt a vault chunk with the granted per-chunk key.
/// Request `{ chunk_key_b64, vault_json }` → `{ ciphertext_b64 }`.
#[wasm_bindgen]
pub fn encrypt_vault_chunk_json(request_json: &str) -> String {
    respond(encrypt_vault_chunk_impl(request_json))
}

/// Decrypt a vault chunk with the granted per-chunk key.
/// Request `{ chunk_key_b64, ciphertext_b64 }` → `{ vault_json }`.
#[wasm_bindgen]
pub fn decrypt_vault_chunk_json(request_json: &str) -> String {
    respond(decrypt_vault_chunk_impl(request_json))
}

/// Password strength. Request `{ password }` → `{ entropy, score, crack_time }`.
#[wasm_bindgen]
pub fn password_strength_json(request_json: &str) -> String {
    respond(password_strength_impl(request_json))
}

// ── Tests (native) ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vela_crypto::kdf;

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
        let key_b64 = B64.encode(kdf::chunk_key(&[7u8; 32], b"vault-data-000000").as_bytes());
        let vault_json = "{\"items\":[],\"tombstones\":[]}";
        let enc = encrypt_vault_chunk_json(
            &serde_json::json!({ "chunk_key_b64": key_b64, "vault_json": vault_json }).to_string(),
        );
        let ct = field(&enc, "ciphertext_b64");
        assert!(!ct.is_empty());
        let dec = decrypt_vault_chunk_json(
            &serde_json::json!({ "chunk_key_b64": key_b64, "ciphertext_b64": ct }).to_string(),
        );
        assert_eq!(field(&dec, "vault_json"), vault_json);
    }

    /// The granted keys are per chunk id: a key for one chunk cannot open
    /// another, so a session only ever reaches the chunks it was granted.
    #[test]
    fn chunk_key_from_another_chunk_fails() {
        let rms = [7u8; 32];
        let enc = encrypt_vault_chunk_json(
            &serde_json::json!({
                "chunk_key_b64": B64.encode(kdf::chunk_key(&rms, b"vault-data-000000").as_bytes()),
                "vault_json": "{}",
            })
            .to_string(),
        );
        let ct = field(&enc, "ciphertext_b64");
        let dec = decrypt_vault_chunk_json(
            &serde_json::json!({
                "chunk_key_b64": B64.encode(kdf::chunk_key(&rms, b"vault-data-000009").as_bytes()),
                "ciphertext_b64": ct,
            })
            .to_string(),
        );
        assert!(!field(&dec, "error").is_empty());
    }

    /// The web bridge must decrypt exactly what the other clients wrote: the
    /// approver derives these keys with `kdf::web_session_chunk_keys`.
    #[test]
    fn granted_keys_match_the_approver_derivation() {
        let rms = [7u8; 32];
        for (id, key) in kdf::web_session_chunk_keys(&rms) {
            assert_eq!(key.as_bytes(), kdf::chunk_key(&rms, id.as_bytes()).as_bytes());
        }
    }



    #[test]
    fn signing_keypair_sign_and_verify() {
        // ML-DSA-87 keygen + sign need a large stack; mirror the server test harness.
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let kp = generate_signing_keypair();
                let vk_b64 = field(&kp, "vk_b64");
                let sk_b64 = field(&kp, "sk_b64");
                assert_eq!(B64.decode(&vk_b64).unwrap().len(), 2624);

                let device_id = "11111111-1111-1111-1111-111111111111";
                let challenge_b64 = B64.encode([3u8; 32]);
                let sig_resp = create_auth_signature_json(
                    &serde_json::json!({
                        "sk_b64": sk_b64,
                        "device_id": device_id,
                        "challenge_b64": challenge_b64,
                    })
                    .to_string(),
                );
                let sig_b64 = field(&sig_resp, "signature_b64");

                // Verify with the core, exactly as the server would.
                let vk_bytes: [u8; signing::HYBRID_VK_LEN] =
                    B64.decode(&vk_b64).unwrap().try_into().unwrap();
                let vk = signing::HybridVerifyingKey::from_bytes(&vk_bytes).unwrap();
                let sig_bytes: [u8; signing::HYBRID_SIG_LEN] =
                    B64.decode(&sig_b64).unwrap().try_into().unwrap();
                let sig = signing::HybridSignature::from_bytes(&sig_bytes).unwrap();
                let message = signing::auth_message(device_id, &B64.decode(&challenge_b64).unwrap());
                assert!(signing::verify(&vk, &message, &sig).unwrap());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn password_strength_scores() {
        let out = password_strength_json(&serde_json::json!({ "password": "Tr0ub4dor&3xtra!" }).to_string());
        assert!(!field(&out, "score").is_empty());
    }
}
