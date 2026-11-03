//! WebAssembly bridge for the VELA core, used by the ephemeral web vault client
//! (see `EPHEMERAL_WEB_ACCESS_DESIGN.md`).
//!
//! Every exported function takes a JSON request string and returns a JSON
//! response string. On error the response is `{"error": "..."}`. The core logic
//! lives in plain `*_impl` functions so it is exercised by native `cargo test`;
//! the `#[wasm_bindgen]` wrappers only adapt them to the browser ABI.

use std::cell::RefCell;
use std::collections::BTreeMap;

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
struct OpenLinkRequest {
    /// The link key from the URL fragment (base64url, no padding).
    link_key_b64: String,
    /// Optional passphrase for a protected link.
    #[serde(default)]
    passphrase: Option<String>,
    /// Argon2id salt (base64 standard), present only for passphrase links.
    #[serde(default)]
    salt_b64: Option<String>,
    ciphertext_b64: String,
}

#[derive(Serialize)]
struct OpenLinkResponse {
    secret_json: String,
}

#[derive(Deserialize)]
struct EncryptChunkRequest {
    /// The per-chunk key granted for this chunk id — **not** the RMS. A web
    /// session never receives the root seed (audit D-2).
    chunk_key_b64: String,
    vault_json: String,
    chunk_id: String,
    /// The clock this chunk will be stored under, bound into the ciphertext so
    /// the server cannot replay an older revision (audit C-2).
    lamport_clock: i64,
    /// Current account key epoch. Absent callers and explicit epoch 1 both use
    /// the fleet's legacy chunk AAD; epoch binding begins at epoch 2.
    #[serde(default)]
    epoch: Option<u64>,
}

#[derive(Serialize)]
struct EncryptChunkResponse {
    ciphertext_b64: String,
}

#[derive(Deserialize)]
struct AdmittedDecryptChunkRequest {
    /// The per-chunk key granted for this chunk id — **not** the RMS.
    chunk_key_b64: String,
    ciphertext_b64: String,
    /// Chunk id and the revision the server claimed for it. Both are bound into
    /// the ciphertext's AAD, so a mislabelled or replayed blob fails to open.
    chunk_id: String,
    lamport_clock: i64,
    /// Vault key epoch the server's `GET /vault/sync` manifest reports. A
    /// malicious server controls this integer; the tab's own floor is what
    /// makes it meaningful (see `AdmissionState`).
    key_epoch: i64,
}

#[derive(Serialize)]
struct AdmittedDecryptChunkResponse {
    vault_json: String,
    /// Revision the verified policy admitted, so the caller records exactly
    /// what passed instead of the manifest entry it asked for.
    lamport_clock: i64,
}

/// Per-tab admission state.
///
/// The web client has **no durable store**: this lives in WASM memory and dies
/// with the page (a reload needs a fresh grant, and starts a fresh first
/// contact). The mobile bridges keep the same facts in Keystore/Keychain-backed
/// settings and pass them in; the browser has no such store, so the state lives
/// beside the policy instead of in the (server-facing) caller.
#[derive(Default)]
struct AdmissionState {
    /// First positive epoch this tab admitted. Every later download must use
    /// exactly this epoch (`plan_sync_epoch_match`); there is no adoption path
    /// on the web, so a rotation forces a re-grant.
    epoch_floor: Option<i64>,
    /// Highest revision this tab admitted for each chunk id.
    last_seen: BTreeMap<String, i64>,
}

thread_local! {
    static ADMISSION: RefCell<AdmissionState> = RefCell::new(AdmissionState::default());
}

fn admitted_epoch_floor() -> Option<i64> {
    ADMISSION.with(|state| state.borrow().epoch_floor)
}

fn admitted_last_seen(chunk_id: &str) -> Option<i64> {
    ADMISSION.with(|state| state.borrow().last_seen.get(chunk_id).copied())
}

/// Record the facts of an admission that already passed every gate. Callers
/// must only call this after the plaintext was produced and decoded, so a
/// failed attempt never moves the floor or the per-chunk baseline.
fn record_admission(epoch: i64, chunk_id: &str, lamport_clock: i64) {
    ADMISSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.epoch_floor.is_none() {
            state.epoch_floor = Some(epoch);
        }
        state
            .last_seen
            .entry(chunk_id.to_string())
            .and_modify(|seen| *seen = (*seen).max(lamport_clock))
            .or_insert(lamport_clock);
    });
}

#[cfg(test)]
fn reset_admission_state() {
    ADMISSION.with(|state| *state.borrow_mut() = AdmissionState::default());
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
    let req: AuthSignatureRequest =
        serde_json::from_str(request_json).map_err(|e| e.to_string())?;
    let sk_bytes = B64
        .decode(req.sk_b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let sk = signing::HybridSigningKey::from_bytes(&sk_bytes).map_err(|e| e.to_string())?;
    let challenge = B64
        .decode(req.challenge_b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let message = signing::auth_message(&req.device_id, &challenge);
    let signature = signing::sign(&sk, &message).map_err(|e| e.to_string())?;
    Ok(AuthSignatureResponse {
        signature_b64: B64.encode(signature.to_bytes()),
    })
}

fn open_share_impl(request_json: &str) -> Result<OpenShareResponse, String> {
    let req: OpenShareRequest = serde_json::from_str(request_json).map_err(|e| e.to_string())?;
    let dk_bytes = B64
        .decode(req.share_dk_b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let sk = kem::HybridSecretKey::from_bytes(&dk_bytes).map_err(|e| e.to_string())?;
    let capsule = B64
        .decode(req.capsule_b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let plaintext = kem::open_share(&sk, &capsule).map_err(|e| e.to_string())?;
    Ok(OpenShareResponse {
        item_json: String::from_utf8(plaintext).map_err(|e| e.to_string())?,
    })
}

/// Open a one-off link payload. The key came in the URL fragment, so the server
/// never had it; a passphrase link additionally needs the passphrase.
fn open_link_impl(request_json: &str) -> Result<OpenLinkResponse, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let req: OpenLinkRequest = serde_json::from_str(request_json).map_err(|e| e.to_string())?;
    let key_bytes = URL_SAFE_NO_PAD
        .decode(req.link_key_b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let link_key: [u8; vela_crypto::link::LINK_KEY_LEN] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "link key must be 32 bytes".to_string())?;
    let salt = match req.salt_b64.as_deref() {
        Some(salt) if !salt.is_empty() => B64.decode(salt.as_bytes()).map_err(|e| e.to_string())?,
        _ => Vec::new(),
    };
    let ciphertext = B64
        .decode(req.ciphertext_b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let passphrase = req
        .passphrase
        .as_deref()
        .filter(|p| !p.is_empty())
        .map(|p| p.as_bytes());
    let plaintext = vela_crypto::link::open_link(&link_key, passphrase, &salt, &ciphertext)
        .map_err(|e| e.to_string())?;
    Ok(OpenLinkResponse {
        secret_json: String::from_utf8(plaintext.to_vec()).map_err(|e| e.to_string())?,
    })
}

fn encrypt_vault_chunk_impl(request_json: &str) -> Result<EncryptChunkResponse, String> {
    let req: EncryptChunkRequest = serde_json::from_str(request_json).map_err(|e| e.to_string())?;
    let key = decode_key(&req.chunk_key_b64)?;
    let ciphertext = vela_crypto::rekey::seal_fleet_chunk(
        &key,
        req.vault_json.as_bytes(),
        req.epoch.unwrap_or(1),
        &req.chunk_id,
        req.lamport_clock,
    )
    .map_err(|e| e.to_string())?;
    Ok(EncryptChunkResponse {
        ciphertext_b64: B64.encode(ciphertext),
    })
}

/// Production web download admission (U-27, mirroring the mobile bridges).
///
/// The server supplies `lamport_clock`, `key_epoch` and the blob; neither is
/// trusted on its own. This function:
///
/// 1. refuses any blob without the self-describing sealed header, because the
///    pre-C-2 unsealed shape binds neither the chunk id nor the revision — an
///    open would make the rollback decision below meaningless;
/// 2. pins the first admitted epoch as this tab's floor and thereafter requires
///    exact agreement through the verified `plan_sync_epoch_match` (a lower
///    epoch is a downgrade, a higher one an unadopted rotation: both refuse);
/// 3. performs the real AEAD open, so `aad_binding_verified` below is a fact
///    about successful Rust decryption, never a JSON boolean; and
/// 4. runs the verified `plan_chunk_download` rollback decision against the
///    highest revision this tab already admitted for the chunk.
///
/// Only after all four does plaintext leave this function. The floor and the
/// per-chunk baselines are tab-local (WASM memory); there is no durable state.
fn decrypt_admitted_vault_chunk_impl(
    request_json: &str,
) -> Result<AdmittedDecryptChunkResponse, String> {
    let req: AdmittedDecryptChunkRequest =
        serde_json::from_str(request_json).map_err(|e| e.to_string())?;
    let ciphertext = B64
        .decode(req.ciphertext_b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let key = decode_key(&req.chunk_key_b64)?;

    // A sealed blob is the only shape whose opening checks the labels below.
    if !aead::is_sealed(&ciphertext) {
        return Err(format!(
            "chunk \"{}\" uses the old unsealed format, which does not bind it to its chunk \
             or revision; open the vault in an app to migrate it",
            req.chunk_id
        ));
    }

    // First contact pins the tab's floor; nothing in a web grant authenticates
    // the epoch (the approver sends `key_epoch` to the server, not to us, and
    // the capsule is sealed to a public key the server also holds), so the
    // first manifest epoch is server-asserted — U-27's residual risk.
    let floor = admitted_epoch_floor();
    let local_epoch = floor.unwrap_or(req.key_epoch);
    if !vela_sync_policy::plan_sync_epoch_match(vela_sync_policy::SyncEpochFacts {
        server_epoch: req.key_epoch,
        local_epoch,
    }) {
        return Err(match floor {
            Some(seen) if req.key_epoch < seen => format!(
                "the server offered vault key epoch {} but this page already used epoch {}; \
                 refusing the downgrade",
                req.key_epoch, seen
            ),
            Some(seen) => format!(
                "the vault key epoch changed to {} while this page was open (it was {}); \
                 reload this page and approve access again from your app",
                req.key_epoch, seen
            ),
            None => format!(
                "the server offered an invalid vault key epoch {}",
                req.key_epoch
            ),
        });
    }

    let epoch =
        u64::try_from(req.key_epoch).map_err(|_| "vault key epoch must be positive".to_string())?;
    let plaintext = vela_crypto::rekey::open_fleet_chunk(
        &key,
        &ciphertext,
        epoch,
        &req.chunk_id,
        req.lamport_clock,
    )
    .map_err(|e| {
        format!(
            "could not authenticate chunk \"{}\" at epoch {} revision {}: {e}",
            req.chunk_id, req.key_epoch, req.lamport_clock
        )
    })?;

    let last_seen = admitted_last_seen(&req.chunk_id);
    match vela_sync_policy::plan_chunk_download(vela_sync_policy::ChunkDownloadFacts {
        server_lamport: req.lamport_clock,
        last_seen_lamport: last_seen,
        // Only a sealed blob that opened under its epoch/chunk/revision AAD
        // reaches this line; the request cannot set this fact.
        aad_binding_verified: true,
        key_epoch_positive: req.key_epoch >= vela_sync_policy::INITIAL_EPOCH,
    }) {
        vela_sync_policy::ChunkDownloadDecision::Accept(permit) => {
            let vault_json = String::from_utf8(plaintext.to_vec()).map_err(|e| e.to_string())?;
            record_admission(req.key_epoch, &req.chunk_id, permit.lamport());
            Ok(AdmittedDecryptChunkResponse {
                vault_json,
                lamport_clock: permit.lamport(),
            })
        }
        vela_sync_policy::ChunkDownloadDecision::Reject => Err(format!(
            "the server returned revision {} of chunk \"{}\" but this page already admitted \
             revision {}; refusing the rollback",
            req.lamport_clock,
            req.chunk_id,
            last_seen.map_or_else(|| "none".to_string(), |seen| seen.to_string())
        )),
    }
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

/// Open a one-off link payload. Request
/// `{ link_key_b64, passphrase?, salt_b64?, ciphertext_b64 }` → `{ secret_json }`.
/// The key travels in the URL fragment; the server only ever had ciphertext.
#[wasm_bindgen]
pub fn open_link_json(request_json: &str) -> String {
    respond(open_link_impl(request_json))
}

/// Encrypt a vault chunk with the granted per-chunk key.
/// Request `{ chunk_key_b64, vault_json, chunk_id, lamport_clock, epoch? }`
/// → `{ ciphertext_b64 }`.
#[wasm_bindgen]
pub fn encrypt_vault_chunk_json(request_json: &str) -> String {
    respond(encrypt_vault_chunk_impl(request_json))
}

/// Admit and decrypt a vault chunk on the production download path.
/// Request `{ chunk_key_b64, ciphertext_b64, chunk_id, lamport_clock, key_epoch }`
/// → `{ vault_json, lamport_clock }`.
///
/// The older `decrypt_vault_chunk_json` export is gone: it had no admission
/// decision and no production caller after `webVELA/src/main.ts` switched here.
#[wasm_bindgen]
pub fn decrypt_admitted_vault_chunk_json(request_json: &str) -> String {
    respond(decrypt_admitted_vault_chunk_impl(request_json))
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
    fn open_link_roundtrip_matches_the_sender_seal() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let link_key = vela_crypto::link::generate_link_key();
        let salt = vela_crypto::link::generate_salt();
        let secret = b"{\"name\":\"GitHub\",\"password\":\"hunter2\"}";

        let ciphertext = vela_crypto::link::seal_link(&link_key, None, &salt, secret).unwrap();
        let req = serde_json::json!({
            "link_key_b64": URL_SAFE_NO_PAD.encode(link_key),
            "ciphertext_b64": B64.encode(&ciphertext),
        })
        .to_string();
        assert_eq!(
            field(&open_link_json(&req), "secret_json").as_bytes(),
            secret
        );

        // A passphrase link needs both halves.
        let protected =
            vela_crypto::link::seal_link(&link_key, Some(b"correct horse"), &salt, secret).unwrap();
        let req = serde_json::json!({
            "link_key_b64": URL_SAFE_NO_PAD.encode(link_key),
            "passphrase": "correct horse",
            "salt_b64": B64.encode(&salt),
            "ciphertext_b64": B64.encode(&protected),
        })
        .to_string();
        assert_eq!(
            field(&open_link_json(&req), "secret_json").as_bytes(),
            secret
        );

        let missing_passphrase = serde_json::json!({
            "link_key_b64": URL_SAFE_NO_PAD.encode(link_key),
            "salt_b64": B64.encode(&salt),
            "ciphertext_b64": B64.encode(&protected),
        })
        .to_string();
        assert!(open_link_json(&missing_passphrase).contains("error"));
    }

    fn number(json: &str, key: &str) -> i64 {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        v.get(key).and_then(|x| x.as_i64()).unwrap_or_default()
    }

    fn chunk_key(chunk_id: &str) -> [u8; 32] {
        *kdf::chunk_key(&[7u8; 32], chunk_id.as_bytes()).as_bytes()
    }

    fn seal(
        key: &[u8; 32],
        chunk_id: &str,
        lamport_clock: i64,
        epoch: u64,
        vault_json: &str,
    ) -> String {
        B64.encode(
            vela_crypto::rekey::seal_fleet_chunk(
                key,
                vault_json.as_bytes(),
                epoch,
                chunk_id,
                lamport_clock,
            )
            .unwrap(),
        )
    }

    fn admit(
        key: &[u8; 32],
        ciphertext_b64: &str,
        chunk_id: &str,
        lamport_clock: i64,
        key_epoch: i64,
    ) -> String {
        decrypt_admitted_vault_chunk_json(
            &serde_json::json!({
                "chunk_key_b64": B64.encode(key),
                "ciphertext_b64": ciphertext_b64,
                "chunk_id": chunk_id,
                "lamport_clock": lamport_clock,
                "key_epoch": key_epoch,
            })
            .to_string(),
        )
    }

    #[test]
    fn admitted_download_roundtrips_and_returns_the_admitted_clock() {
        reset_admission_state();
        let key = chunk_key("vault-data-000000");
        let vault_json = "{\"items\":[],\"tombstones\":[]}";
        let ct = seal(&key, "vault-data-000000", 4, 1, vault_json);
        let dec = admit(&key, &ct, "vault-data-000000", 4, 1);
        assert_eq!(field(&dec, "vault_json"), vault_json);
        assert_eq!(number(&dec, "lamport_clock"), 4);
    }

    #[test]
    fn admitted_download_refuses_unsealed_legacy_blobs() {
        reset_admission_state();
        let key = chunk_key("vault-data-000000");
        // The pre-C-2 shape: a fresh nonce and no AAD at all, so the server can
        // relabel it as any chunk or revision.
        let unsealed = B64.encode(aead::encrypt(&key, b"{\"items\":[]}").unwrap());
        let refused = admit(&key, &unsealed, "vault-data-000000", 4, 1);
        let error = field(&refused, "error");
        assert!(
            error.contains("unsealed"),
            "unsealed blob must be refused: {refused}"
        );
        assert!(field(&refused, "vault_json").is_empty());
    }

    #[test]
    fn admitted_download_refuses_epoch_below_the_tab_floor() {
        reset_admission_state();
        let key = chunk_key("vault-data-000000");
        let at_epoch_3 = seal(&key, "vault-data-000000", 4, 3, "{\"items\":[]}");
        assert_eq!(
            field(
                &admit(&key, &at_epoch_3, "vault-data-000000", 4, 3),
                "vault_json"
            ),
            "{\"items\":[]}"
        );

        // Once the tab has admitted epoch 3, an epoch-1 blob — the shape with
        // no epoch binding — must not be accepted even though it opens.
        let at_epoch_1 = seal(&key, "vault-data-000000", 5, 1, "{\"items\":[\"old\"]}");
        let downgraded = admit(&key, &at_epoch_1, "vault-data-000000", 5, 1);
        let error = field(&downgraded, "error");
        assert!(
            error.contains("epoch 1") && error.contains("downgrade"),
            "epoch downgrade must be refused: {downgraded}"
        );
        assert!(field(&downgraded, "vault_json").is_empty());

        // The floor did not move: epoch 3 still admits.
        let later = seal(&key, "vault-data-000000", 6, 3, "{\"items\":[\"new\"]}");
        assert_eq!(
            field(
                &admit(&key, &later, "vault-data-000000", 6, 3),
                "vault_json"
            ),
            "{\"items\":[\"new\"]}"
        );
    }

    #[test]
    fn admitted_download_refuses_an_epoch_change_after_the_pin() {
        reset_admission_state();
        let key = chunk_key("vault-data-000000");
        let at_epoch_3 = seal(&key, "vault-data-000000", 4, 3, "{}");
        assert_eq!(
            field(
                &admit(&key, &at_epoch_3, "vault-data-000000", 4, 3),
                "vault_json"
            ),
            "{}"
        );

        // There is no epoch-adoption path in the browser: a rotation needs a
        // fresh grant, so a higher epoch is refused rather than trusted.
        let at_epoch_4 = seal(&key, "vault-data-000000", 5, 4, "{}");
        let rotated = admit(&key, &at_epoch_4, "vault-data-000000", 5, 4);
        let error = field(&rotated, "error");
        assert!(
            error.contains("changed") && error.contains("reload"),
            "epoch change must be refused: {rotated}"
        );
    }

    #[test]
    fn admitted_download_refuses_rollback_and_allows_equal_redelivery() {
        reset_admission_state();
        let key = chunk_key("vault-data-000000");
        let latest = seal(&key, "vault-data-000000", 7, 2, "{\"items\":[\"latest\"]}");
        assert_eq!(
            field(
                &admit(&key, &latest, "vault-data-000000", 7, 2),
                "vault_json"
            ),
            "{\"items\":[\"latest\"]}"
        );

        let older = seal(&key, "vault-data-000000", 3, 2, "{\"items\":[\"old\"]}");
        let rollback = admit(&key, &older, "vault-data-000000", 3, 2);
        let error = field(&rollback, "error");
        assert!(
            error.contains("rollback") && error.contains("revision 7"),
            "older revision must be refused: {rollback}"
        );
        assert!(field(&rollback, "vault_json").is_empty());

        // The policy admits an equal clock (redelivery of the same revision).
        assert_eq!(
            field(
                &admit(&key, &latest, "vault-data-000000", 7, 2),
                "vault_json"
            ),
            "{\"items\":[\"latest\"]}"
        );
    }

    #[test]
    fn admitted_download_refuses_nonpositive_epochs() {
        reset_admission_state();
        let key = chunk_key("vault-data-000000");
        let ct = seal(&key, "vault-data-000000", 4, 1, "{}");
        for epoch in [0, -1] {
            let refused = admit(&key, &ct, "vault-data-000000", 4, epoch);
            assert!(
                field(&refused, "error").contains("invalid vault key epoch"),
                "epoch {epoch} must be refused: {refused}"
            );
        }
    }

    #[test]
    fn admitted_download_binds_the_chunk_id() {
        reset_admission_state();
        let key_a = chunk_key("vault-data-000000");
        let key_b = chunk_key("vault-data-000009");
        let ct = seal(&key_a, "vault-data-000000", 4, 2, "{\"items\":[]}");
        let refused = admit(&key_b, &ct, "vault-data-000009", 4, 2);
        assert!(
            field(&refused, "error").contains("could not authenticate"),
            "a blob relabelled as another chunk must fail: {refused}"
        );
    }

    /// A failed first contact must not pin the floor: the server cannot use a
    /// probe to lower it, and the correct epoch still works afterwards.
    #[test]
    fn admitted_download_does_not_pin_a_failed_first_attempt() {
        reset_admission_state();
        let key = chunk_key("vault-data-000000");
        let at_epoch_3 = seal(&key, "vault-data-000000", 4, 3, "{\"items\":[]}");
        let wrong_claim = admit(&key, &at_epoch_3, "vault-data-000000", 4, 2);
        assert!(
            field(&wrong_claim, "error").contains("could not authenticate"),
            "the blob is epoch-3 bound: {wrong_claim}"
        );
        assert_eq!(
            field(
                &admit(&key, &at_epoch_3, "vault-data-000000", 4, 3),
                "vault_json"
            ),
            "{\"items\":[]}"
        );
    }

    #[test]
    fn epoch_chunk_roundtrip_rejects_wrong_or_legacy_epoch() {
        reset_admission_state();
        let key = chunk_key("vault-data-000000");
        let key_b64 = B64.encode(key);
        let request = |epoch: Option<u64>| {
            serde_json::json!({
                "chunk_key_b64": key_b64,
                "vault_json": "{}",
                "chunk_id": "vault-data-000000",
                "lamport_clock": 4,
                "epoch": epoch,
            })
            .to_string()
        };
        let ct = field(
            &encrypt_vault_chunk_json(&request(Some(2))),
            "ciphertext_b64",
        );
        assert_eq!(
            field(&admit(&key, &ct, "vault-data-000000", 4, 2), "vault_json"),
            "{}"
        );

        // An epoch-2 blob is bound to its epoch; the epoch-1 AAD cannot open it.
        reset_admission_state();
        let wrong_epoch = admit(&key, &ct, "vault-data-000000", 4, 1);
        assert!(
            field(&wrong_epoch, "error").contains("could not authenticate"),
            "epoch binding must reject a wrong claimed epoch: {wrong_epoch}"
        );

        // The crypto layer keeps the epoch-1 shape readable at epoch 1 only;
        // above it the legacy fallback is refused. The bridge gate rejects the
        // downgrade before this point, so assert the underlying rule directly.
        let legacy = field(&encrypt_vault_chunk_json(&request(None)), "ciphertext_b64");
        let legacy_bytes = B64.decode(&legacy).unwrap();
        let err =
            vela_crypto::rekey::open_fleet_chunk(&key, &legacy_bytes, 2, "vault-data-000000", 4)
                .unwrap_err()
                .to_string();
        assert!(
            err.contains("legacy chunk ciphertext is forbidden"),
            "epoch-2 open must refuse the legacy shape: {err}"
        );
    }

    #[test]
    fn epoch_one_uses_the_fleet_legacy_chunk_format() {
        let key = [29u8; 32];
        let key_b64 = B64.encode(key);
        let chunk_id = "vault-data-000000";
        let lamport_clock = 7;
        let request = serde_json::json!({
            "chunk_key_b64": key_b64,
            "vault_json": "{\"items\":[]}",
            "chunk_id": chunk_id,
            "lamport_clock": lamport_clock,
            "epoch": 1,
        })
        .to_string();

        let web_ciphertext = B64
            .decode(field(&encrypt_vault_chunk_json(&request), "ciphertext_b64"))
            .unwrap();
        let opened_by_legacy_client =
            aead::open_vault_chunk(&key, &web_ciphertext, chunk_id, lamport_clock).unwrap();
        assert_eq!(opened_by_legacy_client.as_slice(), b"{\"items\":[]}");

        let legacy_ciphertext = aead::seal(
            &key,
            b"{\"items\":[]}",
            &aead::vault_chunk_aad(chunk_id, lamport_clock),
        )
        .unwrap();
        reset_admission_state();
        let opened_by_web = admit(
            &key,
            &B64.encode(legacy_ciphertext),
            chunk_id,
            lamport_clock,
            1,
        );
        assert_eq!(field(&opened_by_web, "vault_json"), "{\"items\":[]}");

        let invalid = serde_json::json!({
            "chunk_key_b64": key_b64,
            "vault_json": "{}",
            "chunk_id": chunk_id,
            "lamport_clock": lamport_clock,
            "epoch": 0,
        })
        .to_string();
        assert!(encrypt_vault_chunk_json(&invalid).contains("epoch must be positive"));
        // A first contact with a nonpositive epoch has no floor yet, so the
        // epoch policy itself refuses it.
        reset_admission_state();
        let invalid_open = admit(
            &key,
            &B64.encode(web_ciphertext),
            chunk_id,
            lamport_clock,
            0,
        );
        assert!(invalid_open.contains("invalid vault key epoch"));
    }

    /// The granted keys are per chunk id: a key for one chunk cannot open
    /// another, so a session only ever reaches the chunks it was granted.
    #[test]
    fn chunk_key_from_another_chunk_fails() {
        reset_admission_state();
        let rms = [7u8; 32];
        let key_a = *kdf::chunk_key(&rms, b"vault-data-000000").as_bytes();
        let key_b = *kdf::chunk_key(&rms, b"vault-data-000009").as_bytes();
        let ct = seal(&key_a, "vault-data-000000", 4, 1, "{}");
        let dec = admit(&key_b, &ct, "vault-data-000009", 4, 1);
        assert!(field(&dec, "error").contains("could not authenticate"));
    }

    /// The web bridge must decrypt exactly what the other clients wrote: the
    /// approver derives these keys with `kdf::web_session_chunk_keys`.
    #[test]
    fn granted_keys_match_the_approver_derivation() {
        let rms = [7u8; 32];
        for (id, key) in kdf::web_session_chunk_keys(&rms) {
            assert_eq!(
                key.as_bytes(),
                kdf::chunk_key(&rms, id.as_bytes()).as_bytes()
            );
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
                let message =
                    signing::auth_message(device_id, &B64.decode(&challenge_b64).unwrap());
                assert!(signing::verify(&vk, &message, &sig).unwrap());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn password_strength_scores() {
        let out = password_strength_json(
            &serde_json::json!({ "password": "Tr0ub4dor&3xtra!" }).to_string(),
        );
        assert!(!field(&out, "score").is_empty());
    }
}
