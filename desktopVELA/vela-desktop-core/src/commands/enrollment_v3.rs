//! Enrollment v3, the client side of audit P-1.
//!
//! In v2 the primary generated the joining device's whole identity and shipped
//! the private half to it inside the enrollment code, alongside the symmetric
//! key the RMS capsule was sealed under. Reading the code was possession of the
//! vault, permanently, because the RMS never rotates.
//!
//! Here the code carries a grant id and a server URL and nothing else. The
//! joining device generates its own keypair, presents only the public half, and
//! the primary seals the RMS to that public key. An intercepted code buys an
//! enrollment *attempt*.
//!
//! # The one invariant this file exists to hold
//!
//! **The joining device computes and displays the fingerprint of its own key,
//! locally, from the keypair it just generated — never a value that arrived over
//! the wire.** [`begin_enrollment_join`] hashes `identity.hybrid_vk` in memory
//! and nothing in the joining path reads a fingerprint from a response. If that
//! ever changed, the user's comparison would degrade from "two devices agree
//! about a key" to "two devices agree about a number", and every binding the
//! server added would stop meaning anything.
//!
//! # Why the primary asks the user to *pick*
//!
//! "Do these match?" fails open: yes is the habitual answer. The primary shows
//! the real fingerprint among indistinguishable decoys and the user picks the
//! one their other device displays, so not looking fails (n-1)/n of the time.
//! Two things make that real, and both live here rather than in any UI:
//!
//! * the choices are computed **once** per claim and cached, so polling cannot
//!   reshuffle them, and
//! * a wrong pick **destroys the pending enrollment** ([`confirm_enrollment`]).
//!   Left retryable, an n-way choice becomes a 1-in-1 by exhaustion.
//!
//! The correct answer never crosses this module's boundary: callers get the
//! shuffled list, and confirmation is by value.

use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
    Engine as _,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::api::ApiClient;
use crate::audit::{record_audit_event, AuditAction};
use crate::crypto;
use crate::AppState;
use vela_crypto::verification::{enrollment_fingerprint, enrollment_fingerprint_choices};

pub const ENROLLMENT_CODE_V3_PREFIX: &str = "VELA-ENROLL:v3:";

/// How many fingerprints the primary offers.
///
/// Four puts blind tapping at a 75% failure rate while staying glanceable —
/// above five people start matching the first group instead of reading, which
/// quietly undoes the point. [`enrollment_fingerprint_choices`] clamps to its
/// own bounds regardless.
pub const FINGERPRINT_CHOICE_COUNT: usize = 4;

/// The entire payload of a v3 code. Compare with v2's, which carried a device
/// id, a full keypair including the private half, the RMS transfer key, and the
/// server URL.
#[derive(Serialize, Deserialize)]
struct EnrollmentGrantLocator {
    v: u8,
    /// Server URL.
    u: String,
    /// Grant id.
    g: String,
}

// ── Primary side ────────────────────────────────────────────────────────────

/// What the primary is holding between opening a grant and completing it.
///
/// `fingerprint` is the correct answer and deliberately stays in here: it is
/// compared against the user's pick inside [`confirm_enrollment`] and is never
/// returned to a caller.
pub struct PendingEnrollment {
    pub grant_id: String,
    hybrid_ek: Vec<u8>,
    hybrid_vk: Vec<u8>,
    fingerprint: String,
    choices: Vec<String>,
    device_name: Option<String>,
    device_type: Option<String>,
}

/// A claim, as the primary should render it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimedDevice {
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    /// The real fingerprint among decoys, shuffled. Which one is real is not
    /// said here, and cannot be inferred from the list.
    pub fingerprint_choices: Vec<String>,
    /// True when the OS random source failed and no decoys could be generated.
    /// The list then holds only the real value and the UI must fall back to a
    /// plain side-by-side comparison — a guessable decoy set would look like a
    /// check without being one.
    pub decoys_unavailable: bool,
}

/// A freshly opened grant, ready to be shown as a QR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentInvite {
    pub code: String,
    pub grant_id: String,
    pub expires_in: u64,
}

/// Open a grant and encode it as an enrollment code.
///
/// Unlike v2 this performs no key generation, no capsule, and no enrollment:
/// nothing is created on the account until the user has confirmed a fingerprint.
pub async fn open_enrollment_invite(state: &AppState) -> Result<EnrollmentInvite, String> {
    if !state.is_unlocked() {
        return Err("Vault is locked. Please unlock before enrolling a new device.".to_string());
    }

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url.clone());
    let token = state.get_session_token().ok_or("Not authenticated")?;

    let (grant, new_token) = client
        .open_enrollment_grant(&token)
        .await
        .map_err(|e| format!("Failed to open an enrollment grant: {e}"))?;
    if let Some(t) = new_token {
        state.session.write().set_server_token(t);
    }

    let locator = EnrollmentGrantLocator {
        v: 3,
        u: server_url,
        g: grant.grant_id.clone(),
    };
    let json = serde_json::to_string(&locator).map_err(|e| format!("Serialization error: {e}"))?;
    let code = format!("{ENROLLMENT_CODE_V3_PREFIX}{}", B64URL.encode(json));

    *state.pending_enrollment.write() = None;

    Ok(EnrollmentInvite {
        code,
        grant_id: grant.grant_id,
        expires_in: grant.expires_in,
    })
}

/// Check whether a device has claimed the grant yet.
///
/// Returns `Ok(None)` while nobody has. Once a claim exists the fingerprint
/// choices are built **once** and cached: polling must not reshuffle the list
/// under the user's finger, and re-rolling it would hand a blind tapper repeated
/// attempts at the same question.
pub async fn poll_enrollment_claim(
    state: &AppState,
    grant_id: &str,
) -> Result<Option<ClaimedDevice>, String> {
    if let Some(pending) = state.pending_enrollment.read().as_ref() {
        if pending.grant_id == grant_id {
            return Ok(Some(pending.as_claimed_device()));
        }
    }

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let token = state.get_session_token().ok_or("Not authenticated")?;

    let (claim, new_token) = client
        .get_enrollment_claim(&token, grant_id)
        .await
        .map_err(|e| format!("Failed to read the enrollment claim: {e}"))?;
    if let Some(t) = new_token {
        state.session.write().set_server_token(t);
    }
    let Some(claim) = claim else {
        return Ok(None);
    };

    let hybrid_ek = B64
        .decode(&claim.hybrid_ek)
        .map_err(|_| "Server returned an unreadable device key".to_string())?;
    let hybrid_vk = B64
        .decode(&claim.hybrid_vk)
        .map_err(|_| "Server returned an unreadable device key".to_string())?;

    // Over the key itself, not over anything the joining device said about it.
    let fingerprint = enrollment_fingerprint(&hybrid_vk);
    let choices = enrollment_fingerprint_choices(&fingerprint, FINGERPRINT_CHOICE_COUNT);

    let pending = PendingEnrollment {
        grant_id: grant_id.to_string(),
        hybrid_ek,
        hybrid_vk,
        fingerprint,
        choices,
        device_name: claim.device_name,
        device_type: claim.device_type,
    };
    let view = pending.as_claimed_device();
    *state.pending_enrollment.write() = Some(pending);
    Ok(Some(view))
}

/// Enrol the claimed device, if `chosen` is the fingerprint it is displaying.
///
/// A wrong pick discards the pending enrollment rather than allowing another
/// try. That is the difference between a choice and a formality: with one
/// attempt at n options, confirming without looking fails (n-1)/n of the time;
/// with unlimited attempts it succeeds every time, eventually.
pub async fn confirm_enrollment(
    state: &AppState,
    grant_id: &str,
    chosen: &str,
) -> Result<String, String> {
    if !state.is_unlocked() {
        return Err("Vault is locked. Please unlock before enrolling a new device.".to_string());
    }

    let (hybrid_ek, hybrid_vk) = {
        let mut guard = state.pending_enrollment.write();
        let pending = guard
            .as_ref()
            .filter(|p| p.grant_id == grant_id)
            .ok_or("This enrollment is no longer pending. Please start again.")?;

        if !fingerprints_match(&pending.fingerprint, chosen) {
            // Gone, not retryable.
            *guard = None;
            return Err("That is not the code the other device is showing. \
                        The enrollment has been cancelled — start again and compare carefully."
                .to_string());
        }
        (pending.hybrid_ek.clone(), pending.hybrid_vk.clone())
    };

    let rms: [u8; 32] = {
        let crypto_guard = state.crypto.read();
        let c = crypto_guard.as_ref().ok_or("Vault is locked")?;
        c.rms_as_bytes()
    };
    let crypto_for_keys = crypto::Crypto::new(&rms);

    let own_keys = state
        .store
        .load_identity_keys(&crypto_for_keys)
        .map_err(|e| format!("Failed to load identity keys: {e}"))?
        .ok_or("No identity keys found. Please re-create your vault.")?;
    if own_keys.hybrid_sk.is_empty() {
        return Err("This vault was created before enrollment support was added. \
                    Please re-create the vault to enable device enrollment."
            .to_string());
    }

    // Sealed to the claimed public key, whose private half never left the
    // joining device. In v2 this was a symmetric key carried in the code.
    let rms_capsule = crypto::seal_rms_to_device(&hybrid_ek, &rms)
        .map_err(|e| format!("Failed to seal the vault key to that device: {e}"))?;

    // ML-DSA signing is compute-heavy and stack-hungry.
    let sk_bytes = own_keys.hybrid_sk.clone();
    let (ek, vk, capsule) = (hybrid_ek.clone(), hybrid_vk.clone(), rms_capsule.clone());
    let signature = tokio::task::spawn_blocking(move || {
        crypto::sign_enrollment(&sk_bytes, &ek, &vk, &capsule)
    })
    .await
    .map_err(|e| format!("Thread join error: {e}"))?
    .map_err(|e| format!("Signing failed: {e}"))?;

    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let token = state.get_session_token().ok_or("Not authenticated")?;

    // No key material in this call by design: the server enrols what it stored
    // at claim time, so the key the user just confirmed and the key that gets
    // enrolled are the same object.
    let (device_id, new_token) = client
        .complete_enrollment(
            &token,
            grant_id,
            &B64.encode(&rms_capsule),
            &B64.encode(&signature),
        )
        .await
        .map_err(|e| format!("Enrollment failed: {e}"))?;
    if let Some(t) = new_token {
        state.session.write().set_server_token(t);
    }

    *state.pending_enrollment.write() = None;

    let own_device_id = state.store.load_device_id().unwrap_or_default();
    tracing::info!(
        new_device_id = %device_id,
        enrolled_by = %own_device_id,
        "New device enrolled (v3)"
    );
    record_audit_event(
        state,
        AuditAction::DeviceEnrolled {
            device_id: device_id.clone(),
            enrolling_device_id: Some(own_device_id),
        },
    );

    Ok(device_id)
}

/// Abandon a pending enrollment. The grant expires on its own; this just stops
/// this device from completing it.
pub fn cancel_enrollment(state: &AppState) {
    *state.pending_enrollment.write() = None;
}

impl PendingEnrollment {
    fn as_claimed_device(&self) -> ClaimedDevice {
        ClaimedDevice {
            device_name: self.device_name.clone(),
            device_type: self.device_type.clone(),
            fingerprint_choices: self.choices.clone(),
            decoys_unavailable: self.choices.len() < 2,
        }
    }
}

/// Compare a user's pick against the answer.
///
/// Whitespace differences are the UI's fault, not the user's, so they are
/// ignored; nothing else is. This is not a secret comparison — the choices were
/// all on screen — so a plain equality is honest here.
fn fingerprints_match(actual: &str, chosen: &str) -> bool {
    actual.trim() == chosen.trim()
}

// ── Joining side ────────────────────────────────────────────────────────────

/// The keypair this device generated, held between claiming and enrolling.
///
/// Private halves only exist here and in the identity file written at the very
/// end — they are never sent anywhere, which is the whole change.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PendingJoin {
    #[zeroize(skip)]
    pub grant_id: String,
    #[zeroize(skip)]
    server_url: String,
    #[zeroize(skip)]
    hybrid_ek: Vec<u8>,
    #[zeroize(skip)]
    hybrid_vk: Vec<u8>,
    hybrid_sk: Vec<u8>,
    hybrid_dk: Vec<u8>,
    share_ek: Vec<u8>,
    share_dk: Vec<u8>,
    /// This device's own fingerprint, computed here from `hybrid_vk` above.
    #[zeroize(skip)]
    fingerprint: String,
    /// Filled once the primary has confirmed and the server has enrolled us.
    #[zeroize(skip)]
    device_id: Option<String>,
}

/// What the joining device shows its user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub grant_id: String,
    /// Computed locally from the key this device just generated. The user reads
    /// it off this screen and finds the match on the primary.
    pub fingerprint: String,
    pub server_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinStatus {
    /// The user has not confirmed on the primary yet.
    Waiting,
    Enrolled,
}

/// Whether a code is a v3 one. Both versions are in circulation until old
/// installs age out, and the prefix is the only thing that has to be read to
/// tell them apart.
pub fn is_v3_enrollment_code(code: &str) -> bool {
    code.trim().starts_with(ENROLLMENT_CODE_V3_PREFIX)
}

/// Generate this device's identity, claim the grant with its public half, and
/// return the fingerprint for the user to match.
///
/// The fingerprint returned here is computed from `identity.hybrid_vk` — bytes
/// that were generated in this process moments earlier and have not left it.
/// Nothing in this function reads a fingerprint from the server.
pub async fn begin_enrollment_join(state: &AppState, code: &str) -> Result<JoinRequest, String> {
    let trimmed = code.trim();
    let encoded = trimmed
        .strip_prefix(ENROLLMENT_CODE_V3_PREFIX)
        .ok_or("This is not a v3 enrollment code")?;
    let json = B64URL
        .decode(encoded)
        .map_err(|e| format!("Invalid enrollment code (base64url error): {e}"))?;
    let locator: EnrollmentGrantLocator = serde_json::from_slice(&json)
        .map_err(|e| format!("Invalid enrollment code (JSON error): {e}"))?;
    if locator.v != 3 {
        return Err("Unsupported enrollment code version".to_string());
    }
    if locator.u.is_empty() {
        return Err("Enrollment code names no server".to_string());
    }

    // ML-DSA keygen is stack-heavy; spawn on a blocking thread with enough stack.
    let identity = tokio::task::spawn_blocking(crypto::generate_identity_keypair)
        .await
        .map_err(|e| format!("Thread join error: {e}"))?
        .map_err(|e| format!("Keypair generation failed: {e}"))?;

    let fingerprint = enrollment_fingerprint(&identity.hybrid_vk);

    let client = ApiClient::with_url(locator.u.clone());
    let device_name = crate::audit::get_device_name();
    client
        .claim_enrollment_grant(
            &locator.g,
            &B64.encode(&identity.hybrid_ek),
            &B64.encode(&identity.hybrid_vk),
            &device_name,
            "desktop",
        )
        .await
        .map_err(|e| format!("Could not use this enrollment code: {e}"))?;

    *state.server_url.write() = locator.u.clone();
    *state.pending_join.write() = Some(PendingJoin {
        grant_id: locator.g.clone(),
        server_url: locator.u.clone(),
        hybrid_ek: identity.hybrid_ek.clone(),
        hybrid_vk: identity.hybrid_vk.clone(),
        hybrid_sk: identity.hybrid_sk.clone(),
        hybrid_dk: identity.hybrid_dk.clone(),
        share_ek: identity.share_ek.clone(),
        share_dk: identity.share_dk.clone(),
        fingerprint: fingerprint.clone(),
        device_id: None,
    });

    Ok(JoinRequest {
        grant_id: locator.g,
        fingerprint,
        server_url: locator.u,
    })
}

/// Ask the server whether the primary has confirmed yet.
///
/// Proved by a signature over the grant id under the key this device claimed
/// with — it has no session, since the `device_id` it is asking for is what a
/// session would need.
pub async fn poll_enrollment_join(state: &AppState, grant_id: &str) -> Result<JoinStatus, String> {
    let (server_url, sk, already) = {
        let guard = state.pending_join.read();
        let pending = guard
            .as_ref()
            .filter(|p| p.grant_id == grant_id)
            .ok_or("This device is not waiting on that enrollment code.")?;
        (
            pending.server_url.clone(),
            pending.hybrid_sk.clone(),
            pending.device_id.clone(),
        )
    };
    if already.is_some() {
        return Ok(JoinStatus::Enrolled);
    }

    let gid = grant_id.to_string();
    let signature = tokio::task::spawn_blocking(move || {
        crypto::sign_enrollment_result(&sk, &gid)
    })
    .await
    .map_err(|e| format!("Thread join error: {e}"))?
    .map_err(|e| format!("Signing failed: {e}"))?;

    let client = ApiClient::with_url(server_url);
    let device_id = client
        .collect_enrollment_result(grant_id, &signature)
        .await
        .map_err(|e| format!("Enrollment could not be confirmed: {e}"))?;

    match device_id {
        None => Ok(JoinStatus::Waiting),
        Some(id) => {
            if let Some(pending) = state.pending_join.write().as_mut() {
                if pending.grant_id == grant_id {
                    pending.device_id = Some(id);
                }
            }
            Ok(JoinStatus::Enrolled)
        }
    }
}

/// Finish joining: authenticate, open the capsule sealed to this device, and
/// bring the vault down.
///
/// The capsule is opened with `hybrid_dk`, generated in
/// [`begin_enrollment_join`] and never transmitted. In v2 the equivalent key
/// arrived inside the enrollment code, which is why reading the code was enough
/// to read the vault.
pub async fn finish_enrollment_join(
    state: &AppState,
    grant_id: &str,
    password: String,
) -> Result<(), String> {
    let (server_url, device_id, hybrid_ek, hybrid_vk, hybrid_sk, hybrid_dk, share_ek, share_dk) = {
        let guard = state.pending_join.read();
        let pending = guard
            .as_ref()
            .filter(|p| p.grant_id == grant_id)
            .ok_or("This device is not waiting on that enrollment code.")?;
        let device_id = pending
            .device_id
            .clone()
            .ok_or("This enrollment has not been confirmed on the other device yet.")?;
        (
            pending.server_url.clone(),
            device_id,
            pending.hybrid_ek.clone(),
            pending.hybrid_vk.clone(),
            pending.hybrid_sk.clone(),
            pending.hybrid_dk.clone(),
            pending.share_ek.clone(),
            pending.share_dk.clone(),
        )
    };

    state
        .store
        .save_device_id(&device_id)
        .map_err(|e| format!("Failed to save device ID: {e}"))?;
    *state.server_url.write() = server_url.clone();
    let client = ApiClient::with_url(server_url);

    // ── authenticate ────────────────────────────────────────────────────────
    let challenge_resp = client
        .get_challenge()
        .await
        .map_err(|e| format!("Failed to get challenge: {e}"))?;
    let challenge_bytes = B64
        .decode(&challenge_resp.challenge)
        .map_err(|_| "Invalid challenge encoding")?;

    let (auth_sk, cb, did) = (hybrid_sk.clone(), challenge_bytes, device_id.clone());
    let signature = tokio::task::spawn_blocking(move || {
        crypto::create_auth_signature(&auth_sk, &cb, &did)
    })
    .await
    .map_err(|e| format!("Thread join error: {e}"))?
    .map_err(|e| format!("Challenge signature failed: {e}"))?;

    let verify_resp = client
        .verify_signature(&crate::api::VerifyRequest {
            device_id: device_id.clone(),
            challenge: challenge_resp.challenge,
            signature,
            device_name: Some(crate::audit::get_device_name()),
            device_type: Some("desktop".to_string()),
        })
        .await
        .map_err(|e| format!("Server authentication failed: {e}"))?;

    let token = verify_resp.token;
    let user_id = verify_resp.user_id;

    // ── open the capsule with our own key ───────────────────────────────────
    let (capsule_resp, _) = client
        .get_capsule(&token)
        .await
        .map_err(|e| format!("Failed to download RMS capsule: {e}"))?;
    let capsule_bytes = B64
        .decode(&capsule_resp.capsule)
        .map_err(|_| "Invalid capsule encoding")?;
    let rms = crypto::open_rms_from_capsule(&hybrid_dk, &capsule_bytes).map_err(|e| {
        format!("The vault key was not sealed to this device — enrollment aborted: {e}")
    })?;

    // ── persist and unlock ──────────────────────────────────────────────────
    crate::biometric::store_password_encrypted(&rms, &password)
        .map_err(|e| format!("Failed to store vault key: {e}"))?;

    let crypto_obj = crate::crypto::Crypto::new(&rms);
    state
        .store
        .save_identity_keys_full(
            &crate::store::IdentityKeysStore {
                hybrid_ek,
                hybrid_dk,
                hybrid_vk,
                hybrid_sk,
                share_ek,
                share_dk,
            },
            &crypto_obj,
        )
        .map_err(|e| format!("Failed to save identity keys: {e}"))?;

    let vault =
        super::devices::download_vault_after_enrollment(&crypto_obj, &client, &token).await?;
    state
        .store
        .save_vault(&vault, &crypto_obj)
        .map_err(|e| format!("Failed to save vault locally: {e}"))?;
    state
        .store
        .save_device_id_with_user_id(&device_id, &user_id)
        .map_err(|e| format!("Failed to save user ID: {e}"))?;

    {
        let mut session = state.session.write();
        session.set_server_token(token);
        session.unlock(device_id.clone(), user_id, 15 * 60);
    }
    {
        let mut crypto_state = state.crypto.write();
        *crypto_state = Some(crypto_obj);
    }
    {
        let mut vault_state = state.vault.write();
        *vault_state = vault;
    }

    *state.pending_join.write() = None;

    record_audit_event(state, AuditAction::VaultUnlocked);
    tracing::info!(device_id = %device_id, "Enrollment join complete (v3)");
    Ok(())
}

/// Give up on joining, wiping the keypair that was generated for it.
pub fn cancel_enrollment_join(state: &AppState) {
    *state.pending_join.write() = None;
}

/// This device's own fingerprint for a pending join, for a UI that needs to
/// redraw it. Read from local state, never re-fetched.
pub fn pending_join_fingerprint(state: &AppState, grant_id: &str) -> Option<String> {
    state
        .pending_join
        .read()
        .as_ref()
        .filter(|p| p.grant_id == grant_id)
        .map(|p| p.fingerprint.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locator(code: &str) -> EnrollmentGrantLocator {
        let encoded = code.strip_prefix(ENROLLMENT_CODE_V3_PREFIX).expect("prefix");
        serde_json::from_slice(&B64URL.decode(encoded).expect("base64url")).expect("json")
    }

    fn encode(loc: &EnrollmentGrantLocator) -> String {
        format!(
            "{ENROLLMENT_CODE_V3_PREFIX}{}",
            B64URL.encode(serde_json::to_string(loc).unwrap())
        )
    }

    /// The point of the whole change: everything a v2 code carried that was
    /// worth stealing must be absent from a v3 one.
    #[test]
    fn a_v3_code_carries_no_key_material() {
        let code = encode(&EnrollmentGrantLocator {
            v: 3,
            u: "https://vault.example".into(),
            g: "11111111-1111-1111-1111-111111111111".into(),
        });
        let decoded = String::from_utf8(
            B64URL
                .decode(code.strip_prefix(ENROLLMENT_CODE_V3_PREFIX).unwrap())
                .unwrap(),
        )
        .unwrap();
        for forbidden in ["hybrid_sk", "hybrid_dk", "transfer_key", "device_id", "k\":"] {
            assert!(
                !decoded.contains(forbidden),
                "a v3 code must not carry {forbidden}: {decoded}"
            );
        }
        let loc = locator(&code);
        assert_eq!(loc.v, 3);
        assert_eq!(loc.g, "11111111-1111-1111-1111-111111111111");
    }

    #[test]
    fn v2_and_v3_codes_are_told_apart_by_prefix() {
        assert!(is_v3_enrollment_code(
            "VELA-ENROLL:v3:eyJ2IjozLCJ1IjoiIiwiZyI6IiJ9"
        ));
        // v2 installs are still out there and their codes must not be taken for
        // v3 ones — the two payloads share no shape at all.
        assert!(!is_v3_enrollment_code("VELA-ENROLL:v2:abc123"));
        assert!(!is_v3_enrollment_code("nonsense"));
        // Pasted codes pick up incidental whitespace.
        assert!(is_v3_enrollment_code("  VELA-ENROLL:v3:abc\n"));
    }

    #[test]
    fn a_pick_must_equal_the_answer() {
        let a = enrollment_fingerprint(&[1u8; 2624]);
        let b = enrollment_fingerprint(&[2u8; 2624]);
        assert!(fingerprints_match(&a, &a));
        assert!(fingerprints_match(&a, &format!("  {a}  ")));
        assert!(!fingerprints_match(&a, &b));
        // A near miss is a miss: one wrong digit is exactly what a substituted
        // key looks like.
        let mut near = a.clone();
        near.replace_range(0..1, if a.starts_with('0') { "1" } else { "0" });
        assert!(!fingerprints_match(&a, &near));
    }

    /// The fingerprint the joining device shows is over its own key.
    ///
    /// This is the invariant the whole layer rests on, so it is asserted
    /// directly rather than left to the reader of `begin_enrollment_join`.
    #[test]
    fn the_joining_fingerprint_is_over_the_devices_own_key() {
        let identity = crypto::generate_identity_keypair().expect("keypair");
        let shown = enrollment_fingerprint(&identity.hybrid_vk);

        // A primary reading this device's claim computes the same value from the
        // same public key, which is what makes the comparison mean something.
        assert_eq!(shown, enrollment_fingerprint(&identity.hybrid_vk));

        // And it is specific to this device.
        let other = crypto::generate_identity_keypair().expect("keypair");
        assert_ne!(shown, enrollment_fingerprint(&other.hybrid_vk));
    }

    /// A joining device must be able to open what a primary sealed to it.
    ///
    /// The two halves are generated and used in different functions and one of
    /// them crosses the network, so the round trip is pinned here.
    #[test]
    fn a_capsule_sealed_to_a_claim_opens_with_the_joining_devices_key() {
        let identity = crypto::generate_identity_keypair().expect("keypair");
        let rms = [9u8; 32];

        // What `confirm_enrollment` does, from the public key in the claim.
        let capsule = crypto::seal_rms_to_device(&identity.hybrid_ek, &rms).expect("seal");
        // What `finish_enrollment_join` does, from the private half it kept.
        assert_eq!(
            crypto::open_rms_from_capsule(&identity.hybrid_dk, &capsule).expect("open"),
            rms
        );

        let other = crypto::generate_identity_keypair().expect("keypair");
        assert!(
            crypto::open_rms_from_capsule(&other.hybrid_dk, &capsule).is_err(),
            "another device's key must not open it"
        );
    }
}
