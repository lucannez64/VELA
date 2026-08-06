//! WebAuthn ceremonies, performed by the desktop core.
//!
//! This is the M7 tier of the release ladder
//! (`security/formal/m7_oneshot_assertion.spthy`). Where the autofill path in
//! [`crate::ipc`] hands a browser a reusable password — and is bounded by the
//! working set as a result — this path hands it a signature over
//! `<origin, challenge>` and nothing else. The credential key is used where it
//! is stored and never crosses the IPC boundary, which is what the model's
//! `credential_never_leaks` says: the property holds *even for the credential
//! in active use*, because there is no code path that emits one.
//!
//! Two invariants are load-bearing, and both are enforced by types here rather
//! than by convention:
//!
//! 1. **One ceremony per human action.** [`PresenceToken`] is minted only by
//!    [`crate::presence`], is neither `Clone` nor `Copy`, and is taken by value
//!    by both ceremonies. One token buys exactly one assertion — the compile-
//!    time form of the model's `assertions_bounded_by_presence`. Without this
//!    the assertion path is a free oracle a co-resident process can call at
//!    will, which is the exact defect the first version of the model had.
//! 2. **An assertion is scoped to one relying party.** A credential is looked
//!    up by exact RP ID and the RP ID hash is signed as part of
//!    `authenticatorData`, so a signature minted for one origin verifies
//!    nowhere else — the model's `assertion_is_origin_bound`.
//!
//! The request/response types are deliberately plain structs rather than the
//! extension's message shapes: the browser shim is one front end, and an OS
//! passkey provider (macOS `ASCredentialProviderExtension`, the Windows plugin
//! authenticator API) has to be able to drive the same two functions later.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use ciborium::value::Value as Cbor;
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::credential_key::{generate_credential_id, CredentialKey, COSE_ALG_ES256};
use crate::vault::{VaultItem, VaultMeta};
use crate::AppState;

/// Authenticator data flags (WebAuthn §6.1).
mod flags {
    /// User present.
    pub const UP: u8 = 0x01;
    /// User verified — a biometric or PIN, not merely a click.
    pub const UV: u8 = 0x04;
    /// Attested credential data is included (registration only).
    pub const AT: u8 = 0x40;
}

/// All-zero AAGUID.
///
/// A model identifier would say "this credential lives in VELA" to every
/// relying party a user registers with, which is a cross-site correlation
/// handle they did not ask for. `none` attestation does not need one, so the
/// spec's zero value is both the private choice and the honest one.
const AAGUID: [u8; 16] = [0u8; 16];

/// Proof that a human authorised exactly one ceremony.
///
/// The direct analogue of the `UserPresence` linear fact in
/// `m7_oneshot_assertion.spthy`: minted only by a human action, consumed by the
/// ceremony that uses it. Not `Clone`, not `Copy`, and taken by value below, so
/// the "one assertion per human action" bound is checked by the compiler
/// instead of being a comment somebody can drift away from.
#[must_use = "a presence token that is not spent on a ceremony wasted a prompt"]
pub struct PresenceToken {
    /// True when the human proved presence with a biometric or PIN, false when
    /// they merely confirmed a dialog. Decides whether `UV` may be set.
    verified: bool,
}

impl PresenceToken {
    /// Mint a token. Crate-private on purpose: [`crate::presence`] is the only
    /// thing that may decide a human was present.
    pub(crate) fn mint(verified: bool) -> Self {
        Self { verified }
    }

    /// Did the human prove presence with a real verification factor?
    pub fn is_verified(&self) -> bool {
        self.verified
    }
}

// ── Requests and responses ────────────────────────────────────────────────────

/// A registration ceremony (`navigator.credentials.create`).
#[derive(Debug, Clone)]
pub struct MakeCredentialRequest {
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    /// SHA-256 of the `clientDataJSON` the caller built. The core never sees
    /// the origin directly — the shim builds the envelope in the page context,
    /// where the real origin is, and the relying party verifies it there too.
    pub client_data_hash: [u8; 32],
    /// COSE algorithm identifiers the relying party said it accepts.
    pub algorithms: Vec<i32>,
    /// Credential IDs the relying party already has for this user.
    pub excluded_credential_ids: Vec<String>,
    /// The relying party asked for user *verification*, not merely presence.
    pub require_user_verification: bool,
}

#[derive(Debug, Clone)]
pub struct MakeCredentialResponse {
    pub credential_id: String,
    pub attestation_object: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// The vault item created for this credential.
    pub item_id: String,
}

/// An authentication ceremony (`navigator.credentials.get`).
#[derive(Debug, Clone)]
pub struct GetAssertionRequest {
    pub rp_id: String,
    pub client_data_hash: [u8; 32],
    /// Credential IDs from `allowCredentials`. Empty means a discoverable
    /// ("resident") credential request: any passkey for this RP will do.
    pub allow_credential_ids: Vec<String>,
    pub require_user_verification: bool,
}

#[derive(Debug, Clone)]
pub struct GetAssertionResponse {
    pub credential_id: String,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

/// Everything that can go wrong in a ceremony, in terms the shim can map onto
/// the `DOMException` names a page expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasskeyError {
    /// The vault is locked, so there is nothing to sign with.
    VaultLocked,
    /// No credential in the vault matches this relying party.
    NoCredential,
    /// The relying party demanded user verification and this machine could only
    /// establish user presence.
    UserVerificationUnavailable,
    /// A credential for this relying party and user already exists.
    CredentialExcluded,
    /// The relying party accepts no algorithm this authenticator implements.
    UnsupportedAlgorithm,
    /// Something in the stored credential could not be used.
    Malformed(String),
}

impl std::fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VaultLocked => write!(f, "Vault is locked"),
            Self::NoCredential => write!(f, "No passkey for this site"),
            Self::UserVerificationUnavailable => {
                write!(f, "This site requires biometric or PIN verification, which this machine cannot provide")
            }
            Self::CredentialExcluded => write!(f, "A passkey for this account already exists"),
            Self::UnsupportedAlgorithm => write!(f, "This site does not accept ES256"),
            Self::Malformed(what) => write!(f, "Stored passkey is unusable: {what}"),
        }
    }
}

// ── Ceremony: registration ────────────────────────────────────────────────────

/// Create a credential, store it in the vault, and return the attestation.
///
/// Consumes `token`: one human action, one credential.
pub fn make_credential(
    state: &AppState,
    request: &MakeCredentialRequest,
    token: PresenceToken,
) -> Result<MakeCredentialResponse, PasskeyError> {
    if !request.algorithms.is_empty() && !request.algorithms.contains(&COSE_ALG_ES256) {
        return Err(PasskeyError::UnsupportedAlgorithm);
    }
    if request.require_user_verification && !token.is_verified() {
        return Err(PasskeyError::UserVerificationUnavailable);
    }

    {
        let session = state.session.read();
        if !session.active || session.is_expired() {
            return Err(PasskeyError::VaultLocked);
        }
    }
    if state.crypto.read().is_none() {
        return Err(PasskeyError::VaultLocked);
    }

    // `excludeCredentials` exists so a relying party can stop a second
    // credential being minted for an account that already has one.
    if !request.excluded_credential_ids.is_empty() {
        let vault = state.vault.read();
        if request
            .excluded_credential_ids
            .iter()
            .any(|id| vault.passkey_by_credential_id(id).is_some())
        {
            return Err(PasskeyError::CredentialExcluded);
        }
    }

    let key = CredentialKey::generate()
        .map_err(|e| PasskeyError::Malformed(format!("key generation failed: {e}")))?;
    let credential_id = generate_credential_id()
        .map_err(|e| PasskeyError::Malformed(format!("credential id generation failed: {e}")))?;
    let credential_id_b64 = B64URL.encode(credential_id);
    let public_key_cose = key.public_key_cose();

    let attested = AttestedCredentialData {
        credential_id: &credential_id,
        public_key_cose: &public_key_cose,
    };
    // A freshly minted credential starts its counter at 1 for its own
    // registration, matching what the first assertion will be compared against.
    let authenticator_data =
        build_authenticator_data(&request.rp_id, ceremony_flags(&token, true), 1, Some(attested));
    let attestation_object = build_attestation_object(&authenticator_data)
        .map_err(|e| PasskeyError::Malformed(format!("attestation encoding failed: {e}")))?;

    let now = chrono::Utc::now();
    let device_id = state.session.read().device_id.clone();
    let item_id = uuid::Uuid::new_v4().to_string();
    let item = VaultItem::Passkey {
        meta: VaultMeta {
            id: item_id.clone(),
            name: if request.rp_name.is_empty() {
                request.rp_id.clone()
            } else {
                request.rp_name.clone()
            },
            notes: None,
            created_at: now,
            updated_at: now,
            last_modified_device: device_id,
            favorite: false,
            shared: false,
            share_recipient: None,
        },
        rp_id: request.rp_id.clone(),
        rp_name: request.rp_name.clone(),
        credential_id: credential_id_b64.clone(),
        user_handle: B64URL.encode(&request.user_handle),
        user_name: request.user_name.clone(),
        user_display_name: request.user_display_name.clone(),
        private_key: B64URL.encode(key.to_scalar_bytes()),
        sign_count: 1,
    };

    {
        let mut vault = state.vault.write();
        vault.add_item(item);
    }
    persist(state);

    Ok(MakeCredentialResponse {
        credential_id: credential_id_b64,
        attestation_object,
        authenticator_data,
        item_id,
    })
}

// ── Ceremony: authentication ──────────────────────────────────────────────────

/// Sign one assertion for `request.rp_id`.
///
/// Consumes `token`: one human action, one assertion. The credential key is
/// loaded, used and dropped inside this function — it is never returned, logged
/// or placed in any response type.
pub fn get_assertion(
    state: &AppState,
    request: &GetAssertionRequest,
    token: PresenceToken,
) -> Result<GetAssertionResponse, PasskeyError> {
    if request.require_user_verification && !token.is_verified() {
        return Err(PasskeyError::UserVerificationUnavailable);
    }

    {
        let session = state.session.read();
        if !session.active || session.is_expired() {
            return Err(PasskeyError::VaultLocked);
        }
    }
    if state.crypto.read().is_none() {
        return Err(PasskeyError::VaultLocked);
    }

    // Pull everything needed out under the read lock, then drop it: the
    // signature is computed without holding the vault.
    let (item_id, credential_id, user_handle_b64, scalar_b64, next_count) = {
        let vault = state.vault.read();
        // Exact RP ID match, and only among credentials the relying party
        // offered when it named any. Both narrowings matter: the first is what
        // makes the assertion origin-bound, the second stops a request for one
        // account being answered with another account's credential.
        let candidates = vault.passkeys_for_rp(&request.rp_id);
        let chosen = candidates
            .iter()
            .find(|item| {
                request.allow_credential_ids.is_empty()
                    || item
                        .credential_id()
                        .is_some_and(|id| request.allow_credential_ids.iter().any(|a| a == id))
            })
            .ok_or(PasskeyError::NoCredential)?;

        let VaultItem::Passkey {
            meta,
            credential_id,
            user_handle,
            private_key,
            sign_count,
            ..
        } = chosen
        else {
            // `passkeys_for_rp` only ever yields this variant.
            return Err(PasskeyError::NoCredential);
        };

        (
            meta.id.clone(),
            credential_id.clone(),
            user_handle.clone(),
            private_key.clone(),
            sign_count.saturating_add(1),
        )
    };

    let scalar = B64URL
        .decode(&scalar_b64)
        .map_err(|e| PasskeyError::Malformed(format!("private key is not base64url: {e}")))?;
    let key = CredentialKey::from_scalar(&scalar)
        .map_err(|e| PasskeyError::Malformed(format!("private key rejected: {e}")))?;

    let authenticator_data =
        build_authenticator_data(&request.rp_id, ceremony_flags(&token, false), next_count, None);

    // WebAuthn §6.3.3: the signature covers authenticatorData ‖ clientDataHash.
    // The RP ID hash is inside authenticatorData, which is what binds this
    // signature to this origin and makes it worthless at any other.
    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(&authenticator_data);
    signed.extend_from_slice(&request.client_data_hash);
    let signature = key.sign_der(&signed);

    bump_sign_count(state, &item_id, next_count);

    Ok(GetAssertionResponse {
        credential_id,
        authenticator_data,
        signature,
        user_handle: B64URL.decode(&user_handle_b64).unwrap_or_default(),
    })
}

// ── Encoding helpers (pure) ───────────────────────────────────────────────────

struct AttestedCredentialData<'a> {
    credential_id: &'a [u8],
    public_key_cose: &'a [u8],
}

fn ceremony_flags(token: &PresenceToken, registration: bool) -> u8 {
    let mut f = flags::UP;
    if token.is_verified() {
        f |= flags::UV;
    }
    if registration {
        f |= flags::AT;
    }
    f
}

/// Build `authenticatorData` (WebAuthn §6.1).
///
/// `rpIdHash ‖ flags ‖ signCount ‖ [attestedCredentialData]`.
fn build_authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    attested: Option<AttestedCredentialData<'_>>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());

    if let Some(attested) = attested {
        out.extend_from_slice(&AAGUID);
        // Credential ID length is a 2-byte big-endian field, so a longer ID
        // than this could not be expressed.
        let len = u16::try_from(attested.credential_id.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(attested.credential_id);
        out.extend_from_slice(attested.public_key_cose);
    }

    out
}

/// Build the `attestationObject` CBOR with `none` attestation.
///
/// `none` is the right choice for a software authenticator: there is no
/// hardware root to attest to, and claiming otherwise would be a lie a relying
/// party might act on.
fn build_attestation_object(authenticator_data: &[u8]) -> Result<Vec<u8>, String> {
    let object = Cbor::Map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
        (
            Cbor::Text("authData".into()),
            Cbor::Bytes(authenticator_data.to_vec()),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&object, &mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

// ── Vault plumbing ────────────────────────────────────────────────────────────

fn bump_sign_count(state: &AppState, item_id: &str, next: u32) {
    {
        let mut vault = state.vault.write();
        if let Some(VaultItem::Passkey { sign_count, .. }) = vault.get_item_mut(item_id) {
            *sign_count = next;
        }
    }
    persist(state);
}

fn persist(state: &AppState) {
    let vault = state.vault.read();
    let crypto = state.crypto.read();
    if let Some(crypto) = crypto.as_ref() {
        if let Err(e) = state.store.save_vault(&vault, crypto) {
            // Not fatal to the ceremony in flight — the assertion is already
            // signed and the relying party will accept it. A counter that fails
            // to persist can only cause a future "cloned authenticator" warning,
            // which is far better than refusing a login the user asked for.
            warn!("Failed to persist vault after passkey ceremony: {}", e);
        }
    }
}
