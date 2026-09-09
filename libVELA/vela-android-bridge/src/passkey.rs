//! Stateless WebAuthn primitives for the Android passkey provider.
//!
//! The Android app is a *passkey provider* (see
//! `security/passkey-android-provider-adr.md`): websites and apps route
//! `navigator.credentials.create/get` through Android's Credential Manager to
//! VELA, and VELA answers with a signature minted from a passkey stored in its
//! own (Kotlin) vault.
//!
//! The ceremony invariants are the desktop core's
//! (`desktopVELA/vela-desktop-core/src/passkey.rs`), and the byte layouts here
//! are deliberately the same code, mirrored:
//!
//! - `build_authenticator_data` / `build_attestation_object` / COSE key
//!   encoding are line-for-line ports of the desktop's — including the
//!   all-zero AAGUID (a model identifier would be a cross-site correlation
//!   handle the user did not ask for) and `none` attestation (there is no
//!   hardware root to attest to, and claiming otherwise would be a lie).
//! - What is *not* mirrored is the desktop's `PresenceToken`: the JNI boundary
//!   cannot carry a linear type, so "one ceremony per human action" is
//!   enforced on the Kotlin side — the prompt activity runs at most one
//!   ceremony per approval and passes `verified` only for a real biometric/PIN
//!   step, which is what decides the `UV` flag in `authenticatorData`.
//!
//! The functions are stateless on purpose: key material lives in the Kotlin
//! vault (sealed with the rest of it) and crosses this boundary as one call's
//! input, used and dropped here. Nothing is cached, and no function returns a
//! private key — key generation is the one exception, and it returns the fresh
//! key exactly once so the caller can store it.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use ciborium::value::Value as Cbor;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// COSE algorithm identifier for ECDSA w/ SHA-256 — the one every WebAuthn
/// verifier implements, so the only one a provider can count on.
pub const COSE_ALG_ES256: i32 = -7;

/// All-zero AAGUID — see the module docs.
const AAGUID: [u8; 16] = [0u8; 16];

/// Authenticator data flags (WebAuthn §6.1).
pub mod flags {
    /// User present.
    pub const UP: u8 = 0x01;
    /// User verified — a biometric or PIN, not merely a click.
    pub const UV: u8 = 0x04;
    /// Attested credential data is included (registration only).
    pub const AT: u8 = 0x40;
}

// ── Keygen ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct KeygenRequest {
    /// COSE algorithm identifiers the relying party accepts. Empty means
    /// "anything this authenticator implements".
    #[serde(default)]
    pub algorithms: Vec<i32>,
}

#[derive(Debug, Serialize)]
pub struct KeygenResponse {
    pub credential_id_b64: String,
    /// The ES256 private scalar, base64url. This is the one call that returns
    /// a secret: the caller stores it in the sealed vault and never gets it
    /// back — every later use goes through [`sign`].
    pub scalar_b64: String,
    pub cose_public_key_b64: String,
}

/// Generate a fresh credential keypair and its opaque credential ID.
pub fn keygen(request: &KeygenRequest) -> Result<KeygenResponse, String> {
    if !request.algorithms.is_empty() && !request.algorithms.contains(&COSE_ALG_ES256) {
        return Err("this site does not accept ES256".to_string());
    }

    let secret = SecretKey::random(&mut OsRng);
    let signing = SigningKey::from(&secret);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&secret.to_bytes());

    let mut credential_id = [0u8; 32];
    getrandom::getrandom(&mut credential_id)
        .map_err(|e| format!("OS random source unavailable: {e}"))?;

    let cose = cose_key_es256(&signing);

    Ok(KeygenResponse {
        credential_id_b64: B64URL.encode(credential_id),
        scalar_b64: B64URL.encode(scalar),
        cose_public_key_b64: B64URL.encode(cose),
    })
}

// ── authenticatorData ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthDataRequest {
    pub rp_id: String,
    /// WebAuthn §6.1 flags — UP/UV/AT, from [`flags`].
    pub flags: u8,
    pub sign_count: u32,
    /// Present for registration: the attested credential data to embed.
    #[serde(default)]
    pub credential_id_b64: String,
    #[serde(default)]
    pub cose_public_key_b64: String,
}

#[derive(Debug, Serialize)]
pub struct AuthDataResponse {
    pub authenticator_data_b64: String,
}

/// Build `authenticatorData` (WebAuthn §6.1):
/// `rpIdHash ‖ flags ‖ signCount ‖ [attestedCredentialData]`.
///
/// The RP ID hash is what binds every later signature to this one origin —
/// the caller hands the platform's RP ID through unchanged or the assertion
/// verifies nowhere.
pub fn build_authenticator_data(request: &AuthDataRequest) -> Result<AuthDataResponse, String> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&Sha256::digest(request.rp_id.as_bytes()));
    out.push(request.flags);
    out.extend_from_slice(&request.sign_count.to_be_bytes());

    let attested =
        !(request.credential_id_b64.is_empty() && request.cose_public_key_b64.is_empty());
    if attested {
        let credential_id = B64URL
            .decode(&request.credential_id_b64)
            .map_err(|e| format!("credential id is not base64url: {e}"))?;
        let cose = B64URL
            .decode(&request.cose_public_key_b64)
            .map_err(|e| format!("COSE public key is not base64url: {e}"))?;

        out.extend_from_slice(&AAGUID);
        // Credential ID length is a 2-byte big-endian field, so a longer ID
        // than this could not be expressed.
        let len = u16::try_from(credential_id.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&credential_id);
        out.extend_from_slice(&cose);
    }

    Ok(AuthDataResponse {
        authenticator_data_b64: B64URL.encode(out),
    })
}

// ── attestationObject ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationRequest {
    pub authenticator_data_b64: String,
}

#[derive(Debug, Serialize)]
pub struct AttestationResponse {
    pub attestation_object_b64: String,
}

/// Build the `attestationObject` CBOR with `none` attestation:
/// `{"fmt": "none", "attStmt": {}, "authData": ...}`.
pub fn build_attestation_object(
    request: &AttestationRequest,
) -> Result<AttestationResponse, String> {
    let authenticator_data = B64URL
        .decode(&request.authenticator_data_b64)
        .map_err(|e| format!("authenticator data is not base64url: {e}"))?;

    let object = Cbor::Map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
        (
            Cbor::Text("authData".into()),
            Cbor::Bytes(authenticator_data),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&object, &mut bytes).map_err(|e| e.to_string())?;

    Ok(AttestationResponse {
        attestation_object_b64: B64URL.encode(bytes),
    })
}

// ── Signing ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    /// The stored ES256 private scalar, base64url.
    pub scalar_b64: String,
    /// The message to sign — `authenticatorData ‖ SHA-256(clientDataJSON)`,
    /// composed by the caller (WebAuthn §6.3.3).
    pub message_b64: String,
}

#[derive(Debug, Serialize)]
pub struct SignResponse {
    pub signature_der_b64: String,
}

/// Sign one message with a stored credential key.
///
/// The scalar is decoded, used and dropped inside this call; only the DER
/// signature (the thing WebAuthn carries) comes back.
pub fn sign(request: &SignRequest) -> Result<SignResponse, String> {
    let scalar = B64URL
        .decode(&request.scalar_b64)
        .map_err(|e| format!("private key is not base64url: {e}"))?;
    let message = B64URL
        .decode(&request.message_b64)
        .map_err(|e| format!("message is not base64url: {e}"))?;

    let key = CredentialKey::from_scalar(&scalar)?;
    Ok(SignResponse {
        signature_der_b64: B64URL.encode(key.sign_der(&message)),
    })
}

// ── Key type (mirror of the desktop core's `credential_key.rs`) ──────────────

struct CredentialKey {
    signing: SigningKey,
}

impl CredentialKey {
    fn from_scalar(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err(format!(
                "credential key must be 32 bytes, got {}",
                bytes.len()
            ));
        }
        let secret =
            SecretKey::from_slice(bytes).map_err(|e| format!("P-256 secret key decode: {e}"))?;
        Ok(Self {
            signing: SigningKey::from(&secret),
        })
    }

    /// Sign `message` and return the DER-encoded ECDSA signature. WebAuthn
    /// carries ES256 signatures in ASN.1 DER, not the fixed 64-byte form.
    fn sign_der(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing.sign(message);
        signature.to_der().as_bytes().to_vec()
    }
}

/// The credential's public key, CBOR-encoded as a COSE_Key in CTAP2 canonical
/// form — the fixed five-entry layout (`1, 3, -1, -2, -3`) the desktop writes,
/// pinned by the tests below.
fn cose_key_es256(signing: &SigningKey) -> Vec<u8> {
    let verifying: &VerifyingKey = signing.as_ref();
    let point = verifying.as_affine().to_encoded_point(false);
    let x = point.x().expect("P-256 point always has an X coordinate");
    let y = point
        .y()
        .expect("uncompressed P-256 point always has a Y coordinate");

    let mut out = Vec::with_capacity(77);
    out.push(0xA5); // map(5)

    out.push(0x01); // key 1 (kty)
    out.push(0x02); //   value 2 (EC2)

    out.push(0x03); // key 3 (alg)
    out.push(0x26); //   value -7 (ES256)

    out.push(0x20); // key -1 (crv)
    out.push(0x01); //   value 1 (P-256)

    out.push(0x21); // key -2 (x)
    out.push(0x58); //   bytes, 1-byte length follows
    out.push(x.len() as u8);
    out.extend_from_slice(x.as_slice());

    out.push(0x22); // key -3 (y)
    out.push(0x58); //   bytes, 1-byte length follows
    out.push(y.len() as u8);
    out.extend_from_slice(y.as_slice());

    out
}

// ── Tests ────────────────────────────────────────────────────────────────────
//
// The desktop's layouts are the reference implementation; these tests pin the
// mirror to the same shapes (the ADR's guard: the two transports stay
// behaviorally identical).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_round_trips_through_the_stored_scalar() {
        let generated = keygen(&KeygenRequest { algorithms: vec![] }).unwrap();

        // The COSE key is derivable from the scalar alone: restore, re-sign,
        // and verify the way a relying party would.
        let scalar = B64URL.decode(&generated.scalar_b64).unwrap();
        let key = CredentialKey::from_scalar(&scalar).unwrap();
        let cose = B64URL.decode(&generated.cose_public_key_b64).unwrap();

        let message = b"authenticatorData || clientDataHash";
        let sig = key.sign_der(message);
        assert!(verify_es256(&cose, message, &sig));
    }

    #[test]
    fn keygen_refuses_a_relying_party_without_es256() {
        let error = keygen(&KeygenRequest {
            algorithms: vec![-8, -257],
        })
        .unwrap_err();
        assert!(error.contains("ES256"), "{error}");
    }

    #[test]
    fn credential_ids_do_not_repeat() {
        let a = keygen(&KeygenRequest { algorithms: vec![] }).unwrap();
        let b = keygen(&KeygenRequest { algorithms: vec![] }).unwrap();
        assert_ne!(a.credential_id_b64, b.credential_id_b64);
        assert_ne!(a.scalar_b64, b.scalar_b64);
    }

    #[test]
    fn a_short_scalar_is_refused_rather_than_padded() {
        assert!(CredentialKey::from_scalar(&[0u8; 16]).is_err());
    }

    #[test]
    fn authenticator_data_matches_the_webauthn_layout() {
        let response = build_authenticator_data(&AuthDataRequest {
            rp_id: "example.com".to_string(),
            flags: flags::UP | flags::UV,
            sign_count: 42,
            credential_id_b64: String::new(),
            cose_public_key_b64: String::new(),
        })
        .unwrap();

        let data = B64URL.decode(&response.authenticator_data_b64).unwrap();
        // rpIdHash (32) ‖ flags (1) ‖ signCount (4)
        assert_eq!(data.len(), 37);
        assert_eq!(Sha256::digest(b"example.com").as_slice(), &data[..32]);
        assert_eq!(data[32], flags::UP | flags::UV);
        assert_eq!(&data[33..37], &42u32.to_be_bytes());
    }

    #[test]
    fn registration_data_embeds_attested_credential_data() {
        let generated = keygen(&KeygenRequest { algorithms: vec![] }).unwrap();
        let response = build_authenticator_data(&AuthDataRequest {
            rp_id: "example.com".to_string(),
            flags: flags::UP | flags::AT,
            sign_count: 1,
            credential_id_b64: generated.credential_id_b64.clone(),
            cose_public_key_b64: generated.cose_public_key_b64.clone(),
        })
        .unwrap();

        let data = B64URL.decode(&response.authenticator_data_b64).unwrap();
        // 37 fixed + AAGUID (16) + id length (2) + id (32) + COSE key (77)
        assert_eq!(data.len(), 37 + 16 + 2 + 32 + 77);
        assert_eq!(&data[37..53], &[0u8; 16]); // zero AAGUID
        assert_eq!(&data[53..55], &32u16.to_be_bytes()); // credential id length
        let credential_id = B64URL.decode(&generated.credential_id_b64).unwrap();
        assert_eq!(&data[55..87], &credential_id[..]);
        // COSE key in the canonical layout the desktop pins: map(5), then the
        // five entries in CTAP2 canonical key order.
        assert_eq!(&data[87..93], &[0xA5, 0x01, 0x02, 0x03, 0x26, 0x20]);
        assert_eq!(&data[93..97], &[0x01, 0x21, 0x58, 0x20]);
        assert_eq!(&data[129..132], &[0x22, 0x58, 0x20]);
    }

    #[test]
    fn attestation_object_carries_none_attestation() {
        let data = build_authenticator_data(&AuthDataRequest {
            rp_id: "example.com".to_string(),
            flags: flags::UP,
            sign_count: 1,
            credential_id_b64: String::new(),
            cose_public_key_b64: String::new(),
        })
        .unwrap();

        let response = build_attestation_object(&AttestationRequest {
            authenticator_data_b64: data.authenticator_data_b64.clone(),
        })
        .unwrap();

        let bytes = B64URL.decode(&response.attestation_object_b64).unwrap();
        let value: Cbor = ciborium::from_reader(&bytes[..])
            .map_err(|e| e.to_string())
            .unwrap();
        let Cbor::Map(entries) = value else {
            panic!("not a CBOR map")
        };
        let get = |key: &str| {
            entries
                .iter()
                .find(|(k, _)| matches!(k, Cbor::Text(t) if t == key))
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("missing key {key}"))
        };
        assert!(matches!(get("fmt"), Cbor::Text(fmt) if fmt == "none"));
        assert!(matches!(get("attStmt"), Cbor::Map(m) if m.is_empty()));
        assert!(matches!(get("authData"), Cbor::Bytes(_)));
    }

    #[test]
    fn a_signature_does_not_verify_for_a_different_message() {
        let generated = keygen(&KeygenRequest { algorithms: vec![] }).unwrap();
        let cose = B64URL.decode(&generated.cose_public_key_b64).unwrap();

        let signed = sign(&SignRequest {
            scalar_b64: generated.scalar_b64.clone(),
            message_b64: B64URL.encode(b"one origin"),
        })
        .unwrap();
        let signature = B64URL.decode(&signed.signature_der_b64).unwrap();

        assert!(verify_es256(&cose, b"one origin", &signature));
        assert!(!verify_es256(&cose, b"another origin", &signature));
    }

    /// Verify the way a relying party would: DER signature against the COSE
    /// public key. Mirror of the desktop's `verify_der`.
    fn verify_es256(cose: &[u8], message: &[u8], signature_der: &[u8]) -> bool {
        let expected_len = 10 + 32 + 3 + 32;
        if cose.len() != expected_len || cose[0] != 0xA5 {
            return false;
        }
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&cose[10..42]);
        sec1.extend_from_slice(&cose[45..77]);

        let Ok(verifying) = VerifyingKey::from_sec1_bytes(&sec1) else {
            return false;
        };
        let Ok(signature) = Signature::from_der(signature_der) else {
            return false;
        };
        use p256::ecdsa::signature::Verifier;
        verifying.verify(message, &signature).is_ok()
    }
}
