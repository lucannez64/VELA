//! WebAuthn credential keys: ECDSA P-256 / SHA-256 (COSE alg `-7`, "ES256").
//!
//! Deliberately here and not in `vela-crypto`, which holds VELA's own *device
//! identity* key (hybrid ML-DSA-87 + Ed25519, because VELA controls both ends
//! and can insist on post-quantum). Two reasons:
//!
//!  * `serverVELA` depends on `vela-crypto` by path and has no use for WebAuthn
//!    credential keys. Putting `p256` there drags an ECDSA stack into the
//!    server's dependency graph, where it fails the `multiple-versions = deny`
//!    gate in `security/deny.toml` by splitting the resolution of unrelated
//!    transitive crates. Nothing is gained by making the server carry it.
//!  * WebAuthn code already lives in this crate — see [`crate::webauthn`], the
//!    CTAP2 client used for recovery — so this is where a reader looks for it.
//!
//! A passkey credential key is verified by somebody else's relying party, so
//! the algorithm is not ours to choose: ES256 is the one every WebAuthn verifier implements, and it is
//! the only one a deployment can count on. EdDSA (`-8`) is in the registry but
//! is refused often enough in practice that offering it alone would strand
//! users on real sites.
//!
//! One keypair per credential, i.e. per (relying party, user handle) — never
//! one device key reused across origins. That is what makes a stolen assertion
//! useless anywhere but the origin it was minted for, and it is the property
//! the formal model calls `assertion_is_origin_bound`
//! (`security/formal/m7_oneshot_assertion.spthy`). The private half is written
//! into the vault, sealed with everything else, and never leaves the desktop
//! core: only signatures cross the IPC boundary.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use p256::elliptic_curve::rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// COSE algorithm identifier for ECDSA w/ SHA-256, as a relying party expects
/// to see it in `pubKeyCredParams` and in the credential public key.
pub const COSE_ALG_ES256: i32 = -7;

/// Length of a raw P-256 private scalar, which is how the key is stored.
pub const CREDENTIAL_KEY_LEN: usize = 32;

/// Length of a generated credential ID.
///
/// Anything unpredictable and collision-free works — the value is opaque to the
/// relying party, which only ever echoes it back. 32 bytes matches what real
/// authenticators emit and leaves no room for a birthday collision across a
/// vault.
pub const CREDENTIAL_ID_LEN: usize = 32;

// ── Key type ──────────────────────────────────────────────────────────────────

/// A single credential's ECDSA P-256 private key.
///
/// Zeroized on drop. It is written to the vault (sealed) rather than kept in an
/// enclave, because a passkey has to survive sync to the user's other devices;
/// the boundary it must not cross is the IPC socket, not the disk.
#[derive(ZeroizeOnDrop)]
pub struct CredentialKey {
    #[zeroize(skip)]
    signing: SigningKey,
    /// Retained so the key can be re-serialised without asking `p256` for the
    /// scalar again, and so it is zeroized on drop.
    scalar: [u8; CREDENTIAL_KEY_LEN],
}

impl CredentialKey {
    /// Generate a fresh credential keypair from the OS CSPRNG.
    pub fn generate() -> Result<Self, String> {
        let secret = SecretKey::random(&mut OsRng);
        Self::from_secret(secret)
    }

    /// Reconstruct a credential key from its stored 32-byte private scalar.
    pub fn from_scalar(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != CREDENTIAL_KEY_LEN {
            return Err(format!(
                "credential key must be {CREDENTIAL_KEY_LEN} bytes, got {}",
                bytes.len()
            ));
        }
        let secret = SecretKey::from_slice(bytes)
            .map_err(|e| format!("P-256 secret key decode: {e}"))?;
        Self::from_secret(secret)
    }

    fn from_secret(secret: SecretKey) -> Result<Self, String> {
        let mut scalar = [0u8; CREDENTIAL_KEY_LEN];
        scalar.copy_from_slice(&secret.to_bytes());
        Ok(Self {
            signing: SigningKey::from(&secret),
            scalar,
        })
    }

    /// The raw private scalar, for sealing into the vault.
    ///
    /// The only caller that should ever want this is vault persistence. It is
    /// deliberately not `Serialize` — a passkey item serialises this through an
    /// explicit encode step, so a stray `serde_json::to_value` on a credential
    /// cannot pick the private half up by accident.
    pub fn to_scalar_bytes(&self) -> [u8; CREDENTIAL_KEY_LEN] {
        self.scalar
    }

    /// Sign `message` and return the DER-encoded ECDSA signature.
    ///
    /// WebAuthn carries ES256 signatures in ASN.1 DER, not the fixed 64-byte
    /// form — a verifier handed the raw `r ‖ s` will reject it.
    pub fn sign_der(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing.sign(message);
        signature.to_der().as_bytes().to_vec()
    }

    /// This credential's public key, CBOR-encoded as a COSE_Key.
    ///
    /// This is the `credentialPublicKey` a relying party stores at registration
    /// and verifies against on every subsequent assertion.
    pub fn public_key_cose(&self) -> Vec<u8> {
        let verifying: &VerifyingKey = self.signing.as_ref();
        let point = verifying.as_affine().to_encoded_point(false);
        // Uncompressed SEC1: 0x04 ‖ X (32) ‖ Y (32).
        let x = point.x().expect("P-256 point always has an X coordinate");
        let y = point.y().expect("uncompressed P-256 point always has a Y coordinate");
        cose_key_es256(x.as_slice(), y.as_slice())
    }
}

/// Hand-encode the COSE_Key CBOR map for an ES256 public key.
///
/// Deliberately not routed through a CBOR library: the structure is fixed at
/// five entries with fixed-width values, WebAuthn wants it in CTAP2 canonical
/// form, and the canonical key order here (`1, 3, -1, -2, -3` — one-byte
/// encodings sorted bytewise as `0x01, 0x03, 0x20, 0x21, 0x22`) is easier to
/// guarantee by construction than to coax out of a generic encoder. The exact
/// byte layout is pinned by [`tests::cose_key_layout_is_canonical`].
fn cose_key_es256(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(77);
    out.push(0xA5); // map(5)

    out.push(0x01); // key 1 (kty)
    out.push(0x02); //   value 2 (EC2)

    out.push(0x03); // key 3 (alg)
    out.push(0x26); //   value -7 (ES256), major type 1 with argument 6

    out.push(0x20); // key -1 (crv)
    out.push(0x01); //   value 1 (P-256)

    out.push(0x21); // key -2 (x)
    out.push(0x58); //   bytes, 1-byte length follows
    out.push(x.len() as u8);
    out.extend_from_slice(x);

    out.push(0x22); // key -3 (y)
    out.push(0x58); //   bytes, 1-byte length follows
    out.push(y.len() as u8);
    out.extend_from_slice(y);

    out
}

/// Generate an opaque credential ID.
pub fn generate_credential_id() -> Result<[u8; CREDENTIAL_ID_LEN], String> {
    let mut id = [0u8; CREDENTIAL_ID_LEN];
    getrandom::getrandom(&mut id).map_err(|e| format!("OS random source unavailable: {e}"))?;
    Ok(id)
}

/// Verify a DER-encoded ES256 signature against a COSE_Key public key.
///
/// Present so tests can check an assertion the way a relying party would,
/// rather than trusting the signer to agree with itself.
pub fn verify_der(cose_public_key: &[u8], message: &[u8], signature_der: &[u8]) -> Result<bool, String> {
    use p256::ecdsa::signature::Verifier;

    let (x, y) = parse_cose_key_es256(cose_public_key)?;
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);

    let verifying = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| format!("P-256 public key decode: {e}"))?;
    let signature =
        Signature::from_der(signature_der).map_err(|e| format!("ES256 signature decode: {e}"))?;

    Ok(verifying.verify(message, &signature).is_ok())
}

/// Pull `x` and `y` back out of the fixed COSE_Key layout written above.
fn parse_cose_key_es256(cose: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let expected_len = 10 + 32 + 3 + 32;
    if cose.len() != expected_len || cose[0] != 0xA5 {
        return Err("not an ES256 COSE_Key in the layout this module writes".to_string());
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&cose[10..42]);
    y.copy_from_slice(&cose[45..77]);
    Ok((x, y))
}

impl Zeroize for CredentialKey {
    fn zeroize(&mut self) {
        self.scalar.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verifies_like_a_relying_party_would() {
        let key = CredentialKey::generate().unwrap();
        let cose = key.public_key_cose();
        let message = b"authenticatorData || clientDataHash";

        let sig = key.sign_der(message);

        assert!(verify_der(&cose, message, &sig).unwrap());
    }

    #[test]
    fn a_signature_does_not_verify_for_a_different_message() {
        let key = CredentialKey::generate().unwrap();
        let cose = key.public_key_cose();

        let sig = key.sign_der(b"one origin");

        assert!(!verify_der(&cose, b"another origin", &sig).unwrap());
    }

    #[test]
    fn a_signature_does_not_verify_under_another_credentials_key() {
        let mine = CredentialKey::generate().unwrap();
        let theirs = CredentialKey::generate().unwrap();
        let message = b"authenticatorData || clientDataHash";

        let sig = mine.sign_der(message);

        assert!(!verify_der(&theirs.public_key_cose(), message, &sig).unwrap());
    }

    #[test]
    fn a_key_round_trips_through_its_stored_scalar() {
        let original = CredentialKey::generate().unwrap();
        let message = b"authenticatorData || clientDataHash";

        let restored = CredentialKey::from_scalar(&original.to_scalar_bytes()).unwrap();

        assert_eq!(original.public_key_cose(), restored.public_key_cose());
        assert!(verify_der(&original.public_key_cose(), message, &restored.sign_der(message)).unwrap());
    }

    #[test]
    fn a_short_scalar_is_refused_rather_than_padded() {
        assert!(CredentialKey::from_scalar(&[0u8; 16]).is_err());
    }

    #[test]
    fn cose_key_layout_is_canonical() {
        let cose = cose_key_es256(&[0xAA; 32], &[0xBB; 32]);

        // map(5), then the five entries in CTAP2 canonical key order.
        assert_eq!(&cose[..6], &[0xA5, 0x01, 0x02, 0x03, 0x26, 0x20]);
        assert_eq!(&cose[6..10], &[0x01, 0x21, 0x58, 0x20]);
        assert_eq!(&cose[10..42], &[0xAA; 32]);
        assert_eq!(&cose[42..45], &[0x22, 0x58, 0x20]);
        assert_eq!(&cose[45..77], &[0xBB; 32]);
        assert_eq!(cose.len(), 77);
    }

    #[test]
    fn credential_ids_do_not_repeat() {
        let a = generate_credential_id().unwrap();
        let b = generate_credential_id().unwrap();
        assert_ne!(a, b);
    }
}
